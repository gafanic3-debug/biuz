import asyncio
import json
import logging
import os
import platform
import signal
import subprocess
import sys
import time

import aiohttp

from config import FLARESOLVERR_TIMEOUT, FLARESOLVERR_URL

logger = logging.getLogger(__name__)

_flaresolverr_process: asyncio.subprocess.Process | None = None
_flaresolverr_owner = False  # True se questo worker ha avviato FlareSolverr
_flaresolverr_ready = asyncio.Event()
_FLARESOLVERR_IDLE_TIMEOUT = 60
_FLARESOLVERR_STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "flaresolverr_state.json")
_FLARESOLVERR_STATE_FILE = os.path.normpath(_FLARESOLVERR_STATE_FILE)
_FLARESOLVERR_LOCK_FILE = _FLARESOLVERR_STATE_FILE + ".lock"


async def _find_flaresolverr_script() -> str | None:
    """Cerca lo script FlareSolverr in varie posizioni."""
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "flaresolverr", "src", "flaresolverr.py"),
        os.path.join(os.getcwd(), "flaresolverr", "src", "flaresolverr.py"),
        os.path.join(os.getcwd(), "src", "flaresolverr.py"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


async def _find_flaresolverr_dir() -> str | None:
    script_path = await _find_flaresolverr_script()
    if script_path:
        return os.path.dirname(os.path.dirname(script_path))
    return None


def _read_fs_state() -> dict | None:
    try:
        with open(_FLARESOLVERR_STATE_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, Exception):
        return None


def _write_fs_state(data: dict):
    tmp = _FLARESOLVERR_STATE_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, _FLARESOLVERR_STATE_FILE)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass


def _remove_fs_state():
    try:
        os.remove(_FLARESOLVERR_STATE_FILE)
    except FileNotFoundError:
        pass
    try:
        os.remove(_FLARESOLVERR_LOCK_FILE)
    except FileNotFoundError:
        pass


def _try_claim_lock() -> bool:
    try:
        fd = os.open(_FLARESOLVERR_LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
        return True
    except FileExistsError:
        return False
    except Exception:
        return False


def _release_lock():
    try:
        os.remove(_FLARESOLVERR_LOCK_FILE)
    except FileNotFoundError:
        pass


def _is_pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def _my_pid() -> int:
    return os.getpid()


def _collect_process_tree(pid: int) -> list[int]:
    """Raccoglie tutti i PID dell'albero (foglie→radice) per kill sicuro."""
    result = []
    try:
        children = []
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                try:
                    with open(f"/proc/{entry}/status", "r") as f:
                        for line in f:
                            if line.startswith("PPid:"):
                                if int(line.split()[1]) == pid:
                                    children.append(int(entry))
                                break
                except (FileNotFoundError, ValueError, OSError):
                    pass
        for child in children:
            result.extend(_collect_process_tree(child))
        result.append(pid)
    except Exception:
        pass
    return result


async def ensure_flaresolverr() -> bool:
    global _flaresolverr_process, _flaresolverr_owner

    if not FLARESOLVERR_URL:
        return False

    if _flaresolverr_process and _flaresolverr_process.returncode is None:
        _touch_last_used()
        return True

    state = _read_fs_state()
    if state:
        pid = state.get("pid", 0)
        if _is_pid_alive(pid) and state.get("status") == "ready":
            if await _is_flaresolverr_alive():
                _touch_last_used()
                return True
        else:
            _remove_fs_state()

    if _try_claim_lock():
        _flaresolverr_owner = True
        _flaresolverr_ready.clear()
        script = await _find_flaresolverr_script()
        if not script:
            _release_lock()
            _flaresolverr_owner = False
            logger.warning("FlareSolverr script not found, skipping auto-start")
            return False

        fs_dir = os.path.dirname(os.path.dirname(script))
        logger.info("Starting FlareSolverr lazily from %s ...", fs_dir)

        try:
            _flaresolverr_process = await asyncio.create_subprocess_exec(
                sys.executable, script,
                cwd=fs_dir,
                env={**os.environ, "PORT": "8191"},
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )

            for attempt in range(30):
                await asyncio.sleep(1)
                if _flaresolverr_process.returncode is not None:
                    logger.error("FlareSolverr exited prematurely (code %s)", _flaresolverr_process.returncode)
                    _remove_fs_state()
                    _release_lock()
                    _flaresolverr_owner = False
                    return False
                if await _is_flaresolverr_alive():
                    _write_fs_state({
                        "pid": _flaresolverr_process.pid,
                        "owner_pid": _my_pid(),
                        "status": "ready",
                        "url": FLARESOLVERR_URL,
                        "last_used": time.time(),
                    })
                    logger.info("FlareSolverr is ready")
                    _flaresolverr_ready.set()
                    return True

            logger.warning("FlareSolverr failed to start within 30s")
            _remove_fs_state()
            _release_lock()
            _flaresolverr_owner = False
            return False
        except Exception as e:
            logger.error("FlareSolverr start failed: %s", e)
            _remove_fs_state()
            _release_lock()
            _flaresolverr_owner = False
            return False
    else:
        logger.info("FlareSolverr being started by another worker, waiting...")
        for _ in range(30):
            await asyncio.sleep(1)
            state = _read_fs_state()
            if state and state.get("status") == "ready":
                if await _is_flaresolverr_alive():
                    _touch_last_used()
                    return True
        logger.warning("Timeout waiting for another worker to start FlareSolverr")
        return False


def _touch_last_used():
    state = _read_fs_state()
    if state:
        state["last_used"] = time.time()
        _write_fs_state(state)


async def _is_flaresolverr_alive() -> bool:
    """Verifica se FlareSolverr risponde."""
    try:
        endpoint = f"{FLARESOLVERR_URL.rstrip('/')}/v1"
        async with aiohttp.ClientSession() as s:
            async with s.post(endpoint, json={"cmd": "sessions.list"}, timeout=3) as r:
                return r.status == 200
    except Exception:
        return False


async def try_shutdown_idle_flaresolverr():
    if not _flaresolverr_owner:
        return
    if not _flaresolverr_process or _flaresolverr_process.returncode is not None:
        return
    state = _read_fs_state()
    if not state:
        return
    if time.time() - state.get("last_used", 0) > _FLARESOLVERR_IDLE_TIMEOUT:
        logger.info("FlareSolverr idle >%ss, shutting down", _FLARESOLVERR_IDLE_TIMEOUT)
        await shutdown_flaresolverr()

async def shutdown_flaresolverr():
    global _flaresolverr_process, _flaresolverr_owner
    proc = _flaresolverr_process
    _flaresolverr_process = None
    _flaresolverr_owner = False
    _remove_fs_state()
    _release_lock()

    if not proc or proc.returncode is not None:
        return

    pid = proc.pid
    if platform.system() == "Windows":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True, timeout=10,
            )
        except Exception:
            pass
    else:
        try:
            pids = _collect_process_tree(pid)
            for p in pids:
                try:
                    os.kill(p, signal.SIGTERM)
                except (ProcessLookupError, OSError):
                    pass
            await asyncio.sleep(2)
            for p in pids:
                try:
                    os.kill(p, signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except (asyncio.TimeoutError, ProcessLookupError):
                pass
            subprocess.run(
                ["pkill", "-f", "chromium.*headless"],
                capture_output=True, timeout=5,
            )
        except ProcessLookupError:
            pass
        except Exception:
            pass


class SolverSessionManager:
    """
    Gestore delle sessioni FlareSolverr.
    Supporta sessioni persistenti esplicite o sessioni temporanee.
    """

    _instance = None
    _persistent_sessions = {}  # {key: session_id}
    _sessions_file = "persistent_sessions.json"
    _lock = asyncio.Lock()
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SolverSessionManager, cls).__new__(cls)
        return cls._instance

    async def _init_if_needed(self):
        if self._initialized:
            return
        async with self._lock:
            if self._initialized:
                return
            if os.path.exists(self._sessions_file):
                try:
                    with open(self._sessions_file, "r") as f:
                        self._persistent_sessions = json.load(f)
                    logger.info(
                        f"FlareSolverr: Caricate {len(self._persistent_sessions)} sessioni persistenti dal file."
                    )
                except Exception as e:
                    logger.warning(f"FlareSolverr: Errore caricamento sessioni: {e}")
            self._initialized = True

    def _save_sessions(self):
        try:
            with open(self._sessions_file, "w") as f:
                json.dump(self._persistent_sessions, f)
        except Exception as e:
            logger.warning(f"FlareSolverr: Errore salvataggio sessioni: {e}")

    async def get_session(self, proxy: str = None) -> tuple[str, bool]:
        """
        Ottiene una sessione FlareSolverr temporanea.
        Ritorna una tupla (session_id, is_persistent).
        """
        await self._init_if_needed()
        if not FLARESOLVERR_URL:
            return None, False
        if not await ensure_flaresolverr():
            return None, False

        session_id = await self._create_session(proxy)
        return session_id, False

    async def get_persistent_session(self, key: str, proxy: str = None) -> str:
        """Ottiene o crea una sessione persistente identificata da una chiave."""
        await self._init_if_needed()
        if not FLARESOLVERR_URL:
            return None
        if not await ensure_flaresolverr():
            return None

        async with self._lock:
            if key in self._persistent_sessions:
                sid = self._persistent_sessions[key]
                if await self._session_exists(sid):
                    return sid
                logger.info(f"FlareSolverr: Sessione {sid} per {key} non piu valida o scaduta.")

            logger.info(f"FlareSolverr: Creazione nuova sessione persistente per chiave: {key}")
            session_id = await self._create_session(proxy)
            if session_id:
                self._persistent_sessions[key] = session_id
                self._save_sessions()
            return session_id

    async def _session_exists(self, session_id: str) -> bool:
        endpoint = f"{FLARESOLVERR_URL.rstrip('/')}/v1"
        payload = {"cmd": "sessions.list"}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(endpoint, json=payload, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return session_id in data.get("sessions", [])
            except Exception:
                pass
        return False

    async def _create_session(self, proxy: str = None) -> str:
        endpoint = f"{FLARESOLVERR_URL.rstrip('/')}/v1"
        payload = {
            "cmd": "sessions.create",
            "maxTimeout": (FLARESOLVERR_TIMEOUT + 60) * 1000,
        }
        if proxy:
            solver_proxy = proxy.replace("socks5h://", "socks5://") if proxy.startswith("socks5h://") else proxy
            payload["proxy"] = {"url": solver_proxy}

        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    endpoint,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("status") == "ok":
                            return data.get("session")
            except Exception as e:
                logger.error(f"FlareSolverr: Errore creazione sessione: {e}")
        return None

    async def release_session(self, session_id: str, is_persistent: bool):
        """Chiude la sessione se non e persistente."""
        if not session_id or is_persistent or not FLARESOLVERR_URL:
            return

        endpoint = f"{FLARESOLVERR_URL.rstrip('/')}/v1"
        payload = {"cmd": "sessions.destroy", "session": session_id}
        async with aiohttp.ClientSession() as session:
            try:
                await session.post(endpoint, json=payload, timeout=10)
            except Exception:
                pass


solver_manager = SolverSessionManager()
