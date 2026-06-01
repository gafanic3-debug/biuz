import asyncio
import json
import logging
import os
import sys
import time

import aiohttp

from config import FLARESOLVERR_TIMEOUT, FLARESOLVERR_URL

logger = logging.getLogger(__name__)

_flaresolverr_process: asyncio.subprocess.Process | None = None
_flaresolverr_starting = False
_flaresolverr_lock = asyncio.Lock()
_flaresolverr_last_used: float = 0.0
_FLARESOLVERR_IDLE_TIMEOUT = 60  # secondi prima di spegnere FlareSolverr inutilizzato


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
    """Cerca la directory di FlareSolverr."""
    script_path = await _find_flaresolverr_script()
    if script_path:
        return os.path.dirname(os.path.dirname(script_path))
    return None


async def ensure_flaresolverr() -> bool:
    """Avvia FlareSolverr lazy se non già in esecuzione.

    Returns True se FlareSolverr è attivo e raggiungibile.
    """
    global _flaresolverr_process, _flaresolverr_starting, _flaresolverr_last_used

    if not FLARESOLVERR_URL:
        return False

    wait_for_start = False
    async with _flaresolverr_lock:
        if _flaresolverr_starting:
            _flaresolverr_last_used = time.time()
            wait_for_start = True
        elif await _is_flaresolverr_alive():
            _flaresolverr_last_used = time.time()
            return True
        elif _flaresolverr_process and _flaresolverr_process.returncode is None:
            _flaresolverr_last_used = time.time()
            return True
        else:
            script = await _find_flaresolverr_script()
            if not script:
                logger.warning("FlareSolverr script not found, skipping auto-start")
                return False

            fs_dir = os.path.dirname(os.path.dirname(script))
            logger.info("Starting FlareSolverr lazily from %s ...", fs_dir)
            _flaresolverr_starting = True

    if wait_for_start:
        for _ in range(30):
            await asyncio.sleep(1)
            if await _is_flaresolverr_alive():
                _flaresolverr_last_used = time.time()
                return True
        return False

    # Sblocca il lock durante l'avvero (può richiedere secondi)
    try:
        _flaresolverr_process = await asyncio.create_subprocess_exec(
            sys.executable, os.path.basename(script),
            cwd=fs_dir,
            env={**os.environ, "PORT": "8191"},
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        for attempt in range(30):
            await asyncio.sleep(1)
            if _flaresolverr_process.returncode is not None:
                logger.error("FlareSolverr exited prematurely (code %s)", _flaresolverr_process.returncode)
                return False
            if await _is_flaresolverr_alive():
                logger.info("FlareSolverr is ready")
                _flaresolverr_last_used = time.time()
                return True

        logger.warning("FlareSolverr failed to start within 30s")
        return False
    except Exception as e:
        logger.error("FlareSolverr start failed: %s", e)
        return False
    finally:
        _flaresolverr_starting = False


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
    """Ferma FlareSolverr se inattivo oltre il timeout configurato."""
    global _flaresolverr_process
    if _flaresolverr_process and _flaresolverr_process.returncode is None:
        if time.time() - _flaresolverr_last_used > _FLARESOLVERR_IDLE_TIMEOUT:
            logger.info("FlareSolverr idle >%ss, shutting down", _FLARESOLVERR_IDLE_TIMEOUT)
            await shutdown_flaresolverr()

async def shutdown_flaresolverr():
    """Ferma FlareSolverr se avviato da noi."""
    global _flaresolverr_process
    if _flaresolverr_process and _flaresolverr_process.returncode is None:
        _flaresolverr_process.terminate()
        try:
            await asyncio.wait_for(_flaresolverr_process.wait(), timeout=10)
        except asyncio.TimeoutError:
            _flaresolverr_process.kill()
        _flaresolverr_process = None


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
