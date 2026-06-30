import asyncio
import json
import logging
import os
import shutil
from typing import Any

from extractors.base import BaseExtractor, ExtractorError
logger = logging.getLogger(__name__)

EMBEDST_ORIGIN = "https://embed.st"

# Absolute path to the Node.js headless runner (no browser).
_RUNNER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "embedst_runner.mjs")


class EmbedStExtractor(BaseExtractor):
    """Extractor for embed.st / embedsports embeds.

    embed.st gates the stream URL behind an obfuscated wasm-bindgen module
    (lock.js + lock.wasm) that runs in-page. A pure HTTP/regex extraction is
    not possible, so we execute the page's own JS+WASM in a headless Node vm
    sandbox (no browser, no Playwright) and capture the .m3u8 URL the WASM
    computes and fetches at runtime.

    Requires Node.js (>= 18, for native fetch + WebAssembly) on PATH, invoked
    with --experimental-vm-modules (embed.st uses dynamic ESM import()).
    """

    def __init__(self, request_headers: dict, proxies: list = None, bypass_warp: bool = False):
        super().__init__(request_headers, proxies, extractor_name="embedst")
        self.bypass_warp_active = bypass_warp
        self.mediaflow_endpoint = "hls_manifest_proxy"
        self._curl_session = None

    @staticmethod
    def _node_bin() -> str | None:
        return shutil.which("node")

    async def extract(self, url: str, **kwargs) -> dict[str, Any]:
        node = self._node_bin()
        if not node:
            raise ExtractorError("EmbedSt: node binary not found on PATH (required for headless WASM extraction)")

        # If this is a streamed.pk/watch/ page, resolve the embed.st iframe URL first.
        url = await self._resolve_embed_url(url)

        if "embed.st/embed/" not in url.lower() and "embedsports.top/embed/" not in url.lower():
            raise ExtractorError("EmbedSt: invalid embed URL (expected embed.st/embed/...)")

        if not os.path.exists(_RUNNER):
            raise ExtractorError(f"EmbedSt: runner script not found at {_RUNNER}")

        env = dict(os.environ)
        if kwargs.get("background_refresh") or kwargs.get("force_refresh"):
            env["EMBEDST_DEBUG"] = "1"

        try:
            proc = await asyncio.create_subprocess_exec(
                node, "--experimental-vm-modules", _RUNNER, url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError as exc:
            raise ExtractorError(f"EmbedSt: failed to spawn node: {exc}") from exc

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            raise ExtractorError("EmbedSt: node runner timed out")

        out = stdout.decode("utf-8", errors="ignore").strip() if stdout else ""
        if proc.returncode != 0 or not out:
            err = stderr.decode("utf-8", errors="ignore")[-800:] if stderr else ""
            raise ExtractorError(f"EmbedSt: runner failed (rc={proc.returncode}): {err}")

        try:
            data = json.loads(out)
        except json.JSONDecodeError as exc:
            raise ExtractorError(f"EmbedSt: invalid runner output: {exc}") from exc

        m3u8 = data.get("m3u8")
        if not m3u8:
            raise ExtractorError(f"EmbedSt: no m3u8 captured ({data.get('error', 'unknown')})")

        headers = data.get("headers") or {}
        # The stream CDN (strmd.st) needs exactly these headers (UA/Referer/Origin).
        # Do NOT forward the browser client's request_headers here: they contain
        # Host: <localhost> and the admin Cookie, which make strmd.st drop the
        # connection. Per-call overrides come via query params, not request_headers.
        final_headers = dict(headers)

        logger.info("EmbedSt extracted: %s", m3u8[:90])

        # Fetch the manifest content so the proxy can rewrite variant URLs.
        # strmd.st rejects plain aiohttp (TLS/HTTP-2 disconnect) but curl_cffi
        # (Chrome impersonation) works. The runner's own Node fetch is 403 here,
        # so we fetch the body from Python.
        captured_manifest = await self._fetch_manifest(m3u8, final_headers)

        return {
            "destination_url": m3u8,
            "request_headers": final_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
            "captured_manifest": captured_manifest,
            "captured_manifests": {m3u8: captured_manifest} if captured_manifest else {},
            "bypass_warp": self.bypass_warp_active,
        }

    async def _resolve_embed_url(self, url: str) -> str:
        """If given a streamed.pk/watch/ page URL, fetch it and extract the embed.st iframe src."""
        if "streamed.pk/watch/" not in (url or "").lower():
            return url
        try:
            session = await self._get_session(url)
            headers = {"User-Agent": self.base_headers["User-Agent"], "Referer": "https://streamed.pk/"}
            async with session.get(url, headers=headers, timeout=30) as resp:
                if resp.status != 200:
                    raise ExtractorError(f"EmbedSt: streamed.pk returned HTTP {resp.status}")
                html = await resp.text()
        except ExtractorError:
            raise
        except Exception as exc:
            raise ExtractorError(f"EmbedSt: failed to fetch streamed.pk page: {exc}") from exc

        import re
        m = re.search(r'https?://(?:embed\.st|embedsports\.top)/embed/[^"\'<>)\s]+', html, re.IGNORECASE)
        if not m:
            raise ExtractorError("EmbedSt: no embed.st iframe found on streamed.pk page")
        resolved = m.group(0)
        logger.info("EmbedSt: streamed.pk -> %s", resolved[:80])
        return resolved

    async def _get_curl_session(self):
        """Get or create a persistent curl_cffi session."""
        if self._curl_session is None:
            from curl_cffi import AsyncSession
            self._curl_session = AsyncSession(impersonate="chrome124")
        return self._curl_session

    async def _fetch_manifest(self, url: str, headers: dict) -> str | None:
        try:
            s = await self._get_curl_session()
            resp = await s.get(url, headers=headers, timeout=20, allow_redirects=True)
            if resp.status_code == 200:
                return resp.text
            logger.debug("EmbedSt manifest fetch curl_cffi status %s", resp.status_code)
        except Exception as exc:
            logger.debug("EmbedSt curl_cffi manifest fetch failed: %s", exc)
        # Fallback to aiohttp
        try:
            session = await self._get_session(url)
            async with session.get(url, headers=headers, timeout=20) as resp:
                if resp.status == 200:
                    return await resp.text()
                logger.debug("EmbedSt manifest fetch aiohttp status %s", resp.status)
        except Exception as exc:
            logger.debug("EmbedSt aiohttp manifest fetch failed: %s", exc)
        return None

    async def close(self):
        if self._curl_session is not None:
            try:
                await self._curl_session.close()
            except Exception:
                pass
            self._curl_session = None
        if self.session and not self.session.closed:
            await self.session.close()
