import base64
import yarl
import json
import logging
import re
import urllib.parse
from typing import Any, Optional

import aiohttp
import config as _cfg
from config import FLARESOLVERR_URL, FLARESOLVERR_TIMEOUT, get_solver_proxy_url, build_proxy_with_auth, get_ordered_proxies_for_url, should_allow_direct_fallback
from curl_cffi.requests import AsyncSession
from utils.solver_manager import ensure_flaresolverr

logger = logging.getLogger(__name__)

class ExtractorError(Exception):
    pass

class CinemaCityExtractor:
    """CinemaCity m3u8 extractor (FlareSolverr CF + curl_cffi requests)."""

    def __init__(self, request_headers: dict, proxies: list = None):
        self.request_headers = request_headers
        self.proxies = proxies or _cfg.GLOBAL_PROXIES
        self._cookies = None
        self._user_agent = None
        self.base_url = "https://cinemacity.cc"
        self.flaresolverr_url = FLARESOLVERR_URL
        self.flaresolverr_timeout = FLARESOLVERR_TIMEOUT
        self.last_used_proxy = None

    @staticmethod
    def _normalize_proxy_url(proxy_value: str) -> str:
        proxy_value = proxy_value.strip()
        if proxy_value.startswith("socks5://"):
            return proxy_value.replace("socks5://", "socks5h://", 1)
        if proxy_value.startswith("socks4://") or proxy_value.startswith("socks4a://"):
            return proxy_value
        if "://" not in proxy_value:
            return f"socks5h://{proxy_value}"
        return proxy_value

    async def _ensure_cookies(self):
        if self._cookies and self._user_agent:
            return
        await ensure_flaresolverr()
        endpoint = f"{self.flaresolverr_url.rstrip('/')}/v1"
        proxies_to_try = get_ordered_proxies_for_url(self.base_url, "cinemacity", self.proxies)
        if should_allow_direct_fallback(proxies_to_try):
            proxies_to_try.append(None)
        logger.info(f"CinemaCity FS proxy list ({len(proxies_to_try)}): {[p or 'direct' for p in proxies_to_try[:5]]}...")

        for proxy in proxies_to_try:
            payload = {"cmd": "request.get", "url": self.base_url, "maxTimeout": (self.flaresolverr_timeout + 60) * 1000}
            if proxy:
                p = build_proxy_with_auth(proxy)
                if p:
                    payload["proxy"] = p
            async with aiohttp.ClientSession() as s:
                async with s.post(endpoint, json=payload, timeout=aiohttp.ClientTimeout(total=self.flaresolverr_timeout + 95)) as r:
                    d = await r.json()
            if d.get("status") == "ok":
                self._cookies = {c["name"]: c["value"] for c in d["solution"].get("cookies", [])}
                self._user_agent = d["solution"].get("userAgent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
                self.last_used_proxy = self._normalize_proxy_url(proxy) if proxy else None
                logger.info(f"CinemaCity: FS cookies via {proxy or 'direct'}: {list(self._cookies.keys())}")
                return
            logger.warning("CinemaCity FS failed via %s: %s", proxy or "direct", d.get("message", ""))
        raise ExtractorError("FlareSolverr: all attempts failed for cinemacity")

    def _build_cookie_str(self, extra_cookies: str = "") -> str:
        parts = [f"{k}={v}" for k, v in self._cookies.items()]
        if extra_cookies:
            parts.append(extra_cookies)
        return "; ".join(parts)

    async def _fetch_page(self, url: str, session_cookies: str = "") -> tuple[str, dict]:
        await self._ensure_cookies()
        cookie_str = self._build_cookie_str(session_cookies)

        request_kwargs = {}
        if self.last_used_proxy:
            request_kwargs["proxies"] = {"http": self.last_used_proxy, "https": self.last_used_proxy}

        async with AsyncSession(impersonate="chrome124") as sess:
            r = await sess.get(url, headers={
                "User-Agent": self._user_agent,
                "Cookie": cookie_str,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Referer": "https://cinemacity.cc/",
            }, timeout=_cfg.PROXY_TEST_TIMEOUT, **request_kwargs)
            html = r.text
            resp_cookies = dict(r.cookies) if hasattr(r, 'cookies') else {}
            logger.info(f"CinemaCity: curl_cffi status={r.status_code} len={len(html)}")
            return html, resp_cookies

    def base64_decode(self, data: str) -> str:
        try:
            missing_padding = len(data) % 4
            if missing_padding: data += '=' * (4 - missing_padding)
            decoded_bytes = base64.b64decode(data)
            try: return decoded_bytes.decode('utf-8')
            except: return decoded_bytes.decode('latin-1')
        except: return ""

    def get_session_cookies(self) -> str:
        return self.base64_decode("ZGxlX3VzZXJfaWQ9NDg4Mjc7IGRsZV9wYXNzd29yZD03N2VjM2E4MTZjOThmMTRlZWI5M2RlNGI0YWM0ZjBiZDs=")

    def extract_json_array(self, decoded: str) -> Optional[str]:
        start = decoded.find("file:")
        if start == -1: start = decoded.find("sources:")
        if start == -1: return None
        start = decoded.find("[", start)
        if start == -1: return None
        depth = 0
        for i in range(start, len(decoded)):
            if decoded[i] == "[": depth += 1
            elif decoded[i] == "]": depth -= 1
            if depth == 0: return decoded[start:i+1]
        return None

    def _collect_file_entries(self, items) -> list[dict]:
        entries = []
        if isinstance(items, list):
            for item in items:
                entries.extend(self._collect_file_entries(item))
        elif isinstance(items, dict):
            if isinstance(items.get("file"), str) and items.get("file"):
                entries.append(items)
            folder = items.get("folder")
            if isinstance(folder, list):
                entries.extend(self._collect_file_entries(folder))
        return entries

    def pick_stream(self, file_data, media_type: str, season: int = 1, episode: int = 1) -> Optional[str]:
        if isinstance(file_data, str): return file_data
        if isinstance(file_data, list):
            if media_type == 'movie' or all(isinstance(x, dict) and "file" in x and "folder" not in x for x in file_data):
                return file_data[0].get('file') if file_data else None

            selected_season = None
            for s in file_data:
                if not isinstance(s, dict) or "folder" not in s: continue
                title = s.get('title', "").lower()
                if re.search(rf"(?:season|stagione|s)\s*0*{season}\b", title, re.I):
                    selected_season = s['folder']
                    break
            if not selected_season and file_data:
                for s in file_data:
                    if isinstance(s, dict) and "folder" in s:
                        selected_season = s['folder']
                        break
            if not selected_season: return None

            selected_ep = None
            episode_candidates = self._collect_file_entries(selected_season)
            for e in episode_candidates:
                if not isinstance(e, dict) or "file" not in e: continue
                title = e.get('title', "").lower()
                if re.search(rf"(?:episode|episodio|e)\s*0*{episode}\b", title, re.I):
                    selected_ep = e['file']
                    break
            if not selected_ep:
                idx = max(0, int(episode) - 1)
                if episode_candidates:
                    ep_data = episode_candidates[idx] if idx < len(episode_candidates) else episode_candidates[0]
                    selected_ep = ep_data.get('file')

            if selected_ep:
                logger.debug(f"CinemaCity: Selected S{season}E{episode} -> {selected_ep[:50]}...")
            else:
                logger.warning(f"CinemaCity: Failed to find S{season}E{episode} in file_data")
            return selected_ep
        return None

    def _parse_atob_data(self, html: str) -> any:
        for match in re.finditer(r'(?:window\.)?atob\s*\(\s*["\'](.*?)["\']\s*\)', html, re.I):
            encoded = match.group(1)
            if len(encoded) < 50: continue
            decoded = self.base64_decode(encoded)
            if not decoded: continue

            if decoded.strip().startswith("["):
                try:
                    data = json.loads(decoded)
                    if data: return data
                except json.JSONDecodeError:
                    pass

            raw_json = self.extract_json_array(decoded)
            if raw_json:
                try:
                    clean = re.sub(r'\\(.)', r'\1', raw_json)
                    data = json.loads(clean)
                except json.JSONDecodeError:
                    try:
                        data = json.loads(raw_json)
                    except json.JSONDecodeError:
                        pass
                if data: return data

            # Playerjs file param: file:'[{"title":"TS","file":"https://...",...}]'
            pj_match = re.search(r"file\s*:\s*'(\[.*?\])'", decoded, re.I | re.S)
            if pj_match:
                raw_json_str = pj_match.group(1).replace("\\'", "'").replace('\\"', '"')
                try:
                    data = json.loads(raw_json_str)
                    if data: return data
                except json.JSONDecodeError:
                    pass

            file_match = re.search(r'(?:file|sources)\s*:\s*["\'](.*?)["\']', decoded, re.I)
            if file_match:
                f_url = file_match.group(1)
                if '.m3u8' in f_url or '.mp4' in f_url:
                    return f_url
        return None

    def _parse_script_data(self, html: str) -> any:
        for script_match in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.I | re.S):
            script = script_match.group(1)
            if not script: continue

            for pattern in [r'file\s*:\s*(\[.*?\])\s*[,;]', r'sources\s*:\s*(\[.*?\])\s*[,;]']:
                match = re.search(pattern, script, re.I | re.S)
                if match:
                    try:
                        data = json.loads(match.group(1))
                        if data: return data
                    except json.JSONDecodeError:
                        pass

            url_match = re.search(r'["\'](https?://[^"\']*\.m3u8[^"\']*)["\']', script)
            if url_match:
                return url_match.group(1)

        for pattern in [r'file:\s*(\[.*?\])\s*}', r'sources:\s*(\[.*?\])\s*}']:
            match = re.search(pattern, html, re.I | re.S)
            if match:
                try:
                    data = json.loads(match.group(1))
                    if data: return data
                except json.JSONDecodeError:
                    pass
        return None

    async def extract(self, url: str, **kwargs) -> dict:
        cookies = self.get_session_cookies()

        media_type = kwargs.get('type')
        if not media_type:
            lowered_url = url.lower()
            if "/tv-series/" in lowered_url or "/serie-tv/" in lowered_url:
                media_type = "series"
            else:
                media_type = "movie"

        url_params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)

        s_val = kwargs.get('s') or kwargs.get('season') or url_params.get('s', [None])[0] or url_params.get('season', ['1'])[0]
        e_val = kwargs.get('e') or kwargs.get('episode') or url_params.get('e', [None])[0] or url_params.get('episode', ['1'])[0]

        season = int(s_val) if str(s_val).isdigit() else 1
        episode = int(e_val) if str(e_val).isdigit() else 1
        if media_type == "movie" and (url_params.get('s') or url_params.get('season') or url_params.get('e') or url_params.get('episode')):
            media_type = "series"

        html, dynamic_cookies = await self._fetch_page(url, cookies)

        if not html or len(html) < 100:
            logger.warning(f"CinemaCity: failed to fetch page (len={len(html)})")
            raise ExtractorError("Failed to retrieve page content")

        file_data = self._parse_atob_data(html)
        if not file_data:
            file_data = self._parse_script_data(html)

        if not file_data:
            logger.warning("CinemaCity: no stream data in page (len=%d)", len(html))
            snippet = html[3000:5000] if len(html) > 5000 else html[:2000]
            logger.debug("CinemaCity snippet: %s", snippet[:500])
            raise ExtractorError("Stream not found")

        iframe_match = re.search(r'<iframe[^>]+src=["\']([^"\']*player\.php[^"\']*)["\']', html, re.I)
        player_referer = urllib.parse.urljoin(url, iframe_match.group(1)) if iframe_match else url

        stream_url = self.pick_stream(file_data, media_type, season, episode)
        if not stream_url: raise ExtractorError("Pick failed")

        safe_url = str(yarl.URL(stream_url, encoded=True))

        merged_cookies = {}
        for c in cookies.split(";"):
            if "=" in c:
                k, v = c.strip().split("=", 1)
                merged_cookies[k] = v
        if self._cookies:
            merged_cookies.update(self._cookies)
        if dynamic_cookies:
            merged_cookies.update(dynamic_cookies)

        clean_cookies = "; ".join([f"{k}={v}" for k, v in merged_cookies.items()]).strip().rstrip(';')

        try:
            origin = urllib.parse.urlparse(url)
            origin_str = f"{origin.scheme}://{origin.netloc}"
        except Exception:
            origin_str = self.base_url

        return {
            "destination_url": safe_url,
            "request_headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Referer": player_referer, "Origin": origin_str,
                "Cookie": clean_cookies, "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5", "Connection": "keep-alive"
            },
            "mediaflow_endpoint": "hls_manifest_proxy" if ".m3u8" in safe_url else "proxy_stream_endpoint"
        }

    async def close(self):
        pass
