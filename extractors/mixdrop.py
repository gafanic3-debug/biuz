import asyncio
import logging
import re
import time
import os
from urllib.parse import urlparse, urljoin, urlencode

import aiohttp
from aiohttp import ClientSession, TCPConnector
from bs4 import BeautifulSoup

from config import (
    FLARESOLVERR_URL, 
    FLARESOLVERR_TIMEOUT, 
    get_proxy_for_url, 
    TRANSPORT_ROUTES, 
    get_solver_proxy_url, 
    GLOBAL_PROXIES,
    get_connector_for_proxy
)
from utils.cookie_cache import CookieCache
from utils.solver_manager import solver_manager

logger = logging.getLogger(__name__)

class ExtractorError(Exception):
    pass

class Settings:
    flaresolverr_url = FLARESOLVERR_URL
    flaresolverr_timeout = FLARESOLVERR_TIMEOUT

settings = Settings()

class MixdropExtractor:
    _result_cache = {} # {(url, bypass_warp): (result, timestamp)}

    def __init__(self, request_headers: dict = None, proxies: list = None, bypass_warp: bool = False):
        self.request_headers = request_headers or {}
        self.base_headers = self.request_headers.copy()
        if "User-Agent" not in self.base_headers and "user-agent" not in self.base_headers:
             self.base_headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        self.proxies = proxies or GLOBAL_PROXIES
        self.cookie_cache = CookieCache("universal")
        self.mediaflow_endpoint = "proxy_stream_endpoint"
        self.bypass_warp_active = bypass_warp
        self.session = None
    async def _get_session(self, proxy: str = None) -> aiohttp.ClientSession:
        """Create a session, optionally with a proxy connector."""
        connector = None
        if proxy:
            connector = get_connector_for_proxy(proxy)
        
        if proxy:
            return aiohttp.ClientSession(headers=self.base_headers, connector=connector)
            
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(headers=self.base_headers)
        return self.session

    async def _request_flaresolverr(self, cmd: str, url: str = None, post_data: str = None, session_id: str = None, wait: int = 0, headers: dict | None = None) -> dict:
        endpoint = f"{settings.flaresolverr_url.rstrip('/')}/v1"
        payload = {"cmd": cmd, "maxTimeout": (settings.flaresolverr_timeout + 60) * 1000}
        if wait > 0: payload["wait"] = wait
        fs_headers = {}
        if url: 
            payload["url"] = url
            proxy = get_proxy_for_url(url, TRANSPORT_ROUTES, self.proxies, bypass_warp=self.bypass_warp_active)
            if proxy:
                payload["proxy"] = {"url": proxy}
                fs_headers["X-Proxy-Server"] = get_solver_proxy_url(proxy)
        if post_data: payload["postData"] = post_data
        if session_id: payload["session"] = session_id
        async with aiohttp.ClientSession() as fs_session:
            async with fs_session.post(endpoint, json=payload, headers=fs_headers, timeout=settings.flaresolverr_timeout + 95) as resp:
                data = await resp.json()
        if data.get("status") != "ok": raise ExtractorError(f"FlareSolverr: {data.get('message')}")
        return data

    def _step_headers(self, ua: str, referer: str | None = None) -> dict:
        headers = {"User-Agent": ua}
        if referer:
            headers["Referer"] = referer
        return headers

    async def _light_fetch(
        self,
        headers: dict,
        cookies: dict,
        session_id: str,
        target_url: str,
        post_data: dict | None = None,
        referer: str | None = None,
        force_flaresolverr: bool = False,
    ) -> tuple[str | None, str]:
        request_headers = dict(headers)
        if referer:
            request_headers["Referer"] = referer
            
        if force_flaresolverr:
            try:
                fs_cmd = "request.post" if post_data else "request.get"
                fs_res = await self._request_flaresolverr(fs_cmd, target_url, urlencode(post_data) if post_data else None, session_id=session_id)
                sol = fs_res.get("solution", {})
                cookies.update({c["name"]: c["value"] for c in sol.get("cookies", [])})
                return sol.get("response", ""), sol.get("url", target_url)
            except Exception:
                return None, target_url

        async def try_path(p, is_fs=False):
            try:
                request_headers = dict(headers)
                if referer: request_headers["Referer"] = referer
                
                if is_fs:
                    fs_cmd = "request.post" if post_data else "request.get"
                    fs_res = await self._request_flaresolverr(fs_cmd, target_url, urlencode(post_data) if post_data else None, session_id=session_id)
                    sol = fs_res.get("solution", {})
                    return sol.get("response", ""), sol.get("url", target_url), {c["name"]: c["value"] for c in sol.get("cookies", [])}
                else:
                    connector = get_connector_for_proxy(p) if p else TCPConnector(ssl=False)
                    async with ClientSession(connector=connector, headers=self.base_headers) as local_session:
                        if post_data:
                            async with local_session.post(target_url, data=post_data, cookies=cookies, headers=request_headers, timeout=12) as r:
                                if r.status == 200:
                                    text = await r.text()
                                    if not any(m in text.lower() for m in ["cf-challenge", "ray id", "checking your browser"]):
                                        return text, str(r.url), {k: v.value for k, v in r.cookies.items()}
                        else:
                            async with local_session.get(target_url, cookies=cookies, headers=request_headers, timeout=12) as r:
                                if r.status == 200:
                                    text = await r.text()
                                    if not any(m in text.lower() for m in ["cf-challenge", "ray id", "checking your browser"]):
                                        return text, str(r.url), {k: v.value for k, v in r.cookies.items()}
            except: pass
            return None

        # 1. Try Preferred Proxy, Direct, and FlareSolverr in parallel
        preferred_proxy = get_proxy_for_url(target_url, TRANSPORT_ROUTES, self.proxies, self.bypass_warp_active)
        tasks = [
            asyncio.create_task(try_path(preferred_proxy)) if preferred_proxy else None,
            asyncio.create_task(try_path(None)),
            asyncio.create_task(try_path(None, is_fs=True))
        ]
        tasks = [t for t in tasks if t]
        
        for task in asyncio.as_completed(tasks):
            res = await task
            if res:
                text, final_url, new_cookies = res
                cookies.update(new_cookies)
                return text, final_url

        return None, target_url

    def _unpack(self, packed_js: str) -> str:
        try:
            match = re.search(r'}\(\'(.*)\',(\d+),(\d+),\'(.*)\'\.split\(\'\|\'\)', packed_js)
            if not match:
                match = re.search(r'\}\(([\s\S]*?),\s*(\d+),\s*(\d+),\s*\'([\s\S]*?)\'\.split\(\'\|\'\)', packed_js)
            if not match: return packed_js
            p, a, c, k = match.groups()
            p = p.strip("'\"")
            a, c, k = int(a), int(c), k.split('|')
            def e(c):
                res = ""
                if c >= a: res = e(c // a)
                return res + "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"[c % a]
            d = {e(i): (k[i] if k[i] else e(i)) for i in range(c)}
            for i in range(c):
                if str(i) not in d: d[str(i)] = k[i] if k[i] else str(i)
            return re.sub(r'\b(\w+)\b', lambda m: d.get(m.group(1), m.group(1)), p)
        except Exception as e:
            logger.debug(f"Unpack failed: {e}")
            return packed_js

    async def extract(self, url: str, **kwargs) -> dict:
        normalized_url = url.strip().replace(" ", "%20")
        cache_key = (normalized_url, self.bypass_warp_active)
        if cache_key in MixdropExtractor._result_cache:
            result, timestamp = MixdropExtractor._result_cache[cache_key]
            if time.time() - timestamp < 600:
                logger.info(f"🚀 [Cache Hit] Using cached extraction result for: {normalized_url}")
                return result

        logger.info(f"🔍 [Cache Miss] Extracting new link for: {normalized_url}")
        proxy = get_proxy_for_url(normalized_url, TRANSPORT_ROUTES, self.proxies, self.bypass_warp_active)
        final_session_id = await solver_manager.get_persistent_session("mixdrop", proxy)
        session_id = final_session_id
        is_persistent = True
        try:
            ua, cookies = self.base_headers.get("User-Agent"), {}
            if "/f/" in url: url = url.replace("/f/", "/e/")
            if "/mix/" in url: url = url.replace("/mix/", "/e/")
            
            mirrors = [
                url,
                url.replace("mixdrop.co", "mixdrop.vip"),
                url.replace("mixdrop.co", "m1xdrop.bz"),
                url.replace("mixdrop.co", "mixdrop.ch"),
                url.replace("mixdrop.co", "mixdrop.ps"),
                url.replace("mixdrop.co", "mixdrop.ag"),
            ]
            
            async def solve_url(current_url, depth=0):
                if depth > 3: return None
                try:
                    m_headers = self._step_headers(ua, current_url)
                    pref_p = get_proxy_for_url(current_url, TRANSPORT_ROUTES, self.proxies, self.bypass_warp_active)
                    
                    async def fetch_direct():
                        try:
                            connector = get_connector_for_proxy(pref_p) if pref_p else TCPConnector(ssl=False)
                            async with ClientSession(connector=connector, headers=self.base_headers) as local_session:
                                async with local_session.get(current_url, cookies=cookies, headers=m_headers, timeout=10) as r:
                                    if r.status == 200:
                                        t = await r.text()
                                        if not any(m in t.lower() for m in ["cf-challenge", "robot", "checking your browser"]):
                                            return t, str(r.url), ua, {}
                        except: pass
                        return None

                    async def fetch_fs():
                        try:
                            res = await self._request_flaresolverr("request.get", current_url, session_id=session_id, wait=0)
                            sol = res.get("solution", {})
                            return sol.get("response", ""), sol.get("url", current_url), sol.get("userAgent", ua), {c["name"]: c["value"] for c in sol.get("cookies", [])}
                        except: pass
                        return None

                    tasks = [asyncio.create_task(fetch_direct()), asyncio.create_task(fetch_fs())]
                    for t in asyncio.as_completed(tasks):
                        res = await t
                        if res and res[0]:
                            html, final_url, ua_res, new_cookies = res
                            cookies.update(new_cookies)
                            
                            # Unpack JS
                            if "eval(function(p,a,c,k,e,d)" in html:
                                for block in re.findall(r'eval\(function\(p,a,c,k,e,d\).*?\}\(.*\)\)', html, re.S):
                                    html += "\n" + self._unpack(block)

                            # Find video patterns
                            patterns = [
                                r'(?:MDCore|vsConfig)\.wurl\s*=\s*["\']([^"\']+)["\']', 
                                r'source\s*src\s*=\s*["\']([^"\']+)["\']', 
                                r'file:\s*["\']([^"\']+)["\']', 
                                r'["\'](https?://[^\s"\']+\.(?:mp4|m3u8)[^\s"\']*)["\']',
                                r'wurl\s*:\s*["\']([^"\']+)["\']'
                            ]
                            for p in patterns:
                                match = re.search(p, html)
                                if match:
                                    v_url = match.group(1)
                                    if v_url.startswith("//"): v_url = "https:" + v_url
                                    return self._build_result(v_url, final_url, ua_res, cookies=cookies)

                            # Check for iframes
                            soup = BeautifulSoup(html, "lxml")
                            iframe = soup.find("iframe", src=re.compile(r'/e/|/emb', re.I))
                            if iframe:
                                iframe_url = urljoin(final_url, iframe["src"])
                                return await solve_url(iframe_url, depth + 1)
                except: pass
                return None

            # Test all mirrors in parallel
            mirror_tasks = [asyncio.create_task(solve_url(m)) for m in mirrors]
            for mt in asyncio.as_completed(mirror_tasks):
                result = await mt
                if result:
                    MixdropExtractor._result_cache[cache_key] = (result, time.time())
                    return result

            raise ExtractorError("Mixdrop: Video source not found")
        finally:
            if final_session_id:
                await solver_manager.release_session(final_session_id, is_persistent)

    def _build_result(self, video_url: str, referer: str, ua: str, cookies: dict = None) -> dict:
        headers = {"Referer": referer, "User-Agent": ua, "Origin": f"https://{urlparse(referer).netloc}"}
        if cookies:
            headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        return {"destination_url": video_url, "request_headers": headers, "mediaflow_endpoint": self.mediaflow_endpoint, "bypass_warp": self.bypass_warp_active}

    async def close(self):
        if self.session and not self.session.closed: await self.session.close()
