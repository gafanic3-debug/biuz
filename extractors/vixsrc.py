import asyncio
import json
import logging
import os
import random
import re
import threading
import time
from typing import Any, Dict
from urllib.parse import parse_qs, parse_qsl, urlencode, urljoin, urlparse, urlunparse

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from aiohttp_socks import ProxyError as AioProxyError
from python_socks import ProxyError as PyProxyError
from config import get_proxy_for_url, TRANSPORT_ROUTES, GLOBAL_PROXIES, get_connector_for_proxy, SELECTED_PROXY_CONTEXT, get_solver_proxy_url
from config import PROXY_TEST_TIMEOUT, PROXY_TEST_CONCURRENCY
from config import FLARESOLVERR_URL, FLARESOLVERR_TIMEOUT, WARP_PROXY_URL

logger = logging.getLogger(__name__)


class ExtractorError(Exception):
    """Eccezione personalizzata per errori di estrazione."""


class VixSrcExtractor:
    """VixSrc URL extractor per risolvere link VixSrc."""
    def __init__(self, request_headers: dict, proxies: list = None):
        self.request_headers = request_headers
        self.base_headers = self._default_headers()
        self.session = None
        self.mediaflow_endpoint = "hls_manifest_proxy"
        self._session_lock = asyncio.Lock()
        self.proxies = []
        for proxy in list(proxies or []) + list(GLOBAL_PROXIES):
            if proxy and proxy not in self.proxies:
                self.proxies.append(proxy)
        self.is_vixsrc = True
        self.extractor_name = "vixsrc"
        self.last_used_proxy = None
        self.flaresolverr_url = FLARESOLVERR_URL
        self.flaresolverr_timeout = FLARESOLVERR_TIMEOUT
        self._fs_cookies = None
        self._fs_user_agent = None
        self._fs_proxy = None
        logger.info(
            "VixSrc proxy config: transport_routes=%d extractor_proxies=%d resolved_vixsrc=%s",
            len(TRANSPORT_ROUTES),
            len(self.proxies or []),
            get_proxy_for_url("https://vixsrc.to/", TRANSPORT_ROUTES, self.proxies or []),
        )
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

    @staticmethod
    def _default_headers() -> dict:
        return {
            "user-agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.5",
            "accept-encoding": "gzip, deflate",
            "connection": "keep-alive",
        }

    async def _ensure_fs_cookies(self, target_url: str):
        if self._fs_cookies and self._fs_user_agent:
            return
        site = self._normalize_base_site(target_url)
        endpoint = f"{self.flaresolverr_url.rstrip('/')}/v1"
        warp = WARP_PROXY_URL.strip()
        proxies_to_try = []
        if warp:
            proxies_to_try.append(get_solver_proxy_url(warp))
        route_proxy = get_proxy_for_url(site, TRANSPORT_ROUTES, self.proxies)
        if route_proxy:
            solver_route_proxy = get_solver_proxy_url(route_proxy)
            if solver_route_proxy not in proxies_to_try:
                proxies_to_try.append(solver_route_proxy)
        # FlareSolverr opens a browser per attempt; keep this short.
        # Normal Cloudflare bypass is handled by curl_cffi proxy rotation first.
        for proxy in (self.proxies or [])[:3]:
            solver_proxy = get_solver_proxy_url(proxy) if proxy else None
            if solver_proxy and solver_proxy not in proxies_to_try:
                proxies_to_try.append(solver_proxy)
        if None not in proxies_to_try:
            proxies_to_try.append(None)
        for proxy in proxies_to_try:
            payload = {"cmd": "request.get", "url": site, "maxTimeout": (self.flaresolverr_timeout + 60) * 1000}
            if proxy:
                payload["proxy"] = proxy
            try:
                async with aiohttp.ClientSession() as s:
                    async with s.post(endpoint, json=payload, timeout=aiohttp.ClientTimeout(total=self.flaresolverr_timeout + 95)) as r:
                        d = await r.json()
                if d.get("status") == "ok":
                    self._fs_cookies = {c["name"]: c["value"] for c in d["solution"].get("cookies", [])}
                    self._fs_user_agent = d["solution"].get("userAgent",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
                    self._fs_proxy = proxy
                    self.last_used_proxy = self._normalize_proxy_url(proxy) if proxy else None
                    logger.info(f"VixSrc: FS cookies via {proxy or 'direct'}: {list(self._fs_cookies.keys())}")
                    return
                logger.warning("FS failed via %s: %s", proxy or "direct", d.get("message", ""))
            except Exception as e:
                logger.warning("FS error via %s: %s", proxy or "direct", e)
        raise ExtractorError("FlareSolverr: all attempts failed")

    async def _make_fs_request(self, url: str, headers: dict = None):
        from curl_cffi.requests import AsyncSession as CurlAsyncSession
        await self._ensure_fs_cookies(url)
        cookie_str = "; ".join(f"{k}={v}" for k, v in self._fs_cookies.items())
        final_headers = {
            "User-Agent": self._fs_user_agent,
            "Cookie": cookie_str,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        if headers:
            final_headers.update(headers)
        final_headers.pop("accept-encoding", None)

        request_kwargs = {}
        if self._fs_proxy:
            proxy_url = self._normalize_proxy_url(self._fs_proxy)
            request_kwargs["proxies"] = {"http": proxy_url, "https": proxy_url}

        async with CurlAsyncSession(impersonate="chrome124") as sess:
            r = await sess.get(url, headers=final_headers, timeout=30, allow_redirects=True, **request_kwargs)
            html = r.text
            logger.info(f"VixSrc FS: curl_cffi status={r.status_code} len={len(html) if html else 0} for {url}")
            if r.status_code != 200:
                raise ExtractorError(f"FlareSolverr fetch failed: HTTP {r.status_code} for {url}")
            class MockResponse:
                def __init__(self, text_content, status, response_url):
                    self._text = text_content
                    self.status = status
                    self.status_code = status
                    self.text = text_content
                    self.url = response_url
                    self.headers = {}
                async def text_async(self):
                    return self._text
                def raise_for_status(self):
                    if self.status >= 400:
                        raise ExtractorError(f"FS HTTP error {self.status}")
            return MockResponse(html, r.status_code, url)

    def _fresh_headers(self, **extra_headers) -> dict:
        headers = self._default_headers()
        headers.update(extra_headers)
        return headers

    async def _make_curl_request(self, url: str, headers: dict = None):
        """Fetch Cloudflare-protected embeds with curl_cffi and proxy rotation."""
        from curl_cffi.requests import AsyncSession as CurlAsyncSession

        class MockResponse:
            def __init__(self, text_content, status, response_url):
                self._text = text_content
                self.status = status
                self.status_code = status
                self.text = text_content
                self.url = response_url
                self.headers = {}

            async def text_async(self):
                return self._text

            def raise_for_status(self):
                if self.status >= 400:
                    raise ExtractorError(f"curl_cffi HTTP error {self.status} for {self.url}")

        proxies_to_try = []
        for proxy in self.proxies or []:
            if proxy and proxy not in proxies_to_try:
                proxies_to_try.append(proxy)
        route_proxy = get_proxy_for_url(url, TRANSPORT_ROUTES, self.proxies)
        logger.info(
            "VixSrc curl proxy lookup: url=%s transport_routes=%d extractor_proxies=%d resolved=%d route_proxy=%s",
            url,
            len(TRANSPORT_ROUTES),
            len(self.proxies or []),
            len(proxies_to_try),
            route_proxy,
        )
        if route_proxy and route_proxy not in proxies_to_try:
            proxies_to_try.append(route_proxy)
        # Always try direct connection as last resort
        if None not in proxies_to_try:
            proxies_to_try.append(None)

        impersonations = ["chrome131", "chrome124", "chrome120"]
        last_status = None
        last_error = None
        final_headers = self._fresh_headers(**(headers or {}))

        # Remove User-Agent to avoid TLS fingerprint mismatch with impersonation
        final_headers.pop("User-Agent", None)
        final_headers.pop("user-agent", None)

        timeout = int(os.environ.get("VIXSRC_PROXY_TIMEOUT", str(PROXY_TEST_TIMEOUT)))
        concurrency = max(1, int(os.environ.get("VIXSRC_PROXY_CONCURRENCY", str(PROXY_TEST_CONCURRENCY))))

        async def _try_one(proxy_value: str | None, imp: str):
            request_kwargs = {}
            proxy = self._normalize_proxy_url(proxy_value) if proxy_value else None
            if proxy:
                request_kwargs["proxies"] = {"http": proxy, "https": proxy}
            try:
                async with CurlAsyncSession(impersonate=imp) as session:
                    resp = await session.get(
                        url,
                        headers=final_headers,
                        timeout=timeout,
                        allow_redirects=True,
                        **request_kwargs,
                    )
                    content = resp.text
                if 200 <= resp.status_code < 300:
                    return True, proxy, MockResponse(content, resp.status_code, url), None, resp.status_code
                return False, proxy, None, None, resp.status_code
            except Exception as exc:
                return False, proxy, None, exc, None

        for imp in impersonations:
            logger.info(
                "VixSrc curl_cffi testing %d proxies for %s (imp=%s, concurrency=%d, timeout=%ss)",
                len(proxies_to_try), url, imp, concurrency, timeout,
            )
            semaphore = asyncio.Semaphore(concurrency)

            async def _limited(proxy_value):
                async with semaphore:
                    return await _try_one(proxy_value, imp)

            tasks = [asyncio.create_task(_limited(proxy_value)) for proxy_value in proxies_to_try]
            try:
                for task in asyncio.as_completed(tasks):
                    ok, proxy, response, exc, status = await task
                    if ok:
                        for pending in tasks:
                            if not pending.done():
                                pending.cancel()
                        await asyncio.gather(*tasks, return_exceptions=True)
                        self.last_used_proxy = proxy
                        logger.info("curl_cffi success via %s for %s (imp=%s)", proxy or "direct", url, imp)
                        return response
                    if isinstance(status, int):
                        last_status = status
                    if exc:
                        last_error = exc
            finally:
                for pending in tasks:
                    if not pending.done():
                        pending.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

        if last_error:
            raise ExtractorError(f"curl_cffi request failed for {url}: {last_error}")
        raise ExtractorError(f"curl_cffi HTTP error {last_status} for {url}")

    @staticmethod
    def _normalize_base_site(url: str) -> str:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ExtractorError("Invalid VixSrc URL")
        return f"{parsed.scheme}://{parsed.netloc}"

    def _get_random_proxy(self):
        """Restituisce un proxy casuale dalla lista."""
        return random.choice(self.proxies) if self.proxies else None

    def _build_session_for_proxy(self, proxy: str | None) -> ClientSession:
        timeout = ClientTimeout(total=60, connect=30, sock_read=30)
        if proxy:
            logger.debug("Using proxy %s for VixSrc session.", proxy)
            connector = get_connector_for_proxy(proxy)
        else:
            connector = TCPConnector(
                limit=0,
                limit_per_host=0,
                keepalive_timeout=30,
                enable_cleanup_closed=True,
                force_close=False,
                use_dns_cache=True,
            )
        return ClientSession(
            timeout=timeout,
            connector=connector,
            headers=self._default_headers(),
            cookie_jar=aiohttp.CookieJar(),
        )

    @staticmethod
    def _raise_if_embed_expired(url: str):
        parsed = urlparse(url)
        if "/embed/" not in parsed.path:
            return
        expires = parse_qs(parsed.query).get("expires", [None])[0]
        if not expires:
            return
        try:
            expires_ts = int(expires)
        except (TypeError, ValueError):
            return
        now_ts = int(time.time())
        if expires_ts <= now_ts:
            raise ExtractorError(
                f"Expired VixSrc embed URL (expired at {expires_ts}, current {now_ts}). "
                "Use the original /movie/ or /tv/ URL to refresh tokens."
            )

    @staticmethod
    def _inherit_query_if_missing(absolute_url: str, base_query: str) -> str:
        if not base_query:
            return absolute_url
        parsed_url = urlparse(absolute_url)
        if parsed_url.query:
            return absolute_url
        return urlunparse(parsed_url._replace(query=base_query))

    @staticmethod
    def _make_live(manifest_text: str) -> str:
        out_lines = []
        for line in (manifest_text or "").splitlines():
            stripped = line.strip()
            if stripped == "#EXT-X-ENDLIST":
                continue
            if stripped.startswith("#EXT-X-PLAYLIST-TYPE"):
                out_lines.append("#EXT-X-PLAYLIST-TYPE:EVENT")
                continue
            out_lines.append(line)
        if not any(line.startswith("#EXT-X-PLAYLIST-TYPE") for line in out_lines):
            for idx, line in enumerate(out_lines):
                if line.strip() == "#EXTM3U":
                    out_lines.insert(idx + 1, "#EXT-X-PLAYLIST-TYPE:EVENT")
                    break
        return "\n".join(out_lines)

    async def _capture_hls_manifests(self, m3u8_url: str, stream_headers: dict):
        master_response = await self._make_robust_request(
            m3u8_url,
            headers=stream_headers,
            retries=1,
        )
        master_url = str(master_response.url)
        master_text = master_response.text
        if "#EXTM3U" not in master_text:
            raise ExtractorError("VixSrc extracted URL did not return a valid HLS manifest")
        if "#EXTINF" in master_text:
            master_text = self._make_live(master_text)

        captured_map = {master_url: master_text}
        master_lines = master_text.splitlines()
        variant_urls = []
        base_query = urlparse(master_url).query

        def add_variant(raw_url: str):
            raw_url = (raw_url or "").strip()
            if not raw_url or raw_url.startswith("#"):
                return
            variant_url = self._inherit_query_if_missing(
                urljoin(master_url, raw_url),
                base_query,
            )
            if variant_url not in variant_urls:
                variant_urls.append(variant_url)

        for idx, line in enumerate(master_lines):
            if line.startswith("#EXT-X-STREAM-INF:") and idx + 1 < len(master_lines):
                add_variant(master_lines[idx + 1])
            elif line.startswith("#EXT-X-MEDIA:") and 'URI="' in line:
                uri_start = line.find('URI="') + 5
                uri_end = line.find('"', uri_start)
                if uri_start > 4 and uri_end > uri_start:
                    add_variant(line[uri_start:uri_end])

        for variant_url in variant_urls:
            try:
                variant_response = await self._make_robust_request(
                    variant_url,
                    headers=stream_headers,
                    retries=1,
                )
                variant_final_url = str(variant_response.url)
                variant_text = variant_response.text
                if "#EXTM3U" not in variant_text:
                    logger.warning("VixSrc variant is not a valid HLS manifest: %s", variant_url)
                    continue
                if "#EXTINF" in variant_text:
                    variant_text = self._make_live(variant_text)
                captured_map[variant_final_url] = variant_text
            except Exception as exc:
                logger.warning("VixSrc variant capture failed %s: %s", variant_url, exc)

        return master_url, master_text, captured_map

    async def _get_session(self, url: str = None):
        """Ottiene una sessione HTTP persistente."""
        if self.session is None or self.session.closed:
            proxy = None
            if url:
                proxy = get_proxy_for_url(url, TRANSPORT_ROUTES, self.proxies)
            else:
                proxy = self._get_random_proxy()
            if proxy:
                proxy = self._normalize_proxy_url(proxy)
                self.last_used_proxy = proxy
            self.session = self._build_session_for_proxy(proxy)
        return self.session

    async def _make_robust_request(
        self, url: str, headers: dict = None, retries: int = 1, initial_delay: int = 2
    ):
        """Effettua richieste HTTP robuste con retry automatico."""
        final_headers = headers or {}

        for attempt in range(retries):
            try:
                session = await self._get_session(url)
                logger.info("Attempt %s/%s for URL: %s", attempt + 1, retries, url)

                async with session.get(url, headers=final_headers) as response:
                    response.raise_for_status()
                    content = await response.text()

                    class MockResponse:
                        def __init__(self, text_content, status, headers_dict, response_url):
                            self._text = text_content
                            self.status = status
                            self.headers = headers_dict
                            self.url = response_url
                            self.status_code = status
                            self.text = text_content

                        async def text_async(self):
                            return self._text

                        def raise_for_status(self):
                            if self.status >= 400:
                                raise aiohttp.ClientResponseError(
                                    request_info=None,
                                    history=None,
                                    status=self.status,
                                )

                    logger.info("Request successful for %s at attempt %s", url, attempt + 1)
                    return MockResponse(content, response.status, response.headers, response.url)

            except (
                aiohttp.ClientConnectionError,
                aiohttp.ServerDisconnectedError,
                aiohttp.ClientPayloadError,
                asyncio.TimeoutError,
                OSError,
                ConnectionResetError,
                AioProxyError,
                PyProxyError,
            ) as e:
                is_proxy_err = isinstance(e, (AioProxyError, PyProxyError))
                is_timeout = isinstance(e, asyncio.TimeoutError)
                err_type = "Proxy" if is_proxy_err else ("Timeout" if is_timeout else "Connection")
                
                logger.warning(
                    "%s error attempt %s for %s: %s", err_type, attempt + 1, url, str(e)
                )

                # Reset session
                if self.session and not self.session.closed:
                    try:
                        await self.session.close()
                    except Exception:
                        pass
                self.session = None
                
                if is_proxy_err and SELECTED_PROXY_CONTEXT.get():
                    logger.info("Clearing sticky proxy context due to ProxyError")
                    SELECTED_PROXY_CONTEXT.set(None)


                if attempt < retries - 1:
                    delay = initial_delay * (2**attempt)
                    logger.info("Waiting %s seconds before next attempt...", delay)
                    await asyncio.sleep(delay)
                else:
                    raise ExtractorError(f"All {retries} attempts failed for {url}: {str(e)}")

            except aiohttp.ClientResponseError as e:
                if e.status == 404:
                    raise ExtractorError(f"VixSrc content not found (404): {url}")

                if e.status == 403 and attempt == retries - 1:
                    try:
                        logger.info("aiohttp 403, trying curl_cffi with configured proxies for %s", url)
                        headers_403 = final_headers or self._default_headers()
                        return await self._make_curl_request(url, headers=headers_403)
                    except Exception as cffi_exc:
                        logger.warning("curl_cffi fallback failed for %s: %s", url, cffi_exc)

                if attempt == retries - 1:
                    raise ExtractorError(f"Final HTTP error {e.status} for {url}: {str(e)}")
                await asyncio.sleep(initial_delay)

            except Exception as e:
                logger.error("Non-network error attempt %s for %s: %s", attempt + 1, url, str(e))
                if attempt == retries - 1:
                    raise ExtractorError(f"Final error for {url}: {str(e)}")
                await asyncio.sleep(initial_delay)

    async def _parse_html_simple(self, html_content: str, tag: str, attrs: dict = None):
        """Parser HTML semplificato senza BeautifulSoup."""
        try:
            if tag == "div" and attrs and attrs.get("id") == "app":
                pattern = r'<div[^>]*id="app"[^>]*data-page="([^"]*)"[^>]*>'
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    return {"data-page": match.group(1)}

            elif tag == "iframe":
                pattern = r'<iframe[^>]*src="([^"]*)"[^>]*>'
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    return {"src": match.group(1)}

            elif tag == "script":
                scripts = re.findall(
                    r"<script[^>]*>(.*?)</script>",
                    html_content,
                    re.DOTALL | re.IGNORECASE,
                )
                for script in scripts:
                    if "window.masterPlaylist" in script or "'token':" in script:
                        return script

                pattern = r"<body[^>]*>.*?<script[^>]*>(.*?)</script>"
                match = re.search(pattern, html_content, re.DOTALL | re.IGNORECASE)
                if match:
                    return match.group(1)

        except Exception as e:
            logger.error("HTML parsing error: %s", e)

        return None

    async def _resolve_embed_url_from_api(self, url: str) -> str | None:
        """Resolve the current embed URL through VixSrc JSON API."""
        parsed = urlparse(url)
        site_url = self._normalize_base_site(url)
        path_parts = [part for part in parsed.path.strip("/").split("/") if part]

        api_url = None
        if len(path_parts) >= 2 and path_parts[0] == "movie":
            api_url = f"{site_url}/api/movie/{path_parts[1]}"
        elif len(path_parts) >= 4 and path_parts[0] == "tv":
            api_url = f"{site_url}/api/tv/{path_parts[1]}/{path_parts[2]}/{path_parts[3]}"

        if not api_url:
            return None

        api_headers = {
            "accept": "application/json, text/plain, */*",
            "referer": url,
            **self._default_headers(),
        }
        try:
            logger.info("Trying VixSrc API via curl_cffi proxy rotation: %s", api_url)
            response = await self._make_curl_request(api_url, headers=api_headers)
        except Exception as curl_err:
            # 404 means content not found — FS won't help, skip cascading fallbacks
            if "404" in str(curl_err):
                raise ExtractorError(f"VixSrc API endpoint not found (404): {api_url}")
            logger.warning("curl_cffi failed for API, trying robust: %s", curl_err)
            try:
                response = await self._make_robust_request(api_url, headers=api_headers)
            except Exception as robust_err:
                if "404" in str(robust_err):
                    raise ExtractorError(f"VixSrc content not found (404): {api_url}")
                logger.warning("Robust failed for API, trying FS fallback: %s", robust_err)
                response = await self._make_fs_request(
                    api_url,
                    headers={"accept": "application/json, text/plain, */*", "referer": url},
                )

        try:
            payload = json.loads(response.text)
        except json.JSONDecodeError as exc:
            raise ExtractorError(f"Invalid API response from {api_url}: {exc}")

        embed_path = payload.get("src")
        if not embed_path:
            raise ExtractorError(f"Missing embed src in API response from {api_url}")

        return urljoin(site_url, embed_path)

    def _extract_playlist_from_embed(self, script_content: str) -> str:
        """Extract playlist URL from current embed structure, with legacy fallback."""
        master_playlist_match = re.search(
            r"window\.masterPlaylist\s*=\s*\{.*?params\s*:\s*\{(?P<params>.*?)\}\s*,\s*url\s*:\s*['\"](?P<url>[^'\"]+)['\"]",
            script_content,
            re.DOTALL,
        )
        if master_playlist_match:
            params_block = master_playlist_match.group("params")
            playlist_url = master_playlist_match.group("url").replace("\\/", "/")

            token_match = re.search(
                r"['\"]token['\"]\s*:\s*['\"]([^'\"]+)['\"]", params_block
            )
            expires_match = re.search(
                r"['\"]expires['\"]\s*:\s*['\"](\d+)['\"]", params_block
            )
            asn_match = re.search(
                r"['\"]asn['\"]\s*:\s*['\"]([^'\"]*)['\"]", params_block
            )

            if token_match and expires_match:
                parsed_playlist_url = urlparse(playlist_url)
                query_params = parse_qsl(parsed_playlist_url.query, keep_blank_values=True)
                query_params.extend(
                    [
                        ("token", token_match.group(1)),
                        ("expires", expires_match.group(1)),
                    ]
                )
                if "window.canPlayFHD = true" in script_content or "canPlayFHD" in script_content:
                    query_params.append(("h", "1"))
                query_params.append(("lang", "it"))
                if asn_match and asn_match.group(1):
                    query_params.append(("asn", asn_match.group(1)))
                return urlunparse(parsed_playlist_url._replace(query=urlencode(query_params)))

        token_match = re.search(r"['\"]token['\"]\s*:\s*['\"](\w+)['\"]", script_content)
        expires_match = re.search(r"['\"]expires['\"]\s*:\s*['\"](\d+)['\"]", script_content)
        server_url_match = re.search(r"url\s*:\s*['\"]([^'\"]+)['\"]", script_content)

        if not all([token_match, expires_match, server_url_match]):
            token_match = token_match or re.search(
                r"token['\"]\s*:\s*['\"]([^'\"]+)['\"]", script_content
            )
            expires_match = expires_match or re.search(
                r"expires['\"]\s*:\s*['\"](\d+)['\"]", script_content
            )

        if not all([token_match, expires_match, server_url_match]):
            raise ExtractorError("Missing mandatory parameters in JS script (token/expires/url)")

        server_url = server_url_match.group(1).replace("\\/", "/")
        parsed_server_url = urlparse(server_url)
        query_params = parse_qsl(parsed_server_url.query, keep_blank_values=True)
        query_params.extend(
            [
                ("token", token_match.group(1)),
                ("expires", expires_match.group(1)),
            ]
        )

        if "window.canPlayFHD = true" in script_content or "canPlayFHD" in script_content:
            query_params.append(("h", "1"))

        query_params.append(("lang", "it"))
        asn_match = re.search(r"['\"]asn['\"]\s*:\s*['\"]([^'\"]*)['\"]", script_content)
        if asn_match and asn_match.group(1):
            query_params.append(("asn", asn_match.group(1)))

        return urlunparse(parsed_server_url._replace(query=urlencode(query_params)))

    async def version(self, site_url: str) -> str:
        """Ottiene la versione del sito VixSrc parent."""
        base_url = f"{site_url}/request-a-title"

        try:
            response = await self._make_fs_request(
                base_url,
                headers={"referer": f"{site_url}/"},
            )
        except Exception:
            response = await self._make_robust_request(
                base_url,
                headers={
                    "Referer": f"{site_url}/",
                    "Origin": f"{site_url}",
                    **self._default_headers(),
                },
            )

        if response.status_code != 200:
            raise ExtractorError("Obsolete URL")

        app_div = await self._parse_html_simple(response.text, "div", {"id": "app"})
        if app_div and app_div.get("data-page"):
            try:
                data_page = app_div["data-page"].replace("&quot;", '"')
                data = json.loads(data_page)
                return data["version"]
            except (KeyError, json.JSONDecodeError, AttributeError) as e:
                raise ExtractorError(f"Version parsing failure: {e}")

        raise ExtractorError("Unable to find version data")

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Estrae URL VixSrc."""
        try:
            parsed_url = urlparse(url)
            response = None

            if "/playlist/" in parsed_url.path:
                logger.info("URL is already a VixSrc manifest, no extraction required.")
                selected_proxy = kwargs.get("proxy") or parse_qs(parsed_url.query).get("proxy", [None])[0]
                logger.debug(f"Extractor Debug: Extractor result selected_proxy: {selected_proxy}")
                stream_headers = self._fresh_headers()
                # Use cookies and UA from the request (e.g. cf_clearance forwarded by redirect)
                req_h = kwargs.get("request_headers") or {}
                if req_h.get("Cookie"):
                    stream_headers["Cookie"] = req_h["Cookie"]
                if req_h.get("User-Agent"):
                    stream_headers["User-Agent"] = req_h["User-Agent"]
                if self._fs_cookies:
                    cookie_str = "; ".join(f"{k}={v}" for k, v in self._fs_cookies.items())
                    stream_headers["Cookie"] = cookie_str
                    if self._fs_user_agent:
                        stream_headers["User-Agent"] = self._fs_user_agent
                captured_manifest = None
                captured_manifests = {}
                destination_url = url
                try:
                    destination_url, captured_manifest, captured_manifests = await self._capture_hls_manifests(
                        url,
                        stream_headers,
                    )
                except Exception as exc:
                    if kwargs.get("background_refresh") or kwargs.get("force_refresh"):
                        raise
                    logger.warning("VixSrc manifest capture failed, continuing without capture: %s", exc)
                return {
                    "destination_url": destination_url,
                    "request_headers": stream_headers,
                    "captured_manifest": captured_manifest,
                    "captured_manifests": captured_manifests,
                    "mediaflow_endpoint": self.mediaflow_endpoint,
                    "selected_proxy": selected_proxy or self.last_used_proxy,
                }

            if "/embed/" in parsed_url.path:
                self._raise_if_embed_expired(url)
                if parsed_url.netloc.lower().endswith("vixcloud.co"):
                    vix_url = url.replace("vixcloud.co", "vixsrc.to")
                    logger.info("Rewrote URL to vixsrc.to: %s", vix_url)
                else:
                    vix_url = url
                try:
                    response = await self._make_curl_request(
                        vix_url,
                        headers=self._fresh_headers(referer=self._normalize_base_site(vix_url) + "/"),
                    )
                except Exception as curl_err:
                    logger.warning("curl_cffi failed for embed %s, trying FS fallback: %s", vix_url, curl_err)
                    try:
                        response = await self._make_fs_request(
                            vix_url,
                            headers={"referer": self._normalize_base_site(vix_url) + "/"},
                        )
                    except Exception as fs_err:
                        logger.warning("FS failed for %s, no more fallbacks: %s", vix_url, fs_err)
            elif "iframe" in url:
                site_url = url.split("/iframe")[0]
                version = await self.version(site_url)
                response = await self._make_robust_request(
                    url,
                    headers=self._fresh_headers(
                        **{"x-inertia": "true", "x-inertia-version": version}
                    ),
                )

                iframe_data = await self._parse_html_simple(response.text, "iframe")
                if iframe_data and iframe_data.get("src"):
                    iframe_url = iframe_data["src"]
                    response = await self._make_robust_request(
                        iframe_url,
                        headers=self._fresh_headers(
                            **{"x-inertia": "true", "x-inertia-version": version}
                        ),
                    )
                else:
                    raise ExtractorError("No iframe found in response")
            elif "/movie/" in parsed_url.path or "/tv/" in parsed_url.path:
                embed_url = await self._resolve_embed_url_from_api(url)
                if embed_url:
                    try:
                        response = await self._make_curl_request(
                            embed_url,
                            headers=self._fresh_headers(referer=url),
                        )
                    except Exception as curl_err:
                        logger.warning("curl_cffi failed for embed %s, trying robust/FS: %s", embed_url, curl_err)
                        try:
                            response = await self._make_robust_request(
                                embed_url,
                                headers=self._fresh_headers(referer=url),
                            )
                        except Exception as robust_err:
                            logger.warning("Robust failed for embed %s, trying FS fallback: %s", embed_url, robust_err)
                            response = await self._make_fs_request(
                                embed_url,
                                headers={"referer": url},
                            )
                else:
                    try:
                        response = await self._make_curl_request(url)
                    except Exception as curl_err:
                        logger.warning("curl_cffi failed for %s, trying robust/FS: %s", url, curl_err)
                        try:
                            response = await self._make_robust_request(url)
                        except Exception as robust_err:
                            logger.warning("Robust failed for %s, trying FS fallback: %s", url, robust_err)
                            response = await self._make_fs_request(url)
            else:
                raise ExtractorError("Unsupported VixSrc URL type")

            if response.status_code != 200:
                raise ExtractorError("URL component extraction failed, invalid request")

            async def _extract_from_html(html: str) -> str | None:
                """Try to extract playlist URL from HTML via script content, then data-page JSON."""
                script = await self._parse_html_simple(html, "script")
                if script:
                    try:
                        return self._extract_playlist_from_embed(script)
                    except ExtractorError:
                        pass
                app_div = await self._parse_html_simple(html, "div", {"id": "app"})
                if not app_div or not app_div.get("data-page"):
                    return None
                try:
                    data_page = app_div["data-page"].replace("&quot;", '"')
                    data = json.loads(data_page)
                    def _search_json(obj):
                        results = {}
                        if isinstance(obj, dict):
                            for k, v in obj.items():
                                kl = k.lower()
                                if kl in ("token", "expires", "url", "src") and isinstance(v, str):
                                    results[kl] = v
                                elif not (results.get("token") and results.get("expires") and results.get("url")):
                                    results.update(_search_json(v))
                        elif isinstance(obj, list):
                            for item in obj:
                                results.update(_search_json(item))
                                if results.get("token") and results.get("expires") and results.get("url"):
                                    break
                        return results
                    found = _search_json(data)
                    if found.get("token") and found.get("expires") and found.get("url"):
                        parsed_url = urlparse(found["url"])
                        query_params = parse_qsl(parsed_url.query, keep_blank_values=True)
                        query_params.extend([("token", found["token"]), ("expires", found["expires"])])
                        if "canPlayFHD" in html:
                            query_params.append(("h", "1"))
                        query_params.append(("lang", "it"))
                        return urlunparse(parsed_url._replace(query=urlencode(query_params)))
                except (json.JSONDecodeError, Exception):
                    pass
                return None

            final_url = await _extract_from_html(response.text)

            if not final_url:
                raise ExtractorError("No playlist data found in response")

            # Rewrite vixcloud.co → vixsrc.to in the final URL too
            final_url = final_url.replace("vixcloud.co", "vixsrc.to")
            stream_url = url.replace("vixcloud.co", "vixsrc.to")

            stream_headers = self._fresh_headers(Referer=stream_url)
            # Pass cf_clearance cookie so the streaming proxy can fetch playlist
            if self._fs_cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in self._fs_cookies.items())
                stream_headers["Cookie"] = cookie_str
                if self._fs_user_agent:
                    stream_headers["User-Agent"] = self._fs_user_agent
            captured_manifest = None
            captured_manifests = {}
            try:
                final_url, captured_manifest, captured_manifests = await self._capture_hls_manifests(
                    final_url,
                    stream_headers,
                )
            except Exception as exc:
                if kwargs.get("background_refresh") or kwargs.get("force_refresh"):
                    raise
                logger.warning("VixSrc manifest capture failed, continuing without capture: %s", exc)
            logger.info("VixSrc URL extracted successfully: %s", final_url)
            return {
                "destination_url": final_url,
                "request_headers": stream_headers,
                "captured_manifest": captured_manifest,
                "captured_manifests": captured_manifests,
                "mediaflow_endpoint": self.mediaflow_endpoint,
                "selected_proxy": self.last_used_proxy,
            }

        except Exception as e:
            logger.error("VixSrc extraction failed: %s", str(e))
            raise ExtractorError(f"VixSrc extraction completely failed: {str(e)}")

    async def close(self):
        """Chiude definitivamente la sessione."""
        if self.session and not self.session.closed:
            try:
                await self.session.close()
            except Exception:
                pass
            self.session = None
