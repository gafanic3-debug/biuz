import asyncio
import aiohttp
import logging
import random
import re
import socket
from urllib.parse import urlparse
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from aiohttp.resolver import DefaultResolver
from config import FLARESOLVERR_TIMEOUT, FLARESOLVERR_URL, get_connector_for_proxy, get_solver_proxy_url, build_proxy_with_auth, get_extractor_proxies, get_ordered_proxies_for_url, should_allow_direct_fallback
import config as _cfg
from utils.solver_manager import ensure_flaresolverr


logger = logging.getLogger(__name__)

class StaticResolver(DefaultResolver):
    """Custom resolver to force specific IPs for domains (bypass hijacking)."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mapping = {}

    async def resolve(self, host, port=0, family=socket.AF_INET):
        if host in self.mapping:
            ip = self.mapping[host]
            logger.debug(f"StaticResolver: forcing {host} -> {ip}")
            # Format required by aiohttp: list of dicts
            return [{
                'hostname': host,
                'host': ip,
                'port': port,
                'family': family,
                'proto': 0,
                'flags': 0
            }]
        return await super().resolve(host, port, family)

class ExtractorError(Exception):
    pass

class MaxstreamExtractor:
    """Maxstream URL extractor."""

    def __init__(self, request_headers: dict, proxies: list = None):
        self.request_headers = request_headers
        self.base_headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate",
            "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
        }
        self.session = None
        self.mediaflow_endpoint = "hls_proxy"
        self.proxies = proxies or []
        self.cookies = {} # Persistent cookies for the session
        self.selected_proxy = None
        self.resolver = StaticResolver()
    def _get_random_proxy(self):
        return random.choice(self.proxies) if self.proxies else None

    def _get_proxies_for_url(self, url: str) -> list[str]:
        """Build ordered proxy list: extractor-specific first, then route/global, then WARP."""
        return get_ordered_proxies_for_url(url, "maxstream", self.proxies)

    async def _get_session(self, proxy=None):
        """Get or create session, optionally with a specific proxy."""
        # Note: we use our custom resolver only for non-proxy requests
        # because proxies handle their own DNS resolution.
        
        timeout = ClientTimeout(total=45, connect=15, sock_read=30)
        if proxy:
            connector = get_connector_for_proxy(proxy)
            return ClientSession(timeout=timeout, connector=connector, headers=self.base_headers)
        
        if self.session is None or self.session.closed:
            connector = TCPConnector(
                limit=0, 
                limit_per_host=0, 
                keepalive_timeout=60, 
                enable_cleanup_closed=True, 
                resolver=self.resolver # Use custom StaticResolver
            )
            self.session = ClientSession(timeout=timeout, connector=connector, headers=self.base_headers)
        return self.session

    async def _resolve_doh(self, domain: str) -> list[str]:
        """Resolve domain using DNS-over-HTTPS (Google) to bypass local DNS hijacking."""
        try:
            # Using Google DoH API
            url = f"https://dns.google/resolve?name={domain}&type=A"
            proxy = next(iter(self._get_proxies_for_url(url)), None)
            connector = get_connector_for_proxy(proxy) if proxy else TCPConnector(ssl=False)
            async with ClientSession(timeout=ClientTimeout(total=5), connector=connector) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        ips = [ans['data'] for ans in data.get('Answer', []) if ans.get('type') == 1]
                        if ips:
                            logger.debug(f"DoH resolved {domain} to {ips}")
                            return ips
        except Exception as e:
            logger.debug(f"DoH resolution failed for {domain}: {e}")
        return []

    async def _fetch(self, url: str, method="GET", is_binary=False, **kwargs):
        """Request using direct/configured proxy routes only."""
        if url.startswith("data:"):
            import base64
            try:
                _, data = url.split(",", 1)
                decoded = base64.b64decode(data)
                return decoded if is_binary else decoded.decode("utf-8", errors="ignore")
            except Exception as e:
                logger.error(f"Failed to decode data URI: {e}")
                return b"" if is_binary else ""

        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Load from solver cache if empty
        if not self.cookies and "maxstream" in domain:
            import json
            import os
            import time
            cache_file = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "cache", "solver_cookies.json"))
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, "r") as f:
                        cache_data = json.load(f)
                    domain_cache = cache_data.get(domain)
                    if domain_cache:
                        # Check timestamp (must be less than 10 mins old)
                        if time.time() - domain_cache.get("timestamp", 0) < 600:
                            cookies_list = domain_cache.get("cookies", [])
                            self.cookies = {c["name"]: c["value"] for c in cookies_list}
                            ua = domain_cache.get("userAgent")
                            if ua:
                                self.base_headers["user-agent"] = ua
                                self.base_headers["User-Agent"] = ua
                                if "headers" in kwargs:
                                    kwargs["headers"]["user-agent"] = ua
                                    kwargs["headers"]["User-Agent"] = ua
                            logger.info(f"Maxstream: loaded {len(self.cookies)} cached cookies from solver cache for domain: {domain}")
                except Exception as e:
                    logger.debug(f"Failed to load solver cookies: {e}")

        headers = kwargs.get("headers") or self.base_headers
        post_data = kwargs.get("data")
        proxies = self._get_proxies_for_url(url)
        allow_direct = should_allow_direct_fallback(proxies)
        paths = [{"proxy": proxy, "use_ip": None} for proxy in proxies]
        if allow_direct:
            paths.append({"proxy": None, "use_ip": None})

        if allow_direct and "maxstream" in domain:
            for ip in (await self._resolve_doh(domain))[:2]:
                paths.append({"proxy": None, "use_ip": ip})

        last_error = None
        for path in paths:
            proxy = path["proxy"]
            local_resolver = StaticResolver()
            if path["use_ip"]:
                local_resolver.mapping[domain] = path["use_ip"]

            timeout = ClientTimeout(total=25, connect=10, sock_read=20)
            connector = get_connector_for_proxy(proxy) if proxy else TCPConnector(resolver=local_resolver, ssl=False)
            try:
                async with ClientSession(timeout=timeout, connector=connector, headers=self.base_headers) as session:
                    call_kwargs = kwargs.copy()
                    if self.cookies:
                        call_kwargs["cookies"] = self.cookies
                    async with session.request(method, url, ssl=False, **call_kwargs) as response:
                        content = await response.read() if is_binary else await response.text()
                        status = response.status
                        
                        if not is_binary and self._is_cloudflare_challenge(content, status):
                            logger.info("Cloudflare challenge page detected in Maxstream direct fetch (status %s). Triggering solver...", status)
                            fs_result = await self._fetch_with_flaresolverr(url, method=method, headers=headers, post_data=post_data)
                            if fs_result:
                                return fs_result
                                
                        response.raise_for_status()
                        self.selected_proxy = proxy
                        for k, v in response.cookies.items():
                            self.cookies[k] = v.value
                        return content
            except Exception as e:
                last_error = e
                logger.debug(f"Path failed ({proxy or 'direct'}): {e}")

        if not is_binary and "maxstream.video" in domain:
            cffi_result = await self._fetch_with_curl_cffi(
                url,
                method=method,
                headers=headers,
                data=post_data,
            )
            if cffi_result:
                return cffi_result

            fs_result = await self._fetch_with_flaresolverr(url, method=method, headers=headers, post_data=post_data)
            if fs_result:
                return fs_result

        raise ExtractorError(f"Connection failed for {url}: {last_error}")

    async def _fetch_with_curl_cffi(self, url: str, method="GET", headers=None, data=None):
        try:
            from curl_cffi import requests as cffi_requests
        except ImportError:
            logger.debug("curl_cffi not installed, skipping Maxstream browser request")
            return None

        proxies = self._get_proxies_for_url(url)
        if should_allow_direct_fallback(proxies):
            proxies.append(None)
        request_headers = dict(headers or self.base_headers)
        loop = asyncio.get_running_loop()

        def do_request(proxy, profile):
            try:
                proxies_arg = {"http": proxy, "https": proxy} if proxy else None
                response = cffi_requests.request(
                    method,
                    url,
                    headers=request_headers,
                    data=data,
                    cookies=self.cookies or None,
                    proxies=proxies_arg,
                    impersonate=profile,
                    timeout=_cfg.PROXY_TEST_TIMEOUT,
                    allow_redirects=True,
                    verify=False,
                )
                cookies = {}
                try:
                    cookies = {cookie.name: cookie.value for cookie in response.cookies.jar}
                except Exception:
                    cookies = dict(response.cookies) if response.cookies else {}
                return response.status_code, response.text, cookies, proxy, profile
            except Exception as exc:
                logger.debug(f"curl_cffi maxstream error for {url}: proxy={proxy or 'direct'} profile={profile}: {exc}")
                return 0, None, {}, proxy, profile

        for profile in ("chrome131", "chrome124", "edge101"):
            semaphore = asyncio.Semaphore(_cfg.PROXY_TEST_CONCURRENCY)

            async def _limited(proxy):
                async with semaphore:
                    return await loop.run_in_executor(None, do_request, proxy, profile)

            specific = [p for p in get_extractor_proxies("maxstream") if p in proxies]
            proxy_batches = [specific, [p for p in proxies if p not in specific]] if specific else [proxies]

            for proxy_batch in proxy_batches:
                if not proxy_batch:
                    continue
                tasks = [asyncio.create_task(_limited(proxy)) for proxy in proxy_batch]
                try:
                    for task in asyncio.as_completed(tasks):
                        status, text, cookies, used_proxy, used_profile = await task
                        if cookies:
                            self.cookies.update(cookies)
                        if status < 400 and text:
                            for pending in tasks:
                                if not pending.done():
                                    pending.cancel()
                            await asyncio.gather(*tasks, return_exceptions=True)
                            self.selected_proxy = used_proxy
                            logger.debug(f"curl_cffi maxstream success via {used_proxy or 'direct'} profile={used_profile}")
                            return text
                        logger.debug(f"curl_cffi maxstream failed for {url}: status={status} proxy={used_proxy or 'direct'} profile={used_profile}")
                finally:
                    for pending in tasks:
                        if not pending.done():
                            pending.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
        return None

    async def _fetch_with_flaresolverr(self, url: str, method="GET", headers=None, post_data=None):
        if not FLARESOLVERR_URL:
            logger.debug("FlareSolverr not configured, skipping Maxstream browser fallback")
            return None

        proxy = next(iter(self._get_proxies_for_url(url)), None)
        payload = {
            "cmd": f"request.{method.lower()}",
            "url": url,
            "maxTimeout": (FLARESOLVERR_TIMEOUT + 60) * 1000,
        }
        if post_data:
            payload["postData"] = post_data

        fs_headers = {}
        if proxy:
            p = build_proxy_with_auth(proxy)
            if p:
                payload["proxy"] = p
            fs_headers["X-Proxy-Server"] = get_solver_proxy_url(proxy)

        cookie_header = (headers or {}).get("Cookie") or (headers or {}).get("cookie")
        if cookie_header:
            parsed = urlparse(url)
            payload["cookies"] = [
                {
                    "name": key.strip(),
                    "value": value.strip(),
                    "domain": parsed.hostname,
                    "path": "/",
                    "secure": parsed.scheme == "https",
                }
                for item in cookie_header.split(";")
                if "=" in item
                for key, value in [item.split("=", 1)]
            ]

        await ensure_flaresolverr()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{FLARESOLVERR_URL.rstrip('/')}/v1",
                    json=payload,
                    headers=fs_headers,
                    timeout=ClientTimeout(total=FLARESOLVERR_TIMEOUT + 95),
                ) as response:
                    data = await response.json()
        except Exception as exc:
            logger.debug(f"FlareSolverr maxstream failed for {url}: {exc}")
            return None

        if data.get("status") != "ok":
            logger.debug(f"FlareSolverr maxstream error for {url}: {data.get('message')}")
            return None

        solution = data.get("solution", {})
        cookies = {c["name"]: c["value"] for c in solution.get("cookies", [])}
        if cookies:
            self.cookies.update(cookies)
        html = solution.get("response", "")
        if html and not any(marker in html.lower() for marker in ("just a moment", "cf-challenge", "checking your browser")):
            self.selected_proxy = proxy
            return html
        logger.debug("FlareSolverr maxstream returned Cloudflare challenge or empty response")
        return None

    def _is_cloudflare_challenge(self, html: str, status: int) -> bool:
        """Determines if the response is a Cloudflare verification challenge screen."""
        if status in (403, 503):
            return True
        low_html = html.lower()
        if "cloudflare" in low_html and ("ray id" in low_html or "captcha" in low_html or "turnstile" in low_html or "challenge-platform" in low_html):
            return True
        return False

    async def extract(self, url: str, **kwargs) -> dict:
        """Extract Maxstream URL.

        For /msfld/ folder URLs, callers must pass season=N&episode=M as
        query parameters (forwarded by MFP routes as kwargs).
        """
        input_domain = urlparse(url).netloc.lower()
        if "maxstream.video" not in input_domain:
            raise ExtractorError("Maxstream: redirector URLs are no longer supported")
        maxstream_url = url
        logger.debug(f"Target URL: {maxstream_url}")
        
        # Use strict headers to avoid Error 131
        headers = {
            **self.base_headers,
            "referer": "https://maxstream.video/",
            "origin": "https://maxstream.video",
            "accept-language": "en-US,en;q=0.5"
        }
        
        text = await self._fetch(maxstream_url, headers=headers)
        
        # Direct sources check
        direct_match = re.search(r'sources:\s*\[\{src:\s*"([^"]+)"', text)
        if direct_match:
            return {
                "destination_url": direct_match.group(1),
                "request_headers": {**self.base_headers, "referer": maxstream_url},
                "mediaflow_endpoint": self.mediaflow_endpoint,
                "selected_proxy": self.selected_proxy,
            }

        # Fallback to packer logic
        match = re.search(r"\}\('(.+)',.+,'(.+)'\.split", text)
        if not match:
             match = re.search(r"eval\(function\(p,a,c,k,e,d\).+?\}\('(.+?)',.+?,'(.+?)'\.split", text, re.S)
        
        if not match:
            raise ExtractorError(f"Failed to extract from: {text[:200]}")

        # ... rest of packer logic (terms.index, etc) ...})
        # ... rest of regex logic ...

        # Fallback to packer logic
        match = re.search(r"\}\('(.+)',.+,'(.+)'\.split", text)
        if not match:
            # Maybe it's a different packer signature?
            match = re.search(r"eval\(function\(p,a,c,k,e,d\).+?\}\('(.+?)',.+?,'(.+?)'\.split", text, re.S)
            
        if not match:
            logger.error(f"Failed to find packer script or direct source in: {text[:500]}...")
            raise ExtractorError("Failed to extract URL components")

        s1 = match.group(2)
        # Extract Terms
        terms = s1.split("|")
        try:
            urlset_index = terms.index("urlset")
            hls_index = terms.index("hls")
            sources_index = terms.index("sources")
        except ValueError as e:
            logger.error(f"Required terms missing in packer: {e}")
            raise ExtractorError(f"Missing components in packer: {e}")

        result = terms[urlset_index + 1 : hls_index]
        reversed_elements = result[::-1]
        first_part_terms = terms[hls_index + 1 : sources_index]
        reversed_first_part = first_part_terms[::-1]
        
        first_url_part = ""
        for fp in reversed_first_part:
            if "0" in fp:
                first_url_part += fp
            else:
                first_url_part += fp + "-"

        base_url = f"https://{first_url_part.rstrip('-')}.host-cdn.net/hls/"
        
        if len(reversed_elements) == 1:
            final_url = base_url + "," + reversed_elements[0] + ".urlset/master.m3u8"
        else:
            final_url = base_url
            for i, element in enumerate(reversed_elements):
                final_url += element + ","
            final_url = final_url.rstrip(",") + ".urlset/master.m3u8"

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
            "selected_proxy": self.selected_proxy,
        }

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
