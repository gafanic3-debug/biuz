import logging
import random
import re
import socket
import io
from urllib.parse import urlparse, quote_plus
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from aiohttp.resolver import DefaultResolver
from aiohttp_socks import ProxyConnector
from bs4 import BeautifulSoup
from config import GLOBAL_PROXIES, TRANSPORT_ROUTES, get_proxy_for_url, get_connector_for_proxy

from utils.smart_request import smart_request
from utils.proxy_manager import FreeProxyManager

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
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate",
            "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
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
        self.resolver = StaticResolver()
        self.proxy_manager = FreeProxyManager.get_instance(
            "maxstream",
            [
                "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/all/data.txt",
                "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text",
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
                "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
                "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
                "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt",
                "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
                "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
                "https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt",
                "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
                "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt"
            ]
        )

    def _get_random_proxy(self):
        return random.choice(self.proxies) if self.proxies else None

    def _get_proxies_for_url(self, url: str) -> list[str]:
        """Build ordered proxy list for current URL, honoring TRANSPORT_ROUTES first."""
        ordered = []

        route_proxy = get_proxy_for_url(url, TRANSPORT_ROUTES, GLOBAL_PROXIES)
        if route_proxy:
            ordered.append(route_proxy)

        for proxy in self.proxies:
            if proxy and proxy not in ordered:
                ordered.append(proxy)

        return ordered

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
            async with ClientSession(timeout=ClientTimeout(total=5)) as session:
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

    async def _smart_request(self, url: str, method="GET", is_binary=False, **kwargs):
        """Request with automatic retry using different proxies and resolver fallback on connection failure."""
        if url.startswith("data:"):
            import base64
            try:
                # Support for data URIs (e.g. base64 captchas)
                _, data = url.split(",", 1)
                decoded = base64.b64decode(data)
                return decoded if is_binary else decoded.decode("utf-8", errors="ignore")
            except Exception as e:
                logger.error(f"Failed to decode data URI: {e}")
                return b"" if is_binary else ""

        last_error = None
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Clear previous mapping for this domain to start fresh
        self.resolver.mapping.pop(domain, None)

        # Determine paths to try: Direct, Proxies, and then resolver override
        paths = []
        # Path 1: Direct (system DNS)
        paths.append({"proxy": None, "use_ip": None})
        
        # Path 2: Proxies (route-specific first)
        proxies_for_url = self._get_proxies_for_url(url)
        if proxies_for_url:
            for p in proxies_for_url:
                paths.append({"proxy": p, "use_ip": None})
        
        # Path 3: DoH fallback (override resolver) if it's uprot or maxstream
        if "uprot.net" in domain or "maxstream" in domain:
            real_ips = await self._resolve_doh(domain)
            for ip in real_ips[:2]: # Try first 2 IPs
                paths.append({"proxy": None, "use_ip": ip})
        
        # Path 4: Free Proxies fallback (if it's a redirector or maxstream)
        if any(d in domain for d in ["uprot.net", "safego.cc", "clicka.cc", "maxstream"]):
            try:
                # Use a dummy probe to get current proxies without full validation wait
                free_proxies = await self.proxy_manager.get_proxies(lambda x: True)
                # Randomize to avoid hitting the same failing proxies in sequence
                random.shuffle(free_proxies)
                for p in free_proxies[:10]: # Try more proxies
                    paths.append({"proxy": p, "use_ip": None})
            except Exception as e:
                logger.debug(f"Failed to get free proxies: {e}")
        
        for path in paths:
            proxy = path["proxy"]
            use_ip = path["use_ip"]
            
            if use_ip:
                # CRITICAL: Must destroy old session to flush TCPConnector DNS cache!
                # Otherwise connector reuses cached (hijacked) IP even with new resolver mapping.
                if self.session and not self.session.closed:
                    await self.session.close()
                    self.session = None
                self.resolver.mapping[domain] = use_ip
                logger.debug(f"DoH bypass: forcing {domain} -> {use_ip}")
            else:
                self.resolver.mapping.pop(domain, None)

            session = await self._get_session(proxy=proxy)
            try:
                # Add current cookies to kwargs for aiohttp
                if self.cookies:
                    kwargs["cookies"] = self.cookies
                
                async with session.request(method, url, ssl=False, **kwargs) as response:
                    if response.status < 400:
                        if is_binary:
                            content = await response.read()
                            if proxy: await session.close()
                            return content
                        text = await response.text()
                        
                        # Update persistent cookies
                        for k, v in response.cookies.items():
                            self.cookies[k] = v.value
                        
                        # Check for Cloudflare challenge in successful response
                        if any(marker in text.lower() for marker in ["cf-challenge", "ray id", "checking your browser"]):
                            # Fallback to the global smart_request utility
                            if proxy: await session.close()
                            fs_cmd = f"request.{method.lower()}"
                            # Pass the current proxy and cookies
                            fs_proxies = [proxy] if proxy else self.proxies
                            
                            # Add existing cookies to headers for smart_request to pick up
                            fs_headers = kwargs.get("headers", {}).copy()
                            if self.cookies:
                                fs_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])

                            result = await smart_request(fs_cmd, url, headers=fs_headers, post_data=kwargs.get("data"), proxies=fs_proxies)

                            if isinstance(result, dict):
                                self.cookies.update(result.get("cookies", {}))
                                html = result.get("html", "")
                                
                                # Check if FlareSolverr returned a browser error page (Chromium Authors style)
                                if "Chromium Authors" in html or "id=\"main-frame-error\"" in html:
                                    logger.warning(f"FlareSolverr returned a browser error page on this path, trying next...")
                                    last_error = "FlareSolverr browser error page"
                                    html = ""

                                if html: return html
                            
                            last_error = "FlareSolverr challenge failed or empty response"
                            logger.warning(f"FlareSolverr failed for {url} on this path, trying next path...")
                            continue

                        if proxy: await session.close()
                        return text
                    elif response.status in (403, 503):
                        # Might be Cloudflare block, try FlareSolverr immediately for this path
                        logger.warning(f"HTTP {response.status} on {url}, checking with FlareSolverr...")
                        if proxy: await session.close()
                        fs_cmd = f"request.{method.lower()}"
                        # Pass the current proxy and cookies
                        fs_proxies = [proxy] if proxy else self.proxies
                        
                        fs_headers = kwargs.get("headers", {}).copy()
                        if self.cookies:
                            fs_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])

                        result = await smart_request(fs_cmd, url, headers=fs_headers, post_data=kwargs.get("data"), proxies=fs_proxies)
                        
                        if isinstance(result, dict):
                            self.cookies.update(result.get("cookies", {}))
                            html = result.get("html", "")
                            
                            # Check if FlareSolverr returned a browser error page (Chromium Authors style)
                            if "Chromium Authors" in html or "id=\"main-frame-error\"" in html:
                                logger.warning(f"FlareSolverr returned a browser error page on this path, trying next...")
                                last_error = "FlareSolverr browser error page"
                                html = ""

                            if html: return html
                            
                        last_error = "FlareSolverr block/challenge failed"
                        logger.warning(f"FlareSolverr failed for {url} on this path, trying next path...")
                        continue
                    else:
                        logger.warning(f"Request to {url} failed (Status {response.status}) [Proxy: {proxy}, StaticIP: {use_ip}]")
            except Exception as e:
                logger.warning(f"Request to {url} failed (Error: {e}) [Proxy: {proxy}, StaticIP: {use_ip}]")
                last_error = e
                # If DoH attempt failed, destroy session so next IP gets fresh connector
                if use_ip and self.session and not self.session.closed:
                    await self.session.close()
                    self.session = None
            finally:
                if proxy and 'session' in locals() and not session.closed:
                    await session.close()
        
        raise ExtractorError(f"Connection failed for {url} after trying all paths. Last error: {last_error}")

    async def _solve_uprot_captcha(self, text: str, original_url: str) -> str:
        """Find, download and solve captcha on uprot page."""
        try:
            import ddddocr
        except ImportError:
            logger.error("ddddocr not installed. Cannot solve captcha.")
            return None
            
        # Use lxml and search specifically for the captcha pattern
        soup = BeautifulSoup(text, "lxml")
        
        # 1. Try to find captcha image (including base64)
        img_tag = soup.find("img", src=re.compile(r'data:image/|/captcha|/image/|captcha\.php'))
        if not img_tag:
            # Fallback to regex for captcha image
            img_match = re.search(r'<img[^>]+src=["\']([^"\']*(?:data:image/|captcha|image|captcha\.php)[^"\']*)["\']', text)
            if img_match:
                img_url = img_match.group(1)
            else:
                img_url = None
        else:
            img_url = img_tag["src"]
            
        # 2. Try to find form
        form = soup.find("form")
        if not form:
            # Fallback to regex for form action
            form_match = re.search(r'<form[^>]+action=["\']([^"\']*)["\']', text)
            if form_match:
                form_action = form_match.group(1)
            else:
                form_action = original_url # Assume same URL
        else:
            form_action = form.get("action", "")
            
        if not img_url:
            logger.debug("Captcha image not found in uprot page")
            return None
            
        captcha_url = img_url
        if captcha_url.startswith("/"):
            parsed = urlparse(original_url)
            captcha_url = f"{parsed.scheme}://{parsed.netloc}{captcha_url}"
            
        logger.debug(f"Downloading captcha from: {captcha_url}")
        img_data = await self._smart_request(captcha_url, is_binary=True)
        
        if not img_data:
            logger.debug("Failed to download captcha image")
            return None
            
        # Initialize ddddocr (lazy init for performance)
        if not hasattr(self, '_ocr_engine'):
            import ddddocr
            self._ocr_engine = ddddocr.DdddOcr(show_ad=False)
            
        # Solve
        res = self._ocr_engine.classification(img_data)
        logger.debug(f"Captcha solved: {res}")
        
        # Prepare form action
        from urllib.parse import urlencode
        if not form_action or form_action == "#":
            form_action = original_url
        elif form_action.startswith("/"):
            parsed = urlparse(original_url)
            form_action = f"{parsed.scheme}://{parsed.netloc}{form_action}"
            
        # Prepare data (find the captcha input name)
        # Search in soup or use regex if soup failed
        captcha_input = soup.find("input", {"name": re.compile(r'captcha|code|val', re.I)})
        if not captcha_input:
            field_match = re.search(r'name=["\'](captcha|code|val|captch5)[^"\']*["\']', text, re.I)
            field_name = field_match.group(1) if field_match else "captcha"
        else:
            field_name = captcha_input["name"]
            
        post_data = {field_name: res}
        # Add ALL other form elements (hidden, buttons, etc)
        if form:
            for inp in form.find_all(["input", "button", "select"]):
                name = inp.get("name")
                value = inp.get("value", "")
                if name and name not in post_data:
                    post_data[name] = value
        else:
            # Regex fallback for hidden fields
            for m in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']', text):
                if m.group(1) not in post_data:
                    post_data[m.group(1)] = m.group(2)
        
        logger.debug(f"Submitting captcha to: {form_action} with data: {post_data}")
        headers = {**self.base_headers, "referer": original_url}
        # Use urlencode for FlareSolverr and add a wait time to allow page transition
        solved_text = await self._smart_request(form_action, method="POST", data=urlencode(post_data), headers=headers, wait=3000)
        
        # Try to parse the new page
        try:
            return self._parse_uprot_html(solved_text)
        except:
            return None

    def _parse_uprot_html(self, text: str) -> str:
        """Parse uprot HTML to extract redirect link."""
        # 1. Look for direct links in text (including escaped slashes)
        match = re.search(r'https?://(?:www\.)?(?:stayonline\.pro|maxstream\.video)[^"\'\s<>\\ ]+', text.replace("\\/", "/"))
        if match:
            return match.group(0)
            
        # 2. Look for JavaScript-based redirects
        js_match = re.search(r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', text)
        if js_match:
            return js_match.group(1)
            
        # 3. Look for Meta refresh
        meta_match = re.search(r'content=["\']0;\s*url=([^"\']+)["\']', text, re.I)
        if meta_match:
            return meta_match.group(1)
            
        # 4. Use BeautifulSoup for interactive elements
        soup = BeautifulSoup(text, "lxml")
        
        # Look for Bulma-style buttons or links with "Continue" text
        for btn in soup.find_all(["a", "button"]):
            text_content = btn.get_text().strip().lower()
            if "continue" in text_content or "continua" in text_content or "vai al" in text_content:
                href = btn.get("href")
                if not href and btn.parent.name == "a":
                    href = btn.parent.get("href")
                
                if href and "uprot" not in href:
                    return href
        
        # Specific Bulma selectors
        for selector in ['a[href*="maxstream"]', 'a[href*="stayonline"]', '.button.is-info', '.button.is-success', 'a.button']:
            tag = soup.select_one(selector)
            if tag and tag.get("href") and "uprot" not in tag["href"]:
                return tag["href"]
        
        # If it's a form
        form = soup.find("form")
        if form and form.get("action") and "uprot" not in form["action"]:
            return form["action"]
            
        return None

    def _parse_uprot_folder(self, text: str, season, episode) -> str | None:
        """
        Parse a /msfld/ folder HTML and return the /msfi/ link for the
        requested S{ss}E{ee}. CB01 indexes long anime by absolute episode in
        season 1 (e.g. Naruto S3E2 = 1x85), so callers should pass the
        already-resolved absolute episode when applicable.
        """
        try:
            s_int = int(season)
            e_int = int(episode)
        except (TypeError, ValueError):
            return None
        s_pad = f"{s_int:02d}"
        e_pad = f"{e_int:02d}"
        # Order: most specific first. Each pattern is followed by an msfi href
        # within ~500 chars (the row layout in the folder HTML).
        patterns = [
            rf"S{s_pad}E{e_pad}",
            rf"\b0*{s_int}x0*{e_int}\b",
            rf"\b0*{s_int}&#215;0*{e_int}\b",
            rf"\b0*{s_int}×0*{e_int}\b",
        ]
        for pat in patterns:
            m = re.search(
                rf"{pat}[\s\S]{{0,500}}?href=['\"]([^'\"]+/msfi/[^'\"]+)['\"]",
                text,
                re.I,
            )
            if m:
                return m.group(1)
        return None

    async def get_uprot(self, link: str, season=None, episode=None):
        """Extract MaxStream URL from uprot redirect.

        Supports three uprot path types:
          - /msf/{id}    single movie (legacy alias /mse/ still works upstream)
          - /msfi/{id}   single episode (NOT to be rewritten)
          - /msfld/{id}  folder of episodes; requires season + episode kwargs to
                         pick the right /msfi/ link inside the folder HTML
        """
        # Map only the modern /msf/ single-video path to its legacy /mse/ alias.
        # A naive str.replace("msf", "mse") corrupts /msfld/ into /mseld/ (404)
        # and /msfi/ into /msei/ (a deprecated path that returns 500 for new IDs).
        link = re.sub(r"/msf/", "/mse/", link)

        # Direct request (user should provide non-datacenter proxy in GLOBAL_PROXY)
        text = await self._smart_request(link)

        # If this is a folder URL, resolve the requested episode first, then
        # continue the normal flow on the picked /msfi/ link.
        if "/msfld/" in link:
            if season is None or episode is None:
                raise ExtractorError(
                    "msfld folder URL requires 'season' and 'episode' parameters"
                )
            episode_link = self._parse_uprot_folder(text, season, episode)
            if not episode_link:
                raise ExtractorError(
                    f"Episode S{season}E{episode} not found in msfld folder"
                )
            link = episode_link
            text = await self._smart_request(link)

        # 1. Try normal parse
        res = self._parse_uprot_html(text)
        if res:
            return res

        # 2. If no link, try puzzle/captcha solver
        logger.debug("Direct link not found, checking for captcha...")
        res = await self._solve_uprot_captcha(text, link)
        if res:
            return res

        # If we see "Cloudflare" or "Challenge" in text, it's a block
        if "cf-challenge" in text or "ray id" in text.lower() or "checking your browser" in text.lower():
            raise ExtractorError("Cloudflare block (Browser check/Challenge)")

        logger.error(f"Uprot Parse Failure. Content: {text[:2000]}...")
        raise ExtractorError("Redirect link not found in uprot page")

    async def extract(self, url: str, **kwargs) -> dict:
        """Extract Maxstream URL.

        For /msfld/ folder URLs, callers must pass season=N&episode=M as
        query parameters (forwarded by MFP routes as kwargs).
        """
        season = kwargs.get("season")
        episode = kwargs.get("episode")
        maxstream_url = await self.get_uprot(url, season=season, episode=episode)
        logger.debug(f"Target URL: {maxstream_url}")
        
        # Use strict headers to avoid Error 131
        headers = {
            **self.base_headers,
            "referer": "https://uprot.net/",
            "accept-language": "en-US,en;q=0.5"
        }
        
        text = await self._smart_request(maxstream_url, headers=headers)
        
        # Direct sources check
        direct_match = re.search(r'sources:\s*\[\{src:\s*"([^"]+)"', text)
        if direct_match:
            return {
                "destination_url": direct_match.group(1),
                "request_headers": {**self.base_headers, "referer": maxstream_url},
                "mediaflow_endpoint": self.mediaflow_endpoint,
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
        }

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
