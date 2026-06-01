from services.proxy_shared import *
from utils.solver_manager import try_shutdown_idle_flaresolverr

class HLSProxyCoreMixin:

    async def shorten_hls_url(self, url: str) -> str:
        """Codifica l'URL direttamente in base64 (nessuna memoria usata per mappe)."""
        if not url:
            return ""
        encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return f"u_{encoded}"

    def _refresh_segment_token(self, segment_url: str) -> str | None:
        """
        For signed-token CDN URLs (VidXgo), rewrite the query of the requested
        segment so it uses the freshest token currently known in
        `captured_hls_manifest_map`. Matches by segment path: the path
        component (everything before `?`) is stable across token rotations,
        while the query holds the rotating token.

        Returns the rewritten URL, or None if no match (caller falls back to
        the original URL).
        """
        try:
            parsed = urllib.parse.urlparse(segment_url)
        except Exception:
            return None
        if not parsed.query:
            return None
        seg_path = parsed.path
        if not seg_path:
            return None
        # Only meaningful for hosts that put a rotating VidXgo-style `e=` token
        # in the query.
        q = urllib.parse.parse_qs(parsed.query)
        if "e" not in q:
            return None
        # Scan all captured variant manifests. The most recently refreshed
        # one wins (highest stored_at).
        candidates = []
        for entry in self.captured_hls_manifest_map.values():
            captured_url, captured_manifest, _, stored_at, _, _ = entry
            if not captured_manifest:
                continue
            # Signed CDNs may rotate hostnames and path prefixes together with
            # tokens, so match the stable tail rather than the full URL/path.
            for abs_seg in self._iter_hls_manifest_urls(captured_url, captured_manifest):
                cand = urllib.parse.urlparse(abs_seg)
                if self._segment_paths_match(seg_path, cand.path):
                    candidates.append((stored_at, abs_seg))
                    break
        if not candidates:
            return None
        candidates.sort(key=lambda x: x[0], reverse=True)
        fresh_url = candidates[0][1]
        if fresh_url == segment_url:
            return None
        logger.debug("Refreshed segment token: %s -> %s", segment_url[-60:], fresh_url[-60:])
        return fresh_url

    async def _refresh_captured_hls_for_segment(
        self,
        segment_url: str,
        bypass_warp: bool = False,
        forced_proxy: str | None = None,
    ) -> bool:
        """Re-extract a captured HLS source that contains the requested segment."""
        matches = self._captured_hls_matches_for_segment(segment_url)
        forced_proxy = urllib.parse.unquote(forced_proxy) if forced_proxy else None

        seen_sources = set()
        for _, source_url, captured_headers, entry_ttl in sorted(matches, key=lambda item: item[0], reverse=True):
            if source_url in seen_sources:
                continue
            seen_sources.add(source_url)
            try:
                proxy_token = SELECTED_PROXY_CONTEXT.set(forced_proxy)
                strict_proxy_token = STRICT_PROXY_CONTEXT.set(bool(forced_proxy))
                try:
                    extractor = await self.get_extractor(
                        source_url,
                        captured_headers,
                        bypass_warp=bypass_warp,
                    )
                    refreshed = await extractor.extract(
                        source_url,
                        request_headers=captured_headers,
                        force_refresh=True,
                        background_refresh=True,
                        bypass_warp=bypass_warp,
                        proxy=forced_proxy,
                    )
                finally:
                    SELECTED_PROXY_CONTEXT.reset(proxy_token)
                    STRICT_PROXY_CONTEXT.reset(strict_proxy_token)
                refreshed_headers = refreshed.get("request_headers", captured_headers)
                refreshed_manifests = list((refreshed.get("captured_manifests") or {}).items())
                if not refreshed_manifests and refreshed.get("captured_manifest"):
                    refreshed_manifests = [(
                        refreshed.get("destination_url"),
                        refreshed.get("captured_manifest"),
                    )]

                stored_any = False
                for refreshed_url, refreshed_manifest in refreshed_manifests:
                    if not refreshed_url or not refreshed_manifest:
                        continue
                    await self.store_captured_hls_manifest(
                        refreshed_url,
                        refreshed_manifest,
                        refreshed_headers,
                        ttl=entry_ttl,
                        source_url=source_url,
                    )
                    stored_any = True
                if stored_any:
                    logger.info("captured HLS refreshed on segment 403: %s", source_url)
                    return True
            except Exception as exc:
                logger.debug("Captured HLS on-demand refresh failed for %s: %s", source_url, exc)
        return False

    def _captured_hls_matches_for_segment(self, segment_url: str):
        try:
            parsed = urllib.parse.urlparse(segment_url)
        except Exception:
            return []
        if not parsed.path:
            return []

        matches = []
        for entry in self.captured_hls_manifest_map.values():
            captured_url, captured_manifest, captured_headers, stored_at, entry_ttl, source_url = entry
            if not captured_manifest or not source_url:
                continue
            for abs_seg in self._iter_hls_manifest_urls(captured_url, captured_manifest):
                cand = urllib.parse.urlparse(abs_seg)
                if self._segment_paths_match(parsed.path, cand.path):
                    matches.append((stored_at, source_url, captured_headers, entry_ttl))
                    break
        return matches

    @staticmethod
    def _iter_hls_manifest_urls(captured_url: str, captured_manifest: str):
        base_query = urllib.parse.urlparse(captured_url).query
        for line in captured_manifest.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            abs_url = urllib.parse.urljoin(captured_url, line)
            parsed_abs = urllib.parse.urlparse(abs_url)
            if base_query and not parsed_abs.query:
                abs_url = urllib.parse.urlunparse(parsed_abs._replace(query=base_query))
            yield abs_url

    @staticmethod
    def _parse_signed_expiry_ts(u: str) -> float | None:
        """Parse HLS signed URL expiry from VidXgo `e=`."""
        try:
            params = urllib.parse.parse_qs(urllib.parse.urlparse(u).query)
            raw_e = params.get("e", [None])[0]
            if raw_e:
                return float(raw_e) / 1000.0
        except Exception:
            return None
        return None

    @staticmethod
    def _segment_paths_match(old_path: str, candidate_path: str) -> bool:
        if old_path == candidate_path:
            return True

        old_parts = [part for part in old_path.split("/") if part]
        candidate_parts = [part for part in candidate_path.split("/") if part]
        if not old_parts or not candidate_parts:
            return False

        if old_parts[-1] != candidate_parts[-1]:
            return False

        common_tail = min(3, len(old_parts), len(candidate_parts))
        return old_parts[-common_tail:] == candidate_parts[-common_tail:]

    async def store_captured_hls_manifest(
        self,
        url: str,
        manifest: str,
        headers: dict,
        ttl: int = 30,
        source_url: str = None,
    ) -> str:
        now = time.time()
        expired_keys = [
            key for key, (_, _, _, ts, entry_ttl, _) in self.captured_hls_manifest_map.items()
            if now - ts > entry_ttl
        ]
        for key in expired_keys:
            self.captured_hls_manifest_map.pop(key, None)

        stable_key = self._captured_manifest_stable_key(source_url, url)
        url_id = f"cm_{hashlib.md5(stable_key.encode()).hexdigest()[:12]}"
        self.captured_hls_manifest_map[url_id] = (url, manifest, headers, now, ttl, source_url)
        if source_url and (
            url_id not in self.captured_hls_refresh_tasks
            or self.captured_hls_refresh_tasks[url_id].done()
        ):
            async def refresh_loop():
                while url_id in self.captured_hls_manifest_map:
                    await asyncio.sleep(2)
                    entry = self.captured_hls_manifest_map.get(url_id)
                    if not entry:
                        break
                    captured_url, _, captured_headers, stored_at, entry_ttl, entry_source_url = entry
                    # Prefer the actual signed-URL expiry when present,
                    # falling back to the static entry_ttl window.
                    expiry_ts = self._parse_signed_expiry_ts(captured_url)
                    now_ts = time.time()
                    if expiry_ts is not None:
                        seconds_left = expiry_ts - now_ts
                    else:
                        seconds_left = entry_ttl - (now_ts - stored_at)
                    # Refresh proactively when <60s remain on the token.
                    if seconds_left > 60:
                        await asyncio.sleep(min(seconds_left - 60, 60))
                        continue
                    # Hard GC only if the entry is long-dead AND no signed URL
                    # to consult (avoid evicting entries that still have valid e=).
                    if expiry_ts is None and now_ts - stored_at > entry_ttl:
                        self.captured_hls_manifest_map.pop(url_id, None)
                        break
                    try:
                        extractor = await self.get_extractor(
                            entry_source_url,
                            captured_headers,
                        )
                        refreshed = await extractor.extract(
                            entry_source_url,
                            request_headers=captured_headers,
                            force_refresh=True,
                            background_refresh=True,
                        )
                        captured_stable_key = self._captured_manifest_stable_key(
                            entry_source_url,
                            captured_url,
                        )
                        refreshed_manifests = list(
                            (refreshed.get("captured_manifests") or {}).items()
                        )
                        if not refreshed_manifests and refreshed.get("captured_manifest"):
                            refreshed_manifests = [(
                                refreshed.get("destination_url"),
                                refreshed.get("captured_manifest"),
                            )]
                        for refreshed_url, refreshed_manifest in reversed(refreshed_manifests):
                            if refreshed_url and self._captured_manifest_stable_key(
                                entry_source_url,
                                refreshed_url,
                            ) == captured_stable_key:
                                refreshed_headers = refreshed.get("request_headers", captured_headers)
                                # CRITICAL: bump stored_at so the entry is not
                                # GC'd by the entry_ttl check above, and so the
                                # next refresh cycle uses the fresh signed URL
                                # to compute seconds_left.
                                self.captured_hls_manifest_map[url_id] = (
                                    refreshed_url,
                                    refreshed_manifest,
                                    refreshed_headers,
                                    time.time(),
                                    entry_ttl,
                                    entry_source_url,
                                )
                                logger.info(
                                    "captured HLS refreshed %s (token_left=%.0fs)",
                                    entry_source_url,
                                    (self._parse_signed_expiry_ts(refreshed_url) or 0) - time.time(),
                                )
                                break
                    except Exception as exc:
                        logger.debug("Captured HLS background refresh failed for %s: %s", entry_source_url, exc)

            self.captured_hls_refresh_tasks[url_id] = asyncio.create_task(refresh_loop())
        return url_id

    @staticmethod
    def _captured_manifest_stable_key(source_url: str | None, manifest_url: str) -> str:
        if not source_url:
            return manifest_url

        parsed = urllib.parse.urlparse(manifest_url)
        path_parts = [part for part in parsed.path.split("/") if part]
        suffix = "/".join(path_parts[-3:]) or manifest_url
        volatile_params = {"e"}
        stable_params = [
            (key, value)
            for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            if key.lower() not in volatile_params
        ]
        stable_query = urllib.parse.urlencode(stable_params)
        if stable_query:
            suffix = f"{suffix}?{stable_query}"
        return f"{source_url}|{suffix}"

    async def start_tasks(self):
        """Starts background tasks for the proxy."""
        asyncio.create_task(self._update_latest_version())
        if ENABLE_WARP:
            asyncio.create_task(self._update_warp_status_loop())
        asyncio.create_task(self._cleanup_stale_sessions())

    async def _cleanup_stale_sessions(self):
        """Periodically close stale extractors unused for >30s."""
        while True:
            await asyncio.sleep(60)
            now = time.time()
            stale_ext = [
                k for k, t in self._extractor_atimes.items()
                if now - t > 30 and k in self.extractors
            ]
            for key in stale_ext:
                ext = self.extractors.pop(key, None)
                self._extractor_atimes.pop(key, None)
                if ext and hasattr(ext, 'close'):
                    try:
                        await ext.close()
                    except Exception:
                        pass
                logger.info("🧹 Cleaned stale extractor: %s", key)
            for key, task in list(self.captured_hls_refresh_tasks.items()):
                if task.done():
                    self.captured_hls_refresh_tasks.pop(key, None)
            await try_shutdown_idle_flaresolverr()

    async def _update_warp_status_loop(self):
        """Periodically checks WARP status via Cloudflare trace (Universal)."""
        while True:
            try:
                # We use the proxy session to check if the SOCKS5H proxy is working
                session, _ = await self._get_proxy_session(
                    "https://www.cloudflare.com/cdn-cgi/trace",
                    forced_proxy=WARP_PROXY_URL,
                )
                async with session.get("https://www.cloudflare.com/cdn-cgi/trace", timeout=5) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if "warp=on" in text:
                            self.warp_status = "Connected"
                        else:
                            self.warp_status = "Disconnected"
                    else:
                        self.warp_status = "Error"
            except Exception:
                self.warp_status = "Disconnected"

            await asyncio.sleep(60) # Check every minute

    async def _update_latest_version(self):
        """Periodically checks GitHub for the latest version in the background."""
        while True:
            await self._refresh_latest_version()
            # Check every hour in background
            await asyncio.sleep(3600)

    async def _refresh_latest_version(self):
        """Checks GitHub config.py for the latest version with cache busting.
        Can be called on-demand (e.g. on page refresh).
        """
        try:
            # Use a timestamp to bypass GitHub's cache
            cache_buster = int(time.time())
            url = f"https://raw.githubusercontent.com/realbestia1/EasyProxy/main/config.py?t={cache_buster}"

            # Use a direct session with a short timeout to not block UI too long
            session = await self._get_session()
            async with session.get(url, timeout=2) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    # Use regex to find APP_VERSION = "..." or '...'
                    match = re.search(r'APP_VERSION\s*=\s*["\']([^"\']+)["\']', text)
                    if match:
                        new_version = match.group(1)
                        if self.latest_version != new_version:
                            self.latest_version = new_version
                            logger.info(f"🆕 Latest version updated: {self.latest_version}")
                    else:
                        if self.latest_version == "Checking...":
                            self.latest_version = "Unknown"
                else:
                    if self.latest_version == "Checking...":
                        self.latest_version = "Error"
        except Exception as e:
            if self.latest_version == "Checking...":
                self.latest_version = "Unknown"
            logger.debug(f"Version check skipped or failed: {e}")

    @staticmethod
    def _strip_fake_png_header_from_ts(content: bytes) -> bytes:
        """
        Some providers prepend a fake 8-byte PNG signature to TS segments.
        Strip it only when bytes after the header still match TS sync markers.
        """
        png_sig = b"\x89PNG\r\n\x1a\n"
        if len(content) <= 8 or not content.startswith(png_sig):
            return content

        ts_payload = content[8:]
        # MPEG-TS sync byte is 0x47 at packet boundaries.
        if not ts_payload or ts_payload[0] != 0x47:
            return content
        if len(ts_payload) > 188 and ts_payload[188] != 0x47:
            return content

        logger.info(
            "Removed fake PNG header from TS segment (%d -> %d bytes)",
            len(content),
            len(ts_payload),
        )
        return ts_payload

    @staticmethod
    def _compute_key_headers(
        key_url: str, secret_key: str, user_agent: str = None
    ) -> tuple[int, int, str, str] | None:
        """
        Compute X-Key-Timestamp, X-Key-Nonce, X-Fingerprint, and X-Key-Path for a /key/ URL.

        Algorithm:
        1. Extract resource and number from URL pattern /key/{resource}/{number}
        2. ts = Unix timestamp in seconds
        3. hmac_hash = HMAC-SHA256(resource, secret_key).hex()
        4. nonce = proof-of-work: find i where MD5(hmac+resource+number+ts+i)[:4] < 0x1000
        5. fingerprint = SHA256(useragent + screen_resolution + timezone + language).hex()[:16]
        6. key_path = HMAC-SHA256("resource|number|ts|fingerprint", secret_key).hex()[:16]

        Args:
            key_url: The key URL containing /key/{resource}/{number}
            secret_key: The HMAC secret key
            user_agent: The user agent string for fingerprint calculation

        Returns:
            Tuple of (timestamp, nonce, fingerprint, key_path) or None if URL doesn't match pattern
        """
        # Extract resource and number from URL
        pattern = r"/key/([^/]+)/(\d+)"
        match = re.search(pattern, key_url)

        if not match:
            return None

        resource = match.group(1)
        number = match.group(2)

        ts = int(time.time())

        # Compute HMAC-SHA256
        hmac_hash = hmac.new(
            secret_key.encode("utf-8"), resource.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        # Proof-of-work loop
        nonce = 0
        for i in range(100000):
            combined = f"{hmac_hash}{resource}{number}{ts}{i}"
            md5_hash = hashlib.md5(combined.encode("utf-8")).hexdigest()
            prefix_value = int(md5_hash[:4], 16)

            if prefix_value < 0x1000:  # < 4096
                nonce = i
                break

        # Compute fingerprint
        fp_user_agent = (
            user_agent
            if user_agent
            else "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
        )
        fp_screen_res = "1920x1080"
        fp_timezone = "UTC"
        fp_language = "en"

        fp_string = f"{fp_user_agent}{fp_screen_res}{fp_timezone}{fp_language}"

        fingerprint = hashlib.sha256(fp_string.encode("utf-8")).hexdigest()[:16]

        # Compute key-path
        key_path_string = f"{resource}|{number}|{ts}|{fingerprint}"
        key_path = hmac.new(
            secret_key.encode("utf-8"), key_path_string.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:16]

        return ts, nonce, fingerprint, key_path

    async def _get_session(self, prefer_default_family: bool = False, url: str = None):
        if url:
            self._check_dynamic_warp_bypass(url)
        target_attr = "flex_session" if prefer_default_family else "session"
        session = getattr(self, target_attr)
        if session is None or session.closed:
            connector_kwargs = {
                "limit": 0,
                "limit_per_host": 0,
                "keepalive_timeout": 60,
                "enable_cleanup_closed": True,
            }
            if not prefer_default_family:
                connector_kwargs["family"] = socket.AF_INET

            connector = TCPConnector(**connector_kwargs)
            session = aiohttp.ClientSession(
                timeout=ClientTimeout(total=None, connect=30, sock_connect=30, sock_read=None),
                connector=connector,
            )
            setattr(self, target_attr, session)
        return session

    def _check_dynamic_warp_bypass(self, url: str, force: bool = False):
        """Dynamically adds domain to WARP bypass if it matches known patterns or if forced."""
        if not ENABLE_WARP or VERSION_MODE != "Full":
            return

        try:
            from urllib.parse import urlsplit
            domain = urlsplit(url).netloc
            if not domain: return

            if is_dynamic_warp_bypass_candidate(domain, force=force):
                if domain not in BYPASSED_WARP_DOMAINS:
                    # Always bypass base domain for these providers
                    base_domain = ".".join(domain.split(".")[-2:])
                    logging.info(f"⚡ [Dynamic Bypass] Adding {base_domain} (and {domain}) to WARP exclusion list...")

                    os.system(f"warp-cli --accept-tos tunnel host add {base_domain} > /dev/null 2>&1")
                    os.system(f"warp-cli --accept-tos tunnel host add {domain} > /dev/null 2>&1")

                    # In Proxy mode, we must also update the local exclusion list
                    if base_domain not in WARP_EXCLUDE_DOMAINS:
                        WARP_EXCLUDE_DOMAINS.append(base_domain)
                    if domain not in WARP_EXCLUDE_DOMAINS:
                        WARP_EXCLUDE_DOMAINS.append(domain)

                    BYPASSED_WARP_DOMAINS.add(domain)
                    BYPASSED_WARP_DOMAINS.add(base_domain)
                    time.sleep(1.0)
        except Exception as e:
            logging.error(f"❌ Error in dynamic WARP bypass: {e}")

    async def _get_proxy_session(self, url: str, bypass_warp: bool = False, forced_proxy: str | None = None):
        """Get a session with proxy support for the given URL.

        Sessions are cached and reused for the same proxy to improve performance.
        Unused sessions older than 120s are closed and removed.

        Returns: (session, proxy_url) tuple
        - session: The aiohttp ClientSession to use
        - proxy_url: The proxy URL being used, or None for direct connection
        """
        # Trigger dynamic bypass check before getting proxy settings
        self._check_dynamic_warp_bypass(url, force=bypass_warp)

        # ✅ FIX: Decodifica il proxy se è URL-encoded
        if forced_proxy:
            forced_proxy = urllib.parse.unquote(forced_proxy)

        proxy = forced_proxy or get_proxy_for_url(url, TRANSPORT_ROUTES, GLOBAL_PROXIES, bypass_warp=bypass_warp)

        prefer_default_family = prefer_default_family_for_url(url)

        if proxy:
            is_warp = "127.0.0.1:1080" in proxy
            if proxy in self.proxy_sessions:
                cached_session = self.proxy_sessions[proxy]
                if not cached_session.closed:
                    if is_warp:
                        return cached_session, proxy
                    atime = self._proxy_session_atimes.get(proxy, 0)
                    if time.time() - atime > 30:
                        logger.info(f"🧹 Closing idle proxy session: {proxy}")
                        del self.proxy_sessions[proxy]
                        await cached_session.close()
                    else:
                        self._proxy_session_atimes[proxy] = time.time()
                        return cached_session, proxy
                else:
                    del self.proxy_sessions[proxy]

            # Create new session and cache it
            logger.info(f"🌍 Creating proxy session: {proxy}")
            try:
                connector_url = proxy
                rdns = True
                if connector_url.startswith("socks5h://"):
                    connector_url = connector_url.replace("socks5h://", "socks5://")
                    rdns = True
                elif connector_url.startswith("socks4a://"):
                    connector_url = connector_url.replace("socks4a://", "socks4://")
                    rdns = True

                connector = ProxyConnector.from_url(
                    connector_url,
                    limit=0,
                    limit_per_host=0,
                    keepalive_timeout=60,
                    family=socket.AF_INET,
                    rdns=rdns,
                )
                timeout = ClientTimeout(total=None, connect=30, sock_connect=30, sock_read=None)
                session = ClientSession(timeout=timeout, connector=connector)
                self.proxy_sessions[proxy] = session
                self._proxy_session_atimes[proxy] = time.time()
                return session, proxy
            except Exception as e:
                logger.warning(
                    f"⚠️ Failed to create proxy connector: {e}"
                )
                raise

        # Fallback to shared non-proxy session
        session = await self._get_session(prefer_default_family=prefer_default_family)
        return session, None

    async def _retry_special_cdn_request(self, request_target, headers, disable_ssl: bool):
        """Retry a provider-protected CDN once via an alternate aiohttp route."""
        retry_proxy = None
        if ENABLE_WARP and WARP_PROXY_URL and "127.0.0.1" not in WARP_PROXY_URL:
            retry_proxy = WARP_PROXY_URL
        elif ENABLE_WARP and WARP_PROXY_URL:
            from config import is_proxy_alive
            if is_proxy_alive(WARP_PROXY_URL):
                retry_proxy = WARP_PROXY_URL
        elif GLOBAL_PROXIES:
            retry_proxy = GLOBAL_PROXIES[0]

        if not retry_proxy:
            return None

        try:
            connector = get_connector_for_proxy(
                retry_proxy,
                limit=0,
                limit_per_host=0,
                keepalive_timeout=60,
                family=socket.AF_INET,
                rdns=True,
            )
            timeout = ClientTimeout(total=None, connect=30, sock_connect=30, sock_read=None)
            async with ClientSession(timeout=timeout, connector=connector) as retry_session:
                async with retry_session.get(
                    request_target,
                    headers=headers,
                    ssl=not disable_ssl,
                ) as retry_resp:
                    if retry_resp.status not in [200, 206]:
                        return None
                    return {
                        "status": retry_resp.status,
                        "headers": dict(retry_resp.headers),
                        "body": await retry_resp.read(),
                        "proxy": retry_proxy,
                    }
        except Exception as e:
            logger.warning("Provider CDN retry via alternate route failed: %r", e)
            return None

    @staticmethod
    def _query_flag_is_true(value: str | None) -> bool:
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _should_force_direct_from_query(self, request) -> bool:
        direct_param = request.query.get("direct")
        if self._query_flag_is_true(direct_param):
            return True

        for param_name, param_value in request.query.items():
            if not param_name.startswith("h_"):
                continue
            header_name = param_name[2:].replace("_", "-").lower()
            if header_name in {"x-direct-connection", "x-force-direct"}:
                return self._query_flag_is_true(param_value)

        return False

    async def get_extractor(self, url: str, request_headers: dict, host: str = None, bypass_warp: bool = False):
        """Ottiene l'estrattore appropriato per l'URL."""
        result = await resolve_extractor(
            self,
            url,
            request_headers,
            host=host,
            bypass_warp=bypass_warp,
        )
        if result:
            for key in list(self.extractors.keys()):
                if self.extractors[key] is result:
                    self._extractor_atimes[key] = time.time()
                    break
        return result

    async def _resolve_url_id(self, url_id: str) -> str | None:
        """Risolve un url_id nell'URL originale."""
        if not url_id:
            return None
        # CM IDs stored in captured_hls_manifest_map
        if url_id.startswith("cm_") and url_id in self.captured_hls_manifest_map:
            return self.captured_hls_manifest_map[url_id][0]
        # U_ IDs are base64-encoded URLs
        if url_id.startswith("u_"):
            try:
                padded = url_id[2:] + "=="
                return base64.urlsafe_b64decode(padded).decode()
            except Exception:
                return None
        return None

    async def cleanup(self):
        """Pulizia delle risorse"""
        try:
            if self.session and not self.session.closed:
                await self.session.close()
            if self.flex_session and not self.flex_session.closed:
                await self.flex_session.close()

            # Close all cached proxy sessions
            for proxy_url, session in list(self.proxy_sessions.items()):
                if session and not session.closed:
                    await session.close()
            self.proxy_sessions.clear()
            self._proxy_session_atimes.clear()

            # Close all cached curl sessions
            for session in list(self.curl_sessions.values()):
                if session:
                    await session.close()
            self.curl_sessions.clear()

            for extractor in self.extractors.values():
                if hasattr(extractor, "close"):
                    await extractor.close()
            self._extractor_atimes.clear()

            for task in self.captured_hls_refresh_tasks.values():
                task.cancel()
            self.captured_hls_refresh_tasks.clear()
            self.captured_hls_manifest_map.clear()
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
