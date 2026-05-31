from services.proxy_shared import *


class HLSProxyManifestHandlerMixin:

    async def handle_proxy_request(self, request):
        """Gestisce le richieste proxy principali"""
        if not check_password(request):
            logger.warning(
                f"⛔ Access denied: Invalid or missing API Password. IP: {request.remote}"
            )
            return web.Response(status=401, text="Unauthorized: Invalid API Password")

        target_url = request.query.get("url") or request.query.get("d")

        # Check if it's a native MPD request (no HLS conversion)
        is_native_mpd = request.path.endswith("/manifest.mpd")

        bypass_warp = (request.query.get("warp", "").lower() == "off")
        token = BYPASS_WARP_CONTEXT.set(bypass_warp)
        proxy_token = SELECTED_PROXY_CONTEXT.set(None)
        selected_proxy = None
        raw_proxy = request.query.get("proxy")
        if raw_proxy:
            selected_proxy = urllib.parse.unquote(raw_proxy)
            if "://" not in selected_proxy and "%3a" in selected_proxy.lower():
                selected_proxy = urllib.parse.unquote(selected_proxy)
        force_direct = self._should_force_direct_from_query(request)

        try:
            extractor = None

            # --- Gestione URL brevi (Shortened URLs) ---
            url_id = request.query.get("hls_url_id")
            if url_id and url_id in self.captured_hls_manifest_map:
                captured_url, _, _, _, entry_ttl, _ = self.captured_hls_manifest_map[url_id]
                target_url = captured_url
                self.hls_url_map[url_id] = (captured_url, time.time(), entry_ttl)
            if url_id and url_id in self.hls_url_map:
                target_url, stored_at, entry_ttl = self.hls_url_map[url_id]
                if time.time() - stored_at <= entry_ttl:
                    logger.debug(f"🔗 Resolved short URL ID: {url_id}")
                else:
                    self.hls_url_map.pop(url_id, None)
                    target_url = None

            force_refresh = request.query.get("force", "false").lower() == "true"
            redirect_stream = (
                request.query.get("redirect_stream", "true").lower() == "true"
            )

            if not target_url:
                return web.Response(text="Missing 'url' or 'd' parameter", status=400)

            # aiohttp already decodes query parameters once.
            # Do not unquote again here: URLs with embedded encoded separators
            # (for example Firebase Storage object paths using `%2F`) would be
            # corrupted and upstream would respond with HTTP 400.

            # --- GESTIONE HEADER ---
            combined_headers = {}

            # 0. Header passati come h_X=Y
            for param_name, param_value in request.query.items():
                if param_name.startswith("h_"):
                    header_name = param_name[2:]
                    combined_headers[header_name] = param_value

            if (
                url_id
                and url_id in self.captured_hls_manifest_map
                and request.path.endswith("manifest.m3u8")
            ):
                captured_url, captured_manifest, captured_headers, stored_at, entry_ttl, source_url = self.captured_hls_manifest_map[url_id]
                if time.time() - stored_at <= entry_ttl:
                    self.captured_hls_manifest_map[url_id] = (
                        captured_url,
                        captured_manifest,
                        captured_headers,
                        time.time(),
                        entry_ttl,
                        source_url,
                    )
                    self.hls_url_map[url_id] = (captured_url, time.time(), entry_ttl)
                    scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
                    host = request.headers.get("X-Forwarded-Host", request.host)
                    proxy_base = f"{scheme}://{host}"
                    merged_headers = {**captured_headers, **combined_headers}
                    rewritten_manifest = await ManifestRewriter.rewrite_manifest_urls(
                        manifest_content=captured_manifest,
                        base_url=captured_url,
                        proxy_base=proxy_base,
                        stream_headers=merged_headers,
                        original_channel_url=source_url or request.query.get("url") or request.query.get("d", ""),
                        api_password=request.query.get("api_password"),
                        get_extractor_func=lambda url, headers, host=None: self.get_extractor(
                            url, headers, host, bypass_warp=bypass_warp
                        ),
                        no_bypass=request.query.get("no_bypass") == "1",
                        shorten_url_func=None,
                        bypass_warp=bypass_warp,
                        disable_ssl=request.query.get("disable_ssl") == "1",
                        selected_proxy=selected_proxy,
                        force_direct=force_direct,
                    )
                    return web.Response(
                        text=rewritten_manifest,
                        headers={
                            "Content-Type": "application/vnd.apple.mpegurl",
                            "Access-Control-Allow-Origin": "*",
                            "Cache-Control": "no-cache",
                        },
                    )
                self.captured_hls_manifest_map.pop(url_id, None)

            captured_manifest = None
            is_rewritten_hls_segment = request.path.startswith("/proxy/hls/segment.")
            if is_rewritten_hls_segment:
                # For signed-token CDNs (e.g. VidXgo) the original `?d=` URL
                # carries a short-lived token. If the latest captured manifest
                # for the same stream has fresher tokens, use those instead so
                # we never hit 403 on the upstream fetch.
                target_url = self._refresh_segment_token(target_url) or target_url
                extractor = None
                stream_url = target_url
                stream_headers = {}
                for header_name, header_value in combined_headers.items():
                    if header_name.lower() in {
                        "host",
                        "connection",
                        "cache-control",
                        "icy-metadata",
                        "accept-encoding",
                        "content-length",
                        "x-easyproxy-disable-ssl",
                    }:
                        continue
                    stream_headers[header_name] = header_value
            else:
                extractor = await self.get_extractor(target_url, combined_headers, bypass_warp=bypass_warp)

                # ✅ FIX CRITICO: Forza l'aggiornamento degli header dell'estrattore.
                # Siccome gli estrattori vengono memorizzati in self.extractors (cache),
                # se non aggiorniamo request_headers, i segmenti successivi userebbero
                # gli header del primo manifest caricato, ignorando h_Referer/h_Origin.
                if extractor:
                    extractor.request_headers = combined_headers


                # Passa il flag force_refresh all'estrattore
                result = await extractor.extract(
                    target_url,
                    force_refresh=force_refresh,
                    request_headers=combined_headers,
                    bypass_warp=bypass_warp,
                    proxy=request.query.get("proxy")
                )
                bypass_warp = result.get("bypass_warp", bypass_warp)
                stream_url = result["destination_url"]
                stream_headers = result.get("request_headers", {})
                captured_manifest = result.get("captured_manifest")
                captured_manifests = result.get("captured_manifests") or {}
                force_disable_ssl = result.get("disable_ssl", False)
                force_direct = result.get("force_direct", force_direct)

                # Cattura e sanifica il proxy per evitare double-encoding (%253A -> %3A)
                raw_proxy = request.query.get("proxy") or result.get("selected_proxy")
                if raw_proxy:
                    # Sanifica e assegna alla variabile che verrà usata dopo
                    selected_proxy = urllib.parse.unquote(raw_proxy)
                    if "://" not in selected_proxy and "%3a" in selected_proxy.lower():
                        selected_proxy = urllib.parse.unquote(selected_proxy)

                if selected_proxy:
                    logger.debug(f"🎯 Final selected proxy for manifest: {selected_proxy}")

                if force_disable_ssl:
                    if "?" in stream_url:
                        stream_url += "&disable_ssl=1"
                    else:
                        stream_url += "?disable_ssl=1"


            # --- DASH NATIVO: Riscrive il manifest per segmenti proxati (senza conversione) ---
            if is_native_mpd:
                scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
                host = request.headers.get("X-Forwarded-Host", request.host)
                proxy_base = f"{scheme}://{host}"

                # Fetch original manifest if not already captured
                if not captured_manifest:
                    async with self.session.get(stream_url, headers=stream_headers) as resp:
                        if resp.status != 200:
                            return web.Response(text=f"Failed to fetch original MPD: {resp.status}", status=resp.status)
                        captured_manifest = await resp.text()
                        stream_url = str(resp.url)

                # Create DASH session
                session_id = await self._create_dash_session(
                    stream_url.rsplit('/', 1)[0] + '/',
                    stream_headers,
                    clearkey=request.query.get("clearkey") or f"{request.query.get('key_id')}:{request.query.get('key')}" if request.query.get('key_id') else None
                )

                rewritten_mpd = ManifestRewriter.rewrite_mpd_native(
                    manifest_content=captured_manifest,
                    mpd_url=stream_url,
                    proxy_base=proxy_base,
                    stream_headers=stream_headers,
                    session_id=session_id
                )

                return web.Response(
                    text=rewritten_mpd,
                    content_type="application/dash+xml",
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Cache-Control": "no-cache",
                    }
                )

            # Se redirect_stream è False, restituisci il JSON con i dettagli (stile MediaFlow)
            if not redirect_stream:
                # Costruisci l'URL base del proxy
                scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
                host = request.headers.get("X-Forwarded-Host", request.host)
                proxy_base = f"{scheme}://{host}"

                mediaflow_endpoint = (
                    result.get("mediaflow_endpoint", "hls_proxy")
                    if not is_rewritten_hls_segment
                    else "hls_proxy"
                )

                # Determina l'endpoint corretto
                endpoint = "/proxy/hls/manifest.m3u8"

                # Check extension of the actual path, not the whole URL
                path_lower = urllib.parse.urlparse(stream_url).path.lower()
                is_direct_video = any(path_lower.endswith(ext) for ext in [".mp4", ".mkv", ".avi", ".mov", ".flv", ".wmv"])

                if mediaflow_endpoint == "proxy_stream_endpoint" or is_direct_video:
                    endpoint = "/proxy/stream"
                elif ".mpd" in path_lower or "manifest" in path_lower and "dash" in path_lower:
                    endpoint = "/proxy/mpd/manifest.m3u8"

                # Prepariamo i parametri per il JSON
                q_params = {}
                api_password = request.query.get("api_password")
                if api_password:
                    q_params["api_password"] = api_password

                response_data = {
                    "destination_url": stream_url,
                    "request_headers": stream_headers,
                    "mediaflow_endpoint": mediaflow_endpoint,
                    "mediaflow_proxy_url": f"{proxy_base}{endpoint}",  # URL Pulito
                    "query_params": q_params,
                }
                return web.json_response(response_data)

            if captured_manifest and request.path.endswith("manifest.m3u8"):
                scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
                host = request.headers.get("X-Forwarded-Host", request.host)
                proxy_base = f"{scheme}://{host}"
                original_channel_url = request.query.get("url") or request.query.get("d", "")
                api_password = request.query.get("api_password")
                no_bypass = request.query.get("no_bypass") == "1"
                use_short_hls_urls = should_use_short_captured_manifest_urls(
                    original_channel_url,
                    request.query.get("host", ""),
                )
                disable_ssl = request.query.get("disable_ssl") == "1" or force_disable_ssl

                async def shorten_captured_manifest_url(manifest_url: str) -> str:
                    captured_text = captured_manifests.get(manifest_url)
                    if captured_text:
                        return await self.store_captured_hls_manifest(
                            manifest_url,
                            captured_text,
                            stream_headers,
                            ttl=300,
                            source_url=original_channel_url,
                        )
                    return await self.shorten_hls_url(manifest_url)

                rewritten_manifest = await ManifestRewriter.rewrite_manifest_urls(
                    manifest_content=captured_manifest,
                    base_url=stream_url,
                    proxy_base=proxy_base,
                    stream_headers=stream_headers,
                    original_channel_url=original_channel_url,
                    api_password=api_password,
                    get_extractor_func=lambda url, headers, host=None: self.get_extractor(url, headers, host, bypass_warp=bypass_warp),
                    no_bypass=no_bypass,
                    shorten_url_func=shorten_captured_manifest_url if use_short_hls_urls else None,
                    bypass_warp=bypass_warp,
                    disable_ssl=disable_ssl,
                    selected_proxy=selected_proxy,
                    force_direct=force_direct,
                )
                return web.Response(
                    text=rewritten_manifest,
                    headers={
                        "Content-Type": "application/vnd.apple.mpegurl",
                        "Access-Control-Allow-Origin": "*",
                        "Cache-Control": "no-cache",
                    },
                )

            # Aggiungi headers personalizzati da query params
            h_params_found = []
            for param_name, param_value in request.query.items():
                if param_name.startswith("h_"):
                    header_name = param_name[2:]
                    h_params_found.append(header_name)

                    # ✅ FIX: Rimuovi eventuali header duplicati (case-insensitive) presenti in stream_headers
                    # Questo assicura che l'header passato via query param (es. h_Referer) abbia la priorità
                    # e non vada in conflitto con quelli generati dagli estrattori (es. referer minuscolo).
                    keys_to_remove = [
                        k
                        for k in stream_headers.keys()
                        if k.lower() == header_name.lower()
                    ]
                    for k in keys_to_remove:
                        del stream_headers[k]

                    stream_headers[header_name] = param_value

            if h_params_found:
                logger.debug(
                    f"   Headers overridden by query params: {h_params_found}"
                )
            else:
                logger.debug("   No h_ params found in query string.")


            # Stream URL resolved
            # ✅ MPD/DASH handling based on MPD_MODE
            # ✅ FIX: Refined MPD/DASH detection. Use specific patterns to avoid false positives
            # (e.g. "dashinripe" in URL being mistaken for a DASH manifest).
            is_mpd = ".mpd" in stream_url.lower() or "/dash/" in stream_url.lower()
            if is_mpd:
                if MPD_MODE == "ffmpeg" and self.ffmpeg_manager:
                    # FFmpeg transcoding mode
                    logger.info(
                        f"🔄 [FFmpeg Mode] Routing MPD stream: {stream_url}"
                    )

                    # Extract ClearKey if present
                    clearkey_param = request.query.get("clearkey")

                    # Support separate key_id and key params (handling multiple keys)
                    if not clearkey_param:
                        key_id_param = request.query.get("key_id")
                        key_val_param = request.query.get("key")

                        if key_id_param and key_val_param:
                            # Check for multiple keys
                            key_ids = key_id_param.split(",")
                            key_vals = key_val_param.split(",")

                            if len(key_ids) == len(key_vals):
                                clearkey_parts = []
                                for kid, kval in zip(key_ids, key_vals):
                                    clearkey_parts.append(
                                        f"{kid.strip()}:{kval.strip()}"
                                    )
                                clearkey_param = ",".join(clearkey_parts)
                            else:
                                # Fallback or error? defaulting to first or simple concat if mismatch
                                # Let's try to handle single mismatch case gracefully or just use as is
                                if len(key_ids) == 1 and len(key_vals) == 1:
                                    clearkey_param = (
                                        f"{key_id_param}:{key_val_param}"
                                    )
                                else:
                                    logger.warning(
                                        f"Mismatch in key_id/key count: {len(key_ids)} vs {len(key_vals)}"
                                    )
                                    # Try to pair as many as possible
                                    min_len = min(len(key_ids), len(key_vals))
                                    clearkey_parts = []
                                    for i in range(min_len):
                                        clearkey_parts.append(
                                            f"{key_ids[i].strip()}:{key_vals[i].strip()}"
                                        )
                                    clearkey_param = ",".join(clearkey_parts)

                        elif key_val_param:
                            clearkey_param = key_val_param

                    playlist_rel_path = await self.ffmpeg_manager.get_stream(
                        stream_url, stream_headers, clearkey=clearkey_param
                    )

                    if playlist_rel_path:
                        # Construct local URL for the FFmpeg stream
                        scheme = request.headers.get(
                            "X-Forwarded-Proto", request.scheme
                        )
                        host = request.headers.get("X-Forwarded-Host", request.host)
                        local_url = (
                            f"{scheme}://{host}/ffmpeg_stream/{playlist_rel_path}"
                        )

                        # Generate Master Playlist for compatibility
                        master_playlist = (
                            "#EXTM3U\n"
                            "#EXT-X-VERSION:3\n"
                            '#EXT-X-STREAM-INF:BANDWIDTH=6000000,NAME="Live"\n'
                            f"{local_url}\n"
                        )

                        return web.Response(
                            text=master_playlist,
                            content_type="application/vnd.apple.mpegurl",
                            headers={
                                "Access-Control-Allow-Origin": "*",
                                "Cache-Control": "no-cache",
                            },
                        )
                    else:
                        logger.error("❌ FFmpeg failed to start")
                        return web.Response(
                            text="FFmpeg failed to process stream", status=502
                        )
                else:
                    # Legacy mode: use mpd_converter for HLS conversion with server-side decryption
                    logger.info(
                        f"🔄 [Legacy Mode] Converting MPD to HLS: {stream_url}"
                    )

                    if MPDToHLSConverter is None:
                        logger.error(
                            "❌ MPDToHLSConverter not available in legacy mode"
                        )
                        return web.Response(
                            text="Legacy MPD converter not available", status=503
                        )

                    # Fetch the MPD manifest with proxy support
                    ssl_context = None
                    disable_ssl = get_ssl_setting_for_url(
                        stream_url, TRANSPORT_ROUTES
                    )
                    if disable_ssl:
                        ssl_context = False

                    manifest_content = None
                    retries = 2
                    for attempt in range(retries):
                        mpd_proxy = None
                        try:
                            # Use helper to get proxy-enabled session
                            mpd_session, mpd_proxy = await self._get_proxy_session(
                                stream_url, bypass_warp=bypass_warp, forced_proxy=selected_proxy
                            )
                            if mpd_proxy:
                                logger.info(
                                    f"📡 [MPD] Attempt {attempt+1}/{retries} via proxy: {mpd_proxy}"
                                )

                            async with mpd_session.get(
                                stream_url,
                                headers=stream_headers,
                                ssl=ssl_context,
                                allow_redirects=True,
                            ) as resp:
                                # Capture final URL after redirects
                                final_mpd_url = str(resp.url)
                                if final_mpd_url != stream_url:
                                    logger.info(f"↪️ MPD redirected to: {final_mpd_url}")

                                if resp.status != 200:
                                    error_text = await resp.text()
                                    logger.error(f"❌ Failed to fetch MPD (Status {resp.status}) at {stream_url}")
                                    if attempt == retries - 1:
                                        if (mpd_proxy or selected_proxy) == WARP_PROXY_URL:
                                            logger.warning("   [MPD] WARP returned %s, trying direct fallback", resp.status)
                                            async with self.session.get(
                                                stream_url, headers=stream_headers, ssl=ssl_context, allow_redirects=True
                                            ) as direct_resp:
                                                if direct_resp.status == 200:
                                                    manifest_content = await direct_resp.text()
                                                    final_mpd_url = str(direct_resp.url)
                                                    break
                                        return web.Response(
                                            text=f"Failed to fetch MPD: {resp.status}\nResponse: {error_text[:1000]}",
                                            status=502,
                                        )
                                    await asyncio.sleep(1)
                                    continue

                                manifest_content = await resp.text()
                                break # Success

                        except (AioProxyError, PyProxyError, asyncio.TimeoutError, ClientConnectionError, OSError) as e:
                            is_proxy = isinstance(e, (AioProxyError, PyProxyError))
                            # Consider ClientConnectionError/OSError as proxy errors if a proxy was used
                            if not is_proxy and mpd_proxy and isinstance(e, (ClientConnectionError, OSError)):
                                is_proxy = True

                            err_type = "Proxy" if is_proxy else "Timeout"
                            logger.warning(f"⚠️ [MPD] {err_type} error at attempt {attempt+1}: {e}")

                            # Mark local proxy as dead if it failed
                            if mpd_proxy and "127.0.0.1" in mpd_proxy:
                                mark_proxy_dead(mpd_proxy)
                                # Also clear the cached session for this proxy
                                if mpd_proxy in self.proxy_sessions:
                                    logger.info(f"   [MPD] Removing broken proxy session from cache: {mpd_proxy}")
                                    self.proxy_sessions.pop(mpd_proxy, None)

                            # Clear sticky context if it's a proxy error
                            if is_proxy and SELECTED_PROXY_CONTEXT.get():
                                logger.info("   [MPD] Clearing sticky proxy context due to ProxyError")
                                SELECTED_PROXY_CONTEXT.set(None)

                            if attempt < retries - 1:
                                logger.info("   [MPD] Retrying...")
                                await asyncio.sleep(1)
                            elif (mpd_proxy or selected_proxy) and (mpd_proxy or selected_proxy) != WARP_PROXY_URL:
                                return web.Response(text=f"MPD unreachable via configured proxy: {e}", status=502)
                            else:
                                logger.warning("   [MPD] All proxy attempts failed. Trying direct connection as final fallback...")
                                try:
                                    # Final fallback: direct connection
                                    async with self.session.get(
                                        stream_url, headers=stream_headers, ssl=ssl_context, allow_redirects=True
                                    ) as resp:
                                        if resp.status == 200:
                                            manifest_content = await resp.text()
                                            final_mpd_url = str(resp.url)
                                            logger.info("   [MPD] Direct fallback successful!")
                                            break
                                        else:
                                            raise Exception(f"Direct fallback failed with status {resp.status}")
                                except Exception as fallback_err:
                                    logger.error(f"❌ [MPD] Direct fallback failed: {fallback_err}")
                                    return web.Response(text=f"MPD unreachable via proxy and direct: {e}", status=502)
                        except Exception as e:
                            logger.error(f"❌ [MPD] Unexpected error at attempt {attempt+1}: {e}")
                            if attempt == retries - 1:
                                if (mpd_proxy or selected_proxy) and (mpd_proxy or selected_proxy) != WARP_PROXY_URL:
                                    return web.Response(text=f"Unexpected error fetching MPD via configured proxy: {e}", status=500)
                                # Try one last direct fallback even for unexpected errors
                                try:
                                    async with self.session.get(
                                        stream_url, headers=stream_headers, ssl=ssl_context, allow_redirects=True
                                    ) as resp:
                                        if resp.status == 200:
                                            manifest_content = await resp.text()
                                            final_mpd_url = str(resp.url)
                                            logger.info("   [MPD] Direct fallback successful after unexpected error!")
                                            break
                                except: pass
                                return web.Response(text=f"Unexpected error fetching MPD: {e}", status=500)
                            await asyncio.sleep(1)

                    if manifest_content is None:
                         return web.Response(text="Failed to fetch MPD manifest after all attempts", status=502)

                    # Build proxy base URL
                    scheme = request.headers.get(
                        "X-Forwarded-Proto", request.scheme
                    )
                    host = request.headers.get("X-Forwarded-Host", request.host)
                    proxy_base = f"{scheme}://{host}"

                    # Build params string with headers
                    params = "".join(
                        [
                            f"&h_{urllib.parse.quote(key)}={urllib.parse.quote(value)}"
                            for key, value in stream_headers.items()
                        ]
                    )

                    # Add api_password if present
                    api_password = request.query.get("api_password")
                    if api_password:
                        params += f"&api_password={api_password}"

                    # Get ClearKey param
                    clearkey_param = request.query.get("clearkey")
                    if not clearkey_param:
                        key_id_param = request.query.get("key_id")
                        key_val_param = request.query.get("key")

                        if key_id_param and key_val_param:
                            # Check for multiple keys
                            key_ids = key_id_param.split(",")
                            key_vals = key_val_param.split(",")

                            if len(key_ids) == len(key_vals):
                                clearkey_parts = []
                                for kid, kval in zip(key_ids, key_vals):
                                    clearkey_parts.append(
                                        f"{kid.strip()}:{kval.strip()}"
                                    )
                                clearkey_param = ",".join(clearkey_parts)
                            else:
                                if len(key_ids) == 1 and len(key_vals) == 1:
                                    clearkey_param = (
                                        f"{key_id_param}:{key_val_param}"
                                    )
                                else:
                                    logger.warning(
                                        f"Mismatch in key_id/key count: {len(key_ids)} vs {len(key_vals)}"
                                    )
                                    # Try to pair as many as possible
                                    min_len = min(len(key_ids), len(key_vals))
                                    clearkey_parts = []
                                    for i in range(min_len):
                                        clearkey_parts.append(
                                            f"{key_ids[i].strip()}:{key_vals[i].strip()}"
                                        )
                                    clearkey_param = ",".join(clearkey_parts)
                        elif key_val_param:
                            clearkey_param = key_val_param

                    if clearkey_param:
                        params += f"&clearkey={clearkey_param}"

                    # Pass 'ext' param if present (e.g. ext=ts)
                    ext_param = request.query.get("ext")
                    if ext_param:
                        params += f"&ext={ext_param}"

                    # Check if requesting specific representation
                    rep_id = request.query.get("rep_id")

                    converter = MPDToHLSConverter()
                    if rep_id:
                        # Generate media playlist for specific representation
                        # Use final_mpd_url (after redirects) for segment URL construction
                        hls_content = converter.convert_media_playlist(
                            manifest_content,
                            rep_id,
                            proxy_base,
                            final_mpd_url,
                            params,
                            clearkey_param,
                        )
                    else:
                        # Generate master playlist
                        # Use final_mpd_url (after redirects) for segment URL construction
                        hls_content = converter.convert_master_playlist(
                            manifest_content, proxy_base, final_mpd_url, params
                        )

                    return web.Response(
                        text=hls_content,
                        content_type="application/vnd.apple.mpegurl",
                        headers={
                            "Access-Control-Allow-Origin": "*",
                            "Cache-Control": "no-cache",
                        },
                    )

            # Procedi con il proxy dello stream (passando l'eventuale bypass_warp attivato dall'estrattore e il proxy selezionato)
            return await self._proxy_stream(request, stream_url, stream_headers, bypass_warp=bypass_warp, forced_proxy=selected_proxy, force_direct=force_direct)

        except Exception as e:
            error_msg = str(e).lower()

            # Retry extraction once if proxy died during playlist fetch
            if "proxy_dead_retry_extraction" in error_msg and not getattr(request, '_extraction_retried', False):
                request._extraction_retried = True
                logger.warning("⚠️ Proxy died during playlist fetch, re-extracting %s", target_url)
                try:
                    extractor2 = await self.get_extractor(target_url, combined_headers, bypass_warp=bypass_warp)
                    if extractor2:
                        extractor2.request_headers = combined_headers
                        result2 = await extractor2.extract(
                            target_url,
                            force_refresh=force_refresh,
                            request_headers=combined_headers,
                            bypass_warp=bypass_warp,
                        )
                        stream_url2 = result2["destination_url"]
                        stream_headers2 = result2.get("request_headers", {})
                        selected_proxy2 = result2.get("selected_proxy")
                        force_direct2 = result2.get("force_direct", force_direct)
                        logger.info("Re-extraction success: %s", stream_url2[:80])
                        return await self._proxy_stream(request, stream_url2, stream_headers2, bypass_warp=bypass_warp, forced_proxy=selected_proxy2, force_direct=force_direct2)
                except Exception as retry_err:
                    logger.error("Re-extraction failed: %s", retry_err)

            # ✅ MIGLIORATO: Distingui tra errori temporanei (sito offline) ed errori critici
            is_expired_embed = is_expired_embed_error(error_msg)
            is_not_found = "404" in error_msg or "not found" in error_msg
            is_temporary_error = any(
                x in error_msg
                for x in [
                    "403",
                    "forbidden",
                    "502",
                    "bad gateway",
                    "timeout",
                    "connection",
                    "temporarily unavailable",
                ]
            )

            extractor_name = extractor_name_for_log(extractor)

            if is_expired_embed:
                logger.info("Expired VixSrc embed URL rejected: %s", str(e))
                return web.Response(text=str(e), status=410)

            if is_not_found:
                logger.warning(f"🔍 {extractor_name}: Content not found (404). File missing or possible IP block. (Try opening the link in a browser to verify) - {str(e)}")
                return web.Response(text=f"Content not found: {str(e)}", status=404)

            # Gestione errori di connessione o blocchi
            if is_temporary_error:
                if "403" in error_msg or "forbidden" in error_msg:
                    logger.error(f"🚫 {extractor_name}: Access denied (403 Forbidden). Possible IP block or WAF protection. - {str(e)}")
                else:
                    logger.warning(f"📡 {extractor_name}: Connection failed (Timeout/Connection Error). Site might be down or IP is blocked. - {str(e)}")

                return web.Response(
                    text=f"Service temporarily unavailable: {str(e)}", status=503
                )

            # Per errori veri (non temporanei), logga come CRITICAL con traceback completo
            logger.critical(f"❌ Critical error with {extractor_name}: {e}")
            logger.exception(f"Error in proxy request: {str(e)}")
            return web.Response(text=f"Proxy error: {str(e)}", status=500)
        finally:
            BYPASS_WARP_CONTEXT.reset(token)
            SELECTED_PROXY_CONTEXT.reset(proxy_token)
