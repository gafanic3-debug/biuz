"""
ADN — AltadefinizioneStreaming CDN-only extractor.

Resolves /api/player-sources/{movie|tv}/... → first source with provider=cdn,
then returns the signed CDN .mp4 URL. The whole point of routing through
EasyProxy is that the CDN binds `ipsig` to the IP that called the API; since
the API call and the subsequent playback (via /proxy/stream) both egress
from EasyProxy, ipsig matches by construction.

Input URL accepted: the full API endpoint, e.g.
  https://altadefinizionestreaming.com/api/player-sources/movie/299534
  https://altadefinizionestreaming.com/api/player-sources/tv/1399/1/1
"""

import logging
import random
from typing import Optional

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector

from config import (
    get_connector_for_proxy,
    get_proxy_for_url,
)
import config as _cfg

logger = logging.getLogger(__name__)


class ExtractorError(Exception):
    """Exception for extraction errors."""
    pass


class AdnExtractor:
    """AltadefinizioneStreaming CDN extractor."""

    BASE_URL = "https://altadefinizionestreaming.com"
    USER_AGENT = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
    )

    def __init__(self, request_headers: dict, proxies: list = None):
        self.request_headers = request_headers or {}
        self.proxies = proxies or _cfg.GLOBAL_PROXIES
        self.session: Optional[ClientSession] = None

    def _get_random_proxy(self):
        return random.choice(self.proxies) if self.proxies else None

    async def _get_session(self):
        if self.session is None or self.session.closed:
            timeout = ClientTimeout(total=30, connect=15, sock_read=20)
            proxy = get_proxy_for_url(
                self.BASE_URL, global_proxies=self.proxies, bypass_warp=True
            )
            if proxy:
                logger.debug("ADN routing: PROXY (%s)", proxy)
            else:
                logger.debug("ADN routing: DIRECT (WARP excluded host / real IP)")
            connector = (
                get_connector_for_proxy(proxy) if proxy else TCPConnector(limit=0, use_dns_cache=True)
            )
            self.session = ClientSession(
                timeout=timeout,
                connector=connector,
                headers={"User-Agent": self.USER_AGENT},
            )
        return self.session

    async def extract(self, url: str, **kwargs) -> dict:
        # The addon passes the API endpoint directly as `d`. If someone passes
        # a non-API URL by mistake we refuse rather than guess.
        if "/api/player-sources/" not in url:
            raise ExtractorError(
                f"ADN extractor expects an /api/player-sources/... URL, got: {url}"
            )

        headers = {
            "User-Agent": self.USER_AGENT,
            "Referer": f"{self.BASE_URL}/",
            "Accept": "application/json,text/plain,*/*",
        }

        try:
            session = await self._get_session()
            async with session.get(url, headers=headers, timeout=25, ssl=False) as resp:
                if resp.status != 200:
                    raise ExtractorError(f"ADN API HTTP {resp.status}")
                try:
                    payload = await resp.json(content_type=None)
                except Exception:
                    text = await resp.text()
                    raise ExtractorError(f"ADN API non-JSON response: {text[:120]}")
        except aiohttp.ClientError as e:
            raise ExtractorError(f"ADN API request failed: {e}")

        sources = payload.get("sources") if isinstance(payload, dict) else None
        if not isinstance(sources, list) or not sources:
            raise ExtractorError("ADN payload has no sources")

        cdn = next(
            (
                s
                for s in sources
                if isinstance(s, dict)
                and str(s.get("provider", "")).lower() == "cdn"
                and s.get("url")
            ),
            None,
        )
        if not cdn:
            providers = ",".join(str(s.get("provider")) for s in sources if isinstance(s, dict))
            raise ExtractorError(f"ADN: no cdn source (providers={providers})")

        stream_url = str(cdn["url"])
        logger.debug(f"ADN: resolved cdn stream {stream_url[:100]}…")

        return {
            "destination_url": stream_url,
            "request_headers": {
                "User-Agent": self.USER_AGENT,
                "Referer": f"{self.BASE_URL}/",
                "Accept": "*/*",
                "Accept-Language": "it-IT,it;q=0.9,en;q=0.8",
                "Connection": "keep-alive",
            },
            "mediaflow_endpoint": "proxy_stream_endpoint",
        }

    async def close(self):
        if self.session:
            await self.session.close()
