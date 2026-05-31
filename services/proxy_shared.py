import asyncio
import logging
import random
import re
import sys
import os
import time
import socket
import urllib.parse
from urllib.parse import urlparse, urljoin
import base64
import binascii
import hashlib
import hmac
import json
import ssl
import logging
logger = logging.getLogger("services.proxy")
import yarl
import aiohttp
from aiohttp import (
    web,
    ClientSession,
    ClientTimeout,
    TCPConnector,
    ClientPayloadError,
    ServerDisconnectedError,
    ClientConnectionError,
)
from aiohttp_socks import ProxyConnector, ProxyError as AioProxyError
from python_socks import ProxyError as PyProxyError

try:
    from curl_cffi.requests import AsyncSession as CurlAsyncSession
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False
    CurlAsyncSession = None

from config import (
    GLOBAL_PROXIES,
    TRANSPORT_ROUTES,
    get_proxy_for_url,
    get_ssl_setting_for_url,
    get_connector_for_proxy,
    API_PASSWORD,
    check_password,
    MPD_MODE,
    VERSION_MODE,
    APP_VERSION,
    ENABLE_WARP,
    ENABLE_REMUXING,
    WARP_EXCLUDE_DOMAINS,
    WARP_PROXY_URL,
    BYPASS_WARP_CONTEXT,
    SELECTED_PROXY_CONTEXT,
    mark_proxy_dead,
)
from extractors.registry import *
from extractors.provider_hooks import *
from services.manifest_rewriter import ManifestRewriter

# Global registry for domains already bypassed in WARP to avoid redundant os.system calls
BYPASSED_WARP_DOMAINS = set()

# Legacy MPD converter (used when MPD_MODE is not ffmpeg)
MPDToHLSConverter = None
decrypt_segment = None

try:
    from utils.drm_decrypter import decrypt_segment
except ImportError:
    pass

if MPD_MODE in ("legacy", "none", "disabled"):
    try:
        from utils.mpd_converter import MPDToHLSConverter
        logger.info("Legacy MPD converter loaded")
    except ImportError as e:
        logger.warning(f"MPD_MODE=legacy but mpd_converter not found: {e}")

PlaylistBuilder = None
try:
    from routes.playlist_builder import PlaylistBuilder
    logger.info("PlaylistBuilder module loaded.")
except ImportError:
    logger.warning("PlaylistBuilder module not found. PlaylistBuilder functionality disabled.")

# Allow mixin modules to import private helper names via star import.
__all__ = [name for name in globals() if not name.startswith('__')]
