from services.proxy_shared import ENABLE_WARP, PlaylistBuilder, logger
from services.proxy_core import HLSProxyCoreMixin
from services.proxy_dash import HLSProxyDashMixin
from services.proxy_handlers import HLSProxyHandlersMixin
from services.proxy_pages import HLSProxyPagesMixin
from services.proxy_streaming import HLSProxyStreamingMixin


class HLSProxy(
    HLSProxyCoreMixin,
    HLSProxyHandlersMixin,
    HLSProxyDashMixin,
    HLSProxyStreamingMixin,
    HLSProxyPagesMixin,
):
    """Proxy HLS per stream, playlist, DASH e segmenti."""

    def __init__(self, ffmpeg_manager=None):
        self.extractors = {}
        self._extractor_atimes = {}
        self._extractor_stream_atimes = {}
        self.ffmpeg_manager = ffmpeg_manager

        # Inizializza il playlist_builder se il modulo è disponibile
        if PlaylistBuilder:
            self.playlist_builder = PlaylistBuilder()
            logger.info("✅ PlaylistBuilder inizializzato")
        else:
            self.playlist_builder = None

        # Cache per segmenti di inizializzazione (URL -> content)
        self.init_cache = {}

        # Cache per segmenti decriptati (URL -> (content, timestamp))
        self.segment_cache = {}
        self.segment_cache_ttl = 30  # Seconds

        # Prefetch queue for background downloading
        self.prefetch_tasks = set()

        # Sessione condivisa per il proxy (no proxy)
        self.session = None
        self.flex_session = None

        self.captured_hls_manifest_map = {}
        self.captured_hls_refresh_tasks = {}

        # Cache for proxy sessions (proxy_url -> session)
        # This reuses connections for the same proxy to improve performance
        self.proxy_sessions = {}
        self._proxy_session_atimes = {}  # proxy_url -> last access time
        self.curl_sessions = {}  # Registry for pooled curl_cffi sessions

        # Version information
        self.latest_version = "Checking..."
        self.warp_status = "Checking..." if ENABLE_WARP else "Disabled"

        # Registry for DASH native sessions (to handle segment proxying without HLS conversion)
        # session_id -> (base_url, headers, clearkey, timestamp)
        self.dash_sessions = {}
        self.dash_session_ttl = 21600  # 6 hours



__all__ = ["HLSProxy"]
