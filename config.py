import os
import logging
import random
from dotenv import load_dotenv

load_dotenv() # Load variables from .env file

# --- Log Level Configuration ---
# Configurable via LOG_LEVEL env var: DEBUG, INFO, WARNING, ERROR, CRITICAL
# Default: WARNING
LOG_LEVEL_STR = os.environ.get("LOG_LEVEL", "WARNING").upper()
LOG_LEVEL_MAP = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL
}
LOG_LEVEL = LOG_LEVEL_MAP.get(LOG_LEVEL_STR, logging.WARNING)

# Configurazione logging
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Silenzia il warning asyncio "Unknown child process pid" (race condition nota in asyncio)
class AsyncioWarningFilter(logging.Filter):
    def filter(self, record):
        return "Unknown child process pid" not in record.getMessage()

logging.getLogger('asyncio').addFilter(AsyncioWarningFilter())

# Silenzia i log di accesso di aiohttp a meno che non siano errori
# logging.getLogger('aiohttp.access').setLevel(logging.ERROR)

logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

# --- Configurazione Proxy ---
def parse_proxies(proxy_env_var: str) -> list:
    """Analizza una stringa di proxy separati da virgola da una variabile d'ambiente."""
    proxies_str = os.environ.get(proxy_env_var, "").strip()
    if proxies_str:
        return [p.strip() for p in proxies_str.split(',') if p.strip()]
    return []

def parse_transport_routes() -> list:
    """Analizza TRANSPORT_ROUTES nel formato {URL=domain, PROXY=proxy, DISABLE_SSL=true/false}, {URL=domain2, PROXY=proxy2}"""
    routes_str = os.environ.get('TRANSPORT_ROUTES', "").strip()
    if not routes_str:
        return []

    routes = []
    try:
        # Rimuovi spazi e dividi per }, {
        route_parts = [part.strip() for part in routes_str.replace(' ', '').split('},{')]

        for part in route_parts:
            if not part:
                continue

            # Rimuovi { e } se presenti
            part = part.strip('{}')

            # Parsea URL=..., PROXY=..., DISABLE_SSL=...
            url_match = None
            proxy_match = None
            disable_ssl_match = None

            for item in part.split(','):
                if item.startswith('URL='):
                    url_match = item[4:]
                elif item.startswith('PROXY='):
                    proxy_match = item[6:]
                elif item.startswith('DISABLE_SSL='):
                    disable_ssl_str = item[12:].lower()
                    disable_ssl_match = disable_ssl_str in ('true', '1', 'yes', 'on')

            if url_match:
                routes.append({
                    'url': url_match,
                    'proxy': proxy_match if proxy_match else None,
                    'disable_ssl': disable_ssl_match if disable_ssl_match is not None else False
                })

    except Exception as e:
        logger.warning(f"Error parsing TRANSPORT_ROUTES: {e}")

    return routes

def get_proxy_for_url(url: str, transport_routes: list, global_proxies: list) -> str:
    """Trova il proxy appropriato per un URL basato su TRANSPORT_ROUTES"""
    if not url or not transport_routes:
        return random.choice(global_proxies) if global_proxies else None

    # Cerca corrispondenze negli URL patterns
    for route in transport_routes:
        url_pattern = route['url']
        if url_pattern in url:
            proxy_value = route['proxy']
            if proxy_value:
                # Se è un singolo proxy, restituiscilo
                return proxy_value
            else:
                # Se proxy è vuoto, usa connessione diretta
                return None

    # Se non trova corrispondenza, usa global proxies
    return random.choice(global_proxies) if global_proxies else None

def get_ssl_setting_for_url(url: str, transport_routes: list) -> bool:
    """Determina se SSL deve essere disabilitato per un URL basato su TRANSPORT_ROUTES"""
    if not url or not transport_routes:
        return False  # Default: SSL enabled

    # Cerca corrispondenze negli URL patterns
    for route in transport_routes:
        url_pattern = route['url']
        if url_pattern in url:
            return route.get('disable_ssl', False)

    # Se non trova corrispondenza, SSL abilitato per default
    return False

# Configurazione proxy
GLOBAL_PROXIES = parse_proxies('GLOBAL_PROXY')
TRANSPORT_ROUTES = parse_transport_routes()

# Logging configurazione proxy
if GLOBAL_PROXIES: logging.info(f"🌍 Loaded {len(GLOBAL_PROXIES)} global proxies.")
if TRANSPORT_ROUTES: logging.info(f"🚦 Loaded {len(TRANSPORT_ROUTES)} transport rules.")

API_PASSWORD = os.environ.get("API_PASSWORD")
PORT = int(os.environ.get("PORT", 7860))

# --- Recording/DVR Configuration ---
DVR_ENABLED = os.environ.get("DVR_ENABLED", "false").lower() in ("true", "1", "yes")
RECORDINGS_DIR = os.environ.get("RECORDINGS_DIR", "recordings")
MAX_RECORDING_DURATION = int(os.environ.get("MAX_RECORDING_DURATION", 28800))  # 8 hours default
RECORDINGS_RETENTION_DAYS = int(os.environ.get("RECORDINGS_RETENTION_DAYS", 7))  # Auto-cleanup after 7 days

# Create recordings directory if DVR is enabled
if DVR_ENABLED and not os.path.exists(RECORDINGS_DIR):
    os.makedirs(RECORDINGS_DIR)
    logging.info(f"📹 Created recordings directory: {RECORDINGS_DIR}")

# MPD Processing Mode: 'ffmpeg' (transcoding) or 'legacy' (mpd_converter)
MPD_MODE = os.environ.get("MPD_MODE", "legacy").lower()

# --- FlareSolverr / Byparr Configuration ---
FLARESOLVERR_URL = os.environ.get("FLARESOLVERR_URL", "http://localhost:8191").rstrip("/")
FLARESOLVERR_TIMEOUT = int(os.environ.get("FLARESOLVERR_TIMEOUT", 30))
BYPARR_URL = os.environ.get("BYPARR_URL", "http://localhost:8080").rstrip("/")
if MPD_MODE not in ("ffmpeg", "legacy"):
    logging.warning(f"⚠️ MPD_MODE '{MPD_MODE}' is invalid. Using 'legacy' as default.")
    MPD_MODE = "legacy"
logging.info(f"🎬 MPD Mode: {MPD_MODE}")

def check_password(request):
    """Verifica la password API se impostata."""
    if not API_PASSWORD:
        return True

    # Check query param
    api_password_param = request.query.get("api_password")
    if api_password_param == API_PASSWORD:
        return True

    # Check header
    if request.headers.get("x-api-password") == API_PASSWORD:
        return True

    return False
