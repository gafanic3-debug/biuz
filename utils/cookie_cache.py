import json
import os
import tempfile
import time
import logging
import threading

logger = logging.getLogger(__name__)

class CookieCache:
    _locks = {}

    def __init__(self, name: str):
        self.name = name
        self.filename = f"cookie_cache_{name}.json"
        if name not in self._locks:
            self._locks[name] = threading.Lock()

    def get(self, domain: str) -> dict:
        if not os.path.exists(self.filename):
            return None
        try:
            with open(self.filename, "r") as f:
                cache = json.load(f)
            entry = cache.get(domain)
            if entry:
                if entry.get("expiry", 0) > time.time():
                    return entry
                else:
                    logger.debug(f"Cookie cache ({self.name}) expired for domain: {domain}")
        except Exception as e:
            logger.error(f"Error reading cookie cache {self.filename}: {e}")
        return None

    def set(self, domain: str, cookies: dict, ua: str, expiry_delta: int = 7200):
        with self._locks[self.name]:
            cache = {}
            if os.path.exists(self.filename):
                try:
                    with open(self.filename, "r") as f:
                        cache = json.load(f)
                except:
                    pass

            cache[domain] = {
                "cookies": cookies,
                "userAgent": ua,
                "expiry": time.time() + expiry_delta
            }

            try:
                fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(self.filename) or ".", suffix=".tmp")
                with os.fdopen(fd, "w") as f:
                    json.dump(cache, f)
                os.replace(tmp_path, self.filename)
                logger.debug(f"Updated cookie cache {self.filename} for domain: {domain}")
            except Exception as e:
                logger.error(f"Error writing cookie cache {self.filename}: {e}")
