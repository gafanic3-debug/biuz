import re
import base64
import json
import uuid
import time
import asyncio
import ctypes
import multiprocessing as mp
from urllib.parse import urlparse

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

from extractors.base import BaseExtractor, ExtractorError
from utils import python_aesgcm


# ──────────────────────────────────────────────────────────────────────
# Proof-of-Work hash (reverse-engineered from pow--*.js).
# Labelled "sha256-leading-zero-bits" but is a custom 512-word mixing hash.
# Input = nonce + ":" + counter ; find counter with >= difficulty leading
# zero bits over the 8x uint32 output.
# ──────────────────────────────────────────────────────────────────────
_MASK = 0xFFFFFFFF
_BE, _LT, _DR, _LR, _HR = 512, 511, 2, 2654435761, 2246822519


def _pow_hash(data: bytes):
    e0, e1, e2, e3 = 1779033703, 3144134277, 1013904242, 2773480762
    M = _MASK
    for b in data:
        e0 = (e0 + b) & M
        e0 = ((e0 << 7) | (e0 >> 25)) & M
        e0 = (e0 + e1) & M; x = e3 ^ e0; e3 = ((x << 16) | (x >> 16)) & M
        e2 = (e2 + e3) & M; x = e1 ^ e2; e1 = ((x << 12) | (x >> 20)) & M
        e0 = (e0 + e1) & M; x = e3 ^ e0; e3 = ((x << 8) | (x >> 24)) & M
        e2 = (e2 + e3) & M; x = e1 ^ e2; e1 = ((x << 7) | (x >> 25)) & M
    for _ in range(8):
        e0 = (e0 + e1) & M; x = e3 ^ e0; e3 = ((x << 16) | (x >> 16)) & M
        e2 = (e2 + e3) & M; x = e1 ^ e2; e1 = ((x << 12) | (x >> 20)) & M
        e0 = (e0 + e1) & M; x = e3 ^ e0; e3 = ((x << 8) | (x >> 24)) & M
        e2 = (e2 + e3) & M; x = e1 ^ e2; e1 = ((x << 7) | (x >> 25)) & M
    r = [0] * _BE
    for i in range(_BE):
        e0 = (e0 + e1) & M; x = e3 ^ e0; e3 = ((x << 16) | (x >> 16)) & M
        e2 = (e2 + e3) & M; x = e1 ^ e2; e1 = ((x << 12) | (x >> 20)) & M
        e0 = (e0 + e1) & M; x = e3 ^ e0; e3 = ((x << 8) | (x >> 24)) & M
        e2 = (e2 + e3) & M; x = e1 ^ e2; e1 = ((x << 7) | (x >> 25)) & M
        r[i] = (e0 ^ e2) & M
    for _ in range(_DR):
        for s in range(_BE):
            a = r[s] & _LT
            c = (r[s] + r[a]) & M
            c = ((c << 13) | (c >> 19)) & M
            c = (c ^ ((r[(s + 1) & _LT] * _LR) & M)) & M
            r[s] = c
            e0 = (e0 ^ c) & M
            e0 = (e0 + e1) & M; x = e3 ^ e0; e3 = ((x << 16) | (x >> 16)) & M
            e2 = (e2 + e3) & M; x = e1 ^ e2; e1 = ((x << 12) | (x >> 20)) & M
            e0 = (e0 + e1) & M; x = e3 ^ e0; e3 = ((x << 8) | (x >> 24)) & M
            e2 = (e2 + e3) & M; x = e1 ^ e2; e1 = ((x << 7) | (x >> 25)) & M
    n = [0] * 8
    o = _BE // 8
    for i in range(8):
        e0 = (e0 + e1) & M; x = e3 ^ e0; e3 = ((x << 16) | (x >> 16)) & M
        e2 = (e2 + e3) & M; x = e1 ^ e2; e1 = ((x << 12) | (x >> 20)) & M
        e0 = (e0 + e1) & M; x = e3 ^ e0; e3 = ((x << 8) | (x >> 24)) & M
        e2 = (e2 + e3) & M; x = e1 ^ e2; e1 = ((x << 7) | (x >> 25)) & M
        s = e0
        a = i * o
        for cc in range(o):
            d = r[a + cc]
            s = (s + d) & M
            s = ((s << 5) | (s >> 27)) & M
            s = (s ^ ((d * _HR) & M)) & M
        n[i] = (s ^ e2) & M
    return n


def _lz_bits(words) -> int:
    bits = 0
    for n in words:
        if n == 0:
            bits += 32
            continue
        c = 0
        m = 0x80000000
        while m and not (n & m):
            c += 1
            m >>= 1
        return bits + c
    return bits


def _pow_worker(nonce_bytes: bytes, difficulty: int, start: int, step: int,
                found_val, found_flag):
    """Searches counter values start, start+step, start+2*step, ...
    Writes the solution into found_val and sets found_flag to 1."""
    colon = b":"
    s = start
    chunk = 2048
    while not found_flag.value:
        for _ in range(chunk):
            if _lz_bits(_pow_hash(nonce_bytes + colon + str(s).encode())) >= difficulty:
                if not found_flag.value:
                    found_val.value = s
                    found_flag.value = 1
                return
            s += step


def _solve_pow(nonce: str, difficulty: int, timeout: float = 30.0,
               workers: int = None):
    """Parallel PoW solver — splits counter space across N worker processes."""
    if difficulty <= 0:
        return "0"

    n_workers = workers or mp.cpu_count()
    nonce_bytes = nonce.encode("latin-1")

    found_val  = mp.Value(ctypes.c_longlong, -1)
    found_flag = mp.Value(ctypes.c_bool, False)

    procs = [
        mp.Process(target=_pow_worker,
                   args=(nonce_bytes, difficulty, i, n_workers,
                         found_val, found_flag))
        for i in range(n_workers)
    ]
    for p in procs:
        p.start()

    deadline = time.time() + timeout
    while time.time() < deadline:
        if found_flag.value:
            break
        time.sleep(0.05)

    for p in procs:
        p.terminate()
        p.join()

    return str(found_val.value) if found_flag.value else None


class F16PxExtractor(BaseExtractor):
    F16PX_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0"

    def __init__(self, request_headers: dict, proxies: list = None):
        super().__init__(request_headers, proxies, extractor_name="f16px")

    # ── base64url ──
    @staticmethod
    def _b64url_decode(value: str) -> bytes:
        value = value.replace("-", "+").replace("_", "/")
        padding = (-len(value)) % 4
        if padding:
            value += "=" * padding
        return base64.b64decode(value)

    @staticmethod
    def _b64url_encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    @classmethod
    def _int_to_b64url(cls, value) -> str:
        return cls._b64url_encode(int(value).to_bytes(32, "big"))

    @staticmethod
    def _pick_best(sources: list) -> str:
        def label_key(s):
            try:
                return int(s.get("label", 0))
            except Exception:
                return 0
        return sorted(sources, key=label_key, reverse=True)[0]["url"]

    def _join_key_parts(self, parts: list, version: str) -> bytes:
        v = int(version)
        n = len(parts)
        ka = self._b64url_decode(parts[v - 1])
        kb = self._b64url_decode(parts[n - v])
        return ka + kb

    def _decrypt_sources(self, pb: dict) -> list:
        iv = self._b64url_decode(pb["iv"])
        key = self._join_key_parts(pb["key_parts"], pb["version"])
        payload = self._b64url_decode(pb["payload"])
        cipher = python_aesgcm.new(key)
        decrypted = cipher.open(iv, payload)
        if decrypted is None:
            raise ExtractorError("F16PX: GCM authentication failed")
        return json.loads(decrypted.decode("utf-8", "ignore")).get("sources") or []

    # ── attestation (ECDSA P-256, raw r||s signature) ──
    def _build_attest_payload(self, challenge: dict) -> dict:
        key = ECC.generate(curve="P-256")
        digest = SHA256.new(challenge["nonce"].encode())
        signature = DSS.new(key, "fips-186-3", encoding="binary").sign(digest)  # raw r||s
        public_key = {
            "alg": "ES256",
            "crv": "P-256",
            "ext": True,
            "key_ops": ["verify"],
            "kty": "EC",
            "x": self._int_to_b64url(key.pointQ.x),
            "y": self._int_to_b64url(key.pointQ.y),
        }
        return {
            "viewer_id": "",
            "device_id": "",
            "challenge_id": challenge["challenge_id"],
            "nonce": challenge["nonce"],
            "signature": self._b64url_encode(signature),
            "public_key": public_key,
            "client": {
                "user_agent": self.F16PX_USER_AGENT,
                "pixel_ratio": 2,
                "screen_width": 1536,
                "screen_height": 960,
                "color_depth": 24,
                "languages": ["en-US", "en"],
                "timezone": "Europe/Rome",
                "hardware_concurrency": 8,
                "touch_points": 0,
                "pointer_type": "fine,hover",
                "extra": {"vendor": "", "appVersion": "5.0 (Windows)"},
            },
            "storage": {},
            "attributes": {"entropy": "low"},
        }

    async def extract(self, url: str, **kwargs) -> dict:
        parsed = urlparse(url)
        embed_host = parsed.netloc
        embed_origin = f"{parsed.scheme}://{parsed.netloc}"

        match = re.search(r"/e/([A-Za-z0-9]+)", parsed.path or "")
        if not match:
            raise ExtractorError("F16PX: Invalid embed URL")
        code = match.group(1)
        embed_url = f"{embed_origin}/e/{code}"

        # 1) details (on embed host) → embed_frame_url gives the API base + referer
        details_resp = await self._make_request(
            f"{embed_origin}/api/videos/{code}/embed/details",
            headers={
                "Accept": "application/json, text/plain, */*",
                "User-Agent": self.F16PX_USER_AGENT,
                "Referer": embed_url,
                "Origin": embed_origin,
            },
            method="GET",
            retries=1,
        )
        details = json.loads(details_resp.text)
        frame = details.get("embed_frame_url") or embed_url
        api_origin = f"{urlparse(frame).scheme}://{urlparse(frame).netloc}"
        referer = frame

        common = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "User-Agent": self.F16PX_USER_AGENT,
            "Origin": api_origin,
            "Referer": referer,
            "X-Embed-Origin": embed_host,
            "X-Embed-Referer": embed_url,
            "X-Embed-Parent": embed_url,
        }

        # 2) settings → captcha required?
        settings_resp = await self._make_request(
            f"{api_origin}/api/videos/{code}/embed/settings",
            headers=common, method="GET", retries=1,
        )
        try:
            captcha_required = bool(json.loads(settings_resp.text).get("captcha_required"))
        except Exception:
            captcha_required = True

        # 3) challenge
        challenge_resp = await self._make_request(
            f"{api_origin}/api/videos/access/challenge",
            headers=common, method="POST", retries=1, json={},
        )
        challenge = json.loads(challenge_resp.text)

        # 4) attest (sets viewer/device cookies)
        attest_resp = await self._make_request(
            f"{api_origin}/api/videos/access/attest",
            headers=common, method="POST", retries=1,
            json=self._build_attest_payload(challenge),
        )
        attest = json.loads(attest_resp.text)
        fingerprint = {
            "token": attest["token"],
            "viewer_id": attest["viewer_id"],
            "device_id": attest["device_id"],
            "confidence": attest["confidence"],
        }

        cookie = f"byse_viewer_id={fingerprint['viewer_id']}; byse_device_id={fingerprint['device_id']}"
        with_cookie = {**common, "Cookie": cookie}

        # 5+6) captcha PoW (only if required)
        captcha_token = None
        if captcha_required:
            captcha_resp = await self._make_request(
                f"{api_origin}/api/videos/{code}/embed/captcha",
                headers=with_cookie, method="POST", retries=1,
                json={"fingerprint": fingerprint},
            )
            cap = json.loads(captcha_resp.text)
            pow_nonce = cap["pow_nonce"]
            pow_difficulty = cap["pow_difficulty"]
            pow_token = cap["pow_token"]

            # solve off the event loop (difficulty 12 ~ several seconds in CPython;
            # PoW token TTL is 1800s so this is fine)
            loop = asyncio.get_event_loop()
            solution = await loop.run_in_executor(None, _solve_pow, pow_nonce, pow_difficulty)
            if solution is None:
                raise ExtractorError("F16PX: PoW solve timed out")

            verify_resp = await self._make_request(
                f"{api_origin}/api/videos/{code}/embed/captcha/verify",
                headers=with_cookie, method="POST", retries=1,
                json={"pow_token": pow_token, "solution": solution, "fingerprint": fingerprint},
            )
            verify = json.loads(verify_resp.text)
            if verify.get("status") != "ok" or not verify.get("token"):
                raise ExtractorError(f"F16PX: captcha verify failed ({verify})")
            captcha_token = verify["token"]

        # 7) playback — verify token rides in X-Captcha-Token header (not the body)
        playback_headers = dict(with_cookie)
        if captcha_token:
            playback_headers["X-Captcha-Token"] = captcha_token

        playback_resp = await self._make_request(
            f"{api_origin}/api/videos/{code}/embed/playback",
            headers=playback_headers, method="POST", retries=1,
            json={"fingerprint": fingerprint},
        )
        data = json.loads(playback_resp.text)
        if not data:
            raise ExtractorError("F16PX: Empty playback response")

        out_headers = {
            "referer": referer,
            "origin": api_origin,
            "Accept-Language": "en-US,en;q=0.5",
            "Accept": "*/*",
            "User-Agent": self.F16PX_USER_AGENT,
        }

        # Case 1: plain sources
        if data.get("sources"):
            return {
                "destination_url": self._pick_best(data["sources"]),
                "request_headers": out_headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        # Case 2: encrypted playback
        pb = data.get("playback")
        if not pb:
            raise ExtractorError("F16PX: No playback data")
        try:
            sources = self._decrypt_sources(pb)
        except Exception as e:
            raise ExtractorError(f"F16PX: Decryption failed ({e})")
        if not sources:
            raise ExtractorError("F16PX: No sources after decryption")

        return {
            "destination_url": self._pick_best(sources),
            "request_headers": out_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
