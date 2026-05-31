import asyncio
import logging
import os
import sys
from urllib.parse import unquote, urlparse, urlunparse

from playwright.async_api import async_playwright
from config import get_solver_proxy_url

logger = logging.getLogger(__name__)

_lock = asyncio.Lock()
_playwright = None
_browser = None
_context = None
_context_proxy = None
_profile_dir = os.path.join(os.getcwd(), ".shared_chromium_profile")


def _playwright_proxy_config(proxy_url: str | None) -> dict | None:
    proxy_url = get_solver_proxy_url(proxy_url)
    if not proxy_url:
        return None

    parsed = urlparse(proxy_url)
    if parsed.scheme not in {"http", "https", "socks4", "socks5"} or not parsed.hostname:
        return None

    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parsed.port:
        host = f"{host}:{parsed.port}"

    config = {"server": urlunparse((parsed.scheme, host, "", "", "", ""))}
    if parsed.username:
        config["username"] = unquote(parsed.username)
    if parsed.password:
        config["password"] = unquote(parsed.password)
    return config


async def get_shared_browser_context(user_agent: str, proxy_url: str | None = None):
    global _playwright, _browser, _context, _context_proxy
    browser_proxy = get_solver_proxy_url(proxy_url)

    async with _lock:
        if _browser and _context:
            try:
                await _browser.version()
                if _context_proxy == browser_proxy:
                    return _playwright, _browser, _context
                await _context.close()
                _browser = None
                _context = None
                _context_proxy = None
            except Exception:
                _browser = None
                _context = None
                _context_proxy = None

        if not _playwright:
            _playwright = await async_playwright().start()

        if not _browser and not _context:
            _browser = None if browser_proxy else await _connect_existing_browser()
            if not _browser:
                _context = await _launch_persistent_context(user_agent, browser_proxy)
                _browser = _context.browser
                _context_proxy = browser_proxy
                logger.info("🚀 [Shared Browser] Launching persistent instance on port 9222")

        if not _context:
            contexts = _browser.contexts if _browser else []
            if contexts:
                _context = contexts[0]
                _context_proxy = None
            else:
                raise RuntimeError("Shared browser has no reusable persistent context")
        return _playwright, _browser, _context


async def close_shared_browser():
    global _playwright, _browser, _context, _context_proxy

    async with _lock:
        context = _context
        browser = _browser
        playwright = _playwright
        _context = None
        _browser = None
        _playwright = None
        _context_proxy = None

        try:
            if context:
                await context.close()
        except Exception:
            pass
        try:
            if browser:
                await browser.close()
        except Exception:
            pass
        try:
            if playwright:
                await playwright.stop()
        except Exception:
            pass
        logger.info("💤 [Shared Browser] Closed after inactivity")


async def _connect_existing_browser():
    try:
        browser = await _playwright.chromium.connect_over_cdp(
            "http://127.0.0.1:9222",
            timeout=5000,
        )
        logger.info("🔗 [Shared Browser] Connected to existing persistent instance on port 9222")
        return browser
    except Exception:
        return None


async def _launch_persistent_context(user_agent: str, proxy_url: str | None = None):
    chrome_path = os.getenv("CHROME_BIN") or os.getenv("CHROME_EXE_PATH")
    executable_path = chrome_path if chrome_path and os.path.exists(chrome_path) else None
    launch_kwargs = {}
    proxy_config = _playwright_proxy_config(proxy_url)
    if proxy_config:
        launch_kwargs["proxy"] = proxy_config
    try:
        return await _playwright.chromium.launch_persistent_context(
            _profile_dir,
            headless=sys.platform.startswith("linux"),
            executable_path=executable_path,
            user_agent=user_agent,
            viewport={"width": 1366, "height": 768},
            args=[
                "--remote-debugging-port=9222",
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--autoplay-policy=no-user-gesture-required",
                "--disable-web-security",
                "--disable-features=IsolateOrigins,site-per-process",
            ],
            **launch_kwargs,
        )
    except Exception:
        if proxy_url:
            raise
        logger.warning("⚠️ Port 9222 in use, connecting to existing browser...")
        await asyncio.sleep(1)
        browser = await _playwright.chromium.connect_over_cdp(
            "http://127.0.0.1:9222",
            timeout=10000,
        )
        contexts = browser.contexts
        if not contexts:
            raise RuntimeError("Connected browser has no persistent context")
        return contexts[0]
