import asyncio, sys, os
sys.path.insert(0, "/app")
os.environ["PYTHONPATH"] = "/app"

from services.proxy_core import _warp_cli_connect

connected = asyncio.run(_warp_cli_connect())
sys.exit(0 if connected else 1)
