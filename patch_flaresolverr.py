import re
import os

path = os.path.join(os.path.dirname(__file__), 'flaresolverr', 'src', 'utils.py')
p = open(path, 'r').read()

marker = "--disable-audio-service"
if marker in p:
    print("FlareSolverr already patched, skipping")
else:
    flags = [
        "options.add_argument('--disable-audio-service')",
        "options.add_argument('--disable-software-rasterizer')",
        "options.add_argument('--disable-crashpad-foreground')",
        "options.add_argument('--disable-background-networking')",
        "options.add_argument('--disable-component-update')",
        "options.add_argument('--disable-sync')",
        "options.add_argument('--disable-background-timer-throttling')",
        "options.add_argument('--disable-backgrounding-occluded-windows')",
        "options.add_argument('--disable-renderer-backgrounding')",
        "options.add_argument('--disable-features=ChromeWhatsNewUI,TranslateUI,ChromeLabs,InterestFeedContentSuggestions,MediaRouter')",
        "options.add_argument('--single-process')",
    ]

    flag_block = '\n'.join(flags)
    p = p.replace(
        "options.add_argument('--ignore-ssl-errors')",
        "options.add_argument('--ignore-ssl-errors')\n" + flag_block
    )

    p = re.sub(r'^([ \t]*)start_xvfb_display\(\)', r'\1pass', p, flags=re.MULTILINE)

    open(path, 'w').write(p)
    print('OK - FlareSolverr patched with RAM-saving Chrome flags')
