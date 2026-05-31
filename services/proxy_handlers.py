from services.proxy_extractor import HLSProxyExtractorHandlerMixin
from services.proxy_license import HLSProxyLicenseHandlerMixin
from services.proxy_manifest import HLSProxyManifestHandlerMixin


class HLSProxyHandlersMixin(
    HLSProxyManifestHandlerMixin,
    HLSProxyExtractorHandlerMixin,
    HLSProxyLicenseHandlerMixin,
):
    pass
