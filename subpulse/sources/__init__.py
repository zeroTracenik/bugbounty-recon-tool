from typing import List, Dict, Type
from .base import BaseSource
from .crtsh import CrtshSource
from .certspotter import CertSpotterSource
from .hackertarget import HackerTargetSource
from .urlscan import UrlScanSource
from .subdomaincenter import SubdomainCenterSource
from .rapiddns import RapidDnsSource
from .wayback import WaybackSource
from .threatminer import ThreatMinerSource
from .alienvault import AlienVaultSource
from .anubis import AnubisSource
from .sitedossier import SiteDossierSource
from .digitorus import DigitorusSource
from .virustotal import VirusTotalSource
from .securitytrails import SecurityTrailsSource

ALL_SOURCES: List[Type[BaseSource]] = [
    CrtshSource,
    CertSpotterSource,
    HackerTargetSource,
    UrlScanSource,
    SubdomainCenterSource,
    RapidDnsSource,
    WaybackSource,
    ThreatMinerSource,
    AlienVaultSource,
    AnubisSource,
    SiteDossierSource,
    DigitorusSource,
    VirusTotalSource,
    SecurityTrailsSource,
]

def get_sources(api_keys: dict = None, enabled_sources: List[str] = None) -> List[BaseSource]:
    api_keys = api_keys or {}
    instances = []
    for cls in ALL_SOURCES:
        if enabled_sources and cls.name not in enabled_sources:
            continue
        instances.append(cls(api_keys=api_keys))
    return instances
