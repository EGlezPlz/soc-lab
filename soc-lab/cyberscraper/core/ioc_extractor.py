"""
CyberScraper — IOCExtractor v0.1.0
Extrae IOCs de texto plano procedente de advisories, blogs CTI o informes.
Salida: dict compatible con el esquema CTI definido en el proyecto.
"""

import re
import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
import ipaddress


VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Patrones regex defensivos
# ---------------------------------------------------------------------------

# CVE: formato estricto CVE-YYYY-NNNNN (4 dígitos año, 4-7 dígitos ID)
RE_CVE = re.compile(
    r'\bCVE-(?:19|20)\d{2}-\d{4,7}\b',
    re.IGNORECASE
)

# IPv4: solo rangos públicos (se filtran privadas/loopback en post-proceso)
RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# IPv6: forma completa y comprimida (básico, cubre casos más frecuentes en advisories)
RE_IPV6 = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}:'
    r'|:(?::[0-9a-fA-F]{1,4}){1,7}'
)

# Dominios: mínimo dos segmentos, TLD conocido, sin IPs
RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|gov|edu|io|es|de|fr|uk|ru|cn|br|info|biz|xyz|'
    r'mil|int|eu|co|me|cc|tv|tk|ml|ga|cf|gq|onion)\b',
    re.IGNORECASE
)

# URLs completas (http, https, ftp)
RE_URL = re.compile(
    r'https?://[^\s<>"\')\]]+|ftp://[^\s<>"\')\]]+',
    re.IGNORECASE
)

# Hashes por longitud de hex (MD5=32, SHA1=40, SHA256=64)
RE_HASH_MD5    = re.compile(r'\b[0-9a-fA-F]{32}\b')
RE_HASH_SHA1   = re.compile(r'\b[0-9a-fA-F]{40}\b')
RE_HASH_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')

# Email básico
RE_EMAIL = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)

# CVSS score: "CVSS: 9.8" / "CVSS v3.1: 8.1" / "puntuación: 7.5"
RE_CVSS = re.compile(
    r'(?:CVSS(?:\s*v\d(?:\.\d)?)?|puntuaci[oó]n)\s*[:\-]?\s*(\d(?:\.\d)?)\b',
    re.IGNORECASE
)

# Severidad explícita
RE_SEVERITY = re.compile(
    r'\b(critical|cr[ií]tica?|alta|high|media|medium|baja|low|informativa|info)\b',
    re.IGNORECASE
)

SEVERITY_MAP = {
    'critical': 'critical', 'crítica': 'critical', 'critica': 'critical',
    'alta': 'high', 'high': 'high',
    'media': 'medium', 'medium': 'medium',
    'baja': 'low', 'low': 'low',
    'informativa': 'info', 'info': 'info',
}


# ---------------------------------------------------------------------------
# IPs que NO son IOCs — rangos privados/reservados
# ---------------------------------------------------------------------------

_PRIVATE_NETS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),  # link-local
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('255.255.255.255/32'),
]

def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return not any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Dataclasses del esquema CTI
# ---------------------------------------------------------------------------

@dataclass
class Hashes:
    md5:    list[str] = field(default_factory=list)
    sha1:   list[str] = field(default_factory=list)
    sha256: list[str] = field(default_factory=list)

@dataclass
class IOCs:
    cves:    list[str] = field(default_factory=list)
    ips:     list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls:    list[str] = field(default_factory=list)
    hashes:  Hashes    = field(default_factory=Hashes)
    emails:  list[str] = field(default_factory=list)

@dataclass
class CTIRecord:
    source_url:        str
    source_name:       str
    title:             str
    published_at:      Optional[str]
    scraped_at:        str
    tlp:               str
    iocs:              IOCs
    severity:          Optional[str]
    cvss_score:        Optional[float]
    affected_products: list[str]
    tags:              list[str]
    raw_text_hash:     str
    extractor_version: str
    misp_event_id:     Optional[int] = None


# ---------------------------------------------------------------------------
# IOCExtractor principal
# ---------------------------------------------------------------------------

class IOCExtractor:
    """
    Extrae IOCs y metadatos CTI de texto plano.

    Uso básico:
        extractor = IOCExtractor(source_url="https://...", source_name="INCIBE")
        record = extractor.extract(title="...", raw_text="...", published_at="...")
        data = record.to_dict()
    """

    def __init__(
        self,
        source_url: str,
        source_name: str,
        tlp: str = "WHITE",
        tags: list[str] | None = None,
    ):
        self.source_url  = source_url
        self.source_name = source_name
        self.tlp         = tlp
        self.tags        = tags or []

    # ---- extracción principal -----------------------------------------------

    def extract(
        self,
        raw_text: str,
        title: str = "",
        published_at: str | None = None,
        affected_products: list[str] | None = None,
    ) -> CTIRecord:

        text_hash = hashlib.sha256(raw_text.encode()).hexdigest()
        scraped_at = datetime.now(timezone.utc).isoformat()

        iocs = IOCs(
            cves    = self._extract_cves(raw_text),
            ips     = self._extract_ips(raw_text),
            domains = self._extract_domains(raw_text),
            urls    = self._extract_urls(raw_text),
            hashes  = self._extract_hashes(raw_text),
            emails  = self._extract_emails(raw_text),
        )

        return CTIRecord(
            source_url        = self.source_url,
            source_name       = self.source_name,
            title             = title,
            published_at      = published_at,
            scraped_at        = scraped_at,
            tlp               = self.tlp,
            iocs              = iocs,
            severity          = self._extract_severity(raw_text),
            cvss_score        = self._extract_cvss(raw_text),
            affected_products = affected_products or [],
            tags              = self.tags,
            raw_text_hash     = text_hash,
            extractor_version = VERSION,
        )

    def to_dict(self, record: CTIRecord) -> dict:
        d = asdict(record)
        return d

    # ---- métodos de extracción individuales ---------------------------------

    def _extract_cves(self, text: str) -> list[str]:
        found = RE_CVE.findall(text)
        # normalizar a mayúsculas y deduplicar preservando orden
        seen, result = set(), []
        for cve in found:
            cve_upper = cve.upper()
            if cve_upper not in seen:
                seen.add(cve_upper)
                result.append(cve_upper)
        return result

    def _extract_ips(self, text: str) -> list[str]:
        # Primero extraer URLs para excluir IPs que son parte de una URL
        url_chunks = set(RE_URL.findall(text))
        url_text = " ".join(url_chunks)

        seen, result = set(), []
        for ip in RE_IPV4.findall(text):
            if ip in seen:
                continue
            # descartar si aparece dentro de una URL
            if any(ip in url for url in url_chunks):
                continue
            if _is_public_ip(ip):
                seen.add(ip)
                result.append(ip)

        for ip in RE_IPV6.findall(text):
            if ip not in seen:
                seen.add(ip)
                result.append(ip)

        return result

    def _extract_domains(self, text: str) -> list[str]:
        # Extraer URLs primero para no duplicar dominios que ya van en urls[]
        urls = RE_URL.findall(text)
        url_domains = set()
        for url in urls:
            m = re.match(r'https?://([^/?\s]+)', url)
            if m:
                url_domains.add(m.group(1).lower())

        seen, result = set(), []
        for dom in RE_DOMAIN.findall(text):
            dom_l = dom.lower()
            if dom_l not in seen and dom_l not in url_domains:
                seen.add(dom_l)
                result.append(dom_l)
        return result

    def _extract_urls(self, text: str) -> list[str]:
        seen, result = set(), []
        for url in RE_URL.findall(text):
            # limpiar trailing punctuation que el regex puede capturar
            url = url.rstrip('.,;:!?)')
            if url not in seen:
                seen.add(url)
                result.append(url)
        return result

    def _extract_hashes(self, text: str) -> Hashes:
        # SHA256 primero para evitar que sus 64 chars sean también capturados como SHA1/MD5
        sha256_matches = set(RE_HASH_SHA256.findall(text))
        # SHA1: 40 chars — excluir substrings de sha256
        sha1_candidates = RE_HASH_SHA1.findall(text)
        sha1_matches = {
            h for h in sha1_candidates
            if not any(h in s256 for s256 in sha256_matches)
        }
        # MD5: 32 chars — excluir substrings de sha1 y sha256
        md5_candidates = RE_HASH_MD5.findall(text)
        md5_matches = {
            h for h in md5_candidates
            if not any(h in s for s in sha1_matches | sha256_matches)
        }

        return Hashes(
            md5    = sorted(md5_matches),
            sha1   = sorted(sha1_matches),
            sha256 = sorted(sha256_matches),
        )

    def _extract_emails(self, text: str) -> list[str]:
        seen, result = set(), []
        for email in RE_EMAIL.findall(text):
            el = email.lower()
            if el not in seen:
                seen.add(el)
                result.append(el)
        return result

    def _extract_severity(self, text: str) -> Optional[str]:
        m = RE_SEVERITY.search(text)
        if m:
            return SEVERITY_MAP.get(m.group(1).lower())
        return None

    def _extract_cvss(self, text: str) -> Optional[float]:
        m = RE_CVSS.search(text)
        if m:
            try:
                score = float(m.group(1))
                if 0.0 <= score <= 10.0:
                    return score
            except ValueError:
                pass
        return None
