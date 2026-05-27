"""
CyberScraper — adaptador CISA KEV (Known Exploited Vulnerabilities)
Fuente: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

El KEV es un catálogo federal de vulnerabilidades con explotación activa confirmada.
A diferencia de INCIBE, publica un feed JSON oficial — no hay HTML que parsear.

Estructura del JSON:
{
  "title": "CISA Known Exploited Vulnerabilities Catalog",
  "catalogVersion": "2024.03.15",
  "dateReleased": "2024-03-15T00:00:00Z",
  "count": 1100,
  "vulnerabilities": [
    {
      "cveID":                "CVE-2024-XXXXX",
      "vendorProject":        "Cisco",
      "product":              "IOS XE",
      "vulnerabilityName":    "Cisco IOS XE Web UI Privilege Escalation",
      "dateAdded":            "2024-03-15",
      "shortDescription":     "...",
      "requiredAction":       "Apply mitigations...",
      "dueDate":              "2024-04-05",
      "knownRansomwareCampaignUse": "Known" | "Unknown",
      "notes":                "..."
    },
    ...
  ]
}

Por qué el KEV es diferente a INCIBE para el proyecto soc_coverage:
- Solo contiene vulnerabilidades con explotación activa confirmada
- Incluye fecha límite de remediación (dueDate) — accionable directamente
- Indica si hay uso conocido en campañas de ransomware
- Es el estándar de referencia para priorización en SOCs estadounidenses
"""

import json
import requests
from datetime import datetime, timezone
from typing import Optional

from .base_source import BaseSource, SourcePage


KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) "
        "Gecko/20100101 Firefox/124.0"
    ),
    "Accept": "application/json,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}


class CISAKEVSource(BaseSource):
    """
    Adaptador para el catálogo KEV de CISA.

    Diferencias respecto a INCIBESource:
    - No parsea HTML — consume JSON directamente
    - No implementa fetch_urls() / parse_page() porque no hay páginas que visitar
    - Implementa fetch_all() que devuelve todos los registros del catálogo
    - Permite filtrar por dueDate para obtener solo las de vencimiento próximo

    El adaptador puede operar en dos modos según la config:
      - modo "recientes": solo CVEs añadidos en los últimos N días (default: 30)
      - modo "completo": todo el catálogo (útil para análisis histórico)
    """

    def __init__(self, config: dict):
        super().__init__(config)
        self.dias_recientes = config.get("dias_recientes", 30)
        self.modo_completo  = config.get("modo_completo", False)
        self.timeout        = config.get("timeout", 20)

    # ------------------------------------------------------------------
    # BaseSource requiere estos métodos — los implementamos de forma
    # compatible aunque el KEV no siga el modelo fetch_urls/parse_page
    # ------------------------------------------------------------------

    def fetch_urls(self) -> list[str]:
        """El KEV es un único endpoint JSON — devolvemos solo esa URL."""
        return [KEV_URL]

    def parse_page(self, url: str, html: str) -> Optional[SourcePage]:
        """
        El 'html' aquí es en realidad el texto JSON del feed.
        Lo parseamos y construimos un SourcePage con el texto limpio
        de todas las vulnerabilidades relevantes concatenadas.
        Esto mantiene compatibilidad con FetchEngine.
        """
        try:
            data = json.loads(html)
        except json.JSONDecodeError as e:
            print(f"  [CISA KEV] Error al parsear JSON: {e}")
            return None

        vulns = data.get("vulnerabilities", [])
        catalog_date = data.get("dateReleased", "")
        catalog_version = data.get("catalogVersion", "")

        # Filtrar por fecha si no estamos en modo completo
        if not self.modo_completo:
            vulns = self._filtrar_recientes(vulns)

        if not vulns:
            print(f"  [CISA KEV] Sin vulnerabilidades nuevas en los últimos {self.dias_recientes} días")
            return None

        # Construir texto limpio para el IOCExtractor
        # El formato reproduce los campos clave de forma que los regex de
        # IOCExtractor capturen CVEs, severidad y URLs sin modificaciones
        lineas = [
            f"CISA Known Exploited Vulnerabilities Catalog",
            f"Version: {catalog_version}",
            f"Date: {catalog_date}",
            f"Vulnerabilities in this feed: {len(vulns)}",
            "",
        ]

        for v in vulns:
            lineas += [
                f"CVE: {v.get('cveID', '')}",
                f"Vendor/Product: {v.get('vendorProject', '')} {v.get('product', '')}",
                f"Name: {v.get('vulnerabilityName', '')}",
                f"Date Added: {v.get('dateAdded', '')}",
                f"Due Date: {v.get('dueDate', '')}",
                f"Ransomware: {v.get('knownRansomwareCampaignUse', 'Unknown')}",
                f"Description: {v.get('shortDescription', '')}",
                f"Required Action: {v.get('requiredAction', '')}",
                f"Notes: {v.get('notes', '')}",
                "",
            ]

        clean_text = "\n".join(lineas)

        # Productos afectados — lista única de vendor+product
        products = list({
            f"{v.get('vendorProject', '')} {v.get('product', '')}".strip()
            for v in vulns
            if v.get('vendorProject') or v.get('product')
        })

        # Tags adicionales si hay ransomware conocido
        extra_tags = list(self.tags)
        if any(v.get("knownRansomwareCampaignUse") == "Known" for v in vulns):
            extra_tags.append("ransomware")

        return SourcePage(
            url               = KEV_URL,
            source_name       = self.source_name,
            title             = f"CISA KEV — {len(vulns)} vulnerabilidades explotadas activamente",
            clean_text        = clean_text,
            published_at      = catalog_date[:10] if catalog_date else None,
            affected_products = products[:50],  # cap para no saturar MISP
            tlp               = self.tlp,
            tags              = extra_tags,
        )

    # ------------------------------------------------------------------
    # Métodos propios del KEV
    # ------------------------------------------------------------------

    def fetch_all(self) -> Optional[dict]:
        """
        Descarga el catálogo KEV completo y lo devuelve como dict.
        Útil para soc_coverage, que necesita acceso directo a cada CVE
        sin pasar por el IOCExtractor.
        """
        try:
            resp = requests.get(KEV_URL, headers=HEADERS, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            print(f"  [CISA KEV] Error al descargar catálogo: {e}")
            return None

    def get_cve_ids(self, solo_recientes: bool = True) -> list[str]:
        """
        Devuelve solo la lista de IDs de CVE del catálogo.
        Útil para soc_coverage cuando solo necesita los identificadores.
        """
        data = self.fetch_all()
        if not data:
            return []
        vulns = data.get("vulnerabilities", [])
        if solo_recientes:
            vulns = self._filtrar_recientes(vulns)
        return [v["cveID"] for v in vulns if v.get("cveID")]

    def get_ransomware_cves(self) -> list[str]:
        """
        Devuelve CVEs del KEV asociados a campañas de ransomware conocidas.
        Subconjunto de máxima prioridad para soc_coverage.
        """
        data = self.fetch_all()
        if not data:
            return []
        return [
            v["cveID"]
            for v in data.get("vulnerabilities", [])
            if v.get("knownRansomwareCampaignUse") == "Known" and v.get("cveID")
        ]

    def _filtrar_recientes(self, vulns: list[dict]) -> list[dict]:
        """
        Filtra vulnerabilidades añadidas al KEV en los últimos N días.
        """
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.dias_recientes)
        resultado = []
        for v in vulns:
            date_added = v.get("dateAdded", "")
            if not date_added:
                continue
            try:
                dt = datetime.fromisoformat(date_added).replace(tzinfo=timezone.utc)
                if dt >= cutoff:
                    resultado.append(v)
            except ValueError:
                continue
        return resultado
