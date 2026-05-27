"""
soc_coverage/loader.py
Lee los JSONs producidos por CyberScraper y extrae los CVEs
con su contexto (severidad, productos, fuente, en_kev).

No depende de ningún otro módulo de soc_coverage — solo lee
ficheros del sistema y devuelve estructuras simples.
"""

import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CVEEntry:
    """
    Representación mínima de un CVE extraído de un CTIRecord de CyberScraper.
    Es la entrada que recibe el Analyzer.
    """
    cve_id:    str
    fuente:    str
    severidad: Optional[str]
    productos: list[str] = field(default_factory=list)
    tags:      list[str] = field(default_factory=list)
    en_kev:    bool = False   # se marca True si el CVE aparece en un JSON de CISA-KEV


class CyberScraperLoader:
    """
    Carga CTIRecords desde el directorio data/ de CyberScraper
    y los convierte en CVEEntries para el Analyzer.

    Uso:
        loader = CyberScraperLoader("../cyberscraper/data")
        entries = loader.cargar()
        # → lista de CVEEntry con todos los CVEs únicos del directorio
    """

    def __init__(self, data_dir: str = "../cyberscraper/data"):
        self.data_dir = Path(data_dir)

    def cargar(
        self,
        solo_criticos: bool = False,
        fuente: Optional[str] = None,
    ) -> list[CVEEntry]:
        """
        Carga todos los JSONs del directorio y devuelve CVEEntries únicos.

        Parámetros:
            solo_criticos — si True, solo incluye CVEs con severidad critical o high
            fuente        — si se indica, filtra por source_name ("INCIBE-CERT", "CISA-KEV")
        """
        ficheros = sorted(self.data_dir.glob("*.json"))
        if not ficheros:
            print(f"[Loader] No se encontraron JSONs en {self.data_dir}")
            return []

        print(f"[Loader] Ficheros encontrados: {len(ficheros)}")

        # Acumulamos por CVE para deduplicar — si un CVE aparece en INCIBE y KEV,
        # el registro de KEV marca en_kev=True
        cve_map: dict[str, CVEEntry] = {}

        for fichero in ficheros:
            registros = self._leer_fichero(fichero)
            for rec in registros:
                source = rec.get("source_name", "")
                if fuente and source.upper() != fuente.upper():
                    continue

                severidad = rec.get("severity")
                if solo_criticos and severidad not in ("critical", "high"):
                    continue

                es_kev = "CISA" in source.upper() or "KEV" in source.upper()
                cves   = rec.get("iocs", {}).get("cves", [])

                for cve_id in cves:
                    if cve_id in cve_map:
                        # Ya existe — actualizar en_kev si viene del KEV
                        if es_kev:
                            cve_map[cve_id].en_kev = True
                    else:
                        cve_map[cve_id] = CVEEntry(
                            cve_id    = cve_id,
                            fuente    = source,
                            severidad = severidad,
                            productos = rec.get("affected_products", []),
                            tags      = rec.get("tags", []),
                            en_kev    = es_kev,
                        )

        entries = list(cve_map.values())
        print(f"[Loader] CVEs únicos cargados: {len(entries)}")
        if solo_criticos:
            print(f"  (filtro: solo critical/high)")
        if fuente:
            print(f"  (filtro: fuente={fuente})")
        return entries

    def _leer_fichero(self, path: Path) -> list[dict]:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                # Filtrar solo los elementos que sean diccionarios
                return [item for item in raw if isinstance(item, dict)]
            if isinstance(raw, dict):
                return [raw]
            return []
        except (json.JSONDecodeError, IOError) as e:
            print(f"  [WARN] No se pudo leer {path.name}: {e}")
            return []
