"""
soc_coverage/connectors/suricata.py
Conector para Suricata — busca CVEs en ficheros .rules.

Las reglas de Suricata son ficheros de texto plano con este formato:
    alert tcp ... (msg:"ET EXPLOIT CVE-2024-20353 ..."; sid:2045001; rev:1;)

El CVE puede aparecer en:
  - msg:"..." — descripción de la firma
  - metadata: cve CVE-YYYY-NNNNN — metadato explícito (Emerging Threats)
  - reference:cve,YYYY-NNNNN — referencia CVE estándar Snort/Suricata
"""

import re
from pathlib import Path

from ..models import ToolCoverage


# Patrones para los tres formatos posibles de referencia a CVE en Suricata
RE_CVE_MSG       = re.compile(r'CVE[- ]\d{4}[- ]\d{4,7}', re.IGNORECASE)
RE_CVE_METADATA  = re.compile(r'metadata\s*:[^;]*cve\s+([\d-]+)', re.IGNORECASE)
RE_CVE_REFERENCE = re.compile(r'reference\s*:\s*cve\s*,\s*([\d-]+)', re.IGNORECASE)
RE_SID           = re.compile(r'sid\s*:\s*(\d+)', re.IGNORECASE)
RE_MSG           = re.compile(r'msg\s*:\s*"([^"]+)"', re.IGNORECASE)


class SuricataConnector:
    """
    Comprueba cobertura de CVEs en ficheros .rules de Suricata.

    Configuración:
        suricata_rules_dir: directorio con los ficheros .rules
                            (por defecto /etc/suricata/rules)
    """

    def __init__(self, config: dict):
        self.rules_dir = Path(
            config.get("suricata_rules_dir", "/etc/suricata/rules")
        )
        # Cache: CVE → lista de SIDs — se construye una sola vez
        self._cache: dict[str, list[str]] | None = None

    # ------------------------------------------------------------------
    # Método principal
    # ------------------------------------------------------------------

    def verificar(self, cve_id: str) -> ToolCoverage:
        """
        Busca si hay alguna firma Suricata para este CVE.
        Devuelve un ToolCoverage con los SIDs encontrados.
        """
        indice = self._obtener_indice()
        cve_upper = cve_id.upper()

        sids = indice.get(cve_upper, [])

        return ToolCoverage(
            herramienta = "suricata",
            cubre       = len(sids) > 0,
            referencias = sids,
            notas       = (
                f"{len(sids)} firma(s) encontrada(s)"
                if sids else f"Sin firmas para {cve_id}"
            ),
        )

    # ------------------------------------------------------------------
    # Construcción del índice CVE → SIDs
    # ------------------------------------------------------------------

    def _obtener_indice(self) -> dict[str, list[str]]:
        """
        Construye (y cachea) el índice completo CVE → [SIDs].
        Se construye una sola vez por ejecución.
        """
        if self._cache is not None:
            return self._cache

        if not self.rules_dir.exists():
            print(f"  [Suricata] Directorio no encontrado: {self.rules_dir}")
            self._cache = {}
            return self._cache

        ficheros = list(self.rules_dir.glob("*.rules"))
        if not ficheros:
            print(f"  [Suricata] No se encontraron ficheros .rules en {self.rules_dir}")
            self._cache = {}
            return self._cache

        print(f"  [Suricata] Indexando {len(ficheros)} ficheros .rules...")

        indice: dict[str, list[str]] = {}
        total_reglas = 0

        for rules_path in ficheros:
            try:
                for linea in rules_path.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines():
                    linea = linea.strip()
                    # Ignorar comentarios y líneas vacías
                    if not linea or linea.startswith("#"):
                        continue

                    cves_en_linea = self._extraer_cves(linea)
                    if not cves_en_linea:
                        continue

                    sid = self._extraer_sid(linea)
                    total_reglas += 1

                    for cve in cves_en_linea:
                        cve_upper = cve.upper()
                        if cve_upper not in indice:
                            indice[cve_upper] = []
                        if sid and sid not in indice[cve_upper]:
                            indice[cve_upper].append(sid)

            except IOError as e:
                print(f"  [Suricata] No se pudo leer {rules_path.name}: {e}")

        print(f"  [Suricata] Indexadas {total_reglas} reglas con CVE "
              f"({len(indice)} CVEs únicos cubiertos)")

        self._cache = indice
        return self._cache

    def _extraer_cves(self, linea: str) -> list[str]:
        """Extrae todos los CVEs de una línea de regla Suricata."""
        cves = set()

        # Formato 1: CVE en msg o en cualquier parte del texto
        for m in RE_CVE_MSG.findall(linea):
            # Normalizar: CVE-2024-20353 (con guiones)
            normalizado = re.sub(r'[- ]+', '-', m).upper()
            cves.add(normalizado)

        # Formato 2: metadata: cve YYYY-NNNNN
        for m in RE_CVE_METADATA.finditer(linea):
            cves.add(f"CVE-{m.group(1).replace(' ', '-').upper()}")

        # Formato 3: reference:cve,YYYY-NNNNN
        for m in RE_CVE_REFERENCE.finditer(linea):
            cves.add(f"CVE-{m.group(1).replace(' ', '-').upper()}")

        return list(cves)

    def _extraer_sid(self, linea: str) -> str | None:
        """Extrae el SID de una regla Suricata."""
        m = RE_SID.search(linea)
        return m.group(1) if m else None

    # ------------------------------------------------------------------
    # Utilidad: todos los CVEs cubiertos
    # ------------------------------------------------------------------

    def cves_cubiertos(self) -> set[str]:
        """
        Devuelve el conjunto de todos los CVEs que Suricata cubre.
        Útil para análisis inverso — qué cubre el stack completo.
        """
        return set(self._obtener_indice().keys())

    def estadisticas(self) -> dict:
        """Resumen del contenido de las reglas indexadas."""
        indice = self._obtener_indice()
        total_sids = sum(len(sids) for sids in indice.values())
        return {
            "cves_cubiertos":   len(indice),
            "total_firmas":     total_sids,
            "rules_dir":        str(self.rules_dir),
        }
