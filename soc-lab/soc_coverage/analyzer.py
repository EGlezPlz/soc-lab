"""
soc_coverage/analyzer.py
Núcleo de soc_coverage. Orquesta los conectores y produce GapRecords.

Para cada CVEEntry del Loader:
  1. Llama a cada conector activo (Wazuh, Suricata, MISP...)
  2. Agrega los ToolCoverage en un GapRecord
  3. Devuelve un CoverageReport con todas las métricas

Es el único módulo que conoce tanto el Loader como los conectores.
No sabe nada de salidas — eso es trabajo del Reporter.
"""

from dataclasses import dataclass, field
from typing import Optional

from .models import GapRecord, CoverageReport, ToolCoverage
from .loader import CVEEntry
from .connectors.wazuh import WazuhConnector
from .connectors.suricata import SuricataConnector


@dataclass
class AnalyzerConfig:
    """
    Configuración del Analyzer. Se construye desde el config.yaml
    de soc_coverage.
    """
    # Wazuh
    wazuh_enabled:      bool = True
    wazuh_url:          str  = "https://localhost:55000"
    wazuh_user:         str  = "wazuh-wui"
    wazuh_password:     str  = ""
    wazuh_rules_dir:    str  = "/var/ossec/ruleset/rules"

    # Suricata
    suricata_enabled:   bool = True
    suricata_rules_dir: str  = "/etc/suricata/rules"

    # MISP — se reutiliza la conexión de CyberScraper si está disponible
    misp_enabled:       bool = False
    misp_url:           str  = "https://localhost"
    misp_key:           str  = ""

    # Optimización: usar índice invertido cuando hay muchos CVEs
    # En lugar de preguntar por cada CVE, se descarga el índice completo
    # de cada herramienta y se hace la intersección en memoria
    usar_indice_invertido: bool = True

    @classmethod
    def desde_dict(cls, d: dict) -> "AnalyzerConfig":
        cfg = cls()
        for k, v in d.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg


class Analyzer:
    """
    Orquesta los conectores y produce un CoverageReport.

    Uso básico:
        config = AnalyzerConfig.desde_dict(yaml_config)
        analyzer = Analyzer(config)
        report = analyzer.analizar(cve_entries)
    """

    def __init__(self, config: AnalyzerConfig):
        self.config = config
        self._wazuh:    Optional[WazuhConnector]    = None
        self._suricata: Optional[SuricataConnector] = None
        self._misp                                   = None
        self._inicializar_conectores()

    def _inicializar_conectores(self) -> None:
        cfg = self.config
        if cfg.wazuh_enabled:
            self._wazuh = WazuhConnector({
                "wazuh_url":      cfg.wazuh_url,
                "wazuh_user":     cfg.wazuh_user,
                "wazuh_password": cfg.wazuh_password,
                "wazuh_rules_dir": cfg.wazuh_rules_dir,
            })
            print(f"[Analyzer] Conector Wazuh activo ({cfg.wazuh_url})")

        if cfg.suricata_enabled:
            self._suricata = SuricataConnector({
                "suricata_rules_dir": cfg.suricata_rules_dir,
            })
            print(f"[Analyzer] Conector Suricata activo ({cfg.suricata_rules_dir})")

        if cfg.misp_enabled:
            self._inicializar_misp()

    def _inicializar_misp(self) -> None:
        """Intenta conectar con MISP. Si falla, desactiva el conector."""
        try:
            from pymisp import PyMISP
            self._misp = PyMISP(
                self.config.misp_url,
                self.config.misp_key,
                ssl=False,
            )
            print(f"[Analyzer] Conector MISP activo ({self.config.misp_url})")
        except Exception as e:
            print(f"[Analyzer] MISP no disponible: {e} — se omitirá")
            self._misp = None

    # ------------------------------------------------------------------
    # Método principal
    # ------------------------------------------------------------------

    def analizar(self, entries: list[CVEEntry]) -> CoverageReport:
        """
        Analiza una lista de CVEEntries y devuelve un CoverageReport.
        """
        if not entries:
            print("[Analyzer] Sin CVEs que analizar")
            return CoverageReport.desde_gaps([])

        print(f"\n[Analyzer] Analizando {len(entries)} CVEs...")

        # Modo índice invertido: construir el índice una vez
        # y hacer la intersección en memoria — mucho más rápido
        # cuando hay decenas o cientos de CVEs
        if self.config.usar_indice_invertido:
            return self._analizar_con_indice(entries)
        else:
            return self._analizar_uno_a_uno(entries)

    # ------------------------------------------------------------------
    # Estrategia 1: índice invertido (recomendada)
    # ------------------------------------------------------------------

    def _analizar_con_indice(self, entries: list[CVEEntry]) -> CoverageReport:
        """
        Construye el índice CVE→cobertura de cada herramienta una sola vez
        y luego hace la intersección. Óptimo para lotes grandes.
        """
        cve_ids = {e.cve_id.upper() for e in entries}

        # Obtener conjuntos de CVEs cubiertos por cada herramienta
        cubiertos_wazuh: set[str]    = set()
        cubiertos_suricata: set[str] = set()
        cubiertos_misp: set[str]     = set()

        if self._wazuh:
            print("  Construyendo índice Wazuh...")
            cubiertos_wazuh = self._wazuh.cves_cubiertos() & cve_ids

        if self._suricata:
            print("  Construyendo índice Suricata...")
            cubiertos_suricata = self._suricata.cves_cubiertos() & cve_ids

        if self._misp:
            print("  Consultando MISP...")
            cubiertos_misp = self._consultar_misp_batch(cve_ids)

        # Construir GapRecords
        gaps = []
        for entry in entries:
            cve_upper = entry.cve_id.upper()
            cobertura = []

            if self._wazuh:
                cubre = cve_upper in cubiertos_wazuh
                # Para las referencias detalladas, consultar solo si cubre
                refs = []
                if cubre:
                    tc = self._wazuh.verificar(entry.cve_id)
                    refs = tc.referencias
                cobertura.append(ToolCoverage(
                    herramienta = "wazuh",
                    cubre       = cubre,
                    referencias = refs,
                ))

            if self._suricata:
                cubre = cve_upper in cubiertos_suricata
                refs = []
                if cubre:
                    tc = self._suricata.verificar(entry.cve_id)
                    refs = tc.referencias
                cobertura.append(ToolCoverage(
                    herramienta = "suricata",
                    cubre       = cubre,
                    referencias = refs,
                ))

            if self._misp:
                cobertura.append(ToolCoverage(
                    herramienta = "misp",
                    cubre       = cve_upper in cubiertos_misp,
                ))

            gaps.append(GapRecord(
                cve_id    = entry.cve_id,
                fuente    = entry.fuente,
                severidad = entry.severidad,
                en_kev    = entry.en_kev,
                productos = entry.productos,
                tags      = entry.tags,
                cobertura = cobertura,
            ))

        report = CoverageReport.desde_gaps(gaps)
        self._imprimir_resumen(report)
        return report

    # ------------------------------------------------------------------
    # Estrategia 2: uno a uno (para debugging o pocos CVEs)
    # ------------------------------------------------------------------

    def _analizar_uno_a_uno(self, entries: list[CVEEntry]) -> CoverageReport:
        """
        Consulta cada CVE individualmente contra cada conector.
        Más lento pero más informativo para debugging.
        """
        gaps = []
        for i, entry in enumerate(entries, 1):
            print(f"  [{i}/{len(entries)}] {entry.cve_id}")
            cobertura = []

            if self._wazuh:
                cobertura.append(self._wazuh.verificar(entry.cve_id))
            if self._suricata:
                cobertura.append(self._suricata.verificar(entry.cve_id))
            if self._misp:
                cobertura.append(self._verificar_misp(entry.cve_id))

            gaps.append(GapRecord(
                cve_id    = entry.cve_id,
                fuente    = entry.fuente,
                severidad = entry.severidad,
                en_kev    = entry.en_kev,
                productos = entry.productos,
                tags      = entry.tags,
                cobertura = cobertura,
            ))

        report = CoverageReport.desde_gaps(gaps)
        self._imprimir_resumen(report)
        return report

    # ------------------------------------------------------------------
    # MISP helpers
    # ------------------------------------------------------------------

    def _consultar_misp_batch(self, cve_ids: set[str]) -> set[str]:
        """Busca en MISP qué CVEs ya tienen evento."""
        cubiertos = set()
        try:
            for cve_id in cve_ids:
                result = self._misp.search(
                    controller="attributes",
                    type_attribute="vulnerability",
                    value=cve_id,
                    limit=1,
                )
                if result:
                    cubiertos.add(cve_id.upper())
        except Exception as e:
            print(f"  [Analyzer] Error consultando MISP: {e}")
        return cubiertos

    def _verificar_misp(self, cve_id: str) -> ToolCoverage:
        """Verifica un CVE concreto en MISP."""
        try:
            result = self._misp.search(
                controller="attributes",
                type_attribute="vulnerability",
                value=cve_id,
                limit=1,
            )
            tiene = bool(result)
            return ToolCoverage(
                herramienta = "misp",
                cubre       = tiene,
                notas       = "Evento encontrado en MISP" if tiene else "Sin evento en MISP",
            )
        except Exception as e:
            return ToolCoverage(
                herramienta = "misp",
                cubre       = False,
                notas       = f"Error MISP: {e}",
            )

    # ------------------------------------------------------------------
    # Resumen
    # ------------------------------------------------------------------

    def _imprimir_resumen(self, report: CoverageReport) -> None:
        print(f"\n[Analyzer] Resultado:")
        print(f"  CVEs analizados:  {report.total_cves}")
        print(f"  Gaps críticos:    {report.gaps_criticos} "
              f"({report.pct_sin_cobertura}% sin cobertura)")
        por_herramienta = report.gaps_por_herramienta()
        for herramienta, n in sorted(por_herramienta.items()):
            print(f"  Sin cobertura en {herramienta}: {n}")
