"""
soc_coverage/models.py
Modelo de datos central del módulo de auditoría de cobertura.

GapRecord es la unidad mínima de información útil: para cada CVE
del feed, registra qué herramientas lo cubren y cuáles no.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timezone


@dataclass
class ToolCoverage:
    """
    Cobertura de una herramienta concreta para un CVE.
    Cubre tanto herramientas propias (Wazuh, Suricata)
    como fuentes externas de referencia (competencia).
    """
    herramienta:  str            # "wazuh" | "suricata" | "misp" | "elastic" ...
    cubre:        bool           # True si hay regla/firma/evento para este CVE
    referencias:  list[str] = field(default_factory=list)
    # Para Wazuh: IDs de reglas encontradas
    # Para Suricata: SIDs encontrados
    # Para MISP: IDs de eventos
    # Para competencia: URLs o IDs de advisories públicos
    notas:        Optional[str] = None


@dataclass
class GapRecord:
    """
    Resultado del análisis de cobertura para un CVE concreto.
    Un gap es un CVE que no está cubierto por alguna herramienta.
    """

    # ── Identificación ─────────────────────────────────────────────────────
    cve_id:       str
    fuente:       str            # "INCIBE-CERT" | "CISA-KEV"
    severidad:    Optional[str]  # critical | high | medium | low
    en_kev:       bool           # ¿está en el catálogo CISA KEV?
    productos:    list[str] = field(default_factory=list)
    tags:         list[str] = field(default_factory=list)

    # ── Cobertura por herramienta ──────────────────────────────────────────
    cobertura:    list[ToolCoverage] = field(default_factory=list)

    # ── Métricas derivadas ─────────────────────────────────────────────────
    analizado_en: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # ── Propiedades calculadas ─────────────────────────────────────────────

    @property
    def herramientas_sin_cobertura(self) -> list[str]:
        """Lista de herramientas que NO cubren este CVE."""
        return [c.herramienta for c in self.cobertura if not c.cubre]

    @property
    def herramientas_con_cobertura(self) -> list[str]:
        """Lista de herramientas que SÍ cubren este CVE."""
        return [c.herramienta for c in self.cobertura if c.cubre]

    @property
    def gap_critico(self) -> bool:
        """
        True si ninguna herramienta propia cubre este CVE.
        Herramientas propias: wazuh, suricata, misp.
        """
        propias = {"wazuh", "suricata", "misp"}
        cubiertas = set(self.herramientas_con_cobertura)
        return len(propias & cubiertas) == 0

    @property
    def cobertura_propia_pct(self) -> float:
        """
        Porcentaje de herramientas propias que cubren este CVE.
        0.0 = ninguna, 1.0 = todas.
        """
        propias = [c for c in self.cobertura
                   if c.herramienta in {"wazuh", "suricata", "misp"}]
        if not propias:
            return 0.0
        return sum(1 for c in propias if c.cubre) / len(propias)

    def to_dict(self) -> dict:
        d = asdict(self)
        # Añadir propiedades calculadas al dict de salida
        d["herramientas_sin_cobertura"] = self.herramientas_sin_cobertura
        d["herramientas_con_cobertura"] = self.herramientas_con_cobertura
        d["gap_critico"]                = self.gap_critico
        d["cobertura_propia_pct"]       = round(self.cobertura_propia_pct, 2)
        return d


@dataclass
class CoverageReport:
    """
    Informe completo de cobertura para una ejecución.
    Agrega todos los GapRecords y produce métricas globales.
    """
    generado_en:   str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    total_cves:    int = 0
    gaps_criticos: int = 0
    gaps:          list[GapRecord] = field(default_factory=list)

    @classmethod
    def desde_gaps(cls, gaps: list[GapRecord]) -> "CoverageReport":
        return cls(
            total_cves    = len(gaps),
            gaps_criticos = sum(1 for g in gaps if g.gap_critico),
            gaps          = gaps,
        )

    @property
    def pct_sin_cobertura(self) -> float:
        if not self.total_cves:
            return 0.0
        return round(self.gaps_criticos / self.total_cves * 100, 1)

    def gaps_por_herramienta(self) -> dict[str, int]:
        """Cuántos CVEs no cubre cada herramienta."""
        conteo: dict[str, int] = {}
        for gap in self.gaps:
            for h in gap.herramientas_sin_cobertura:
                conteo[h] = conteo.get(h, 0) + 1
        return conteo

    def gaps_criticos_list(self) -> list[GapRecord]:
        return [g for g in self.gaps if g.gap_critico]

    def to_dict(self) -> dict:
        return {
            "generado_en":        self.generado_en,
            "total_cves":         self.total_cves,
            "gaps_criticos":      self.gaps_criticos,
            "pct_sin_cobertura":  self.pct_sin_cobertura,
            "gaps_por_herramienta": self.gaps_por_herramienta(),
            "gaps":               [g.to_dict() for g in self.gaps],
        }
