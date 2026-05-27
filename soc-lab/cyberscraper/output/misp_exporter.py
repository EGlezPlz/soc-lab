"""
CyberScraper — MISPExporter
Convierte CTIRecords en eventos MISP mediante PyMISP.

Mapeo CTIRecord → MISP:
  title + source_name  → Event.info
  published_at         → Event.date
  tlp                  → Tag (TLP:<level>)
  severity             → Tag (cyberscraper:severity=<level>)
  tags[]               → Tags libres
  iocs.cves            → Attribute tipo 'vulnerability'
  iocs.ips             → Attribute tipo 'ip-dst'
  iocs.domains         → Attribute tipo 'domain'
  iocs.urls            → Attribute tipo 'url'
  iocs.hashes.md5      → Attribute tipo 'md5'
  iocs.hashes.sha1     → Attribute tipo 'sha1'
  iocs.hashes.sha256   → Attribute tipo 'sha256'
  iocs.emails          → Attribute tipo 'email-src'
  affected_products    → Attribute tipo 'text' (comment)
  source_url           → Attribute tipo 'link'
"""

from __future__ import annotations
from dataclasses import asdict
from typing import Optional

from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPTag

from core.ioc_extractor import CTIRecord


# Mapeo TLP a tag MISP estándar
TLP_TAGS = {
    "WHITE": "tlp:white",
    "GREEN": "tlp:green",
    "AMBER": "tlp:amber",
    "RED":   "tlp:red",
}

# Distribución MISP según TLP
# 0=org, 1=community, 2=connected, 3=all
TLP_DISTRIBUTION = {
    "WHITE": 3,
    "GREEN": 2,
    "AMBER": 1,
    "RED":   0,
}


class MISPExporter:
    """
    Exporta CTIRecords a MISP como eventos con atributos.

    Uso:
        exporter = MISPExporter(config)
        event_id = exporter.export(record)
    """

    def __init__(self, config: dict):
        url        = config.get("url", "https://localhost")
        key        = config.get("key", "")
        verify_ssl = config.get("verify_ssl", False)

        self.misp = PyMISP(url, key, ssl=verify_ssl)
        self._verify_connection()

    def _verify_connection(self) -> None:
        """Comprueba que MISP responde antes de intentar exportar."""
        try:
            self.misp.misp_instance_version
            print("[MISPExporter] Conexión con MISP OK")
        except Exception as e:
            raise ConnectionError(f"[MISPExporter] No se puede conectar a MISP: {e}")

    # ------------------------------------------------------------------
    # Exportación principal
    # ------------------------------------------------------------------

    def export(self, record: CTIRecord) -> Optional[int]:
        """
        Crea un evento MISP a partir de un CTIRecord.
        Devuelve el event_id asignado por MISP, o None si falla.
        """
        event = self._build_event(record)
        self._add_attributes(event, record)
        self._add_tags(event, record)

        try:
            result = self.misp.add_event(event)
            if isinstance(result, dict) and "Event" in result:
                event_id = int(result["Event"]["id"])
                print(f"  [MISP] Evento creado: id={event_id} — {record.title[:60]}")
                return event_id
            else:
                print(f"  [MISP] Respuesta inesperada: {result}")
                return None
        except Exception as e:
            print(f"  [MISP] Error al crear evento: {e}")
            return None

    def export_many(self, records: list[CTIRecord]) -> dict[str, int]:
        """
        Exporta una lista de CTIRecords.
        Devuelve dict {raw_text_hash: event_id} para los que tuvieron éxito.
        """
        results = {}
        for record in records:
            event_id = self.export(record)
            if event_id:
                results[record.raw_text_hash] = event_id
        return results

    # ------------------------------------------------------------------
    # Construcción del evento
    # ------------------------------------------------------------------

    def _build_event(self, record: CTIRecord) -> MISPEvent:
        event = MISPEvent()

        event.info         = f"[{record.source_name}] {record.title}"
        event.distribution = TLP_DISTRIBUTION.get(record.tlp, 3)
        event.threat_level_id = self._severity_to_threat_level(record.severity)
        event.analysis     = 1  # 0=inicial, 1=en curso, 2=completado

        if record.published_at:
            # MISP acepta fecha en formato YYYY-MM-DD
            event.date = record.published_at[:10]

        return event

    def _severity_to_threat_level(self, severity: Optional[str]) -> int:
        """
        MISP threat levels: 1=High, 2=Medium, 3=Low, 4=Undefined
        """
        return {
            "critical": 1,
            "high":     1,
            "medium":   2,
            "low":      3,
            "info":     4,
        }.get(severity or "", 4)

    # ------------------------------------------------------------------
    # Atributos
    # ------------------------------------------------------------------

    def _add_attributes(self, event: MISPEvent, record: CTIRecord) -> None:
        iocs = record.iocs

        # CVEs
        for cve in iocs.cves:
            self._attr(event, "vulnerability", cve,
                       comment=f"CVE extraído por CyberScraper de {record.source_name}")

        # IPs
        for ip in iocs.ips:
            self._attr(event, "ip-dst", ip)

        # Dominios
        for domain in iocs.domains:
            self._attr(event, "domain", domain)

        # URLs
        for url in iocs.urls:
            self._attr(event, "url", url)

        # Hashes
        for h in iocs.hashes.md5:
            self._attr(event, "md5", h)
        for h in iocs.hashes.sha1:
            self._attr(event, "sha1", h)
        for h in iocs.hashes.sha256:
            self._attr(event, "sha256", h)

        # Emails
        for email in iocs.emails:
            self._attr(event, "email-src", email)

        # Productos afectados — como atributo de texto
        if record.affected_products:
            products_text = " | ".join(record.affected_products)
            self._attr(event, "text", products_text,
                       comment="Productos afectados", category="External analysis")

        # CVSS score — como atributo de texto
        if record.cvss_score is not None:
            self._attr(event, "text", str(record.cvss_score),
                       comment="CVSS score", category="External analysis")

        # URL fuente — siempre presente
        self._attr(event, "url", record.source_url,
                   comment="URL fuente del advisory", category="External analysis")

    def _attr(
        self,
        event: MISPEvent,
        attr_type: str,
        value: str,
        comment: str = "",
        category: str = "Network activity",
    ) -> None:
        """Añade un atributo al evento con valores por defecto razonables."""
        attr             = MISPAttribute()
        attr.type        = attr_type
        attr.value       = value
        attr.comment     = comment
        attr.to_ids      = attr_type in ("ip-dst", "domain", "url", "md5",
                                          "sha1", "sha256", "email-src")
        attr.category    = category
        attr.distribution = event.distribution
        event.add_attribute(**attr)

    # ------------------------------------------------------------------
    # Tags
    # ------------------------------------------------------------------

    def _add_tags(self, event: MISPEvent, record: CTIRecord) -> None:
        # TLP
        tlp_tag = TLP_TAGS.get(record.tlp, "tlp:white")
        event.add_tag(tlp_tag)

        # Severidad como tag propio de CyberScraper
        if record.severity:
            event.add_tag(f"cyberscraper:severity={record.severity}")

        # Fuente
        event.add_tag(f"cyberscraper:source={record.source_name.lower()}")

        # Tags libres del record (del config + los de INCIBE)
        for tag in record.tags:
            event.add_tag(tag)
