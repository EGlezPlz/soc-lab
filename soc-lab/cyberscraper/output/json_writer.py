"""
CyberScraper — JSONWriter
Persiste CTIRecords como ficheros JSON en disco.
Un fichero por registro, nombrado con fecha + fuente + hash corto.
Útil para inspección manual, ingestión posterior en MISP, o archivo.
"""

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from core.ioc_extractor import CTIRecord


class JSONWriter:

    def __init__(self, config: dict):
        self.output_dir = Path(config.get("path", "./data"))
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write(self, record: CTIRecord) -> Path:
        """
        Escribe el CTIRecord en disco.
        Nombre: YYYY-MM-DD_<source_slug>_<hash8>.json
        Devuelve la ruta del fichero creado.
        """
        date_str    = (record.scraped_at or datetime.now(timezone.utc).isoformat())[:10]
        source_slug = record.source_name.lower().replace(" ", "-").replace("/", "-")
        hash_short  = record.raw_text_hash[:8]
        filename    = f"{date_str}_{source_slug}_{hash_short}.json"
        filepath    = self.output_dir / filename

        data = asdict(record)
        filepath.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return filepath

    def write_many(self, records: list[CTIRecord]) -> list[Path]:
        return [self.write(r) for r in records]
