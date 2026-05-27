"""
soc_coverage/output/json_writer.py
Persiste el CoverageReport como JSON en disco.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from ..models import CoverageReport


class JSONWriter:

    def __init__(self, directorio: str = "./data"):
        self.directorio = Path(directorio)
        self.directorio.mkdir(parents=True, exist_ok=True)

    def escribir(self, report: CoverageReport) -> Path:
        fecha   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        fichero = self.directorio / f"coverage_gaps_{fecha}.json"
        fichero.write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"  [JSON] Guardado: {fichero}")
        return fichero
