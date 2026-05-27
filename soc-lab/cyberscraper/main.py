"""
CyberScraper — main.py
Punto de entrada. Lee config.yaml, instancia fuentes y ejecuta el ciclo completo.

Uso:
    python main.py                        # usa config.yaml por defecto
    python main.py --config mi_config.yaml
    python main.py --source incibe        # solo esa fuente
    python main.py --no-misp              # fuerza skip de MISP aunque esté enabled
"""

import sys
import argparse
import yaml
from pathlib import Path

from core.fetch_engine import FetchEngine, DedupStore
from output.json_writer import JSONWriter
from sources.incibe import INCIBESource
from sources.cisa_kev import CISAKEVSource


SOURCE_REGISTRY = {
    "incibe": INCIBESource,
    "cisa_kev": CISAKEVSource,
    # "cisa": CISASource,
}


def load_config(path: str) -> dict:
    config_path = Path(path)
    if not config_path.exists():
        print(f"[ERROR] Fichero de configuración no encontrado: {path}")
        sys.exit(1)
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_source(source_config: dict):
    adapter_name = source_config.get("adapter", "").lower()
    cls = SOURCE_REGISTRY.get(adapter_name)
    if cls is None:
        print(f"[WARN] Adaptador desconocido: {adapter_name!r} — saltando")
        return None
    return cls(source_config)


def build_misp_exporter(output_config: dict, force_skip: bool):
    """Instancia MISPExporter solo si está habilitado y no se fuerza skip."""
    misp_conf = output_config.get("misp", {})
    if force_skip or not misp_conf.get("enabled", False):
        return None
    try:
        from output.misp_exporter import MISPExporter
        return MISPExporter(misp_conf)
    except ConnectionError as e:
        print(f"[WARN] {e} — se omitirá la exportación a MISP")
        return None
    except ImportError:
        print("[WARN] PyMISP no instalado — ejecuta: pip install pymisp")
        return None


def main():
    parser = argparse.ArgumentParser(description="CyberScraper — scraping defensivo CTI")
    parser.add_argument("--config",   default="config.yaml")
    parser.add_argument("--source",   default=None)
    parser.add_argument("--no-misp",  action="store_true",
                        help="Omitir exportación a MISP aunque esté habilitada en config")
    args = parser.parse_args()

    config        = load_config(args.config)
    output_config = config.get("output", {})
    dedup_config  = config.get("scheduler", {})

    # Componentes
    dedup_store  = DedupStore(path=dedup_config.get("dedup_store", "./data/.dedup_hashes.json"))
    fetch_engine = FetchEngine(config=config.get("fetch", {}), dedup_store=dedup_store)
    json_writer  = JSONWriter(output_config.get("json", {})) \
                   if output_config.get("json", {}).get("enabled") else None
    misp_exporter = build_misp_exporter(output_config, force_skip=args.no_misp)

    # Fuentes
    sources_config = config.get("sources", [])
    if args.source:
        sources_config = [s for s in sources_config
                          if s.get("name", "").lower() == args.source.lower()]
        if not sources_config:
            print(f"[ERROR] Fuente no encontrada: {args.source!r}")
            sys.exit(1)

    total_records = 0
    for source_conf in sources_config:
        source = build_source(source_conf)
        if source is None:
            continue

        records = fetch_engine.run(source)
        total_records += len(records)

        for record in records:
            # JSON
            if json_writer:
                path = json_writer.write(record)
                print(f"  [JSON] Guardado: {path}")

            # MISP
            if misp_exporter:
                event_id = misp_exporter.export(record)
                if event_id:
                    record.misp_event_id = event_id
                    # Actualizar el JSON con el event_id
                    if json_writer:
                        json_writer.write(record)

    print(f"\n[CyberScraper] Completado. Total de registros nuevos: {total_records}")


if __name__ == "__main__":
    main()
