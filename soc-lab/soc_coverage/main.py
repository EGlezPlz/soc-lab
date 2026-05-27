"""
soc_coverage/main.py
Punto de entrada del módulo de auditoría de cobertura.

Uso:
    python3 -m soc_coverage.main
    python3 -m soc_coverage.main --solo-criticos
    python3 -m soc_coverage.main --fuente CISA-KEV
    python3 -m soc_coverage.main --config mi_config.yaml
    python3 -m soc_coverage.main --modo uno-a-uno
"""

import argparse
import sys
import yaml
from pathlib import Path

from .loader import CyberScraperLoader
from .analyzer import Analyzer, AnalyzerConfig
from .output.json_writer import JSONWriter
from .output.html_reporter import HTMLReporter


def cargar_config(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        print(f"[ERROR] No se encontró: {path}")
        sys.exit(1)
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def main():
    parser = argparse.ArgumentParser(
        description="soc_coverage — auditoría de cobertura del SOC-LAB"
    )
    parser.add_argument("--config",        default="soc_coverage/config.yaml")
    parser.add_argument("--solo-criticos", action="store_true",
                        help="Analizar solo CVEs critical/high")
    parser.add_argument("--fuente",        default=None,
                        help="Filtrar por fuente: INCIBE-CERT, CISA-KEV")
    parser.add_argument("--modo",          default="indice",
                        choices=["indice", "uno-a-uno"],
                        help="Estrategia de análisis (default: indice)")
    args = parser.parse_args()

    config = cargar_config(args.config)

    # ── Loader ────────────────────────────────────────────────────────
    data_dir = config.get("cyberscraper_data_dir", "../cyberscraper/data")
    loader   = CyberScraperLoader(data_dir)
    entries  = loader.cargar(
        solo_criticos = args.solo_criticos,
        fuente        = args.fuente,
    )

    if not entries:
        print("[soc_coverage] Sin CVEs para analizar. "
              "¿Has ejecutado CyberScraper primero?")
        sys.exit(0)

    # ── Analyzer ──────────────────────────────────────────────────────
    analyzer_conf = AnalyzerConfig.desde_dict({
        **config.get("wazuh",    {}),
        **config.get("suricata", {}),
        **config.get("misp",     {}),
        "usar_indice_invertido": args.modo == "indice",
    })
    analyzer = Analyzer(analyzer_conf)
    report   = analyzer.analizar(entries)

    # ── Salidas ───────────────────────────────────────────────────────
    output_dir = config.get("output_dir", "./data")

    if config.get("output_json", {}).get("enabled", True):
        JSONWriter(output_dir).escribir(report)

    if config.get("output_html", {}).get("enabled", True):
        path = HTMLReporter(output_dir).escribir(report)
        print(f"\n  Abre en el navegador: file://{path.resolve()}")

    print(f"\n[soc_coverage] Completado.")


if __name__ == "__main__":
    main()
