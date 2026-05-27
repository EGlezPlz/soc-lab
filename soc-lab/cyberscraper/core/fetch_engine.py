"""
CyberScraper — FetchEngine
Descarga HTML de las URLs que le pasa cada adaptador.
Gestiona rate limiting, reintentos y deduplicación de contenido ya procesado.
Por ahora usa requests (HTTP estático). Si una fuente necesita JS,
aquí es donde se añadiría Playwright como backend alternativo.
"""

import time
import json
import hashlib
import requests
from pathlib import Path
from typing import Optional

from sources.base_source import BaseSource, SourcePage
from core.ioc_extractor import IOCExtractor, CTIRecord


HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) "
        "Gecko/20100101 Firefox/124.0"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "es-ES,es;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}


class DedupStore:
    """
    Almacén persistente de hashes de contenido ya procesado.
    Evita reprocesar advisories que no han cambiado desde la última ejecución.
    """

    def __init__(self, path: str = "./data/.dedup_hashes.json"):
        self._path = Path(path)
        self._hashes: set[str] = self._load()

    def _load(self) -> set[str]:
        if self._path.exists():
            try:
                return set(json.loads(self._path.read_text()))
            except (json.JSONDecodeError, IOError):
                return set()
        return set()

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(list(self._hashes), indent=2))

    def seen(self, content_hash: str) -> bool:
        return content_hash in self._hashes

    def mark(self, content_hash: str) -> None:
        self._hashes.add(content_hash)


class FetchEngine:
    """
    Orquesta el ciclo completo para una fuente:
      1. Pide URLs al adaptador (fetch_urls)
      2. Descarga el HTML de cada URL
      3. Llama al adaptador para parsear (parse_page → SourcePage)
      4. Comprueba dedup — si el contenido no cambió, lo salta
      5. Pasa el SourcePage al IOCExtractor
      6. Devuelve la lista de CTIRecords producidos
    """

    def __init__(self, config: dict, dedup_store: DedupStore):
        self.timeout       = config.get("timeout", 15)
        self.delay_seconds = config.get("delay_between_requests", 2.0)
        self.max_retries   = config.get("max_retries", 2)
        self.dedup         = dedup_store

    def run(self, source: BaseSource) -> list[CTIRecord]:
        """
        Ejecuta el ciclo completo para un adaptador de fuente.
        Devuelve los CTIRecords generados (solo los nuevos o modificados).
        """
        print(f"\n[FetchEngine] Procesando fuente: {source.source_name}")

        urls = source.fetch_urls()
        print(f"  URLs encontradas: {len(urls)}")

        records = []
        for url in urls:
            html = self._download(url)
            if html is None:
                continue

            page = source.parse_page(url, html)
            if page is None:
                print(f"  [SKIP] parse_page devolvió None para: {url}")
                continue

            if self.dedup.seen(page.content_hash):
                print(f"  [DEDUP] Sin cambios, saltando: {page.title[:60]}")
                continue

            record = self._extract(page)
            if record:
                self.dedup.mark(page.content_hash)
                records.append(record)
                print(f"  [OK] {page.title[:60]}")

            time.sleep(self.delay_seconds)

        self.dedup.save()
        print(f"  Nuevos registros: {len(records)}")
        return records

    def _download(self, url: str) -> Optional[str]:
        """Descarga el HTML con reintentos."""
        for attempt in range(1, self.max_retries + 2):
            try:
                resp = requests.get(url, headers=HEADERS, timeout=self.timeout)
                resp.raise_for_status()
                return resp.text
            except requests.RequestException as e:
                print(f"  [WARN] Intento {attempt} fallido para {url}: {e}")
                if attempt <= self.max_retries:
                    time.sleep(self.delay_seconds * attempt)
        return None

    def _extract(self, page: SourcePage) -> Optional[CTIRecord]:
        """Pasa el SourcePage al IOCExtractor y devuelve el CTIRecord."""
        try:
            extractor = IOCExtractor(
                source_url  = page.url,
                source_name = page.source_name,
                tlp         = page.tlp,
                tags        = page.tags,
            )
            return extractor.extract(
                raw_text          = page.clean_text,
                title             = page.title,
                published_at      = page.published_at,
                affected_products = page.affected_products,
            )
        except Exception as e:
            print(f"  [ERROR] IOCExtractor falló: {e}")
            return None
