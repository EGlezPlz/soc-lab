"""
CyberScraper — adaptador INCIBE-CERT
Fuente: https://www.incibe.es/incibe-cert/alerta-temprana/avisos

Estructura real confirmada por diagnóstico (28/04/2026):
  Índice:   <article class="node--type-content-incibe-avisos node--view-mode-teaser">
              enlaces a advisories: /incibe-cert/alerta-temprana/avisos/<slug>
              enlaces a tags:       /incibe-cert/tags/<tag>  ← se extraen como tags
  Advisory: <article class="node--view-mode-full">
              <div class="node__content container">  ← cuerpo
              <h1> sin clase                         ← título
              texto: "Fecha de publicación  DD/MM/YYYY"
              texto: "Recursos Afectados\n<productos>"
"""

import re
import requests
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import unquote
from bs4 import BeautifulSoup

from .base_source import BaseSource, SourcePage


DEFAULT_MAX_ITEMS = 10
BASE_DOMAIN       = "https://www.incibe.es"
ADVISORY_PREFIX   = "/incibe-cert/alerta-temprana/avisos/"
TAG_PREFIX        = "/incibe-cert/tags/"

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

RE_DATE     = re.compile(r'Fecha de publicaci[oó]n\s+(\d{2})/(\d{2})/(\d{4})')
RE_CVSS_VAL = re.compile(r'CVSS\s+v[\d.]+:\s*([\d.]+)')


class INCIBESource(BaseSource):

    def __init__(self, config: dict):
        super().__init__(config)
        self.max_items = config.get("max_items", DEFAULT_MAX_ITEMS)
        self.timeout   = config.get("timeout", 15)

    # ------------------------------------------------------------------
    # 1. Obtener URLs de advisories individuales desde el índice
    # ------------------------------------------------------------------

    def fetch_urls(self) -> list[str]:
        try:
            resp = requests.get(self.base_url, headers=HEADERS, timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as e:
            print(f"[INCIBE] Error al descargar índice: {e}")
            return []

        return self._extract_advisory_links(resp.text)

    def _extract_advisory_links(self, html: str) -> list[str]:
        soup = BeautifulSoup(html, "html.parser")
        seen, urls = set(), []

        for article in soup.find_all("article", class_="node--type-content-incibe-avisos"):
            for a in article.find_all("a", href=True):
                href = a["href"]
                # solo enlaces a advisories individuales, no a tags ni al índice
                if (href.startswith(ADVISORY_PREFIX)
                        and href != ADVISORY_PREFIX.rstrip("/")
                        and href not in seen):
                    seen.add(href)
                    urls.append(BASE_DOMAIN + href)

            if len(urls) >= self.max_items:
                break

        return urls

    # ------------------------------------------------------------------
    # 2. Parsear un advisory individual
    # ------------------------------------------------------------------

    def parse_page(self, url: str, html: str) -> Optional[SourcePage]:
        soup = BeautifulSoup(html, "html.parser")

        # Contenedor principal — <article class="node--view-mode-full">
        article = soup.find("article", class_="node--view-mode-full")
        if not article:
            return None

        title = self._extract_title(article)
        if not title:
            return None

        body_div   = article.find("div", class_="node__content")
        full_text  = body_div.get_text(separator="\n", strip=True) if body_div else \
                     article.get_text(separator="\n", strip=True)

        # Tags de INCIBE extraídos del índice no están aquí; los recogemos
        # de los enlaces internos del advisory si existen
        page_tags  = self._extract_tags(article)
        # Combinar con los tags del config sin duplicar
        all_tags   = list(dict.fromkeys(self.tags + page_tags))

        return SourcePage(
            url               = url,
            source_name       = self.source_name,
            title             = title,
            clean_text        = full_text,
            published_at      = self._extract_date(full_text),
            affected_products = self._extract_products(full_text),
            tlp               = self.tlp,
            tags              = all_tags,
        )

    # ------------------------------------------------------------------
    # Métodos de extracción individuales
    # ------------------------------------------------------------------

    def _extract_title(self, article) -> str:
        h1 = article.find("h1")
        return h1.get_text(strip=True) if h1 else ""

    def _extract_date(self, text: str) -> Optional[str]:
        """
        Busca "Fecha de publicación  DD/MM/YYYY" en el texto plano del advisory.
        """
        m = RE_DATE.search(text)
        if m:
            day, month, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
            try:
                dt = datetime(year, month, day, tzinfo=timezone.utc)
                return dt.isoformat()
            except ValueError:
                pass
        return None

    def _extract_products(self, text: str) -> list[str]:
        """
        En INCIBE el bloque de productos afectados tiene esta forma:
            Recursos Afectados
            Producto A versión X.
            Producto B versión Y.
        Extrae las líneas entre "Recursos Afectados" y el siguiente bloque.
        """
        products = []
        lines    = text.split("\n")

        in_section = False
        # Marcadores que indican fin de la sección de productos
        end_markers = {"descripción", "descripcion", "solución", "solucion",
                       "referencias", "identificador", "importancia"}

        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            if re.search(r'recursos\s+afectados', line_stripped, re.IGNORECASE):
                in_section = True
                continue

            if in_section:
                if line_stripped.lower() in end_markers:
                    break
                # Líneas cortas y con contenido — productos reales
                if 2 < len(line_stripped) < 200:
                    products.append(line_stripped)

        return products

    def _extract_tags(self, article) -> list[str]:
        """
        INCIBE incluye sus propios tags como enlaces /incibe-cert/tags/<tag>.
        Los recogemos y los añadimos como tags del CTIRecord.
        """
        tags = []
        for a in article.find_all("a", href=True):
            href = a["href"]
            if href.startswith(TAG_PREFIX):
                tag = unquote(href[len(TAG_PREFIX):]).lower().replace("-", "_")
                if tag and tag not in tags:
                    tags.append(tag)
        return tags
