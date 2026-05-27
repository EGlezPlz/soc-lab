"""
CyberScraper — BaseSource
Contrato que todo adaptador de fuente debe implementar.
Un adaptador sabe tres cosas: cómo descargar, cómo extraer texto limpio,
y cómo obtener metadatos (título, fecha, productos afectados).
El IOCExtractor no sabe nada de fuentes — recibe texto limpio y punto.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
import hashlib


@dataclass
class SourcePage:
    """
    Resultado que devuelve un adaptador tras procesar una URL.
    Es lo que recibe el IOCExtractor como entrada.
    """
    url:               str
    source_name:       str
    title:             str
    clean_text:        str           # texto plano sin HTML, listo para extraer IOCs
    published_at:      Optional[str] # ISO8601 o None si no se encontró
    affected_products: list[str]
    tlp:               str
    tags:              list[str]

    @property
    def content_hash(self) -> str:
        """Hash del texto limpio — usado por DedupStore para no reprocesar."""
        return hashlib.sha256(self.clean_text.encode()).hexdigest()


class BaseSource(ABC):
    """
    Clase base para todos los adaptadores de fuente.

    Subclasificar e implementar:
        fetch_urls()  → lista de URLs a procesar
        parse_page()  → convierte HTML crudo en SourcePage

    El FetchEngine llama a fetch_urls() para saber qué descargar,
    descarga el HTML, y llama a parse_page() con el resultado.
    """

    def __init__(self, config: dict):
        self.source_name = config.get("name", "Unknown")
        self.base_url    = config.get("url", "")
        self.tlp         = config.get("tlp", "WHITE")
        self.tags        = config.get("tags", [])

    @abstractmethod
    def fetch_urls(self) -> list[str]:
        """
        Devuelve la lista de URLs concretas a descargar.
        Para un índice de advisories: parsea el índice y extrae los enlaces.
        Para una URL única: devuelve [self.base_url].
        """
        ...

    @abstractmethod
    def parse_page(self, url: str, html: str) -> Optional[SourcePage]:
        """
        Recibe el HTML crudo de una URL y devuelve un SourcePage.
        Devuelve None si la página no tiene contenido útil.
        """
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.source_name!r}>"
