"""
soc_coverage/connectors/wazuh.py
Conector para Wazuh — comprueba si existe cobertura para un CVE.

Dos estrategias de búsqueda, usadas en orden:
  1. API REST de Wazuh (:55000) — busca en las reglas cargadas en memoria
  2. Ficheros XML de reglas — búsqueda directa en disco como fallback

La API es más precisa (busca en reglas activas); los ficheros XML
son más completos (incluyen reglas desactivadas o personalizadas).
"""

import re
import requests
import urllib3
from pathlib import Path
from typing import Optional

from ..models import ToolCoverage

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Campos de una regla Wazuh donde puede aparecer un CVE
# El CVE puede estar en la descripción, en grupos o en el campo cve
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


class WazuhConnector:
    """
    Comprueba cobertura de CVEs contra Wazuh.

    Configuración mínima en config:
        wazuh_url:      "https://localhost:55000"
        wazuh_user:     "wazuh-wui"
        wazuh_password: "tu_password"
        wazuh_rules_dir: "/var/ossec/ruleset/rules"  # opcional, para fallback XML
    """

    def __init__(self, config: dict):
        self.base_url   = config.get("wazuh_url", "https://localhost:55000")
        self.user       = config.get("wazuh_user", "wazuh-wui")
        self.password   = config.get("wazuh_password", "")
        self.rules_dir  = Path(config.get("wazuh_rules_dir", "/var/ossec/ruleset/rules"))
        self.timeout    = config.get("timeout", 10)
        self._token:    Optional[str] = None

    # ------------------------------------------------------------------
    # Método principal
    # ------------------------------------------------------------------

    def verificar(self, cve_id: str) -> ToolCoverage:
        """
        Comprueba si Wazuh tiene alguna regla que cubra este CVE.
        Devuelve un ToolCoverage con el resultado.
        """
        # Intentar primero con la API
        cobertura = self._buscar_via_api(cve_id)
        if cobertura is not None:
            return cobertura

        # Fallback: buscar en ficheros XML
        print(f"  [Wazuh] API no disponible — buscando en ficheros XML")
        return self._buscar_en_xml(cve_id)

    # ------------------------------------------------------------------
    # Estrategia 1: API REST
    # ------------------------------------------------------------------

    def _buscar_via_api(self, cve_id: str) -> Optional[ToolCoverage]:
        """
        Usa la API REST de Wazuh para buscar reglas que mencionen el CVE.
        Devuelve None si la API no está disponible.
        """
        token = self._obtener_token()
        if not token:
            return None

        try:
            # Buscar en el campo description de las reglas
            resp = requests.get(
                f"{self.base_url}/rules",
                headers={"Authorization": f"Bearer {token}"},
                params={
                    "search": cve_id,
                    "limit": 50,
                    "offset": 0,
                },
                verify=False,
                timeout=self.timeout,
            )

            if resp.status_code != 200:
                return None

            data  = resp.json()
            items = data.get("data", {}).get("affected_items", [])

            reglas_encontradas = [
                str(item.get("id", "")) for item in items
                if self._regla_menciona_cve(item, cve_id)
            ]

            return ToolCoverage(
                herramienta  = "wazuh",
                cubre        = len(reglas_encontradas) > 0,
                referencias  = reglas_encontradas,
                notas        = f"Búsqueda via API REST" if reglas_encontradas
                               else f"Sin reglas para {cve_id} en API",
            )

        except requests.RequestException as e:
            print(f"  [Wazuh] Error en API: {e}")
            return None

    def _obtener_token(self) -> Optional[str]:
        """Obtiene o reutiliza el JWT de la API de Wazuh."""
        if self._token:
            return self._token
        try:
            resp = requests.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.user, self.password),
                verify=False,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                self._token = resp.json()["data"]["token"]
                return self._token
        except requests.RequestException:
            pass
        return None

    def _regla_menciona_cve(self, regla: dict, cve_id: str) -> bool:
        """Comprueba si una regla de la API menciona el CVE buscado."""
        cve_upper = cve_id.upper()
        campos = [
            str(regla.get("description", "")),
            str(regla.get("groups", [])),
            # Algunas reglas tienen campo cve explícito
            str(regla.get("cve", "")),
        ]
        return any(cve_upper in campo.upper() for campo in campos)

    # ------------------------------------------------------------------
    # Estrategia 2: Ficheros XML
    # ------------------------------------------------------------------

    def _buscar_en_xml(self, cve_id: str) -> ToolCoverage:
        """
        Busca el CVE directamente en los ficheros XML de reglas de Wazuh.
        Útil cuando la API no está disponible o para reglas personalizadas.
        """
        if not self.rules_dir.exists():
            return ToolCoverage(
                herramienta = "wazuh",
                cubre       = False,
                notas       = f"Directorio de reglas no encontrado: {self.rules_dir}",
            )

        ficheros_xml = list(self.rules_dir.glob("*.xml"))
        if not ficheros_xml:
            return ToolCoverage(
                herramienta = "wazuh",
                cubre       = False,
                notas       = "No se encontraron ficheros XML de reglas",
            )

        cve_upper      = cve_id.upper()
        reglas_ids     = []
        RE_RULE_ID     = re.compile(r'<rule\s+id="(\d+)"', re.IGNORECASE)

        for xml_path in ficheros_xml:
            try:
                contenido = xml_path.read_text(encoding="utf-8", errors="ignore")
                if cve_upper not in contenido.upper():
                    continue

                # Extraer IDs de reglas que contienen el CVE
                # Dividimos por bloques <rule ...> para asociar ID con contenido
                bloques = re.split(r'(?=<rule\s)', contenido, flags=re.IGNORECASE)
                for bloque in bloques:
                    if cve_upper in bloque.upper():
                        m = RE_RULE_ID.search(bloque)
                        if m:
                            reglas_ids.append(f"{xml_path.name}:{m.group(1)}")

            except IOError:
                continue

        return ToolCoverage(
            herramienta = "wazuh",
            cubre       = len(reglas_ids) > 0,
            referencias = reglas_ids,
            notas       = f"Búsqueda en {len(ficheros_xml)} ficheros XML",
        )

    # ------------------------------------------------------------------
    # Utilidad: listar todos los CVEs que Wazuh ya cubre
    # ------------------------------------------------------------------

    def cves_cubiertos(self) -> set[str]:
        """
        Extrae todos los CVEs mencionados en las reglas XML.
        Útil para hacer la búsqueda inversa: en lugar de preguntar
        por CVE concretos, saber de antemano qué cubre Wazuh.
        """
        if not self.rules_dir.exists():
            return set()

        cves = set()
        for xml_path in self.rules_dir.glob("*.xml"):
            try:
                contenido = xml_path.read_text(encoding="utf-8", errors="ignore")
                cves.update(CVE_PATTERN.findall(contenido))
            except IOError:
                continue
        return {c.upper() for c in cves}
