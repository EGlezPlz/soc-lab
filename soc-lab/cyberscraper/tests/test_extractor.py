"""
Test del IOCExtractor contra un advisory sintético tipo INCIBE/CISA.
Cubre los casos más frecuentes en advisories reales.
"""
import json
import sys
sys.path.insert(0, '/home/claude/cyberscraper')
from ioc_extractor import IOCExtractor

ADVISORY_TEXT = """
Múltiples vulnerabilidades críticas en Cisco ASA y Firepower Threat Defense (FTD)

Publicado: 2024-03-15 | Fuente: INCIBE-CERT | Criticidad: Critical
CVSS v3.1: 9.8

Se han identificado dos vulnerabilidades de severidad crítica (CVE-2024-20353 y
CVE-2024-20359) que afectan a Cisco Adaptive Security Appliance (ASA) y
Cisco Firepower Threat Defense (FTD). Adicionalmente, se reporta una vulnerabilidad
de impacto alto: CVE-2024-20358.

Un atacante no autenticado podría explotar estas vulnerabilidades para ejecutar
código remoto o provocar una denegación de servicio (DoS).

Indicadores de compromiso observados en campañas activas:

IPs de C2 confirmadas:
  - 198.51.100.42
  - 203.0.113.17
  - 192.0.2.88

IPs privadas (deben ignorarse en extracción):
  - 192.168.1.1
  - 10.0.0.5
  - 127.0.0.1

Dominios maliciosos:
  - malicious-c2.example.com
  - payload-drop.xyz
  - update-cisco.net

URL de descarga del payload:
  https://malicious-c2.example.com/stage2/loader.bin
  http://payload-drop.xyz/cisco_update.exe

Hashes de los artefactos observados:
  MD5:    d41d8cd98f00b204e9800998ecf8427e
  SHA-1:  da39a3ee5e6b4b0d3255bfef95601890afd80709
  SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Contacto del equipo de análisis: threat-intel@incibe.es

Solución: Aplicar los parches publicados por Cisco. Más información en:
  https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-persist-rce-Ctkqx3U
"""

extractor = IOCExtractor(
    source_url  = "https://www.incibe.es/incibe-cert/avisos/2024/aviso-001",
    source_name = "INCIBE-CERT",
    tlp         = "WHITE",
    tags        = ["rce", "network-device", "cisco"],
)

record = extractor.extract(
    raw_text          = ADVISORY_TEXT,
    title             = "Múltiples vulnerabilidades críticas en Cisco ASA y FTD",
    published_at      = "2024-03-15T10:00:00Z",
    affected_products = ["Cisco ASA", "Cisco Firepower Threat Defense"],
)

result = extractor.to_dict(record)
print(json.dumps(result, indent=2, ensure_ascii=False))
