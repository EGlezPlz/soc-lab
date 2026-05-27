# SOC Lab

Plataforma personal de integración y aprendizaje de herramientas de ciberseguridad. Integra MISP, Wazuh y Suricata en una interfaz web unificada con motor de correlación de amenazas.

Construida como "proto-Guardian" — un entorno de laboratorio funcional para practicar con herramientas SOC reales.

---

## Arquitectura

```
soc-lab/
├── backend/              Python + FastAPI (puerto 8000)
│   ├── main.py           Aplicación principal + CORS + health con caché
│   ├── config.py         Configuración via pydantic-settings
│   ├── routers/
│   │   ├── misp.py       Integración MISP via API REST
│   │   ├── wazuh.py      Integración Wazuh via JWT + docker exec
│   │   ├── suricata.py   Integración Suricata via docker exec + WebSocket
│   │   └── correlation.py Motor de correlación MISP ↔ Wazuh/Suricata
│   └── requirements.txt
├── frontend/             Vue 3 + Vite + Pinia (puerto 5173 dev / 8080 prod)
│   └── src/
│       ├── views/        Dashboard, MISP, Wazuh, Suricata, Correlación
│       ├── stores/       misp.js, wazuh.js, suricata.js, correlation.js
│       ├── components/   TlpBadge, SeverityBadge, ThreatBadge, MispMatchCard
│       └── composables/  usePagination.js
├── cyberscraper/         Scraper modular de threat intelligence (INCIBE-CERT, CISA KEV)
├── soc_coverage/         Análisis de cobertura de detección (Wazuh + Suricata vs MISP IOCs)
├── docker-compose.yml    Stack completo en Docker
├── start.sh              Arranque ordenado de todo el stack
└── stop.sh               Parada ordenada de todo el stack
```

---

## Requisitos previos

El lab depende de tres stacks externos que deben estar levantados antes de arrancar SOC Lab. Cada uno tiene su propio `docker-compose.yml` en su directorio:

| Servicio | Directorio | Puerto |
|----------|-----------|--------|
| MISP | `~/misp-lab/misp-docker/` | 443 (HTTPS) |
| Wazuh | `~/wazuh-lab/` | 55000 (API), 8443 (dashboard) |
| Suricata | `~/suricata-lab/` | — (modo mirror, sin puerto expuesto) |

### Requisitos de sistema

- Docker + Docker Compose
- Python 3.12+
- Node.js 18+
- RAM mínima recomendada: **8 GB** (MISP es el más exigente, necesita ~3-4 GB)
- El contenedor de Suricata debe tener acceso a la interfaz de red del host (modo mirror o TAP)

---

## Instalación desde cero

### 1. Clonar el repositorio

```bash
git clone https://github.com/tu-usuario/soc-lab.git
cd soc-lab
```

### 2. Configurar variables de entorno

```bash
cp backend/.env.example backend/.env
```

Edita `backend/.env` con tus credenciales reales:

```env
MISP_URL=https://localhost
MISP_KEY=<tu-api-key-de-40-chars>
MISP_VERIFYCERT=false

WAZUH_URL=https://localhost:55000
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=<password-del-docker-compose-de-wazuh>

SURICATA_CONTAINER=suricata-mirror
SURICATA_EVE_PATH=/var/log/suricata/eve.json
```

> La API key de MISP se obtiene en `https://localhost/auth_keys` tras el primer login.
> Las credenciales de Wazuh están en `~/wazuh-lab/docker-compose.yml`.

### 3. Levantar los stacks externos

```bash
# MISP (tarda 2-3 minutos en estar healthy)
cd ~/misp-lab/misp-docker && docker compose up -d

# Wazuh
cd ~/wazuh-lab && docker compose up -d

# Suricata
cd ~/suricata-lab && docker compose up -d
```

### 4. Levantar SOC Lab

```bash
cd ~/soc-lab
./start.sh --build   # primera vez (construye imágenes)
./start.sh           # siguientes veces
```

SOC Lab queda disponible en **http://localhost:8080**

---

## Uso diario

```bash
# Arrancar todo
./start.sh

# Parar todo
./stop.sh

# Ver logs del backend
docker logs soc-lab-backend -f

# Ver logs del frontend
docker logs soc-lab-frontend -f
```

Para desarrollo con hot-reload:

```bash
# Backend
cd backend && uvicorn backend.main:app --reload --port 8000

# Frontend
cd frontend && npm run dev
```

---

## Módulos

### SOC Lab (principal)

Interfaz web unificada con cinco vistas:

- **Dashboard** — Estado de todos los servicios en tiempo real
- **MISP** — Eventos e IOCs con badges TLP y paginación
- **Wazuh** — Agentes activos y alertas del HIDS
- **Suricata** — Alertas de red con feed en vivo via WebSocket
- **Correlación** — Motor que cruza IPs de Wazuh/Suricata contra IOCs de MISP

### CyberScraper

Scraper modular de threat intelligence con adaptadores para INCIBE-CERT y CISA KEV. Extrae IOCs via regex y los exporta a MISP via PyMISP.

```bash
cd cyberscraper
python main.py
```

### SOC Coverage

Análisis de cobertura de detección: cruza los IOCs activos en MISP contra las reglas cargadas en Wazuh y Suricata para identificar gaps de cobertura.

```bash
cd soc_coverage
python main.py
```

---

## API endpoints

```
GET  /api/health                  Estado de todos los servicios
GET  /api/misp/events             Listado de eventos MISP
GET  /api/misp/events/{id}        Detalle de evento
GET  /api/misp/iocs               IOCs activos
GET  /api/wazuh/agents            Agentes Wazuh registrados
GET  /api/wazuh/alerts            Alertas recientes
GET  /api/suricata/alerts         Alertas históricas de eve.json
GET  /api/suricata/stats          Estadísticas (total, severidad)
WS   /api/suricata/ws/live        Feed en vivo de alertas
GET  /api/correlation/run         Ejecutar correlación MISP ↔ alertas
```

Documentación Swagger completa en **http://localhost:8000/docs**

---

## Decisiones de arquitectura

| Decisión | Motivo |
|----------|--------|
| requests en lugar de PyMISP | Incompatibilidad de versiones con MISP 2.5 |
| docker exec para logs de Wazuh/Suricata | Evita problemas de permisos con bind mounts |
| pinia-plugin-persistedstate con TTL | Caché de datos entre navegaciones sin peticiones redundantes |
| WebSocket solo en vista Suricata | El feed en vivo no persiste entre navegaciones — es correcto |
| usePagination como composable | Lógica sin template reutilizable en 4 vistas |

---

## Backlog

- [ ] CORTEX — enriquecimiento automático de IOCs (requiere ~4 GB RAM adicionales)
- [ ] OpenVAS — escaneo de vulnerabilidades
- [ ] Kibana embebido — visualización de logs
- [ ] JWT token refresh + persistencia en base de datos
- [ ] Rotación de eve.json para entornos de producción
- [ ] Dockerfile para instalación persistente del agente Wazuh

---

## Notas para producción

- **eve.json** crece sin límite — configurar `logrotate` o rotación nativa de Suricata antes de desplegar en producción
- **Suricata memcap** — ajustar en `suricata.yaml` si el tráfico es intenso
- **MISP_VERIFYCERT** — cambiar a `true` en producción con certificado válido
- **Credenciales** — cambiar todas las contraseñas por defecto antes de exponer a red

---

## Stack técnico

| Capa | Tecnología |
|------|-----------|
| Backend | Python 3.12 + FastAPI + pydantic-settings |
| Frontend | Vue 3 + Vite + Pinia + pinia-plugin-persistedstate |
| Threat Intel | MISP 2.5 (Docker) |
| HIDS | Wazuh 4.x (Docker) |
| NIDS | Suricata + ET rules (65.914 reglas) |
| Contenedores | Docker + Docker Compose |

---

## Patrón arquitectónico

SOC Lab usa una **arquitectura en capas** clásica, apropiada para un proyecto de lab personal:

```
Frontend (Vue 3)
      ↓
Backend (FastAPI) — routers por herramienta
      ↓
Herramientas externas (MISP, Wazuh, Suricata)
```

Cada router accede directamente a su herramienta correspondiente via API REST o `docker exec`. No hay separación entre dominio y adaptadores — a diferencia de una arquitectura hexagonal, el backend no define puertos abstractos ni interfaces intercambiables.

Esta decisión es intencionada: para un lab de aprendizaje, la simplicidad de capas directas es más didáctica y más rápida de construir que una arquitectura hexagonal completa.
