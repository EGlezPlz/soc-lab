import subprocess
import requests
import time
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.routers import misp, wazuh, suricata, correlation
from backend.config import settings

app = FastAPI(
    title="SOC Lab API",
    description="Backend de integración para MISP, Wazuh y Suricata",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(misp.router,         prefix="/api")
app.include_router(wazuh.router,        prefix="/api")
app.include_router(suricata.router,     prefix="/api")
app.include_router(correlation.router,  prefix="/api")

requests.packages.urllib3.disable_warnings()

_health_cache = {"data": None, "ts": 0}
_CACHE_TTL = 30


def _check_misp() -> dict:
    try:
        r = requests.get(
            f"{settings.misp_url}/users/view/me.json",
            headers={"Authorization": settings.misp_key, "Accept": "application/json"},
            verify=False, timeout=5,
        )
        if r.status_code == 200:
            return {"status": "ok", "label": "Online"}
        return {"status": "error", "label": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"status": "error", "label": str(e)[:40]}


def _check_wazuh() -> dict:
    try:
        r = requests.get(
            f"{settings.wazuh_url}/security/user/authenticate",
            auth=(settings.wazuh_user, settings.wazuh_password),
            verify=False, timeout=5,
        )
        if r.status_code == 200:
            return {"status": "ok", "label": "Online"}
        return {"status": "error", "label": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"status": "error", "label": str(e)[:40]}


def _check_suricata() -> dict:
    try:
        result = subprocess.run(
            ["docker", "exec", settings.suricata_container,
             "test", "-f", settings.suricata_eve_path],
            capture_output=True, timeout=5,
        )
        if result.returncode == 0:
            return {"status": "ok", "label": "Online"}
        return {"status": "error", "label": "eve.json no encontrado"}
    except Exception as e:
        return {"status": "error", "label": str(e)[:40]}


@app.get("/api/health")
def health():
    global _health_cache
    now = time.time()

    if _health_cache["data"] and now - _health_cache["ts"] < _CACHE_TTL:
        return _health_cache["data"]

    misp_check     = _check_misp()
    wazuh_check    = _check_wazuh()
    suricata_check = _check_suricata()

    all_ok = all(
        s["status"] == "ok"
        for s in [misp_check, wazuh_check, suricata_check]
    )

    result = {
        "status": "ok" if all_ok else "degraded",
        "services": {
            "misp":     misp_check["status"],
            "wazuh":    wazuh_check["status"],
            "suricata": suricata_check["status"],
        },
        "labels": {
            "misp":     misp_check["label"],
            "wazuh":    wazuh_check["label"],
            "suricata": suricata_check["label"],
        }
    }

    _health_cache = {"data": result, "ts": now}
    return result
