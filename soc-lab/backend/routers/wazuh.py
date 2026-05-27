import subprocess
import json as _json
import requests
from fastapi import APIRouter, HTTPException
from backend.config import settings

router = APIRouter(prefix="/wazuh", tags=["wazuh"])

requests.packages.urllib3.disable_warnings()


def _get_token() -> str:
    r = requests.get(
        f"{settings.wazuh_url}/security/user/authenticate",
        auth=(settings.wazuh_user, settings.wazuh_password),
        verify=False,
        timeout=10,
    )
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Wazuh auth failed: {r.text[:200]}")
    return r.json()["data"]["token"]


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {_get_token()}",
        "Content-Type":  "application/json",
    })
    s.verify = False
    return s


def _url(path: str) -> str:
    return f"{settings.wazuh_url}{path}"


def _serialize_agent(agent: dict) -> dict:
    return {
        "id":             agent.get("id", ""),
        "name":           agent.get("name", ""),
        "ip":             agent.get("ip", "N/A"),
        "status":         agent.get("status", "unknown"),
        "os":             agent.get("os", {}).get("name", "N/A") if agent.get("os") else "N/A",
        "last_keepalive": agent.get("lastKeepAlive", ""),
        "version":        agent.get("version", ""),
        "manager":        agent.get("manager", ""),
    }


@router.get("/status")
def wazuh_status():
    try:
        token = _get_token()
        return {"status": "ok", "url": settings.wazuh_url, "token_ok": bool(token)}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.get("/agents")
def get_agents():
    try:
        r = _session().get(_url("/agents?limit=100&status=active,disconnected"), timeout=10)
        r.raise_for_status()
        data   = r.json()
        agents = [_serialize_agent(a) for a in data["data"]["affected_items"]]
        summary = {
            "total":        data["data"]["total_affected_items"],
            "active":       sum(1 for a in agents if a["status"] == "active"),
            "disconnected": sum(1 for a in agents if a["status"] == "disconnected"),
        }
        return {"agents": agents, "summary": summary}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error consultando Wazuh: {e}")


@router.get("/agents/{agent_id}")
def get_agent(agent_id: str):
    try:
        r = _session().get(_url(f"/agents?agents_list={agent_id}"), timeout=10)
        r.raise_for_status()
        items = r.json()["data"]["affected_items"]
        if not items:
            raise HTTPException(status_code=404, detail="Agente no encontrado")
        return _serialize_agent(items[0])
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error consultando Wazuh: {e}")


@router.get("/alerts")
def get_alerts(agent_id: str | None = None, min_level: int = 0, limit: int = 50):
    try:
        result = subprocess.run(
            ["docker", "exec", settings.wazuh_container,
             "tail", "-n", "500", settings.wazuh_alerts_path],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Error leyendo alertas: {result.stderr}")

        alerts = []
        for line in result.stdout.strip().splitlines():
            if not line:
                continue
            try:
                alert = _json.loads(line)
            except _json.JSONDecodeError:
                continue

            rule  = alert.get("rule", {})
            agent = alert.get("agent", {})
            level = rule.get("level", 0)

            if level < min_level:
                continue
            if agent_id and agent.get("id") != agent_id:
                continue

            alerts.append({
                "id":               alert.get("id", ""),
                "agent_id":         agent.get("id", ""),
                "agent_name":       agent.get("name", ""),
                "rule_id":          rule.get("id", ""),
                "rule_description": rule.get("description", ""),
                "level":            level,
                "timestamp":        alert.get("timestamp", ""),
                "groups":           rule.get("groups", []),
            })

        alerts = list(reversed(alerts))[:limit]
        return {"alerts": alerts, "total": len(alerts)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error consultando alertas: {e}")
