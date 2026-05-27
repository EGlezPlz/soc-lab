import subprocess
import json as _json
import requests
from fastapi import APIRouter, HTTPException
from backend.config import settings

router = APIRouter(prefix="/correlation", tags=["correlation"])

requests.packages.urllib3.disable_warnings()


# ── Helpers reutilizados de otros routers ────────────────────────────────────

def _misp_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": settings.misp_key,
        "Accept":        "application/json",
        "Content-Type":  "application/json",
    })
    s.verify = settings.misp_verifycert
    return s


def _misp_url(path: str) -> str:
    return f"{settings.misp_url}{path}"


def _read_wazuh_alerts(limit: int = 200) -> list[dict]:
    """Lee las últimas N alertas del alerts.json de Wazuh via docker exec."""
    result = subprocess.run(
        ["docker", "exec", settings.wazuh_container,
         "tail", "-n", str(limit), settings.wazuh_alerts_path],
        capture_output=True, text=True, timeout=15
    )
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Error leyendo Wazuh: {result.stderr}")

    alerts = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            alerts.append(_json.loads(line))
        except _json.JSONDecodeError:
            continue
    return alerts


def _extract_ips(alert: dict) -> list[str]:
    """Extrae todas las IPs relevantes de una alerta de Wazuh."""
    ips = set()
    data = alert.get("data", {})

    # IPs directas en campos conocidos
    for field in ["srcip", "src_ip", "dstip", "dest_ip", "win.eventdata.ipAddress"]:
        val = data.get(field, "")
        if val and _is_public_ip(val):
            ips.add(val)

    # IPs en el full_log (búsqueda simple)
    full_log = alert.get("full_log", "")
    for token in full_log.split():
        token = token.strip(".,;:()[]\"'")
        if _is_public_ip(token):
            ips.add(token)

    return list(ips)


def _is_public_ip(ip: str) -> bool:
    """Filtra IPs privadas y locales — solo nos interesan las públicas para correlación."""
    if not ip or len(ip) > 15:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        p = [int(x) for x in parts]
    except ValueError:
        return False
    # Filtrar rangos privados / loopback / link-local
    if p[0] == 10: return False
    if p[0] == 127: return False
    if p[0] == 172 and 16 <= p[1] <= 31: return False
    if p[0] == 192 and p[1] == 168: return False
    if p[0] == 169 and p[1] == 254: return False
    if p[0] == 0: return False
    return True


def _lookup_ip_in_misp(ip: str) -> list[dict]:
    """Busca una IP en MISP y devuelve los eventos donde aparece."""
    try:
        r = _misp_session().post(
            _misp_url("/attributes/restSearch"),
            json={
                "value": ip,
                "type": ["ip-dst", "ip-src", "ip-dst|port", "ip-src|port"],
                "returnFormat": "json",
                "limit": 10,
                "includeEventTags": True,
            },
            timeout=10,
        )
        if r.status_code != 200:
            return []

        attrs = r.json().get("response", {}).get("Attribute", [])
        matches = []
        seen_events = set()

        for attr in attrs:
            event_id = str(attr.get("event_id", ""))
            if event_id in seen_events:
                continue
            seen_events.add(event_id)

            # Extraer TLP de los tags del atributo o del evento
            tags = attr.get("Tag", []) + attr.get("Event", {}).get("Tag", [])
            tlp = "clear"
            for tag in tags:
                name = tag.get("name", "").lower()
                if "tlp:red" in name:   tlp = "red";   break
                if "tlp:amber" in name: tlp = "amber";  break
                if "tlp:green" in name: tlp = "green";  break

            matches.append({
                "event_id":   event_id,
                "event_info": attr.get("Event", {}).get("info", "Sin descripción"),
                "ioc_type":   attr.get("type", ""),
                "ioc_value":  attr.get("value", ""),
                "tlp":        tlp,
                "tags":       [t.get("name", "") for t in tags if "tlp:" not in t.get("name", "").lower()],
                "misp_url":   f"{settings.misp_url}/events/view/{event_id}",
            })

        return matches

    except Exception:
        return []


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/lookup/{ip}")
def lookup_ip(ip: str):
    """
    Busca una IP concreta en MISP.
    Útil para investigar manualmente una IP sospechosa.
    """
    matches = _lookup_ip_in_misp(ip)
    return {
        "ip":      ip,
        "found":   len(matches) > 0,
        "matches": matches,
    }


@router.get("/alerts")
def correlated_alerts(min_level: int = 0, limit: int = 100):
    """
    Devuelve las alertas de Wazuh enriquecidas con información de MISP.
    Las alertas se clasifican en: correlacionadas (IP en MISP) y limpias.
    """
    raw_alerts = _read_wazuh_alerts(limit=limit * 2)

    results = []
    for raw in raw_alerts:
        rule  = raw.get("rule", {})
        agent = raw.get("agent", {})
        level = rule.get("level", 0)

        if level < min_level:
            continue

        ips = _extract_ips(raw)
        misp_matches = []

        for ip in ips:
            matches = _lookup_ip_in_misp(ip)
            for m in matches:
                misp_matches.append({"ip": ip, **m})

        results.append({
            "id":               raw.get("id", ""),
            "timestamp":        raw.get("timestamp", ""),
            "agent_id":         agent.get("id", ""),
            "agent_name":       agent.get("name", ""),
            "rule_id":          rule.get("id", ""),
            "rule_description": rule.get("description", ""),
            "level":            level,
            "groups":           rule.get("groups", []),
            "ips_found":        ips,
            "correlated":       len(misp_matches) > 0,
            "misp_matches":     misp_matches,
        })

        if len(results) >= limit:
            break

    correlated = [r for r in results if r["correlated"]]
    clean      = [r for r in results if not r["correlated"]]

    return {
        "total":           len(results),
        "correlated_count": len(correlated),
        "clean_count":      len(clean),
        "alerts":           results,
    }


@router.get("/summary")
def correlation_summary():
    """
    Resumen rápido para el dashboard:
    cuántas alertas de Wazuh tienen match en MISP.
    """
    try:
        raw_alerts = _read_wazuh_alerts(limit=500)
        total = len(raw_alerts)
        correlated = 0
        high_risk  = []

        for raw in raw_alerts:
            ips = _extract_ips(raw)
            for ip in ips:
                matches = _lookup_ip_in_misp(ip)
                if matches:
                    correlated += 1
                    level = raw.get("rule", {}).get("level", 0)
                    if level >= 8:
                        high_risk.append({
                            "ip":          ip,
                            "alert":       raw.get("rule", {}).get("description", ""),
                            "level":       level,
                            "misp_event":  matches[0].get("event_info", ""),
                            "tlp":         matches[0].get("tlp", "clear"),
                        })
                    break

        return {
            "total_alerts":      total,
            "correlated":        correlated,
            "clean":             total - correlated,
            "high_risk_matches": high_risk[:10],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _read_suricata_alerts(lines: int = 1000) -> list[dict]:
    """Lee las últimas N líneas del eve.json y filtra solo alertas."""
    result = subprocess.run(
        ["docker", "exec", settings.suricata_container,
         "tail", "-n", str(lines), settings.suricata_eve_path],
        capture_output=True, text=True, timeout=15
    )
    if result.returncode != 0:
        return []
    events = []
    for line in result.stdout.strip().splitlines():
        try:
            e = _json.loads(line)
            if e.get("event_type") == "alert":
                events.append(e)
        except _json.JSONDecodeError:
            continue
    return events


@router.get("/suricata")
def correlated_suricata(limit: int = 100):
    """
    Alertas de Suricata enriquecidas con información de MISP.
    Busca src_ip y dest_ip de cada alerta en los IOCs de MISP.
    """
    raw_alerts = _read_suricata_alerts(lines=limit * 2)
    results = []

    for raw in raw_alerts:
        alert_data = raw.get("alert", {})
        src_ip = raw.get("src_ip", "")
        dest_ip = raw.get("dest_ip", "")

        misp_matches = []
        for ip in [src_ip, dest_ip]:
            if _is_public_ip(ip):
                matches = _lookup_ip_in_misp(ip)
                for m in matches:
                    misp_matches.append({"ip": ip, "direction": "src" if ip == src_ip else "dst", **m})

        results.append({
            "flow_id":   raw.get("flow_id", ""),
            "timestamp": raw.get("timestamp", ""),
            "src_ip":    src_ip,
            "src_port":  raw.get("src_port", 0),
            "dest_ip":   dest_ip,
            "dest_port": raw.get("dest_port", 0),
            "proto":     raw.get("proto", ""),
            "severity":  alert_data.get("severity", 3),
            "signature": alert_data.get("signature", ""),
            "category":  alert_data.get("category", ""),
            "correlated":    len(misp_matches) > 0,
            "misp_matches":  misp_matches,
        })

        if len(results) >= limit:
            break

    correlated = [r for r in results if r["correlated"]]
    return {
        "total":            len(results),
        "correlated_count": len(correlated),
        "clean_count":      len(results) - len(correlated),
        "alerts":           results,
    }
