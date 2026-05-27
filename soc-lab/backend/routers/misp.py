import requests
from fastapi import APIRouter, HTTPException
from backend.config import settings

router = APIRouter(prefix="/misp", tags=["misp"])

requests.packages.urllib3.disable_warnings()


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": settings.misp_key,
        "Accept":        "application/json",
        "Content-Type":  "application/json",
    })
    s.verify = settings.misp_verifycert
    return s


def _url(path: str) -> str:
    return f"{settings.misp_url}{path}"


def _tlp_from_tags(tags: list) -> str:
    for tag in tags:
        name = tag.get("name", "").lower() if isinstance(tag, dict) else str(tag).lower()
        if "tlp:red"   in name: return "red"
        if "tlp:amber" in name: return "amber"
        if "tlp:green" in name: return "green"
        if "tlp:clear" in name or "tlp:white" in name: return "clear"
    return "clear"


def _serialize_event(event: dict) -> dict:
    tags = event.get("Tag", [])
    return {
        "id":              str(event.get("id", "")),
        "info":            event.get("info", "Sin descripción"),
        "date":            event.get("date", ""),
        "threat_level":    str(event.get("threat_level_id", "4")),
        "distribution":    str(event.get("distribution", "0")),
        "tlp":             _tlp_from_tags(tags),
        "org":             event.get("Orgc", {}).get("name", "?"),
        "attribute_count": int(event.get("attribute_count", 0)),
        "tags":            [t["name"] for t in tags if isinstance(t, dict)],
    }


def _serialize_attribute(attr: dict, event_id: str) -> dict:
    tags = attr.get("Tag", [])
    return {
        "id":       str(attr.get("id", "")),
        "event_id": event_id,
        "type":     attr.get("type", ""),
        "value":    attr.get("value", ""),
        "tlp":      _tlp_from_tags(tags),
        "comment":  attr.get("comment", ""),
    }


@router.get("/status")
def misp_status():
    try:
        r = _session().get(_url("/users/view/me.json"), timeout=5)
        if r.status_code == 200:
            data = r.json()
            return {"status": "ok", "url": settings.misp_url, "user": data["User"]["email"]}
        return {"status": "error", "code": r.status_code, "message": r.text[:200]}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.get("/events")
def get_events(limit: int = 50):
    try:
        r = _session().post(
            _url("/events/restSearch"),
            json={"limit": limit, "page": 1, "returnFormat": "json"},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        events = [_serialize_event(e["Event"]) for e in data.get("response", [])]
        return {"events": events, "total": len(events)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error consultando MISP: {e}")


@router.get("/events/{event_id}")
def get_event(event_id: str):
    try:
        r = _session().get(_url(f"/events/view/{event_id}"), timeout=10)
        if r.status_code == 404:
            raise HTTPException(status_code=404, detail="Evento no encontrado")
        r.raise_for_status()
        event = r.json().get("Event", {})
        attrs = event.get("Attribute", [])
        iocs  = [_serialize_attribute(a, event_id) for a in attrs]
        return {**_serialize_event(event), "iocs": iocs}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error consultando MISP: {e}")


@router.get("/iocs")
def get_iocs(event_id: str | None = None, ioc_type: str | None = None, limit: int = 200):
    try:
        body = {"limit": limit, "returnFormat": "json"}
        if event_id:
            body["eventid"] = event_id
        if ioc_type:
            body["type"] = ioc_type
        r = _session().post(_url("/attributes/restSearch"), json=body, timeout=15)
        r.raise_for_status()
        data  = r.json()
        attrs = data.get("response", {}).get("Attribute", [])
        iocs  = [_serialize_attribute(a, str(a.get("event_id", ""))) for a in attrs]
        return {"iocs": iocs, "total": len(iocs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error consultando MISP: {e}")
