import asyncio
import subprocess
import json as _json
import random
from datetime import datetime
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from backend.config import settings

router = APIRouter(prefix="/suricata", tags=["suricata"])


def _read_eve(lines: int = 1000) -> list[dict]:
    """Lee las últimas N líneas del eve.json via docker exec."""
    result = subprocess.run(
        ["docker", "exec", settings.suricata_container,
         "tail", "-n", str(lines), settings.suricata_eve_path],
        capture_output=True, text=True, timeout=15
    )
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Error leyendo eve.json: {result.stderr}")

    events = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            events.append(_json.loads(line))
        except _json.JSONDecodeError:
            continue
    return events


def _serialize_alert(event: dict) -> dict:
    alert = event.get("alert", {})
    return {
        "id":        event.get("flow_id", ""),
        "timestamp": event.get("timestamp", ""),
        "event_type": event.get("event_type", ""),
        "src_ip":    event.get("src_ip", ""),
        "src_port":  event.get("src_port", 0),
        "dest_ip":   event.get("dest_ip", ""),
        "dest_port": event.get("dest_port", 0),
        "proto":     event.get("proto", ""),
        "severity":  alert.get("severity", 3),
        "signature": alert.get("signature", ""),
        "category":  alert.get("category", ""),
    }


@router.get("/status")
def suricata_status():
    try:
        result = subprocess.run(
            ["docker", "exec", settings.suricata_container,
             "wc", "-l", settings.suricata_eve_path],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split()[0] if result.returncode == 0 else "?"
        return {"status": "ok", "container": settings.suricata_container, "eve_lines": lines}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.get("/alerts")
def get_alerts(severity: int | None = None, limit: int = 50):
    try:
        events = _read_eve(2000)
        alerts = [_serialize_alert(e) for e in events if e.get("event_type") == "alert"]
        if severity is not None:
            alerts = [a for a in alerts if a["severity"] == severity]
        alerts = list(reversed(alerts))[:limit]
        return {"alerts": alerts, "total": len(alerts)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error consultando Suricata: {e}")


@router.get("/stats")
def get_stats():
    try:
        events = _read_eve(2000)
        alerts = [e for e in events if e.get("event_type") == "alert"]
        by_severity = {
            "high":   sum(1 for a in alerts if a.get("alert", {}).get("severity") == 1),
            "medium": sum(1 for a in alerts if a.get("alert", {}).get("severity") == 2),
            "low":    sum(1 for a in alerts if a.get("alert", {}).get("severity") == 3),
        }
        src_ips = {}
        for a in alerts:
            ip = a.get("src_ip", "")
            src_ips[ip] = src_ips.get(ip, 0) + 1
        top_src = sorted(src_ips, key=src_ips.get, reverse=True)[:5]

        return {
            "total_alerts": len(alerts),
            "by_severity":  by_severity,
            "top_src_ips":  top_src,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error consultando stats: {e}")


@router.websocket("/ws/live")
async def suricata_live(websocket: WebSocket):
    """
    WebSocket que emite alertas de Suricata en tiempo real.
    Lee el eve.json cada 5 segundos y emite las nuevas líneas.
    """
    await websocket.accept()
    last_count = 0

    try:
        # Inicializa el contador con las líneas actuales
        result = subprocess.run(
            ["docker", "exec", settings.suricata_container,
             "wc", "-l", settings.suricata_eve_path],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            last_count = int(result.stdout.strip().split()[0])

        while True:
            await asyncio.sleep(5)

            result = subprocess.run(
                ["docker", "exec", settings.suricata_container,
                 "wc", "-l", settings.suricata_eve_path],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                continue

            current_count = int(result.stdout.strip().split()[0])
            if current_count <= last_count:
                continue

            new_lines = current_count - last_count
            result = subprocess.run(
                ["docker", "exec", settings.suricata_container,
                 "tail", "-n", str(new_lines), settings.suricata_eve_path],
                capture_output=True, text=True, timeout=5
            )
            last_count = current_count

            for line in result.stdout.strip().splitlines():
                try:
                    event = _json.loads(line)
                    if event.get("event_type") == "alert":
                        await websocket.send_json(_serialize_alert(event))
                except (_json.JSONDecodeError, Exception):
                    continue

    except WebSocketDisconnect:
        pass
