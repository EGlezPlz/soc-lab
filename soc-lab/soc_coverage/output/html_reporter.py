"""
soc_coverage/output/html_reporter.py
Genera un informe HTML navegable con los gaps de cobertura.
Se abre directamente en el navegador — sin servidor necesario.
"""

from datetime import datetime, timezone
from pathlib import Path
from ..models import CoverageReport, GapRecord


SEVERIDAD_COLOR = {
    "critical": ("#fee2e2", "#dc2626", "CRÍTICA"),
    "high":     ("#fef3c7", "#d97706", "ALTA"),
    "medium":   ("#e0f2fe", "#0284c7", "MEDIA"),
    "low":      ("#f0fdf4", "#16a34a", "BAJA"),
    None:       ("#f3f4f6", "#6b7280", "—"),
}


def _badge_severidad(sev: str | None) -> str:
    bg, color, label = SEVERIDAD_COLOR.get(sev, SEVERIDAD_COLOR[None])
    return (f'<span style="background:{bg};color:{color};padding:2px 8px;'
            f'border-radius:4px;font-size:11px;font-weight:600">{label}</span>')


def _badge_herramienta(nombre: str, cubre: bool) -> str:
    if cubre:
        return (f'<span style="background:#dcfce7;color:#15803d;padding:2px 8px;'
                f'border-radius:4px;font-size:11px;font-weight:500">✓ {nombre}</span>')
    else:
        return (f'<span style="background:#fee2e2;color:#dc2626;padding:2px 8px;'
                f'border-radius:4px;font-size:11px;font-weight:500">✗ {nombre}</span>')


def _fila_gap(gap: GapRecord, idx: int) -> str:
    bg = "#fef9f9" if gap.gap_critico else "#ffffff"
    badges_cob = " ".join(
        _badge_herramienta(c.herramienta, c.cubre)
        for c in gap.cobertura
    )
    kev = ('<span style="background:#fef3c7;color:#b45309;padding:2px 6px;'
           'border-radius:4px;font-size:10px;font-weight:600">KEV</span>'
           if gap.en_kev else "")
    productos = ", ".join(gap.productos[:3]) + ("…" if len(gap.productos) > 3 else "")
    critico_icon = "🔴 " if gap.gap_critico else ""

    return f"""
    <tr style="background:{bg};border-bottom:1px solid #e5e7eb">
      <td style="padding:10px 12px;font-family:monospace;font-size:13px;white-space:nowrap">
        {critico_icon}{gap.cve_id} {kev}
      </td>
      <td style="padding:10px 12px">{_badge_severidad(gap.severidad)}</td>
      <td style="padding:10px 12px;font-size:12px;color:#374151">{gap.fuente}</td>
      <td style="padding:10px 12px;font-size:12px;color:#6b7280">{productos}</td>
      <td style="padding:10px 12px">{badges_cob}</td>
    </tr>"""


def _tarjeta_metrica(titulo: str, valor: str, subtitulo: str, color: str) -> str:
    return f"""
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;
                padding:20px 24px;flex:1;min-width:160px">
      <div style="font-size:13px;color:#6b7280;margin-bottom:4px">{titulo}</div>
      <div style="font-size:32px;font-weight:700;color:{color}">{valor}</div>
      <div style="font-size:12px;color:#9ca3af;margin-top:2px">{subtitulo}</div>
    </div>"""


class HTMLReporter:

    def __init__(self, directorio: str = "./data"):
        self.directorio = Path(directorio)
        self.directorio.mkdir(parents=True, exist_ok=True)

    def escribir(self, report: CoverageReport) -> Path:
        fecha_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        fichero   = self.directorio / f"coverage_report_{fecha_str}.html"
        fichero.write_text(self._generar(report), encoding="utf-8")
        print(f"  [HTML] Guardado: {fichero}")
        return fichero

    def _generar(self, report: CoverageReport) -> str:
        ahora = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

        # ── Métricas globales ──────────────────────────────────────────
        gaps_criticos   = report.gaps_criticos
        total_cves      = report.total_cves
        pct_sin         = report.pct_sin_cobertura
        pct_con         = round(100 - pct_sin, 1)
        por_herramienta = report.gaps_por_herramienta()

        tarjetas = "".join([
            _tarjeta_metrica("CVEs analizados", str(total_cves),
                             "total en el período", "#1d4ed8"),
            _tarjeta_metrica("Gaps críticos", str(gaps_criticos),
                             "sin cobertura en ninguna herramienta",
                             "#dc2626" if gaps_criticos > 0 else "#16a34a"),
            _tarjeta_metrica("Cobertura", f"{pct_con}%",
                             "CVEs con al menos una herramienta", "#16a34a"),
        ])

        # Barras por herramienta
        barras_herramienta = ""
        for h, n in sorted(por_herramienta.items()):
            pct = round(n / total_cves * 100) if total_cves else 0
            barras_herramienta += f"""
            <div style="margin-bottom:12px">
              <div style="display:flex;justify-content:space-between;
                          font-size:13px;margin-bottom:4px">
                <span style="font-weight:500">{h}</span>
                <span style="color:#6b7280">{n} gaps ({pct}%)</span>
              </div>
              <div style="background:#f3f4f6;border-radius:4px;height:8px">
                <div style="background:#dc2626;border-radius:4px;height:8px;
                            width:{pct}%"></div>
              </div>
            </div>"""

        # ── Tabla de gaps (ordenada: críticos primero, luego por severidad) ──
        orden_sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4}
        gaps_ordenados = sorted(
            report.gaps,
            key=lambda g: (not g.gap_critico, orden_sev.get(g.severidad, 4))
        )

        filas = "".join(_fila_gap(g, i) for i, g in enumerate(gaps_ordenados))

        # ── Gaps críticos para la sección de alerta ────────────────────
        alertas = ""
        for gap in report.gaps_criticos_list():
            productos = ", ".join(gap.productos[:2]) or "—"
            kev_txt   = " · <strong>en KEV</strong>" if gap.en_kev else ""
            alertas += f"""
            <div style="background:#fee2e2;border-left:4px solid #dc2626;
                        padding:10px 14px;margin-bottom:8px;border-radius:0 6px 6px 0">
              <span style="font-family:monospace;font-weight:600">{gap.cve_id}</span>
              &nbsp;{_badge_severidad(gap.severidad)}&nbsp;
              <span style="font-size:12px;color:#6b7280">{gap.fuente}{kev_txt}</span>
              <div style="font-size:12px;color:#374151;margin-top:4px">
                Productos: {productos}
              </div>
            </div>"""

        if not alertas:
            alertas = ('<div style="color:#16a34a;font-size:14px;padding:12px">'
                       '✓ No hay gaps críticos — todos los CVEs tienen al menos '
                       'una herramienta con cobertura</div>')

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Coverage Report — {ahora}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: #f9fafb; color: #111827; font-size: 14px; }}
  h1 {{ font-size: 22px; font-weight: 700; }}
  h2 {{ font-size: 15px; font-weight: 600; margin-bottom: 12px; color: #374151; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #1e3a5f; color: #fff; padding: 10px 12px;
        text-align: left; font-size: 12px; font-weight: 500;
        text-transform: uppercase; letter-spacing: .04em; }}
  tr:hover td {{ background: #f0f9ff !important; }}
  input[type=text] {{ width: 100%; padding: 8px 12px; border: 1px solid #d1d5db;
                      border-radius: 6px; font-size: 13px; outline: none; }}
  input[type=text]:focus {{ border-color: #3b82f6; box-shadow: 0 0 0 2px #bfdbfe; }}
  @media (max-width: 768px) {{ .cards {{ flex-direction: column; }} }}
</style>
</head>
<body>

<div style="background:#1e3a5f;color:#fff;padding:20px 32px">
  <h1>SOC Coverage Report</h1>
  <div style="font-size:13px;color:#93c5fd;margin-top:4px">
    Generado el {ahora} · {total_cves} CVEs analizados
  </div>
</div>

<div style="max-width:1200px;margin:0 auto;padding:24px 32px">

  <!-- Métricas -->
  <div class="cards" style="display:flex;gap:16px;margin-bottom:28px;flex-wrap:wrap">
    {tarjetas}
  </div>

  <!-- Gaps por herramienta -->
  <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;
              padding:20px 24px;margin-bottom:28px">
    <h2>Gaps por herramienta</h2>
    {barras_herramienta if barras_herramienta else
     '<p style="color:#6b7280;font-size:13px">Sin gaps detectados</p>'}
  </div>

  <!-- Alertas críticas -->
  <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;
              padding:20px 24px;margin-bottom:28px">
    <h2>🔴 Gaps críticos — sin cobertura en ninguna herramienta</h2>
    {alertas}
  </div>

  <!-- Tabla completa -->
  <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;
              padding:20px 24px">
    <div style="display:flex;justify-content:space-between;align-items:center;
                margin-bottom:16px">
      <h2 style="margin:0">Todos los CVEs analizados</h2>
      <input type="text" id="filtro" placeholder="Filtrar por CVE, fuente, producto…"
             style="max-width:280px" oninput="filtrar(this.value)">
    </div>
    <div style="overflow-x:auto">
      <table id="tabla">
        <thead>
          <tr>
            <th>CVE</th>
            <th>Severidad</th>
            <th>Fuente</th>
            <th>Productos afectados</th>
            <th>Cobertura</th>
          </tr>
        </thead>
        <tbody id="tbody">{filas}</tbody>
      </table>
    </div>
    <div id="sin-resultados" style="display:none;text-align:center;
         padding:24px;color:#6b7280;font-size:13px">
      No se encontraron resultados para este filtro
    </div>
  </div>

</div>

<script>
function filtrar(q) {{
  q = q.toLowerCase();
  const filas = document.querySelectorAll('#tbody tr');
  let visibles = 0;
  filas.forEach(tr => {{
    const txt = tr.textContent.toLowerCase();
    const mostrar = !q || txt.includes(q);
    tr.style.display = mostrar ? '' : 'none';
    if (mostrar) visibles++;
  }});
  document.getElementById('sin-resultados').style.display =
    visibles === 0 ? 'block' : 'none';
}}
</script>

</body>
</html>"""
