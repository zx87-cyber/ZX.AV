"""
Generates a self-contained, styled HTML scan report (no external deps).
Opening it in any browser and using its print dialog produces a PDF.
"""
import html
import time

from .config import APP_NAME, APP_VERSION


def generate_html_report(history, path):
    rows = []
    for entry in reversed(history):
        result = entry.get("result", "ERROR")
        color = {"CLEAN": "#55B982", "FLAGGED": "#D96565"}.get(result, "#C7A65B")
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(entry.get('target', '')))}</td>"
            f"<td>{html.escape(str(entry.get('type', '')))}</td>"
            f"<td style='color:{color};font-weight:600'>{html.escape(result)}</td>"
            f"<td>{entry.get('detections', 0)}</td>"
            f"<td>{html.escape(str(entry.get('time', '')))}</td>"
            "</tr>"
        )
    clean = sum(1 for e in history if e.get("result") == "CLEAN")
    flagged = sum(1 for e in history if e.get("result") == "FLAGGED")
    errors = sum(1 for e in history if e.get("result") == "ERROR")
    document = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{APP_NAME} Scan Report</title>
<style>
  body {{ background:#101112; color:#D7D7D7; font-family: 'Segoe UI', Arial, sans-serif; padding: 40px; }}
  h1 {{ color:#F1F1F1; margin-bottom: 4px; }}
  .meta {{ color:#8C8F93; margin-bottom: 28px; font-size: 13px; }}
  .stats {{ display:flex; gap:16px; margin-bottom: 28px; }}
  .stat {{ background:#191B1D; border:1px solid #2B2D30; border-radius:8px; padding:14px 20px; }}
  .stat .n {{ font-size:22px; font-weight:700; color:#F1F1F1; }}
  .stat .l {{ font-size:11px; color:#8C8F93; text-transform:uppercase; }}
  table {{ width:100%; border-collapse: collapse; background:#191B1D; border-radius:8px; overflow:hidden; }}
  th, td {{ text-align:left; padding:10px 14px; border-bottom:1px solid #2B2D30; font-size:13px; }}
  th {{ background:#202224; color:#F1F1F1; font-size:11px; text-transform:uppercase; }}
</style>
</head>
<body>
  <h1>{APP_NAME} Scan Report</h1>
  <div class="meta">{APP_NAME} {APP_VERSION} &middot; generated {time.strftime('%Y-%m-%d %H:%M:%S')}</div>
  <div class="stats">
    <div class="stat"><div class="n">{len(history)}</div><div class="l">Total</div></div>
    <div class="stat"><div class="n" style="color:#55B982">{clean}</div><div class="l">Clean</div></div>
    <div class="stat"><div class="n" style="color:#D96565">{flagged}</div><div class="l">Flagged</div></div>
    <div class="stat"><div class="n" style="color:#C7A65B">{errors}</div><div class="l">Errors</div></div>
  </div>
  <table>
    <thead><tr><th>Target</th><th>Type</th><th>Result</th><th>Detections</th><th>Time</th></tr></thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as file:
        file.write(document)
    return path
