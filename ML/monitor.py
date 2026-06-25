#!/usr/bin/env python3
"""
monitor.py — Dashboard read-only untuk hasil klasifikasi ML SOC.
Baca ml-api.log (TIDAK menyentuh API/model), serve halaman di port 8080.

Jalankan:  ~/ml-api/venv/bin/python3 monitor.py
Buka    :  http://<IP-VM-ML>:8080
"""
import json
import re
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOG_PATH = Path(__file__).parent / "ml-api.log"
PORT = 8080
MAX_FEED = 60  # jumlah prediksi terbaru yang ditampilkan

# baris contoh:
# 2026-06-24 09:37:50,530 [INFO] PREDICT srcip=182.8.97.126 rule_id=31101 → FP (conf=0.697) | feat={...}
LINE_RE = re.compile(
    r"^(?P<ts>[\d\-]+ [\d:,]+).*PREDICT srcip=(?P<srcip>\S+)\s+rule_id=(?P<rid>\S+)\s+"
    r"→\s+(?P<label>TP|FP)\s+\(conf=(?P<conf>[\d.]+)\)\s+\|\s+feat=(?P<feat>\{.*\})\s*$"
)


def parse_log():
    """Baca seluruh log, kembalikan (stats, feed terbaru)."""
    tp = fp = 0
    feed = deque(maxlen=MAX_FEED)
    if LOG_PATH.exists():
        with open(LOG_PATH, "r", errors="replace") as f:
            for line in f:
                m = LINE_RE.search(line.strip())
                if not m:
                    continue
                label = m.group("label")
                if label == "TP":
                    tp += 1
                else:
                    fp += 1
                try:
                    feat = json.loads(m.group("feat").replace("'", '"'))
                except Exception:
                    feat = {}
                feed.appendleft({
                    "ts": m.group("ts"),
                    "srcip": m.group("srcip"),
                    "rid": m.group("rid"),
                    "label": label,
                    "conf": round(float(m.group("conf")) * 100, 1),
                    "c10": feat.get("alert_count_10s", "-"),
                    "c30": feat.get("alert_count_30s", "-"),
                    "c60": feat.get("alert_count_60s", "-"),
                    "iat": feat.get("inter_arrival_time", "-"),
                    "std": feat.get("iat_std", "-"),
                })
    total = tp + fp
    return {"total": total, "tp": tp, "fp": fp,
            "fp_pct": round(100 * fp / total, 1) if total else 0}, list(feed)


# nama jenis alert human-readable. Pakai info yang BENAR-BENAR ada (rule_id +
# verdict), TIDAK menebak nama tool (log tak menyimpan itu).
RULE_NAME = {
    "31101": "Web 4xx / 404",
    "31103": "Serangan Web (SQL Injection)",
    "31104": "Serangan Web Umum",
    "31105": "Serangan Web (XSS)",
    "31106": "Serangan Web (balas 200)",
    "31151": "Banyak 404 dari 1 IP",
    "100112": "Lonjakan request web (rate tinggi)",
    "100113": "Serangan DoS terdeteksi",
}

def describe_alert(rid, label):
    base = RULE_NAME.get(str(rid), f"Alert web ({rid})")
    # pertajam pakai verdict untuk rule 4xx/rate yang ambigu
    if str(rid) in ("31101", "31151", "100112"):
        return ("Web Scan / Probing" if label == "TP" else "404 Wajar (benign)")
    return base


PAGE = """<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC ML Monitor</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;font:14px/1.5 ui-monospace,Menlo,Consolas,monospace;padding:24px}
h1{font-size:18px;font-weight:600;margin-bottom:2px}
.sub{color:#8b949e;font-size:12px;margin-bottom:20px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px}
.card .n{font-size:30px;font-weight:700}
.card .l{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.05em}
.tp{color:#f85149}.fp{color:#3fb950}.muted{color:#8b949e}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #21262d;white-space:nowrap}
th{color:#8b949e;font-weight:500;font-size:11px;text-transform:uppercase}
tr.tp-row td:first-child{border-left:3px solid #f85149}
tr.fp-row td:first-child{border-left:3px solid #3fb950}
.badge{padding:2px 8px;border-radius:20px;font-weight:600;font-size:11px}
.badge.tp{background:rgba(248,81,73,.15)}.badge.fp{background:rgba(63,185,80,.15)}
.hi{color:#e6edf3;font-weight:600}
</style></head><body>
<h1>SOC ML Alert Classifier — Live Monitor</h1>
<div class="sub">Membaca ml-api.log · auto-refresh 3 dtk · read-only (tidak mengubah pipeline)</div>
<div class="cards">
  <div class="card"><div class="n">__TOTAL__</div><div class="l">Total Diklasifikasi</div></div>
  <div class="card"><div class="n tp">__TP__</div><div class="l">True Positive (Serangan)</div></div>
  <div class="card"><div class="n fp">__FP__</div><div class="l">False Alarm (Disaring)</div></div>
  <div class="card"><div class="n muted">__FPPCT__%</div><div class="l">Porsi False Alarm</div></div>
</div>
<table><thead><tr>
<th>Waktu</th><th>Verdict</th><th>Jenis</th><th>Conf</th><th>Source IP</th><th>Rule</th>
<th>cnt10s</th><th>cnt30s</th><th>cnt60s</th><th>iat</th><th>iat_std</th>
</tr></thead><tbody>__ROWS__</tbody></table>
<script>setTimeout(()=>location.reload(),3000)</script>
</body></html>"""


def render():
    stats, feed = parse_log()
    rows = []
    for r in feed:
        cls = "tp-row" if r["label"] == "TP" else "fp-row"
        badge = "tp" if r["label"] == "TP" else "fp"
        verdict = "TP — Serangan" if r["label"] == "TP" else "FP — Abaikan"
        jenis = describe_alert(r["rid"], r["label"])
        rows.append(
            f"<tr class='{cls}'><td>{r['ts']}</td>"
            f"<td><span class='badge {badge}'>{verdict}</span></td>"
            f"<td class='hi'>{jenis}</td>"
            f"<td>{r['conf']}%</td><td class='hi'>{r['srcip']}</td><td>{r['rid']}</td>"
            f"<td>{r['c10']}</td><td>{r['c30']}</td><td>{r['c60']}</td>"
            f"<td>{r['iat']}</td><td>{r['std']}</td></tr>"
        )
    if not rows:
        rows = ["<tr><td colspan='11' class='muted'>Belum ada prediksi. "
                "Lancarkan traffic ke target untuk melihat hasil.</td></tr>"]
    return (PAGE.replace("__TOTAL__", str(stats["total"]))
                .replace("__TP__", str(stats["tp"]))
                .replace("__FP__", str(stats["fp"]))
                .replace("__FPPCT__", str(stats["fp_pct"]))
                .replace("__ROWS__", "".join(rows)))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_response(404); self.end_headers(); return
        body = render().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass  # senyap


if __name__ == "__main__":
    print(f"Monitor di http://0.0.0.0:{PORT}  (sumber: {LOG_PATH})")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
