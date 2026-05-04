from __future__ import annotations

import html
import json
import shutil
import tempfile
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from codeflow.analyzer import analyze_paths, generate_mermaid


HOST = "127.0.0.1"
PORT = 8012


def render_page(report: dict[str, Any] | None = None, error: str | None = None) -> str:
    report_html = ""
    if report:
        raw_json = json.dumps(report, indent=2)
        report_html = f"""
        <div class="command-center">
           <input type="text" id="omniSearch" placeholder="Type a query (e.g. 'Xiaomi flow' or 'Auth checks')..." onkeyup="handleOmniSearch()">
           <div class="search-hint">Querying: APIs, Partners, Logic, and Models</div>
        </div>

        <div class="tabs-nav">
          <button class="tab-btn active" onclick="showTab('dashboard')">Dashboard</button>
          <button class="tab-btn" onclick="showTab('diagnostics')">Bugs & Warnings ({report['overview'].get('bugs_found', 0)})</button>
          <button class="tab-btn" onclick="showTab('apis')">API Directory</button>
          <button class="tab-btn" onclick="showTab('flows')">Visual Flows</button>
          <button class="tab-btn" onclick="showTab('schema')">Schema</button>
          <button class="tab-btn" onclick="showTab('configs')">System Configs</button>
          <button class="tab-btn" onclick="showTab('raw')">Raw JSON</button>
        </div>

        <div id="tab-dashboard" class="tab-content active">
          <section class="card summary-card">
            <div class="section-head">
              <div>
                <h2>System Intelligence</h2>
                <p>Real-time backend audit of your Django architecture.</p>
              </div>
              <div class="summary-grid">
                <div><strong>{report["overview"]["files_scanned"]}</strong><span>apps</span></div>
                <div><strong>{report["overview"]["inbound_apis"]}</strong><span>APIs</span></div>
                <div class="{"stat-warning" if report['overview'].get('bugs_found', 0) > 0 else ""}">
                    <strong>{report['overview'].get('bugs_found', 0)}</strong><span>Critical Bugs</span>
                </div>
                <div><strong>{report["overview"]["database_tables"]}</strong><span>ORM Models</span></div>
              </div>
            </div>
          </section>
          
          <div class="panel-grid">
             <section class="card">
                <h3>Logic Checks Detected</h3>
                <div style="margin-top:12px;">{render_pills(report["overview"].get("check_types", []), "No checks")}</div>
             </section>
             <section class="card">
                <h3>External Touches</h3>
                <div style="margin-top:12px;">{render_pills([api["label"] for api in report["apis"]["outbound"][:10]], "No external APIs")}</div>
             </section>
          </div>
        </div>

        <div id="tab-diagnostics" class="tab-content">
          <section class="card">
            <div class="section-head">
               <h2>Automated Bug Reports</h2>
               <p>Static analysis results for Security, Logic, and Performance.</p>
            </div>
            <div class="table-wrap">
              <table class="api-table">
                <thead>
                  <tr><th>Type</th><th>Severity</th><th>Issue</th><th>File</th></tr>
                </thead>
                <tbody>
                  {"".join(render_diagnostic_row(d) for d in report.get("diagnostics", [])) or "<tr><td colspan='4'>No issues detected.</td></tr>"}
                </tbody>
              </table>
            </div>
          </section>
        </div>

        <div id="tab-apis" class="tab-content">
          <div class="split-view">
            <section class="card api-list-pane">
              <div class="section-head">
                 <h2>API Directory</h2>
                 <p>Every discovered endpoint across all project apps. Click to see Spec.</p>
              </div>
              <div class="table-wrap">
                <table class="api-table" id="apiTable">
                  <thead>
                    <tr>
                      <th>App</th>
                      <th>Endpoint</th>
                      <th>Checks</th>
                      <th>Models</th>
                      <th>File</th>
                    </tr>
                  </thead>
                  <tbody>
                    {"".join(render_api_row(api) for api in report["apis"]["inbound"])}
                  </tbody>
                </table>
              </div>
            </section>

            <section class="card api-spec-pane" id="apiSpecPanel">
              <div class="empty-spec">
                <div class="pulse-icon">&rarr;</div>
                <h3>API Specification</h3>
                <p>Select an API from the list to view its payload, exceptions, and success flow.</p>
              </div>
            </section>
          </div>
        </div>

        <div id="tab-flows" class="tab-content">
          <section class="card">
            <div class="section-head">
              <div>
                <h2>Architectural Flow Map</h2>
                <p>Dynamic diagram generated via Mermaid.js. Best for project-wide connectivity.</p>
              </div>
              <div class="diagram-controls">
                <button class="zoom-btn" onclick="zoomDiagram(-0.15)" title="Zoom out">−</button>
                <span class="zoom-label" id="zoom-level">100%</span>
                <button class="zoom-btn" onclick="zoomDiagram(0.15)" title="Zoom in">+</button>
                <button class="zoom-btn" onclick="zoomReset()" title="Reset zoom &amp; pan">⊙</button>
                <button class="copy-button" onclick="copyMermaid()">Copy Code</button>
              </div>
            </div>
            <div class="mermaid-wrap" id="diagram-viewport">
              <div id="diagram-canvas">
                <div id="mermaid-graph">{generate_mermaid(report)}</div>
              </div>
            </div>
          </section>
          
          <section class="card">
             <h3>Partner-Specific Sub-systems</h3>
             <div class="panel-grid" style="margin-top:16px;">
                {"".join(render_partner_flow_card(name, data) for name, data in report["partners"].items())}
             </div>
          </section>
        </div>

        <div id="tab-databases" class="tab-content">
          <section class="card">
            <div class="section-head">
               <h2>Database Operations</h2>
               <p>Every place the Django ORM interacts with your models.</p>
            </div>
            <div class="panel-grid">
               {"".join(render_db_card(db) for db in report["databases"])}
            </div>
          </section>
        </div>

        <div id="tab-schema" class="tab-content">
          <section class="card">
            <div class="section-head">
               <h2>Model Schema</h2>
               <p>Detailed field definitions and relationships extracted from your models.py files.</p>
            </div>
            <div class="panel-grid">
               {"".join(render_model_schema_card(m) for m in report.get("schema", []))}
            </div>
          </section>
        </div>

        <div id="tab-configs" class="tab-content">
          <section class="card">
            <div class="section-head">
               <h2>System Configurations</h2>
               <p>Key/Value pairs extracted from settings.py and config files.</p>
            </div>
            <div class="table-wrap">
              <table class="api-table config-table">
                <thead>
                  <tr><th>Key</th><th>Value</th><th>File</th></tr>
                </thead>
                <tbody>
                  {"".join(f'<tr><td title="{html.escape(c["key"])}"><code>{html.escape(c["key"])}</code></td><td title="{html.escape(str(c["value"]))}">{html.escape(str(c["value"]))}</td><td title="{html.escape(c["file"])}"><small>{html.escape(shorten_path(c["file"]))}</small></td></tr>' for c in report.get("configs", []))}
                </tbody>
              </table>
            </div>
          </section>
        </div>

        <div id="tab-raw" class="tab-content">
          <details class="card raw-card">
            <summary>Raw JSON Data</summary>
            <div class="raw-json-actions">
              <button class="copy-button" type="button" onclick="copyRawJson(this)">Copy JSON</button>
            </div>
            <pre id="raw-json-block">{html.escape(raw_json)}</pre>
          </details>
        </div>
        """

    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Flowprint</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.min.js"></script>
  <script>
    mermaid.initialize({{
      startOnLoad: false,
      theme: 'base',
      flowchart: {{ curve: 'basis', useMaxWidth: false }},
      themeVariables: {{
        primaryColor: '#1d5f8a',
        primaryTextColor: '#ffffff',
        primaryBorderColor: '#38bdf8',
        lineColor: '#64748b',
        background: '#0a1628',
        mainBkg: '#0a1628',
        nodeBorder: '#38bdf8',
        clusterBkg: '#0f1f35',
        titleColor: '#ffffff',
        edgeLabelBackground: '#1e293b',
        tertiaryColor: '#0f1f35',
      }},
    }});
    document.addEventListener('DOMContentLoaded', async () => {{
      const el = document.getElementById('mermaid-graph');
      if (!el) return;
      const code = el.textContent.trim();
      if (!code) return;
      try {{
        const {{ svg }} = await mermaid.render('mermaid_svg_out', code);
        el.innerHTML = svg;
        el.style.background = 'transparent';
      }} catch (err) {{
        el.innerHTML = '<p style="color:#f87171;padding:16px;">Diagram error: ' + err.message + '</p>';
        console.error('Mermaid render error:', err);
      }}
    }});
  </script>
  <style>
    :root {{
      --bg: #07111f;
      --paper: rgba(10, 19, 36, 0.80);
      --paper-strong: rgba(12, 23, 43, 0.94);
      --ink: #ecf7ff;
      --muted: #91abc4;
      --line: rgba(90, 191, 255, 0.18);
      --primary: #62ddff;
      --primary-soft: rgba(38, 126, 190, 0.18);
      --gold-soft: rgba(255, 184, 77, 0.12);
      --rose-soft: rgba(255, 94, 165, 0.10);
      --slate-soft: rgba(109, 255, 202, 0.10);
      --shadow: 0 24px 80px rgba(0, 0, 0, 0.45);
      --error: #ff7b9a;
      --success: #6effc5;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      font-family: "Avenir Next", "Segoe UI", "Helvetica Neue", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(98, 221, 255, 0.20), transparent 24%),
        radial-gradient(circle at right 20%, rgba(162, 108, 255, 0.18), transparent 22%),
        linear-gradient(180deg, #040b16 0%, var(--bg) 60%, #050914 100%);
    }}
    body::before {{
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(116, 191, 248, 0.06) 1px, transparent 1px),
        linear-gradient(90deg, rgba(116, 191, 248, 0.06) 1px, transparent 1px);
      background-size: 32px 32px;
      mask-image: linear-gradient(180deg, rgba(255,255,255,0.22), transparent 85%);
    }}
    main {{
      max-width: 1220px;
      margin: 0 auto;
      padding: 34px 18px 60px;
    }}
    h1, h2, h3, h4, p {{ margin-top: 0; }}
    p {{ color: var(--muted); line-height: 1.6; }}
    .hero, .card {{
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: 28px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(18px);
    }}
    .hero {{
      padding: 40px;
      position: relative;
      overflow: hidden;
    }}
    .tabs-nav {{
      display: flex;
      gap: 10px;
      margin-top: 30px;
      border-bottom: 1px solid var(--line);
      padding-bottom: 12px;
    }}
    .tab-btn {{
      background: transparent;
      border: 1px solid transparent;
      color: var(--muted);
      padding: 10px 20px;
      border-radius: 12px;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.2s;
    }}
    .tab-btn.active {{
      background: var(--primary-soft);
      border-color: var(--primary);
      color: var(--primary);
    }}
    .tab-content {{
      display: none;
    }}
    .tab-content.active {{
      display: block;
    }}
    .search-input {{
      width: 100%;
      max-width: 400px;
      padding: 10px 15px;
      border-radius: 12px;
      background: var(--paper-strong);
      border: 1px solid var(--line);
      color: var(--ink);
    }}
    .api-table {{
       width: 100%;
       border-collapse: collapse;
       margin-top: 20px;
       table-layout: fixed;
    }}
    .api-table th {{
       text-align: left;
       padding: 12px 14px;
       border-bottom: 2px solid var(--line);
       color: var(--primary);
       white-space: nowrap;
    }}
    .api-table td {{
       padding: 12px 14px;
       border-bottom: 1px solid var(--line);
       overflow: hidden;
       text-overflow: ellipsis;
       white-space: nowrap;
       vertical-align: middle;
    }}
    .api-table td:hover {{
       white-space: normal;
       word-break: break-all;
    }}
    /* Config table column widths */
    .config-table th:nth-child(1), .config-table td:nth-child(1) {{ width: 36%; }}
    .config-table th:nth-child(2), .config-table td:nth-child(2) {{ width: 42%; }}
    .config-table th:nth-child(3), .config-table td:nth-child(3) {{ width: 22%; color: var(--muted); }}
    .table-wrap {{
       overflow-x: auto;
       border-radius: 16px;
    }}
    .mermaid-wrap {{
      background: rgba(8, 16, 31, 0.9);
      border: 1px solid var(--line);
      border-radius: 24px;
      padding: 30px;
      overflow: hidden;
      min-height: 500px;
      position: relative;
    }}
    #diagram-canvas {{
      display: inline-block;
      transform-origin: top left;
      cursor: grab;
      user-select: none;
      will-change: transform;
    }}
    #diagram-canvas.dragging {{
      cursor: grabbing;
    }}
    .mermaid {{
      background: transparent !important;
    }}
    .diagram-controls {{
      display: flex;
      align-items: center;
      gap: 8px;
      flex-shrink: 0;
    }}
    .zoom-btn {{
      width: 36px;
      height: 36px;
      border-radius: 10px;
      background: var(--paper-strong);
      border: 1px solid var(--line);
      color: var(--primary);
      font-size: 1.1rem;
      font-weight: 700;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 0;
      box-shadow: none;
      transition: background 0.15s, border-color 0.15s;
    }}
    .zoom-btn:hover {{
      background: var(--primary-soft);
      border-color: var(--primary);
    }}
    .zoom-label {{
      font-size: 0.85rem;
      font-weight: 700;
      color: var(--muted);
      min-width: 44px;
      text-align: center;
    }}
    .command-center input {{
      width: 100%;
      background: transparent;
      border: none;
      color: var(--primary);
      font-size: 1.5rem;
      font-weight: 700;
      outline: none;
    }}
    .search-hint {{
      font-size: 0.85rem;
      color: var(--muted);
      margin-top: 8px;
    }}
    .stat-warning {{
      color: var(--error);
      border: 1px solid var(--error);
      border-radius: 12px;
      background: rgba(255, 123, 154, 0.05);
    }}
    .split-view {{
      display: grid;
      grid-template-columns: 1fr 400px;
      gap: 20px;
      align-items: start;
    }}
    .api-list-pane {{
      display: flex;
      flex-direction: column;
      max-height: calc(100vh - 180px);
    }}
    .api-list-pane .section-head {{
      flex-shrink: 0;
    }}
    .api-list-pane .table-wrap {{
      flex: 1;
      overflow-y: auto;
      overflow-x: auto;
      border-radius: 12px;
    }}
    .api-list-pane .table-wrap::-webkit-scrollbar {{
      width: 6px;
      height: 6px;
    }}
    .api-list-pane .table-wrap::-webkit-scrollbar-track {{
      background: rgba(255,255,255,0.04);
      border-radius: 3px;
    }}
    .api-list-pane .table-wrap::-webkit-scrollbar-thumb {{
      background: rgba(98, 221, 255, 0.35);
      border-radius: 3px;
    }}
    .api-list-pane .table-wrap::-webkit-scrollbar-thumb:hover {{
      background: rgba(98, 221, 255, 0.6);
    }}
    .api-row {{ cursor: pointer; transition: background 0.2s; }}
    .api-row:hover {{ background: rgba(98, 221, 255, 0.05); }}
    .api-row.selected {{ background: rgba(98, 221, 255, 0.13); border-left: 3px solid var(--accent); }}
    .api-spec-pane {{
      position: sticky;
      top: 20px;
      min-height: 400px;
      max-height: calc(100vh - 180px);
      overflow-y: auto;
      border: 1px solid var(--primary);
    }}
    .api-spec-pane::-webkit-scrollbar {{
      width: 6px;
    }}
    .api-spec-pane::-webkit-scrollbar-track {{
      background: rgba(255,255,255,0.04);
      border-radius: 3px;
    }}
    .api-spec-pane::-webkit-scrollbar-thumb {{
      background: rgba(98, 221, 255, 0.35);
      border-radius: 3px;
    }}
    .api-spec-pane::-webkit-scrollbar-thumb:hover {{
      background: rgba(98, 221, 255, 0.6);
    }}
    .empty-spec {{
      text-align: center;
      padding: 60px 20px;
      color: var(--muted);
    }}
    .spec-section {{ margin-bottom: 20px; }}
    .spec-section h4 {{
      color: var(--primary);
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 8px;
    }}
    .spec-header {{ margin-bottom: 20px; }}
    .spec-title {{ font-size: 1.1rem; margin: 0 0 4px; }}
    .spec-source {{ font-size: 0.8rem; color: var(--muted); margin: 0; }}
    .spec-block-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 6px;
    }}
    .spec-label {{
      font-size: 0.7rem;
      font-weight: 700;
      letter-spacing: 1.5px;
      text-transform: uppercase;
    }}
    .payload-label {{ color: var(--primary); }}
    .error-label {{ color: var(--error); }}
    .success-label {{ color: var(--success); }}
    .spec-copy-btn {{
      font-size: 0.72rem;
      padding: 3px 10px;
      border-radius: 6px;
      border: 1px solid rgba(98,221,255,0.3);
      background: rgba(98,221,255,0.07);
      color: var(--primary);
      cursor: pointer;
      transition: all 0.2s;
    }}
    .spec-copy-btn:hover {{
      background: rgba(98,221,255,0.18);
      border-color: var(--primary);
    }}
    .json-block {{
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid rgba(98,221,255,0.12);
      border-radius: 10px;
      padding: 14px 16px;
      font-family: 'JetBrains Mono', 'Fira Code', monospace;
      font-size: 0.8rem;
      line-height: 1.6;
      white-space: pre;
      overflow-x: auto;
    }}
    .error-block {{ border-color: rgba(255,123,154,0.2); }}
    .success-block {{ border-color: rgba(110,255,197,0.2); }}
    .json-key {{ color: var(--primary); }}
    .json-string {{ color: #e8d5a3; }}
    .json-number {{ color: #b5f0a5; }}
    .json-bool {{ color: #ff9f7a; }}
    .json-null {{ color: var(--muted); }}
    .error-block .json-string {{ color: var(--error); }}
    .success-block .json-string {{ color: var(--success); }}
    .curl-block {{ color: #c8a4ff; }}
    .auth-badge {{
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 10px;
      padding: 12px 14px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }}
    .auth-header {{
      display: block;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      color: var(--muted);
      margin-top: 2px;
      word-break: break-all;
    }}
    .auth-classes {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 4px; }}
    .auth-pill {{
      font-size: 0.7rem;
      padding: 2px 8px;
      border-radius: 999px;
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.12);
      color: var(--muted);
    }}
    .pulse-icon {{
      font-size: 2rem;
      animation: pulse 2s infinite;
    }}
    @keyframes pulse {{
      0% {{ opacity: 0.3; }}
      50% {{ opacity: 1; }}
      100% {{ opacity: 0.3; }}
    }}
    .hero::after {{
      content: "";
      position: absolute;
      width: 320px;
      height: 320px;
      right: -80px;
      top: -100px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(98, 221, 255, 0.18), transparent 68%);
    }}
    .eyebrow {{
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(98, 221, 255, 0.12);
      color: #8ce9ff;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 14px;
    }}
    .hero-copy {{
      max-width: 56rem;
      position: relative;
      z-index: 1;
    }}
    .hero h1 {{
      font-size: clamp(2rem, 4vw, 4rem);
      line-height: 1.02;
      margin-bottom: 12px;
      letter-spacing: -0.04em;
    }}
    form {{
      display: grid;
      gap: 16px;
      margin-top: 24px;
      position: relative;
      z-index: 1;
    }}
    #loading-overlay {{
      position: fixed;
      inset: 0;
      background: rgba(4, 10, 22, 0.88);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 9999;
    }}
    .loading-box {{
      width: min(480px, 90vw);
      background: rgba(8, 18, 38, 0.95);
      border: 1px solid rgba(98, 221, 255, 0.22);
      border-radius: 24px;
      padding: 36px 32px;
      box-shadow: 0 32px 80px rgba(0,0,0,0.6), 0 0 0 1px rgba(98,221,255,0.08);
      text-align: center;
    }}
    .loading-title {{
      font-size: 1.15rem;
      font-weight: 700;
      color: var(--ink);
      margin-bottom: 24px;
      letter-spacing: 0.02em;
    }}
    .loading-dots::after {{
      content: '';
      animation: dots 1.4s steps(4, end) infinite;
    }}
    @keyframes dots {{
      0%   {{ content: ''; }}
      25%  {{ content: '.'; }}
      50%  {{ content: '..'; }}
      75%  {{ content: '...'; }}
      100% {{ content: ''; }}
    }}
    .loading-bar-track {{
      width: 100%;
      height: 6px;
      background: rgba(98, 221, 255, 0.1);
      border-radius: 999px;
      overflow: hidden;
      margin-bottom: 16px;
    }}
    .loading-bar-fill {{
      height: 100%;
      width: 0%;
      border-radius: 999px;
      background: linear-gradient(90deg, #3cc8e8, #8f62ff 55%, #ff68d2);
      box-shadow: 0 0 12px rgba(98, 221, 255, 0.5);
      transition: width 0.4s ease;
    }}
    .loading-status {{
      font-size: 0.82rem;
      color: var(--muted);
      min-height: 1.2em;
      transition: opacity 0.3s;
    }}
    .form-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
    }}
    label {{
      display: block;
      font-weight: 700;
      margin-bottom: 8px;
    }}
    input[type="text"], input[type="file"] {{
      width: 100%;
      padding: 13px 14px;
      border-radius: 16px;
      border: 1px solid rgba(98, 221, 255, 0.16);
      background: rgba(5, 15, 30, 0.78);
      color: var(--ink);
      font-size: 1rem;
      box-shadow: inset 0 0 0 1px rgba(98, 221, 255, 0.05);
    }}
    button {{
      width: fit-content;
      border: none;
      border-radius: 999px;
      padding: 14px 22px;
      background: linear-gradient(135deg, #3cc8e8, #8f62ff 55%, #ff68d2);
      color: #07111f;
      font-size: 1rem;
      font-weight: 700;
      cursor: pointer;
      box-shadow: 0 0 0 1px rgba(255,255,255,0.14), 0 16px 40px rgba(98, 221, 255, 0.24);
    }}
    .card {{
      margin-top: 20px;
      padding: 24px;
    }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 18px;
      flex-wrap: wrap;
      margin-bottom: 14px;
    }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 12px;
      min-width: min(100%, 560px);
    }}
    .summary-grid div {{
      background: linear-gradient(180deg, rgba(16, 30, 55, 0.92), rgba(10, 20, 37, 0.82));
      border: 1px solid rgba(98, 221, 255, 0.14);
      border-radius: 18px;
      padding: 14px;
    }}
    .summary-grid strong {{
      display: block;
      font-size: 1.7rem;
      color: #b9f3ff;
    }}
    .stage-strip {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin: 18px 0 20px;
    }}
    .stage-card {{
      border-radius: 20px;
      padding: 16px;
      border: 1px solid rgba(98, 221, 255, 0.12);
      background: linear-gradient(180deg, rgba(10, 18, 34, 0.92), rgba(7, 13, 27, 0.84));
    }}
    .stage-card:nth-child(4n+1) {{ box-shadow: inset 0 0 0 1px rgba(60, 200, 232, 0.12); }}
    .stage-card:nth-child(4n+2) {{ box-shadow: inset 0 0 0 1px rgba(162, 108, 255, 0.14); }}
    .stage-card:nth-child(4n+3) {{ box-shadow: inset 0 0 0 1px rgba(88, 242, 167, 0.14); }}
    .stage-card:nth-child(4n+4) {{ box-shadow: inset 0 0 0 1px rgba(255, 104, 210, 0.12); }}
    .stage-card h4 {{
      margin-bottom: 8px;
    }}
    .stage-card ul {{
      margin: 0;
      padding-left: 18px;
      color: var(--muted);
    }}
    .diagram-wrap {{
      overflow-x: auto;
      background:
        radial-gradient(circle at top left, rgba(60, 200, 232, 0.10), transparent 25%),
        linear-gradient(180deg, rgba(6, 14, 28, 0.95), rgba(8, 16, 30, 0.86));
      border: 1px solid rgba(98, 221, 255, 0.16);
      border-radius: 24px;
      padding: 18px;
    }}
    .partner-card, .file-card {{
      border-top: 1px solid var(--line);
      padding-top: 20px;
      margin-top: 20px;
    }}
    .panel-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
    }}
    .soft-panel {{
      background: linear-gradient(180deg, rgba(10, 18, 34, 0.92), rgba(8, 16, 30, 0.82));
      border: 1px solid rgba(98, 221, 255, 0.12);
      border-radius: 20px;
      padding: 16px;
    }}
    .pill {{
      display: inline-block;
      margin: 4px 8px 4px 0;
      padding: 7px 11px;
      border-radius: 999px;
      background: rgba(98, 221, 255, 0.10);
      color: #d8f8ff;
      font-size: 0.92rem;
      border: 1px solid rgba(98, 221, 255, 0.12);
    }}
    .flow-list, .api-list, .simple-list {{
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 10px;
    }}
    .flow-list li, .api-list li, .simple-list li {{
      background: rgba(8, 16, 31, 0.82);
      border: 1px solid rgba(98, 221, 255, 0.10);
      border-radius: 16px;
      padding: 12px 14px;
    }}
    .function-card {{
      background: rgba(6, 14, 28, 0.82);
      border: 1px solid rgba(98, 221, 255, 0.10);
      border-radius: 18px;
      padding: 16px;
      margin-top: 12px;
    }}
    .function-card h5 {{
      margin: 0 0 6px;
      font-size: 1.05rem;
    }}
    .function-steps {{
      margin: 14px 0 0;
      padding-left: 22px;
      display: grid;
      gap: 10px;
      color: var(--muted);
    }}
    .function-steps li {{
      background: rgba(10, 18, 34, 0.78);
      border: 1px solid rgba(98, 221, 255, 0.08);
      border-radius: 14px;
      padding: 10px 12px;
    }}
    .mini-label {{
      display: inline-block;
      padding: 4px 8px;
      margin-bottom: 8px;
      border-radius: 999px;
      background: rgba(98, 221, 255, 0.10);
      color: #9eeeff;
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }}
    .api-route {{
      font-family: "Courier New", monospace;
      color: #9ae9ff;
      font-weight: 700;
      font-size: 0.95rem;
    }}
    .flow-line {{
      color: var(--muted);
      font-size: 0.95rem;
      margin-top: 4px;
    }}
    details summary {{
      cursor: pointer;
      font-weight: 700;
    }}
    pre {{
      overflow-x: auto;
      white-space: pre-wrap;
      background: rgba(8, 16, 31, 0.88);
      border: 1px solid rgba(98, 221, 255, 0.12);
      padding: 16px;
      border-radius: 18px;
      margin-top: 14px;
      color: #dffbff;
    }}
    .error {{
      color: var(--error);
      font-weight: 700;
    }}
    .raw-json-actions {{
      display: flex;
      justify-content: flex-end;
      margin: 12px 0 0;
    }}
    .copy-button {{
      padding: 10px 14px;
      font-size: 0.92rem;
      box-shadow: none;
    }}
    @media (max-width: 700px) {{
      .hero, .card {{
        border-radius: 22px;
      }}
      button {{
        width: 100%;
      }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="hero-copy">
        <div class="eyebrow">Flowprint</div>
        <h1>The blueprint for your backend.</h1>
        <p>Point it at any folder or upload files. Flowprint maps your APIs, partner logic, database models, and external calls into a live architecture diagram you can explore.</p>
        {error_html}
      </div>
      <form action="/analyze" method="post" enctype="multipart/form-data" id="analyzeForm" onsubmit="startLoading()">
        <div class="form-grid">
          <div>
            <label for="source_path">Analyze an existing local folder</label>
            <input id="source_path" name="source_path" type="text" placeholder="/absolute/path/to/project" />
          </div>
          <div>
            <label for="files">Or upload one or more files</label>
            <input id="files" name="files" type="file" multiple />
          </div>
        </div>
        <button type="submit" id="submitBtn">Generate Flowprint</button>
      </form>

      <div id="loading-overlay" style="display:none;">
        <div class="loading-box">
          <div class="loading-title">Scanning your codebase<span class="loading-dots"></span></div>
          <div class="loading-bar-track">
            <div class="loading-bar-fill" id="loadingBar"></div>
          </div>
          <div class="loading-status" id="loadingStatus">Initializing static analysis...</div>
        </div>
      </div>
    </section>
    {report_html}
  </main>
  <script>
    // ── Loading bar ────────────────────────────────────────────────────────
    const _loadingSteps = [
      [8,   "Discovering source files..."],
      [18,  "Parsing Python AST..."],
      [30,  "Mapping class-based views..."],
      [42,  "Tracing API endpoints..."],
      [54,  "Resolving ORM models..."],
      [65,  "Building partner graph..."],
      [75,  "Detecting exceptions & returns..."],
      [84,  "Generating architecture diagram..."],
      [92,  "Assembling report..."],
      [97,  "Almost there..."],
    ];

    function startLoading() {{
      const overlay = document.getElementById('loading-overlay');
      const btn     = document.getElementById('submitBtn');
      if (!overlay) return;
      overlay.style.display = 'flex';
      if (btn) {{ btn.disabled = true; btn.style.opacity = '0.5'; }}

      let step = 0;
      const bar    = document.getElementById('loadingBar');
      const status = document.getElementById('loadingStatus');

      function tick() {{
        if (step >= _loadingSteps.length) return;
        const [pct, msg] = _loadingSteps[step++];
        if (bar)    bar.style.width = pct + '%';
        if (status) status.textContent = msg;
        // Slow down toward end so it feels like real work
        const delay = step < 6 ? 900 : step < 9 ? 1400 : 2200;
        setTimeout(tick, delay);
      }}
      setTimeout(tick, 200);
    }}

    async function copyRawJson(button) {{
      const block = document.getElementById("raw-json-block");
      if (!block) return;
      const text = block.textContent || "";
      try {{
        await navigator.clipboard.writeText(text);
        const original = button.textContent;
        button.textContent = "Copied";
        setTimeout(() => {{
          button.textContent = original;
        }}, 1400);
      }} catch (error) {{
        button.textContent = "Copy failed";
        setTimeout(() => {{
          button.textContent = "Copy JSON";
        }}, 1600);
      }}
    }}
    
    function showTab(tabId) {{
      document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.getElementById('tab-' + tabId).classList.add('active');
      event.target.classList.add('active');
    }}

    function syntaxHighlight(json) {{
      return json
        .replace(/("(\\u[a-zA-Z0-9]{{4}}|\\[^u]|[^\\"])*"(\\s*:)?|\\b(true|false|null)\\b|-?\\d+(?:\\.\\d*)?(?:[eE][+\\-]?\\d+)?)/g, match => {{
          let cls = 'json-number';
          if (/^"/.test(match)) {{
            cls = /:$/.test(match) ? 'json-key' : 'json-string';
          }} else if (/true|false/.test(match)) {{
            cls = 'json-bool';
          }} else if (/null/.test(match)) {{
            cls = 'json-null';
          }}
          return `<span class="${{cls}}">${{match}}</span>`;
        }});
    }}

    function buildPayloadJson(fields) {{
      if (!fields || fields.length === 0) return {{}};
      const obj = {{}};
      fields.forEach(f => {{ obj[f] = ""; }});
      return obj;
    }}

    function resolveAuth(spec) {{
      // @authorize('key') is the most specific signal — check first
      if (spec.auth_decorator && spec.auth_decorator !== 'login_required' && spec.auth_decorator !== 'staff_member_required') {{
        return {{
          label: '@authorize',
          key: spec.auth_decorator,
          icon: '🔑',
          color: '#62ddff',
          header: 'Authorization: Token <your-token>',
        }};
      }}

      const perms = spec.permission_classes || [];
      const auth  = spec.auth_classes || [];
      const all   = [...perms, ...auth].map(s => s.toLowerCase());
      if (all.some(s => s.includes('allowany')))            return {{ label: 'No Auth Required',     icon: '🔓', color: 'var(--muted)', header: null }};
      if (all.some(s => s.includes('isadmin')))             return {{ label: 'Admin Token Required',  icon: '🔒', color: 'var(--error)', header: 'Authorization: Bearer <admin-token>' }};
      if (all.some(s => s.includes('jwt') || s.includes('simplejwt'))) return {{ label: 'JWT Bearer Token', icon: '🔑', color: '#f0c050', header: 'Authorization: Bearer <jwt-token>' }};
      if (all.some(s => s.includes('sessionauth')))         return {{ label: 'Session Auth',          icon: '🍪', color: '#f0c050', header: 'Cookie: sessionid=<session-id>' }};
      if (all.some(s => s.includes('tokenauthentication'))) return {{ label: 'DRF Token Auth',        icon: '🔑', color: '#f0c050', header: 'Authorization: Token <your-token>' }};
      if (all.some(s => s.includes('isauthentic') || s.includes('login_required'))) return {{ label: 'Authentication Required', icon: '🔒', color: '#f0c050', header: 'Authorization: Bearer <token>' }};
      if (spec.auth_decorator === 'login_required')         return {{ label: '@login_required',       icon: '🔒', color: '#f0c050', header: 'Authorization: Bearer <token>' }};
      if (spec.auth_decorator === 'staff_member_required')  return {{ label: '@staff_member_required',icon: '🔒', color: 'var(--error)', header: 'Authorization: Bearer <admin-token>' }};
      if (perms.length > 0) return {{ label: perms.join(', '), icon: '🔒', color: '#f0c050', header: 'Authorization: Bearer <token>' }};
      return {{ label: 'Unknown — check permission_classes', icon: '⚠️', color: 'var(--muted)', header: 'Authorization: Bearer <token>' }};
    }}

    // Escape HTML so angle-bracket placeholders like <id> survive innerHTML rendering
    function escHtml(s) {{
      return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }}

    function buildCurl(spec, authInfo) {{
      const NL = String.fromCharCode(10);
      const DETAIL_ACTIONS = ['retrieve', 'update', 'partial_update', 'destroy'];

      // Extract method from label: "GET type (list)" → "GET"
      const methodMatch = spec.label.match(/^([A-Z]+)/);
      const method = methodMatch ? methodMatch[1] : 'GET';

      // Build URL path from label pattern "METHOD prefix (action)"
      let urlPath = null;
      const labelMatch = spec.label.match(/^[A-Z\\/]+\\s+([^\\s(]+)\\s+\\(([^)]+)\\)/);
      if (labelMatch) {{
        const prefix = labelMatch[1];
        const action = labelMatch[2];
        const isDetail = DETAIL_ACTIONS.includes(action);
        urlPath = '/' + prefix + '/' + (isDetail ? '<id>/' : '');
      }}

      // Fallback: try path('...') in context
      if (!urlPath && spec.context) {{
        const ctxMatch = spec.context.match(/path\\s*\\(\\s*['"]([^'"]+)['"]/);
        if (ctxMatch) urlPath = '/' + ctxMatch[1];
      }}

      if (!urlPath) urlPath = '/api/your-endpoint/';

      const header = authInfo.header ? escHtml(authInfo.header) : null;
      const lines = ['curl -X ' + method + ' "https://your-api.server' + escHtml(urlPath) + '"'];
      if (header) lines.push('  -H "' + header + '"');
      lines.push('  -H "Content-Type: application/json"');
      if (spec.payload && spec.payload.length && !['GET', 'DELETE'].includes(method)) {{
        const body = {{}};
        spec.payload.forEach(f => {{ body[f] = ''; }});
        const bodyStr = escHtml(JSON.stringify(body, null, 2)).split(NL).join(NL + '       ');
        lines.push("  -d '" + bodyStr + "'");
      }}
      return lines.join(' \\\\' + NL);
    }}

    function showApiSpec(spec, rowEl) {{
      document.querySelectorAll('.api-row.selected').forEach(r => r.classList.remove('selected'));
      if (rowEl) rowEl.classList.add('selected');
      const panel   = document.getElementById('apiSpecPanel');
      const authInfo = resolveAuth(spec);

      // Build payload JSON object
      const payloadObj  = buildPayloadJson(spec.payload);
      const payloadJson = JSON.stringify(payloadObj, null, 2);

      // Success response — flat shape matching real API: {{ status, data, message }}
      const successArr = Array.isArray(spec.success) && spec.success.length
        ? spec.success : (spec.success ? [spec.success] : ['HTTP 200 OK']);
      const firstSuccess = successArr[0] || 'HTTP 200 OK';
      const sm = firstSuccess.match(/HTTP\\s+(\\d{{3}})/);
      const successCode = sm ? parseInt(sm[1]) : 200;
      const successMsg  = firstSuccess.replace(/^HTTP\\s+\\d{{3}}\\s*[—-]?\\s*/, '').replace(/^["']|["']$/g, '').trim() || 'Success';
      const successResp = {{ status: successCode, data: {{}}, message: successMsg }};

      // Error responses — flat array of {{ status, message }}
      const errList = [];
      (spec.exceptions || []).forEach(e => {{
        const em = e.match(/HTTP\\s+(\\d{{3}})/);
        if (em) {{
          const code = parseInt(em[1]);
          const msg  = e.replace(/^HTTP\\s+\\d{{3}}\\s*[—-]?\\s*/, '').replace(/^["']|["']$/g, '').trim() || 'Error';
          if (!errList.find(x => x.status === code && x.message === msg))
            errList.push({{ status: code, message: msg }});
        }} else if (!e.startsWith('HTTP')) {{
          errList.push({{ status: 400, error: e }});
        }}
      }});
      const errResp = errList.length === 1 ? errList[0] : (errList.length ? errList : {{ message: 'No error returns detected' }});

      const curlCmd = buildCurl(spec, authInfo);

      panel.innerHTML = `
        <div class="spec-header">
          <h2 class="spec-title">${{spec.label}}</h2>
          <p class="spec-source">
            ${{spec.serializer ? `<span style="color:var(--primary);margin-right:10px;">⬡ ${{spec.serializer}}</span>` : ''}}
            ${{spec.file}}
          </p>
        </div>

        <div class="spec-section">
          <div class="spec-block-head">
            <span class="spec-label" style="color:${{authInfo.color}};">${{authInfo.icon}} AUTHENTICATION</span>
          </div>
          <div class="auth-badge" style="border-color:${{authInfo.color}}20; background:${{authInfo.color}}0d;">
            <span style="color:${{authInfo.color}}; font-weight:700;">${{authInfo.label}}</span>
            ${{authInfo.key ? `<div style="margin-top:6px;"><span class="auth-pill" style="background:rgba(98,221,255,0.12);border-color:rgba(98,221,255,0.3);color:var(--primary);font-size:0.8rem;padding:4px 10px;">Permission key: <strong>${{authInfo.key}}</strong></span></div>` : ''}}
            ${{authInfo.header ? `<code class="auth-header">${{authInfo.header}}</code>` : ''}}
            ${{(spec.permission_classes||[]).length ? `<div class="auth-classes">${{(spec.permission_classes||[]).map(p=>`<span class="auth-pill">${{p}}</span>`).join('')}}</div>` : ''}}
          </div>
        </div>

        <div class="spec-section">
          <div class="spec-block-head">
            <span class="spec-label payload-label">PAYLOAD</span>
            <button class="spec-copy-btn" onclick="copySpecBlock('payload-block', this)">Copy</button>
          </div>
          <div class="json-block" id="payload-block">${{syntaxHighlight(payloadJson)}}</div>
        </div>

        <div class="spec-section">
          <div class="spec-block-head">
            <span class="spec-label" style="color:#c8a4ff;">CURL EXAMPLE</span>
            <button class="spec-copy-btn" onclick="copySpecBlock('curl-block', this)">Copy</button>
          </div>
          <div class="json-block curl-block" id="curl-block" style="border-color:rgba(200,164,255,0.2); color:#c8a4ff; white-space:pre;">${{curlCmd}}</div>
        </div>


        ${{(spec.outbound_calls||[]).length ? `
        <div class="spec-section">
          <div class="spec-block-head">
            <span class="spec-label" style="color:#ffd166;">OUTBOUND CALLS</span>
          </div>
          <div class="json-block" style="border-color:rgba(255,209,102,0.2);">${{syntaxHighlight(JSON.stringify(spec.outbound_calls, null, 2))}}</div>
        </div>` : ''}}

        <div class="spec-section">
          <div class="spec-block-head">
            <span class="spec-label success-label">SUCCESS RESPONSE</span>
          </div>
          <div class="json-block success-block">${{syntaxHighlight(JSON.stringify(successResp, null, 2))}}</div>
        </div>

        <div class="spec-section">
          <div class="spec-block-head">
            <span class="spec-label error-label">ERROR RESPONSES</span>
          </div>
          <div class="json-block error-block">${{syntaxHighlight(JSON.stringify(errResp, null, 2))}}</div>
        </div>
      `;
    }}

    function copySpecBlock(blockId, btn) {{
      const el = document.getElementById(blockId);
      const text = el ? el.innerText : '';
      navigator.clipboard.writeText(text).then(() => {{
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        btn.style.background = 'rgba(110, 255, 197, 0.2)';
        btn.style.color = 'var(--success)';
        setTimeout(() => {{
          btn.textContent = orig;
          btn.style.background = '';
          btn.style.color = '';
        }}, 1800);
      }});
    }}

    function copyMermaid() {{
      const el = document.getElementById('mermaid-graph');
      navigator.clipboard.writeText(el.textContent);
      alert('Mermaid code copied! Paste into any Mermaid viewer.');
    }}

    // ── Diagram zoom / pan ──────────────────────────────────────────────
    let _zoom = 1.0, _panX = 0, _panY = 0;
    let _dragging = false, _lastX = 0, _lastY = 0;

    function _applyTransform() {{
      const canvas = document.getElementById('diagram-canvas');
      if (!canvas) return;
      canvas.style.transform = `translate(${{_panX}}px, ${{_panY}}px) scale(${{_zoom}})`;
      const lbl = document.getElementById('zoom-level');
      if (lbl) lbl.textContent = Math.round(_zoom * 100) + '%';
    }}

    function zoomDiagram(delta) {{
      _zoom = Math.min(4.0, Math.max(0.15, _zoom + delta));
      _applyTransform();
    }}

    function zoomReset() {{
      _zoom = 1.0; _panX = 0; _panY = 0;
      _applyTransform();
    }}

    document.addEventListener('DOMContentLoaded', () => {{
      const viewport = document.getElementById('diagram-viewport');
      const canvas   = document.getElementById('diagram-canvas');
      if (!viewport || !canvas) return;

      // Trackpad two-finger scroll → pan; pinch (ctrlKey) → zoom toward cursor
      viewport.addEventListener('wheel', (e) => {{
        e.preventDefault();
        if (e.ctrlKey) {{
          // Pinch-to-zoom: zoom toward the pointer
          const rect  = viewport.getBoundingClientRect();
          const mx    = e.clientX - rect.left;
          const my    = e.clientY - rect.top;
          const delta = e.deltaY < 0 ? 0.08 : -0.08;
          const newZ  = Math.min(4.0, Math.max(0.15, _zoom + delta));
          const ratio = newZ / _zoom;
          _panX = mx - ratio * (mx - _panX);
          _panY = my - ratio * (my - _panY);
          _zoom = newZ;
        }} else {{
          // Two-finger scroll → pan
          _panX -= e.deltaX;
          _panY -= e.deltaY;
        }}
        _applyTransform();
      }}, {{ passive: false }});

      // Drag to pan
      canvas.addEventListener('mousedown', (e) => {{
        if (e.button !== 0) return;
        _dragging = true;
        _lastX = e.clientX; _lastY = e.clientY;
        canvas.classList.add('dragging');
        e.preventDefault();
      }});
      window.addEventListener('mousemove', (e) => {{
        if (!_dragging) return;
        _panX += e.clientX - _lastX;
        _panY += e.clientY - _lastY;
        _lastX = e.clientX; _lastY = e.clientY;
        _applyTransform();
      }});
      window.addEventListener('mouseup', () => {{
        if (_dragging) {{
          _dragging = false;
          canvas.classList.remove('dragging');
        }}
      }});

      // Touch / trackpad two-finger pan
      let _lastTouchDist = null;
      viewport.addEventListener('touchstart', (e) => {{
        if (e.touches.length === 2) {{
          const dx = e.touches[0].clientX - e.touches[1].clientX;
          const dy = e.touches[0].clientY - e.touches[1].clientY;
          _lastTouchDist = Math.hypot(dx, dy);
        }}
      }}, {{ passive: true }});
      viewport.addEventListener('touchmove', (e) => {{
        if (e.touches.length === 2) {{
          e.preventDefault();
          const dx   = e.touches[0].clientX - e.touches[1].clientX;
          const dy   = e.touches[0].clientY - e.touches[1].clientY;
          const dist = Math.hypot(dx, dy);
          if (_lastTouchDist) {{
            const ratio = dist / _lastTouchDist;
            _zoom = Math.min(4.0, Math.max(0.15, _zoom * ratio));
            _applyTransform();
          }}
          _lastTouchDist = dist;
        }}
      }}, {{ passive: false }});
      viewport.addEventListener('touchend', () => {{ _lastTouchDist = null; }});
    }});

    function handleOmniSearch() {{
      const query = document.getElementById('omniSearch').value.toLowerCase();
      
      // Auto-switch tabs based on query keywords
      if (query.includes('flow') || query.includes('map')) showTab('flows');
      if (query.includes('bug') || query.includes('error')) showTab('diagnostics');
      if (query.includes('schema') || query.includes('model')) showTab('schema');
      if (query.includes('config')) showTab('configs');
      
      // Apply filtering to all relevant cards
      document.querySelectorAll('.partner-card, .file-card, .api-table tr, .soft-panel').forEach(el => {{
         const text = el.innerText.toLowerCase();
         if (text.includes(query) || !query) {{
            el.style.display = "";
         }} else {{
            el.style.display = "none";
         }}
      }});
    }}
  </script>
</body>
</html>"""


def render_diagnostic_row(d: dict[str, Any]) -> str:
    sev_class = f"severity-{d['severity'].lower()}"
    return f"""
    <tr>
      <td><span class="pill">{html.escape(d["type"])}</span></td>
      <td><span class="{sev_class}">{html.escape(d["severity"])}</span></td>
      <td>{html.escape(d["message"])}</td>
      <td><small>{html.escape(shorten_path(d["file"]))}</small></td>
    </tr>
    """


def render_api_row(api: dict[str, Any]) -> str:
    checks = render_pills(api.get("checks", []), "None")
    # Extract unique model names from db_ops e.g. "create BomType" → "BomType"
    model_names = sorted({op.split(" ", 1)[1] for op in api.get("db_ops", []) if " " in op})
    models = render_pills(model_names, "None")
    app_tag = f'<span class="pill" style="background:var(--primary-soft);">{html.escape(api.get("app", "root"))}</span>'
    
    # Store spec in a data attribute (html.escape handles quotes/angle-brackets safely)
    spec_escaped = html.escape(json.dumps({
        "label": api["label"],
        "payload": api.get("payload", []),
        "exceptions": api.get("exceptions", []),
        "success": api.get("success_paths", ["Returns standard 200/201 Response"]),
        "file": shorten_path(api["file"]),
        "context": api.get("context", ""),
        "permission_classes": api.get("permission_classes", []),
        "auth_classes": api.get("auth_classes", []),
        "db_ops": api.get("db_ops", []),
        "outbound_calls": api.get("outbound_calls", []),
        "serializer": api.get("serializer_class") or "",
        "auth_decorator": api.get("auth_decorator") or "",
    }), quote=True)

    return f"""
    <tr class="api-row" onclick="showApiSpec(JSON.parse(this.dataset.spec), this)" data-spec="{spec_escaped}">
      <td>{app_tag}</td>
      <td><code class="api-route">{html.escape(api["label"])}</code></td>
      <td>{checks}</td>
      <td>{models}</td>
      <td><small>{html.escape(shorten_path(api["file"]))}</small></td>
    </tr>
    """

def render_db_card(db: dict[str, Any]) -> str:
    return f"""
    <div class="soft-panel">
      <div class="mini-label">{html.escape(db["operation"])}</div>
      <h4>{html.escape(db["table"])}</h4>
      <p style="font-size:0.85rem; font-family:monospace; color:var(--primary);">{html.escape(db["context"])}</p>
      <small>File: {html.escape(shorten_path(db["file"]))}</small>
    </div>
    """

def render_model_schema_card(model: dict[str, Any]) -> str:
    fields_html = "".join(
        f"<li><strong>{html.escape(f['name'])}</strong>: <span style='color:var(--primary);'>{html.escape(f['type'])}</span>"
        f"{f' &rarr; {html.escape(f['related_to'])}' if f['related_to'] else ''}</li>"
        for f in model["fields"]
    )
    return f"""
    <div class="soft-panel">
      <h4>{html.escape(model["name"])}</h4>
      <p><small>{html.escape(shorten_path(model["file"]))}</small></p>
      <ul class="simple-list" style="margin-top:10px; font-size:0.85rem;">
        {fields_html or "<li>No fields detected.</li>"}
      </ul>
    </div>
    """


def render_partner_flow_card(name: str, data: dict[str, Any]) -> str:
    return f"""
    <div class="soft-panel">
      <h4>{html.escape(name)} Sub-system</h4>
      <p>Entry: <code>{html.escape(data['inbound_apis'][0]['label'] if data['inbound_apis'] else 'Generic')}</code></p>
      <ul class="simple-list" style="font-size:0.85rem;">
        <li>{len(data['checks'])} logic checks</li>
        <li>{len(data['database_tables'])} model interactions</li>
      </ul>
      <div style="margin-top:12px;">
         {render_pills(data['checks'][:3], "No checks")}
      </div>
    </div>
    """
    files = render_pills(shorten_paths(data["files"]), "No files found")
    inbound = render_api_list(data["inbound_apis"], "No inbound APIs linked to this partner.")
    outbound = render_api_list(data["outbound_apis"], "No outbound APIs linked to this partner.")
    tables = render_database_list(data["database_tables"], "No database table flow linked to this partner.")
    flow = render_flow_list(data["flow_points"], "No flow points collected for this partner.")
    functions = render_function_cards(data["functions"], "No structured function flow linked to this partner.")
    return f"""
    <article class="partner-card">
      <div class="section-head">
        <div>
          <h3>{html.escape(name)}</h3>
          <p>{build_partner_tagline(name, data)}</p>
        </div>
      </div>
      <div class="diagram-wrap">
        {render_architecture_map(build_partner_architecture_graph(name, data), f"{name} partner flow")}
      </div>
      {render_arch_legend()}
      <div class="panel-grid" style="margin-top:16px;">
        <div class="soft-panel">
          <h4>Checks</h4>
          <p>{checks}</p>
          <h4>Files</h4>
          <p>{files}</p>
        </div>
        <div class="soft-panel">
          <h4>Entry APIs</h4>
          <ul class="api-list">{inbound}</ul>
        </div>
        <div class="soft-panel">
          <h4>Database Flow</h4>
          <ul class="api-list">{tables}</ul>
        </div>
        <div class="soft-panel">
          <h4>External APIs</h4>
          <ul class="api-list">{outbound}</ul>
        </div>
      </div>
      <div class="soft-panel" style="margin-top:16px;">
        <h4>Structured Flow</h4>
        {functions}
      </div>
      <div class="soft-panel" style="margin-top:16px;">
        <h4>Decision Evidence</h4>
        <ul class="flow-list">{flow}</ul>
      </div>
    </article>
    """


def render_file_card(item: dict[str, Any]) -> str:
    return f"""
    <article class="file-card">
      <div class="section-head">
        <div>
          <h3>{html.escape(item["path"])}</h3>
          <p>{html.escape(item["summary"])}</p>
        </div>
      </div>
      {render_stage_strip(build_file_stages(item))}
      <div class="panel-grid" style="margin-top:16px;">
        <div class="soft-panel">
          <h4>Partners</h4>
          <p>{render_pills(item["partners"], "None detected")}</p>
          <h4>Checks</h4>
          <p>{render_pills(item["checks"], "None detected")}</p>
        </div>
        <div class="soft-panel">
          <h4>Entry APIs</h4>
          <ul class="api-list">{render_api_list(item["inbound_apis"], "No inbound APIs found.")}</ul>
        </div>
        <div class="soft-panel">
          <h4>Database Flow</h4>
          <ul class="api-list">{render_database_list(item["database_tables"], "No table flow found.")}</ul>
        </div>
        <div class="soft-panel">
          <h4>External APIs</h4>
          <ul class="api-list">{render_api_list(item["outbound_apis"], "No outbound APIs found.")}</ul>
        </div>
      </div>
      <div class="soft-panel" style="margin-top:16px;">
        <h4>Function Breakdown</h4>
        {render_function_cards(item["functions"], "No function-level flow extracted for this file.")}
      </div>
      <div class="soft-panel" style="margin-top:16px;">
        <h4>Flow Hints</h4>
        <ul class="flow-list">{render_flow_list(item["flow_points"], "No flow points detected.")}</ul>
      </div>
    </article>
    """


def build_global_stages(report: dict[str, Any]) -> list[dict[str, Any]]:
    inbound = [item["label"] for item in report["apis"]["inbound"][:3]]
    outbound = [item["label"] for item in report["apis"]["outbound"][:3]]
    databases = [item["label"] for item in report["databases"][:3]]
    partner_names = list(report["partners"].keys())[:5]
    check_names = sorted({check for data in report["partners"].values() for check in data["checks"]})[:5]
    return [
        {"title": "Entry", "items": inbound or ["Scan source files for API entry points"]},
        {"title": "Partner Routing", "items": partner_names or ["No partner branches detected"]},
        {"title": "Checks", "items": check_names or ["No checks detected"]},
        {"title": "Database", "items": databases or ["No database tables detected"]},
        {"title": "External Calls", "items": outbound or ["No outbound APIs detected"]},
        {"title": "Outcomes", "items": build_global_outcomes(report)},
    ]


def build_partner_stages(name: str, data: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"title": "Entry", "items": [item["label"] for item in data["inbound_apis"][:3]] or [f"{name} reached through shared routing"]},
        {"title": "Checks", "items": data["checks"][:5] or ["No checks detected"]},
        {"title": "Decision", "items": [item["summary"] for item in data["flow_points"][:2]] or ["No major branch detected"]},
        {"title": "Database", "items": [item["label"] for item in data["database_tables"][:3]] or ["No table touches found"]},
        {"title": "External APIs", "items": [item["label"] for item in data["outbound_apis"][:3]] or ["No external APIs found"]},
        {"title": "Outcome", "items": build_partner_outcomes(data)},
    ]


def build_file_stages(item: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"title": "Partner Scope", "items": item["partners"][:4] or ["No partner scope detected"]},
        {"title": "Checks", "items": item["checks"][:4] or ["No checks detected"]},
        {"title": "Entry APIs", "items": [api["label"] for api in item["inbound_apis"][:3]] or ["No inbound APIs"]},
        {"title": "Database", "items": [db["label"] for db in item["database_tables"][:3]] or ["No database table flow"]},
        {"title": "External APIs", "items": [api["label"] for api in item["outbound_apis"][:3]] or ["No outbound APIs"]},
        {"title": "Flow Points", "items": [point["summary"] for point in item["flow_points"][:2]] or ["No flow hints"]},
    ]


def build_global_outcomes(report: dict[str, Any]) -> list[str]:
    if report["overview"]["outbound_apis"] > 0:
        return ["Requests continue to partner/external services", "Decisions end in return or response branches"]
    if report["overview"]["database_tables"] > 0:
        return ["Flow persists to database tables", "Decisions end in stored state changes"]
    if report["overview"]["flow_points"] > 0:
        return ["Flow stays internal to the codebase", "Decisions end in local branch outcomes"]
    return ["No strong outcome signals detected"]


def build_partner_outcomes(data: dict[str, Any]) -> list[str]:
    summaries = [point["summary"] for point in data["flow_points"] if "return" in point["summary"].lower()][:2]
    if summaries:
        return summaries
    if data["database_tables"]:
        return ["Partner flow appears to end in table read or write state"]
    if data["outbound_apis"]:
        return ["Partner flow appears to exit via external API call"]
    return ["Outcome is not explicit in scanned lines"]


def build_partner_tagline(name: str, data: dict[str, Any]) -> str:
    return (
        f"{name} touches {len(data['checks'])} check types, {len(data['inbound_apis'])} entry APIs, "
        f"{len(data['database_tables'])} tables, and {len(data['outbound_apis'])} external APIs."
    )


def build_global_architecture_graph(report: dict[str, Any]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    nodes.append(make_node("entry", "entry_api", "Entry APIs", summarize_labels(report["apis"]["inbound"], "Shared routes"), col=0))
    nodes.append(make_node("router", "decision", "Partner Router", summarize_strings(list(report["partners"].keys()), "Shared code path"), col=1))
    edges.append(make_edge("entry", "router", "request"))

    top_y = 110
    gap_y = 170
    for index, (partner, data) in enumerate(list(report["partners"].items())[:6]):
        check_id = f"{partner}-check"
        db_id = f"{partner}-db"
        api_id = f"{partner}-api"
        ok_id = f"{partner}-ok"
        fail_id = f"{partner}-fail"

        y = top_y + index * gap_y
        check_text = summarize_strings(data["checks"], "No checks detected", limit=3)
        db_text = summarize_databases(data["database_tables"], "No database tables", limit=3)
        api_text = summarize_labels(data["outbound_apis"], "No external APIs", limit=2)
        ok_text = summarize_outcomes(data)
        fail_text = summarize_failures(data)

        nodes.extend(
            [
                make_node(check_id, "check", f"{partner} checks", check_text, col=2, row=y),
                make_node(db_id, "database", f"{partner} tables", db_text, col=3, row=y),
                make_node(api_id, "external_api", f"{partner} APIs", api_text, col=4, row=y),
                make_node(ok_id, "success", f"{partner} success", ok_text, col=5, row=y - 52),
                make_node(fail_id, "failure", f"{partner} failure", fail_text, col=5, row=y + 52),
            ]
        )
        edges.extend(
            [
                make_edge("router", check_id, partner),
                make_edge(check_id, db_id, "pass", kind="success"),
                make_edge(check_id, fail_id, "fail", kind="failure"),
                make_edge(db_id, api_id, "read/write"),
                make_edge(api_id, ok_id, "response", kind="success"),
            ]
        )

    return {"nodes": nodes, "edges": edges}


def build_partner_architecture_graph(name: str, data: dict[str, Any]) -> dict[str, Any]:
    inbound_text = summarize_labels(data["inbound_apis"], "Shared route", limit=2)
    check_text = summarize_strings(data["checks"], "No checks detected", limit=4)
    decision_text = summarize_flow(data["flow_points"], fallback="No explicit branch detected")
    database_text = summarize_databases(data["database_tables"], "No database tables", limit=3)
    api_text = summarize_labels(data["outbound_apis"], "No external APIs", limit=3)
    success_text = summarize_outcomes(data)
    failure_text = summarize_failures(data)

    nodes = [
        make_node("entry", "entry_api", "Entry API", inbound_text, col=0),
        make_node("partner", "decision", f"{name} route", summarize_flow(data["flow_points"], fallback=f"Route into {name} logic", only_branch=True), col=1),
        make_node("checks", "check", "Checks", check_text, col=2, row=110),
        make_node("decision", "decision", "Decision", decision_text, col=3, row=110),
        make_node("database", "database", "Database tables", database_text, col=4, row=110),
        make_node("apis", "external_api", "Partner APIs", api_text, col=5, row=110),
        make_node("success", "success", "Success path", success_text, col=6, row=58),
        make_node("failure", "failure", "Failure path", failure_text, col=6, row=162),
    ]
    edges = [
        make_edge("entry", "partner", "request"),
        make_edge("partner", "checks", "partner selected"),
        make_edge("checks", "decision", "evaluate"),
        make_edge("decision", "database", "success", kind="success"),
        make_edge("decision", "failure", "failure", kind="failure"),
        make_edge("database", "apis", "persist/load"),
        make_edge("apis", "success", "partner response", kind="success"),
    ]
    return {"nodes": nodes, "edges": edges}


def render_stage_strip(stages: list[dict[str, Any]]) -> str:
    cards = []
    for stage in stages:
        items = "".join(f"<li>{html.escape(item)}</li>" for item in stage["items"][:3])
        cards.append(
            "<div class=\"stage-card\">"
            f"<div class=\"mini-label\">{html.escape(stage['title'])}</div>"
            f"<h4>{html.escape(stage['title'])}</h4>"
            f"<ul>{items}</ul>"
            "</div>"
        )
    return f'<div class="stage-strip">{"".join(cards)}</div>'


def render_svg_flow(stages: list[dict[str, Any]], title: str) -> str:
    stage_width = 210
    stage_height = 108
    gap = 48
    padding_x = 24
    width = padding_x * 2 + len(stages) * stage_width + max(0, len(stages) - 1) * gap
    height = 220
    svg_parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}" xmlns="http://www.w3.org/2000/svg">',
        "<defs>",
        '<linearGradient id="boxFill" x1="0" y1="0" x2="0" y2="1">',
        '<stop offset="0%" stop-color="#fffdf9" />',
        '<stop offset="100%" stop-color="#f4efe6" />',
        "</linearGradient>",
        "</defs>",
    ]

    y = 52
    for index, stage in enumerate(stages):
        x = padding_x + index * (stage_width + gap)
        svg_parts.append(
            f'<rect x="{x}" y="{y}" rx="22" ry="22" width="{stage_width}" height="{stage_height}" fill="url(#boxFill)" stroke="#d8cebf" />'
        )
        svg_parts.append(
            f'<text x="{x + 18}" y="{y + 28}" font-size="16" font-family="Georgia, serif" font-weight="700" fill="#0f5f56">{html.escape(stage["title"])}</text>'
        )
        for item_index, item in enumerate(stage["items"][:2]):
            svg_parts.append(
                f'<text x="{x + 18}" y="{y + 54 + item_index * 18}" font-size="12" font-family="Georgia, serif" fill="#5f564d">{html.escape(trim_text(item, 28))}</text>'
            )
        if index < len(stages) - 1:
            line_x = x + stage_width
            next_x = x + stage_width + gap
            svg_parts.append(
                f'<line x1="{line_x + 8}" y1="{y + stage_height / 2}" x2="{next_x - 14}" y2="{y + stage_height / 2}" stroke="#0f5f56" stroke-width="3" />'
            )
            svg_parts.append(
                f'<polygon points="{next_x - 14},{y + stage_height / 2 - 6} {next_x},{y + stage_height / 2} {next_x - 14},{y + stage_height / 2 + 6}" fill="#0f5f56" />'
            )
    svg_parts.append("</svg>")
    return "".join(svg_parts)


def render_architecture_map(graph: dict[str, Any], title: str) -> str:
    nodes = graph["nodes"]
    edges = graph["edges"]
    if not nodes:
        return "<p>No diagram data available.</p>"

    col_positions = [30, 250, 470, 690, 910, 1130, 1350]
    default_y = 88
    row_gap = 170
    box_width = 190
    box_height = 84

    type_style = {
        "entry_api": {"fill": "#112b35", "stroke": "#3cc8e8"},
        "decision": {"fill": "#241a3c", "stroke": "#a26cff"},
        "check": {"fill": "#11202f", "stroke": "#7ed7ff"},
        "database": {"fill": "#10281d", "stroke": "#58f2a7"},
        "external_api": {"fill": "#2a1833", "stroke": "#ff68d2"},
        "success": {"fill": "#0d2a23", "stroke": "#49f7a1"},
        "failure": {"fill": "#34161d", "stroke": "#ff7a8e"},
    }

    positioned: dict[str, dict[str, Any]] = {}
    node_counts: dict[int, int] = {}
    for node in nodes:
        raw_col = node.get("col")
        col = raw_col if raw_col is not None else min(len(node_counts), len(col_positions) - 1)
        count = node_counts.get(col, 0)
        x = col_positions[min(col, len(col_positions) - 1)]
        raw_row = node.get("row")
        y = raw_row if raw_row is not None else default_y + count * row_gap
        node_counts[col] = count + 1
        positioned[node["id"]] = {**node, "x": x, "y": y}

    width = max(item["x"] for item in positioned.values()) + box_width + 40
    height = max(item["y"] for item in positioned.values()) + box_height + 40

    svg_parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}" xmlns="http://www.w3.org/2000/svg">',
        "<defs>",
        '<filter id="neon-glow" x="-50%" y="-50%" width="200%" height="200%">',
        '<feGaussianBlur stdDeviation="6" result="blur" />',
        '<feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>',
        "</filter>",
        '<marker id="arrow-green" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto">',
        '<path d="M0,0 L12,6 L0,12 Z" fill="#49f7a1" />',
        "</marker>",
        '<marker id="arrow-red" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto">',
        '<path d="M0,0 L12,6 L0,12 Z" fill="#ff7a8e" />',
        "</marker>",
        '<marker id="arrow-neutral" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto">',
        '<path d="M0,0 L12,6 L0,12 Z" fill="#74bff8" />',
        "</marker>",
        "</defs>",
        f'<text x="24" y="28" font-size="16" font-family="Avenir Next, Segoe UI, sans-serif" font-weight="700" fill="#d9f7ff">{html.escape(title)}</text>',
    ]

    for edge in edges:
        source = positioned[edge["from"]]
        target = positioned[edge["to"]]
        start_x = source["x"] + box_width
        start_y = source["y"] + box_height / 2
        end_x = target["x"]
        end_y = target["y"] + box_height / 2
        mid_x = (start_x + end_x) / 2
        marker = "arrow-neutral"
        color = "#74bff8"
        if edge.get("kind") == "success":
            marker = "arrow-green"
            color = "#49f7a1"
        elif edge.get("kind") == "failure":
            marker = "arrow-red"
            color = "#ff7a8e"
        path = f"M {start_x} {start_y} C {mid_x} {start_y}, {mid_x} {end_y}, {end_x - 10} {end_y}"
        svg_parts.append(
            f'<path d="{path}" fill="none" stroke="{color}" stroke-width="3" marker-end="url(#{marker})" filter="url(#neon-glow)" />'
        )
        label_x = mid_x
        label_y = min(start_y, end_y) - 10 if abs(start_y - end_y) > 24 else start_y - 10
        svg_parts.append(
            f'<text x="{label_x}" y="{label_y}" text-anchor="middle" font-size="11" font-family="Avenir Next, Segoe UI, sans-serif" fill="{color}">{html.escape(edge["label"])}</text>'
        )

    for node in positioned.values():
        style = type_style.get(node["type"], {"fill": "#fffdf9", "stroke": "#d8cebf"})
        x = node["x"]
        y = node["y"]
        svg_parts.append(
            f'<rect x="{x}" y="{y}" rx="20" ry="20" width="{box_width}" height="{box_height}" fill="{style["fill"]}" stroke="{style["stroke"]}" stroke-width="2" filter="url(#neon-glow)" />'
        )
        svg_parts.append(
            f'<text x="{x + 16}" y="{y + 24}" font-size="11" font-family="Avenir Next, Segoe UI, sans-serif" font-weight="700" fill="#8ee5ff">{html.escape(node["type"].replace("_", " ").upper())}</text>'
        )
        svg_parts.append(
            f'<text x="{x + 16}" y="{y + 42}" font-size="16" font-family="Avenir Next, Segoe UI, sans-serif" font-weight="700" fill="#f5fbff">{html.escape(trim_text(node["title"], 22))}</text>'
        )
        for idx, line in enumerate(node["lines"][:2]):
            svg_parts.append(
                f'<text x="{x + 16}" y="{y + 62 + idx * 14}" font-size="11" font-family="Avenir Next, Segoe UI, sans-serif" fill="#cdefff">{html.escape(trim_text(line, 28))}</text>'
            )

    svg_parts.append("</svg>")
    return "".join(svg_parts)


def render_arch_legend() -> str:
    items = [
        ("Entry API", "entry_api"),
        ("Decision", "decision"),
        ("Check", "check"),
        ("Database", "database"),
        ("External API", "external_api"),
        ("Success", "success"),
        ("Failure", "failure"),
    ]
    swatches = []
    fills = {
        "entry_api": "#112b35",
        "decision": "#241a3c",
        "check": "#11202f",
        "database": "#10281d",
        "external_api": "#2a1833",
        "success": "#0d2a23",
        "failure": "#34161d",
    }
    for label, key in items:
        swatches.append(
            f'<span class="pill" style="background:{fills[key]};">{html.escape(label)}</span>'
        )
    swatches.append('<span class="pill">Green arrow = success path</span>')
    swatches.append('<span class="pill">Red arrow = failure path</span>')
    return f'<p style="margin-top:14px;">{"".join(swatches)}</p>'


def make_node(node_id: str, node_type: str, title: str, body: str, col: int | None = None, row: int | None = None) -> dict[str, Any]:
    return {
        "id": node_id,
        "type": node_type,
        "title": title,
        "lines": split_lines(body),
        "col": col if col is not None else infer_col(node_type),
        "row": row,
    }


def make_edge(source: str, target: str, label: str, kind: str = "neutral") -> dict[str, Any]:
    return {"from": source, "to": target, "label": label, "kind": kind}


def infer_col(node_type: str) -> int:
    order = {
        "entry_api": 0,
        "decision": 1,
        "check": 2,
        "database": 3,
        "external_api": 4,
        "success": 5,
        "failure": 5,
    }
    return order.get(node_type, 1)


def split_lines(text: str) -> list[str]:
    return [part.strip() for part in text.split(" | ") if part.strip()]


def summarize_labels(items: list[dict[str, Any]], fallback: str, limit: int = 3) -> str:
    labels = [item["label"] for item in items[:limit]]
    return " | ".join(labels) if labels else fallback


def summarize_strings(items: list[str], fallback: str, limit: int = 3) -> str:
    return " | ".join(items[:limit]) if items else fallback


def summarize_databases(items: list[dict[str, Any]], fallback: str, limit: int = 3) -> str:
    labels = [item["label"] for item in items[:limit]]
    return " | ".join(labels) if labels else fallback


def summarize_flow(items: list[dict[str, Any]], fallback: str, only_branch: bool = False) -> str:
    selected = []
    for item in items:
        summary = item["summary"]
        lowered = summary.lower()
        if only_branch and not any(word in lowered for word in ("if ", "elif", "case", "switch")):
            continue
        selected.append(summary)
        if len(selected) == 2:
            break
    return " | ".join(selected) if selected else fallback


def summarize_outcomes(data: dict[str, Any]) -> str:
    returns = [item["summary"] for item in data["flow_points"] if "return" in item["summary"].lower()]
    if returns:
        return " | ".join(returns[:2])
    if data["database_tables"]:
        return summarize_databases(data["database_tables"], "Database state change", limit=2)
    if data["outbound_apis"]:
        return "Partner API returns downstream response"
    return "Success outcome inferred from branch pass"


def summarize_failures(data: dict[str, Any]) -> str:
    failed = []
    for item in data["flow_points"]:
        summary = item["summary"].lower()
        if any(word in summary for word in ("reject", "denied", "invalid", "error", "inactive", "fail")):
            failed.append(item["summary"])
    if failed:
        return " | ".join(failed[:2])
    if data["checks"]:
        return f"Failure when {data['checks'][0]} check does not pass"
    return "Fallback or rejected path"


def render_pills(items: list[str], empty_text: str) -> str:
    if not items:
        return empty_text
    return "".join(f'<span class="pill">{html.escape(item)}</span>' for item in items)


def render_api_list(items: list[dict[str, Any]], empty_text: str) -> str:
    if not items:
        return f"<li>{html.escape(empty_text)}</li>"
    rendered = []
    for item in items[:8]:
        rendered.append(
            f'<li><div class="api-route">{html.escape(item["label"])}</div>'
            f'<div class="flow-line">{html.escape(item["context"])}</div></li>'
        )
    return "".join(rendered)


def render_database_list(items: list[dict[str, Any]], empty_text: str) -> str:
    if not items:
        return f"<li>{html.escape(empty_text)}</li>"
    rendered = []
    for item in items[:8]:
        rendered.append(
            f'<li><div class="api-route">{html.escape(item["label"])}</div>'
            f'<div class="flow-line">{html.escape(item["context"])}</div></li>'
        )
    return "".join(rendered)


def render_function_cards(items: list[dict[str, Any]], empty_text: str) -> str:
    if not items:
        return f"<p>{html.escape(empty_text)}</p>"
    cards = []
    for item in items[:6]:
        steps = "".join(
            f'<li><span class="mini-label">{html.escape(step["type"])}</span> '
            f'line {step["line"]}: {html.escape(step["label"])}</li>'
            for step in item["ordered_steps"][:10]
        ) or "<li>No ordered steps extracted.</li>"
        calls = render_pills(item["internal_calls"], "No internal calls")
        routes = render_pills(item["routes"], "No route")
        checks = render_pills(item["checks"], "No checks")
        cards.append(
            f"""
            <div class="function-card">
              <div class="section-head">
                <div>
                  <h5>{html.escape(item["name"])}</h5>
                  <p>{html.escape(item["summary"])}</p>
                </div>
                <div class="mini-label">lines {item["line"]}-{item["end_line"]}</div>
              </div>
              <p><strong>Routes:</strong> {routes}</p>
              <p><strong>Checks:</strong> {checks}</p>
              <p><strong>Internal calls:</strong> {calls}</p>
              <ol class="function-steps">{steps}</ol>
            </div>
            """
        )
    return "".join(cards)


def render_flow_list(items: list[dict[str, Any]], empty_text: str) -> str:
    if not items:
        return f"<li>{html.escape(empty_text)}</li>"
    rendered = []
    for item in items[:8]:
        rendered.append(
            f'<li><div class="api-route">{html.escape(shorten_path(item["file"]))} : line {item["line"]}</div>'
            f'<div class="flow-line">{html.escape(item["summary"])}</div></li>'
        )
    return "".join(rendered)


def shorten_paths(paths: list[str]) -> list[str]:
    return [shorten_path(path) for path in paths]


def shorten_path(path: str) -> str:
    candidate = Path(path)
    if len(candidate.parts) >= 3:
        return "/".join(candidate.parts[-3:])
    return path


def trim_text(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "..."


def parse_multipart(headers: Any, body: bytes) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    content_type = headers.get("Content-Type", "")
    boundary_token = "boundary="
    if boundary_token not in content_type:
        raise ValueError("Multipart boundary missing")
    boundary = content_type.split(boundary_token, 1)[1].encode()

    fields: dict[str, list[str]] = {}
    files: list[dict[str, Any]] = []

    for raw_part in body.split(b"--" + boundary):
        part = raw_part.strip()
        if not part or part == b"--":
            continue
        header_blob, _, value = part.partition(b"\r\n\r\n")
        if not value:
            continue
        value = value.rstrip(b"\r\n")
        header_lines = header_blob.decode("utf-8", errors="ignore").split("\r\n")
        part_headers = {}
        for line in header_lines:
            if ":" in line:
                key, raw = line.split(":", 1)
                part_headers[key.strip().lower()] = raw.strip()
        disposition = part_headers.get("content-disposition", "")
        name = extract_disposition_value(disposition, "name")
        filename = extract_disposition_value(disposition, "filename")
        if not name:
            continue
        if filename:
            files.append({"name": name, "filename": filename, "content": value})
        else:
            fields.setdefault(name, []).append(value.decode("utf-8", errors="ignore"))

    return fields, files


def extract_disposition_value(disposition: str, key: str) -> str | None:
    for item in disposition.split(";"):
        item = item.strip()
        if item.startswith(f"{key}="):
            return item.split("=", 1)[1].strip('"')
    return None


class CodeFlowHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.respond_html(render_page())

    def do_POST(self) -> None:
        if self.path != "/analyze":
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        content_type = self.headers.get("Content-Type", "")

        try:
            if content_type.startswith("multipart/form-data"):
                fields, files = parse_multipart(self.headers, body)
            else:
                payload = parse_qs(body.decode("utf-8", errors="ignore"))
                fields = {key: values for key, values in payload.items()}
                files = []
            report = self.handle_analysis(fields, files)
            self.respond_html(render_page(report=report))
        except Exception as exc:  # noqa: BLE001
            self.respond_html(render_page(error=str(exc)), status=HTTPStatus.BAD_REQUEST)

    def handle_analysis(self, fields: dict[str, list[str]], files: list[dict[str, Any]]) -> dict[str, Any]:
        source_path = (fields.get("source_path") or [""])[0].strip()
        paths: list[Path] = []
        temp_dir: Path | None = None

        if source_path:
            target = Path(source_path).expanduser().resolve()
            if not target.exists():
                raise FileNotFoundError(f"Path does not exist: {target}")
            paths.append(target)

        if files:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            temp_dir = Path(tempfile.mkdtemp(prefix=f"uploads-{timestamp}-"))
            for item in files:
                safe_name = Path(item["filename"]).name
                if not safe_name:
                    continue
                target = temp_dir / safe_name
                target.write_bytes(item["content"])
            paths.append(temp_dir)

        if not paths:
            raise ValueError("Provide a folder path or upload at least one file.")

        report = analyze_paths(paths).to_dict()

        if temp_dir and temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)

        return report

    def respond_html(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), CodeFlowHandler)
    print(f"Serving on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
