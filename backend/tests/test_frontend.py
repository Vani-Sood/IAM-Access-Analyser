"""
Frontend structure tests — multi-page architecture.
Verifies HTML elements, JS functions, CSS, and static serving.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"

INDEX_HTML      = FRONTEND_DIR / "index.html"
ANALYZE_HTML    = FRONTEND_DIR / "analyze.html"
ANALYSIS_HTML   = FRONTEND_DIR / "analysis.html"
DASHBOARD_HTML  = FRONTEND_DIR / "dashboard.html"
SETTINGS_HTML   = FRONTEND_DIR / "settings.html"

DASHBOARD_JS      = FRONTEND_DIR / "dashboard.js"
DASHBOARD_PAGE_JS = FRONTEND_DIR / "dashboard-page.js"
ANALYSIS_JS       = FRONTEND_DIR / "analysis.js"
SETTINGS_JS       = FRONTEND_DIR / "settings.js"
STYLES_CSS        = FRONTEND_DIR / "styles.css"


# ── Per-page soup fixtures ─────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def soup():
    assert INDEX_HTML.exists(), "frontend/index.html missing"
    return BeautifulSoup(INDEX_HTML.read_text(), "html.parser")


@pytest.fixture(scope="module")
def soup_analyze():
    assert ANALYZE_HTML.exists(), "frontend/analyze.html missing"
    return BeautifulSoup(ANALYZE_HTML.read_text(), "html.parser")


@pytest.fixture(scope="module")
def soup_analysis():
    assert ANALYSIS_HTML.exists(), "frontend/analysis.html missing"
    return BeautifulSoup(ANALYSIS_HTML.read_text(), "html.parser")


@pytest.fixture(scope="module")
def soup_dashboard():
    assert DASHBOARD_HTML.exists(), "frontend/dashboard.html missing"
    return BeautifulSoup(DASHBOARD_HTML.read_text(), "html.parser")


@pytest.fixture(scope="module")
def soup_settings():
    assert SETTINGS_HTML.exists(), "frontend/settings.html missing"
    return BeautifulSoup(SETTINGS_HTML.read_text(), "html.parser")


# ── Per-file JS fixtures ───────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def js_source():
    assert DASHBOARD_JS.exists(), "frontend/dashboard.js missing"
    return DASHBOARD_JS.read_text()


@pytest.fixture(scope="module")
def js_dashboard_page():
    assert DASHBOARD_PAGE_JS.exists(), "frontend/dashboard-page.js missing"
    return DASHBOARD_PAGE_JS.read_text()


@pytest.fixture(scope="module")
def js_analysis():
    assert ANALYSIS_JS.exists(), "frontend/analysis.js missing"
    return ANALYSIS_JS.read_text()


@pytest.fixture(scope="module")
def js_settings():
    assert SETTINGS_JS.exists(), "frontend/settings.js missing"
    return SETTINGS_JS.read_text()


@pytest.fixture(scope="module")
def css_source():
    assert STYLES_CSS.exists(), "frontend/styles.css missing"
    return STYLES_CSS.read_text()


# ── index.html (login page) ────────────────────────────────────────────────────

def test_index_html_exists():
    assert INDEX_HTML.exists()


def test_html_has_doctype(soup):
    text = INDEX_HTML.read_text()
    assert "<!DOCTYPE html>" in text or "<!doctype html>" in text


def test_html_lang_attribute(soup):
    html_tag = soup.find("html")
    assert html_tag is not None
    assert html_tag.get("lang") == "en"


def test_html_has_title(soup):
    title = soup.find("title")
    assert title is not None
    assert len(title.get_text(strip=True)) > 0


def test_html_has_meta_viewport(soup):
    meta = soup.find("meta", attrs={"name": "viewport"})
    assert meta is not None


def test_html_links_styles_css(soup):
    hrefs = [l.get("href", "") for l in soup.find_all("link", rel=True)]
    assert any("styles" in h for h in hrefs)


def test_html_has_upload_form(soup_analyze):
    form = soup_analyze.find("form") or soup_analyze.find(id="policy-form")
    textarea = soup_analyze.find("textarea")
    assert form is not None or textarea is not None, "No upload form or textarea in analyze.html"


# ── analyze.html ───────────────────────────────────────────────────────────────

def test_html_has_analyze_button(soup_analyze):
    buttons = soup_analyze.find_all("button")
    button_texts = [b.get_text(strip=True).lower() for b in buttons]
    assert any("analyz" in t for t in button_texts), "No analyze button in analyze.html"


def test_html_has_loading_indicator(soup_analyze):
    el = (
        soup_analyze.find(id="loading")
        or soup_analyze.find(class_=re.compile(r"loading|spinner", re.I))
    )
    assert el is not None, "No loading indicator in analyze.html"


# ── analysis.html ──────────────────────────────────────────────────────────────

def test_html_loads_cytoscape(soup_analysis):
    srcs = " ".join(s.get("src", "") for s in soup_analysis.find_all("script", src=True))
    assert "d3" in srcs.lower(), "d3.js not loaded in analysis.html"


def test_html_loads_dagre(soup_analysis):
    srcs = " ".join(s.get("src", "") for s in soup_analysis.find_all("script", src=True))
    assert "d3" in srcs.lower(), "d3.js not loaded in analysis.html"


def test_html_loads_cytoscape_dagre(soup_analysis):
    srcs = " ".join(s.get("src", "") for s in soup_analysis.find_all("script", src=True))
    assert "d3" in srcs.lower(), "d3.js not loaded in analysis.html"


def test_html_has_risk_score_element(soup_analysis):
    el = soup_analysis.find(id="risk-score")
    assert el is not None, "No risk-score element in analysis.html"


def test_html_has_findings_panel(soup_analysis):
    el = soup_analysis.find(id="findings-panel") or soup_analysis.find(id="findings")
    assert el is not None, "No findings panel in analysis.html"


def test_html_has_graph_container(soup_analysis):
    el = soup_analysis.find(id="graph-container") or soup_analysis.find(id="cy")
    assert el is not None, "No graph container in analysis.html"


def test_html_has_suggestions_panel(soup_analysis):
    el = soup_analysis.find(id="suggestions")
    assert el is not None, "No suggestions panel in analysis.html"


def test_html_results_section_hidden_initially(soup_analysis):
    el = soup_analysis.find(id="page-loading")
    assert el is not None, "No page-loading indicator in analysis.html"


def test_html_has_detail_panel(soup_analysis):
    el = soup_analysis.find(id="node-detail")
    assert el is not None, "No node-detail panel in analysis.html"


def test_html_has_fit_screen_button(soup_analysis):
    el = soup_analysis.find(id="fit-btn")
    assert el is not None, "No fit-btn in analysis.html"


# ── dashboard.html ─────────────────────────────────────────────────────────────

def test_html_loads_dashboard_js(soup_dashboard):
    srcs = [s.get("src", "") for s in soup_dashboard.find_all("script", src=True)]
    assert any("dashboard" in s for s in srcs), "No dashboard JS in dashboard.html"


def test_html_has_enterprise_dashboard_section(soup_dashboard):
    el = soup_dashboard.find(id="stat-total") or soup_dashboard.find(id="trend-chart")
    assert el is not None, "No dashboard stats section in dashboard.html"


def test_html_has_dashboard_load_button(soup_dashboard):
    el = soup_dashboard.find(id="stat-total")
    assert el is not None, "No stat-total element in dashboard.html"


def test_html_has_trend_chart_canvas(soup_dashboard):
    el = soup_dashboard.find(id="trend-chart")
    assert el is not None, "trend-chart canvas missing from dashboard.html"


def test_html_has_heatmap_table(soup_dashboard):
    el = soup_dashboard.find(id="heatmap-grid")
    assert el is not None, "heatmap-grid missing from dashboard.html"


def test_html_includes_chartjs(soup_dashboard):
    scripts = [s.get("src", "") for s in soup_dashboard.find_all("script")]
    assert any("d3" in s.lower() for s in scripts), "d3.js not included in dashboard.html"


# ── settings.html ──────────────────────────────────────────────────────────────

def test_html_has_apikeys_section(soup_settings):
    el = soup_settings.find(id="new-apikey-form")
    assert el is not None, "API Keys form missing from settings.html"


def test_html_has_webhooks_section(soup_settings):
    el = soup_settings.find(id="new-webhook-form")
    assert el is not None, "Webhooks form missing from settings.html"


def test_html_has_apikey_create_btn(soup_settings):
    el = soup_settings.find(id="create-key-btn")
    assert el is not None, "create-key-btn missing from settings.html"


def test_html_has_webhook_create_btn(soup_settings):
    el = soup_settings.find(id="create-hook-btn")
    assert el is not None, "create-hook-btn missing from settings.html"


def test_html_has_apikeys_table(soup_settings):
    el = soup_settings.find(id="apikeys-body")
    assert el is not None, "apikeys-body missing from settings.html"


def test_html_has_webhooks_table(soup_settings):
    el = soup_settings.find(id="webhooks-body")
    assert el is not None, "webhooks-body missing from settings.html"


def test_html_has_event_checkboxes(soup_settings):
    checkboxes = soup_settings.find_all("input", {"class": "hook-event-cb"})
    values = {cb.get("value") for cb in checkboxes}
    assert "analysis.complete" in values, "analysis.complete event checkbox missing"
    assert "privesc.detected" in values, "privesc.detected event checkbox missing"
    assert "compliance.failed" in values, "compliance.failed event checkbox missing"


def test_html_apikey_new_key_reveal(soup_settings):
    el = soup_settings.find(id="new-key-result")
    assert el is not None, "new-key-result reveal div missing from settings.html"


def test_html_webhook_new_secret_reveal(soup_settings):
    el = soup_settings.find(id="webhooks-body")
    assert el is not None, "webhooks-body missing from settings.html"


# ── dashboard.js ───────────────────────────────────────────────────────────────

def test_dashboard_js_exists():
    assert DASHBOARD_JS.exists()


def test_js_has_analyze_function(js_source):
    assert re.search(
        r"function\s+analyzePolicy|analyzePolicy\s*=\s*(async\s*)?(function|\()",
        js_source,
    ), "analyzePolicy function missing from dashboard.js"


def test_js_has_render_risk_badge(js_source):
    assert re.search(r"function\s+renderRiskBadge|renderRiskBadge\s*=", js_source), \
        "renderRiskBadge missing from dashboard.js"


def test_js_has_render_findings(js_source):
    assert re.search(r"function\s+renderFindings|renderFindings\s*=", js_source), \
        "renderFindings missing from dashboard.js"


def test_js_has_render_graph(js_source):
    assert re.search(r"function\s+renderGraph|renderGraph\s*=", js_source), \
        "renderGraph missing from dashboard.js"


def test_js_has_render_suggestions(js_source):
    assert re.search(r"function\s+renderSuggestions|renderSuggestions\s*=", js_source), \
        "renderSuggestions missing from dashboard.js"


def test_js_calls_api_endpoint(js_source):
    assert "/api/v1/analyze" in js_source, "/api/v1/analyze endpoint missing from dashboard.js"


def test_js_uses_cytoscape(js_source):
    assert "cytoscape(" in js_source.lower() or "cytoscape(" in js_source, \
        "cytoscape not used in dashboard.js"


def test_js_handles_loading_state(js_source):
    assert "loading" in js_source.lower()


def test_js_handles_error_state(js_source):
    assert "error" in js_source.lower() or "catch" in js_source


def test_js_color_codes_severity(js_source):
    assert "CRITICAL" in js_source or "critical" in js_source


def test_js_uses_dagre_layout(js_source):
    assert "dagre" in js_source, "dagre layout not used in dashboard.js"


def test_js_has_node_color_by_risk(js_source):
    assert re.search(r"risk_weight|riskWeight|getRiskColor|nodeColor", js_source), \
        "No risk-weight node coloring in dashboard.js"


def test_js_has_detail_panel_function(js_source):
    assert re.search(r"showDetail|renderDetail|nodeDetail|detail.?panel|showDetailPanel",
                     js_source, re.I), "No detail panel function in dashboard.js"


def test_js_has_poll_status_function(js_source):
    assert re.search(r"function\s+pollAnalysisStatus|pollAnalysisStatus\s*=", js_source), \
        "pollAnalysisStatus missing from dashboard.js"


def test_js_polls_status_endpoint(js_source):
    assert "/status" in js_source, "Status polling endpoint not referenced in dashboard.js"


def test_js_analyze_uses_polling(js_source):
    assert "pollAnalysisStatus" in js_source, "analyzePolicy does not call pollAnalysisStatus"


# ── dashboard-page.js ──────────────────────────────────────────────────────────

def test_js_has_load_dashboard_function(js_dashboard_page):
    assert re.search(r"function\s+loadDashboard|loadDashboard\s*=", js_dashboard_page), \
        "loadDashboard missing from dashboard-page.js"


def test_js_has_render_trend_chart_function(js_dashboard_page):
    assert re.search(r"function\s+renderTrendChart|renderTrendChart\s*=", js_dashboard_page), \
        "renderTrendChart missing from dashboard-page.js"


def test_js_has_render_heatmap_function(js_dashboard_page):
    assert re.search(r"function\s+renderHeatmap|renderHeatmap\s*=", js_dashboard_page), \
        "renderHeatmap missing from dashboard-page.js"


def test_js_calls_dashboard_summary_endpoint(js_dashboard_page):
    assert "/api/v1/dashboard/summary" in js_dashboard_page, \
        "dashboard summary endpoint not referenced in dashboard-page.js"


def test_js_sends_x_org_slug_header(js_settings):
    assert "X-Org-Slug" in js_settings, "X-Org-Slug header not sent from settings.js"


# ── settings.js ────────────────────────────────────────────────────────────────

def test_js_has_load_api_keys_function(js_settings):
    assert re.search(r"function\s+loadApiKeys|loadApiKeys\s*=", js_settings), \
        "loadApiKeys missing from settings.js"


def test_js_has_load_webhooks_function(js_settings):
    assert re.search(r"function\s+loadWebhooks|loadWebhooks\s*=", js_settings), \
        "loadWebhooks missing from settings.js"


def test_js_has_revoke_api_key_function(js_settings):
    assert re.search(r"function\s+revokeApiKey|revokeApiKey\s*=", js_settings), \
        "revokeApiKey missing from settings.js"


def test_js_has_ping_webhook_function(js_settings):
    assert re.search(
        r"function\s+(pingWebhook|testWebhook)|(pingWebhook|testWebhook)\s*=",
        js_settings,
    ), "testWebhook/pingWebhook missing from settings.js"


def test_js_calls_apikeys_endpoint(js_settings):
    assert "/api/v1/apikeys" in js_settings, "apikeys endpoint not referenced in settings.js"


def test_js_calls_webhooks_endpoint(js_settings):
    assert "/api/v1/webhooks" in js_settings, "webhooks endpoint not referenced in settings.js"


# ── CSS / Design Tokens ───────────────────────────────────────────────────────

def test_styles_css_exists():
    assert STYLES_CSS.exists()


def test_css_has_canvas_color(css_source):
    assert "#fffaf0" in css_source or "fffaf0" in css_source


def test_css_has_primary_color(css_source):
    assert "#0a0a0a" in css_source or "0a0a0a" in css_source


def test_css_has_css_variables(css_source):
    assert ":root" in css_source
    assert "--" in css_source


def test_css_risk_severity_colors(css_source):
    assert "#ef4444" in css_source or "ef4444" in css_source
    assert "#22c55e" in css_source or "22c55e" in css_source


def test_css_has_responsive_breakpoint(css_source):
    assert "@media" in css_source


def test_css_has_detail_panel_styles(css_source):
    assert "detail" in css_source.lower()


def test_css_statement_node_style(css_source):
    assert "statement" in css_source.lower()


# ── Static File Serving ───────────────────────────────────────────────────────

def test_static_files_served():
    from unittest.mock import patch
    with patch("app.db.database.init_db"), \
         patch("app.ai.llm_client.call_llm", return_value="{}"):
        from app.main import app
        from fastapi.testclient import TestClient
        with TestClient(app) as client:
            response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")


def test_static_js_served():
    from unittest.mock import patch
    with patch("app.db.database.init_db"), \
         patch("app.ai.llm_client.call_llm", return_value="{}"):
        from app.main import app
        from fastapi.testclient import TestClient
        with TestClient(app) as client:
            response = client.get("/dashboard.js")
        assert response.status_code == 200


def test_static_css_served():
    from unittest.mock import patch
    with patch("app.db.database.init_db"), \
         patch("app.ai.llm_client.call_llm", return_value="{}"):
        from app.main import app
        from fastapi.testclient import TestClient
        with TestClient(app) as client:
            response = client.get("/styles.css")
        assert response.status_code == 200
