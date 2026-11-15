"""Browser smoke test of the console (Playwright + a real uvicorn process).
Skipped automatically when Playwright or its browser is not installed.
Run:  pip install playwright && playwright install chromium && pytest tests/test_ui.py -v
"""
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"
VIEWS = ["overview", "analyze", "live", "capture", "queue", "hunt", "assets", "batch", "model", "monitor"]


@pytest.fixture(scope="module")
def server():
    env = os.environ | {"LOG_DIR": tempfile.mkdtemp(prefix="zerowatch-ui-"), "ALARM_INTERVAL_SECONDS": "0"}
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app:app", "--port", str(PORT)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        try:
            urllib.request.urlopen(BASE + "/health", timeout=1)
            break
        except OSError:
            time.sleep(0.5)
    yield BASE
    proc.terminate()


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as e:  # browser binary not downloaded
            pytest.skip(f"Chromium is not installed for Playwright: {e}")
        yield b
        b.close()


def open_page(browser, server, **ctx):
    page = browser.new_context(**ctx).new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(server)
    page.wait_for_selector("#presets .chip")
    return page, errors


def test_score_a_flow_and_reject_an_invalid_one(browser, server):
    page, errors = open_page(browser, server)
    page.click("#presets .chip:nth-child(2)")  # SYN flood
    page.wait_for_selector(".verdict.attack")
    assert "Known attack" in page.inner_text("#result") and len(page.query_selector_all(".tips li")) >= 2
    page.click("#break")
    page.wait_for_selector(".error-box")
    assert "HTTP 422" in page.inner_text("#form-error") and "Nothing was scored" in page.inner_text("#result")
    assert errors == []


def test_every_view_loads_and_the_back_button_works(browser, server):
    page, errors = open_page(browser, server, viewport={"width": 1280, "height": 800})
    assert page.evaluate("document.querySelector('.tabs').scrollWidth <= document.querySelector('.tabs').clientWidth"), \
        "all ten tabs must be visible on a laptop screen"
    for view in VIEWS:
        page.click(f"#tab-{view}")
        page.wait_for_function("v => !document.getElementById('view-' + v).hidden && !document.querySelector('#view-' + v + ' .skeleton')", arg=view)
        assert page.url.endswith("#" + view)
    page.go_back()
    assert page.url.endswith("#model") and page.is_visible("#view-model")
    page.goto(server + "/#hunt")  # deep link
    page.wait_for_selector("#view-hunt:not([hidden])")
    assert errors == []


def test_theme_choice_survives_a_reload(browser, server):
    page, _ = open_page(browser, server, color_scheme="dark")
    assert page.evaluate("document.documentElement.dataset.theme") == "dark"
    page.click("#theme")
    page.reload()
    page.wait_for_selector("#presets .chip")
    assert page.evaluate("document.documentElement.dataset.theme") == "light"


def test_phone_width_navigation_is_usable(browser, server):
    page, errors = open_page(browser, server, viewport={"width": 390, "height": 844})
    assert page.evaluate("document.querySelector('.tabs').clientWidth") > 300
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.click("#tab-overview")
    page.wait_for_selector("#overview-out .ov-grid")
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.click("#tab-monitor")
    page.wait_for_selector("#view-monitor:not([hidden]) .stat")
    page.click("#tab-capture")
    page.click("#cap-sample")
    page.wait_for_selector("#cap-out .graph")
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert errors == []


def test_capture_table_filters_and_queue_triage(browser, server):
    page, errors = open_page(browser, server)
    page.click("#tab-capture")
    page.click("#cap-sample")
    page.wait_for_selector("#cap-table tbody tr")
    page.fill("#cap-table input[type=search]", "10.0.0.66")
    page.wait_for_function("() => [...document.querySelectorAll('#cap-table tbody tr')].every(r => r.innerText.includes('10.0.0.66'))")
    page.click("#tab-queue")
    page.wait_for_selector("#queue-table select")
    page.select_option("#queue-table select >> nth=0", "confirmed")
    page.wait_for_selector(".toast")
    assert "labelled as an attack" in page.inner_text(".toast")
    assert errors == []


def test_keyboard_live_stream_and_shadow_controls(browser, server):
    page, errors = open_page(browser, server)
    page.focus("#tab-analyze")
    page.keyboard.press("ArrowRight")
    assert page.url.endswith("#live") and page.evaluate("document.activeElement.id") == "tab-live"
    page.click("#live-toggle")  # server-sent events, no polling
    page.wait_for_function("() => document.querySelectorAll('#live-rows tr.click').length >= 8")
    page.click("#live-toggle")
    assert page.evaluate("document.querySelectorAll('#trace i').length") >= 8
    page.click("#live-reset")
    assert page.inner_text("#live-stats .stat b") == "0"
    page.keyboard.press("9")  # digit shortcut -> Model
    page.wait_for_selector("#model-out .matrix")
    assert page.url.endswith("#model") and page.is_visible("#model-out .roc")
    assert errors == []


def test_no_third_party_requests_and_csp_holds(browser, server):
    page = browser.new_context().new_page()
    outside, blocked = [], []
    page.on("request", lambda r: outside.append(r.url) if not r.url.startswith(server) else None)
    page.on("console", lambda m: blocked.append(m.text) if "Content Security Policy" in m.text else None)
    page.goto(server)
    page.wait_for_selector("#presets .chip")
    page.click("#presets .chip:nth-child(2)")
    page.wait_for_selector(".verdict")
    assert outside == [], "fonts and scripts must come from this origin"
    assert blocked == [], "nothing on the page may violate the Content-Security-Policy"
    assert page.evaluate("document.fonts.check('16px \\'IBM Plex Sans\\'')")


def test_result_scrolls_into_view_on_a_phone(browser, server):
    page, _ = open_page(browser, server, viewport={"width": 390, "height": 844})
    page.click("#presets .chip:nth-child(2)")
    page.wait_for_selector(".verdict")
    page.wait_for_function("() => document.querySelector('#result').getBoundingClientRect().top < innerHeight")
    assert page.evaluate("Math.min(...[...document.querySelectorAll('.tabs button')].map(b => b.getBoundingClientRect().height))") >= 44
