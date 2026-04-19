

import json
import time
import re
import requests
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

XSS_SCORE_THRESHOLD = 7    # only probe pages with xss score equal too or more than this

SCORED_RESULTS_PATH = "scored_results.ndjson"
OUT_PATH = "xss_probe_results.ndjson"


SKIP_TYPES = {"submit", "file", "image", "reset", "button", "hidden"}

REQUEST_TIMEOUT = 15         # seconds


_CANARY = "xsspr0be"

REFLECTED_PAYLOADS = [
    (
        "script_alert",
        f'<script>{_CANARY}(1)</script>',
        re.compile(rf'<script>{_CANARY}\(1\)</script>', re.IGNORECASE),
    ),
    (
        "img_onerror",
        f'"><img src=x onerror={_CANARY}(1)>',
        re.compile(rf'onerror={_CANARY}\(1\)', re.IGNORECASE),
    ),
    (
        "svg_onload",
        f'<svg onload={_CANARY}(1)>',
        re.compile(rf'<svg onload={_CANARY}\(1\)', re.IGNORECASE),
    ),
    (
        "body_onload",
        f'<body onload={_CANARY}(1)>',
        re.compile(rf'<body onload={_CANARY}\(1\)', re.IGNORECASE),
    ),
    (
        "input_autofocus",
        f'" autofocus onfocus={_CANARY}(1) x="',
        re.compile(rf'onfocus={_CANARY}\(1\)', re.IGNORECASE),
    ),
    (
        "javascript_href",
        f'javascript:{_CANARY}(1)',
        re.compile(rf'javascript:{_CANARY}\(1\)', re.IGNORECASE),
    ),
    (
        "template_literal",
        f'`${{{_CANARY}(1)}}`',
        re.compile(rf'\$\{{{_CANARY}\(1\)\}}', re.IGNORECASE),
    ),
    (
        "event_handler_single_quote",
        f"' onmouseover='{_CANARY}(1)' x='",
        re.compile(rf"onmouseover='{_CANARY}\(1\)'", re.IGNORECASE),
    ),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _should_skip_field(field: dict) -> bool:
    """Return True if this field should not be fuzzed."""
    ftype = (field.get("type") or "text").lower()
    if ftype in SKIP_TYPES:
        return True
    if field.get("never_fuzz") is True:
        return True
    return False


def _build_baseline_data(fields: list[dict]) -> dict:
    """Build a form data dict using original/placeholder values."""
    data = {}
    for f in fields:
        name = f.get("name")
        if not name:
            continue
        ftype = (f.get("type") or "text").lower()
        val = f.get("value")
        if val is None:
            if ftype == "password":
                val = "password"
            elif ftype in ("text", "textarea", "select", "search", "email", "tel", "url"):
                val = "test"
            elif ftype == "number":
                val = "1"
            elif ftype == "radio":
                val = f.get("value") or "on"
            elif ftype == "checkbox":
                val = "on"
            else:
                val = "test"
        data[name] = val
    return data


def _unique_form_key(form: dict) -> tuple:

    action = form.get("action", "")
    method = (form.get("method") or "GET").upper()
    field_names = tuple(sorted(
        f["name"] for f in form.get("fields", []) if f.get("name")
    ))
    return (action, method, field_names)


def _load_unique_forms(results_path: str) -> list[dict]:

    seen_keys: set = set()
    unique: list[dict] = []

    try:
        with open(results_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except Exception:
                    continue

                # --- XSS score filter ---
                try:
                    xss_score = int(record.get("score_xss_preprobe") or 0)
                except (TypeError, ValueError):
                    xss_score = 0
                if xss_score < XSS_SCORE_THRESHOLD:
                    continue
                # ------------------------

                page = record.get("page", "")
                forms = record.get("forms") or []
                for form in forms:
                    key = _unique_form_key(form)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    unique.append({"page": page, "form": form})
    except FileNotFoundError:
        print(f"[XSSProber] Input file not found: {results_path}")
    except Exception as e:
        print(f"[XSSProber] Error reading {results_path}: {e}")

    return unique


def _write_result(record: dict, out_path: str) -> None:
    line = json.dumps(record, ensure_ascii=False)
    print(line)
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")




def _probe_field(
    session: requests.Session,
    page: str,
    form: dict,
    target_field: dict,
    out_path: str,
) -> None:
    """Run all XSS payloads against a single form field."""
    action = form.get("action", page)
    method = (form.get("method") or "GET").upper()
    fields = form.get("fields", [])
    field_name = target_field["name"]

    baseline_data = _build_baseline_data(fields)

    for label, payload, detection_re in REFLECTED_PAYLOADS:
        probe_data = dict(baseline_data)
        probe_data[field_name] = payload

        timed_out = False
        status_code = None
        elapsed = None
        reflected = False
        stored = False

        # ---- Submit the payload ------------------------------------------------
        try:
            t0 = time.monotonic()
            if method == "POST":
                resp = session.post(action, data=probe_data, timeout=REQUEST_TIMEOUT)
            else:
                resp = session.get(action, params=probe_data, timeout=REQUEST_TIMEOUT)
            elapsed = time.monotonic() - t0
            status_code = resp.status_code


            if detection_re.search(resp.text):
                reflected = True

        except requests.exceptions.Timeout:
            timed_out = True
        except Exception as e:
            print(f"[XSSProber] Request error on {action} [{field_name}={label}]: {e}")
            continue


        if not timed_out:
            try:
                verify_resp = session.get(action, timeout=REQUEST_TIMEOUT)
                if detection_re.search(verify_resp.text):
                    stored = True
            except Exception:
                pass


        if stored:
            probe_type = "stored"
        elif reflected:
            probe_type = "reflected"
        else:
            probe_type = "none"

        vulnerable = reflected or stored

        _write_result({
            "schema_version": 1,
            "source": "xss_prober",
            "discovered_at": _iso_now(),
            "page": page,
            "form_action": action,
            "form_method": method,
            "field": field_name,
            "probe_type": probe_type,
            "payload_label": label,
            "payload": payload,
            "vulnerable": vulnerable,
            "reflected": reflected,
            "stored": stored,
            "timed_out": timed_out,
            "status_code": status_code,
            "elapsed_seconds": round(elapsed, 3) if elapsed is not None else None,
        }, out_path)

        if vulnerable:
            print(
                f"[!] Potential XSS ({probe_type}) — {action} | field={field_name} | "
                f"payload={label}"
            )

        time.sleep(0.05)   # small delay between requests


# ---------------------------------------------------------------------------
# Main probing routine
# ---------------------------------------------------------------------------

def probe_forms(
    session: requests.Session,
    scored_results_path: str = SCORED_RESULTS_PATH,
    out_path: str = OUT_PATH,
) -> None:

    # Truncate output file at start of run
    open(out_path, "w", encoding="utf-8").close()

    form_entries = _load_unique_forms(scored_results_path)
    print(f"[XSSProber] Loaded {len(form_entries)} unique form(s) to probe.")

    for entry in form_entries:
        page = entry["page"]
        form = entry["form"]
        action = form.get("action", page)
        method = (form.get("method") or "GET").upper()
        fields = form.get("fields", [])

        fuzzable = [f for f in fields if f.get("name") and not _should_skip_field(f)]

        if not fuzzable:
            print(f"[XSSProber] Skipping form at {action} — no fuzzable fields.")
            continue

        print(f"[XSSProber] Probing form: {method} {action} | fields: {[f['name'] for f in fuzzable]}")

        for field in fuzzable:
            _probe_field(session, page, form, field, out_path)
            time.sleep(0.1)   # small delay between fields


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def main(
    scored_results_path: str = SCORED_RESULTS_PATH,
    out_path: str = OUT_PATH,
) -> None:
    session = requests.Session()
    probe_forms(session, scored_results_path=scored_results_path, out_path=out_path)
    print(f"[XSSProber] Done. Results written to {out_path}")


if __name__ == "__main__":
    main()