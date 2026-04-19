import json
import re
import os
from urllib.parse import urlparse, urlunparse
from datetime import datetime, timezone


XSS_PARAM_HINTS = {
    "q", "query", "search", "s", "message", "comment", "content", "title", "name"
}

SQLI_PARAM_HINTS = {
    "id", "user_id", "uid", "pid", "productid", "order", "sort",
    "offset", "limit", "page", "cat", "category", "customerid",
    "record", "row", "key"
}

HTML_EXTS = {".php", ".asp", ".aspx", ".jsp", ".html", ""}

SEG_XSS = {"search", "query", "message", "comment", "feedback", "review", "post", "article", "profile"}
SEG_SQLI = {"item", "product", "order", "user", "account", "record", "row", "detail", "edit", "update"}

NUM_SEG = re.compile(r"/\d+(?:/|$)")


def _norm(u: str) -> str:
    try:
        p = urlparse(u)
        return urlunparse((p.scheme, p.netloc, p.path, "", p.query, ""))
    except Exception:
        return u or ""


def _is_numeric(v):
    try:
        int(str(v).strip())
        return True
    except:
        return False


def _ext_of_path(path: str) -> str:
    i = path.rfind('.')
    if i == -1 or '/' in path[i + 1:]:
        return ''
    return path[i:].lower()


def _merge_records(paths: list[str]) -> dict:
    rec_by_url: dict[str, dict] = {}

    for path in paths:
        if not path or not os.path.exists(path):
            continue

        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue

                    url = obj.get("page") or obj.get("url")
                    if not url:
                        continue

                    k = _norm(url.lower())

                    R = rec_by_url.setdefault(
                        k,
                        {
                            "page": k,
                            "links": [],
                            "get_params": {},
                            "forms": [],
                            "depth": None,
                            "discovered_at": None,
                            "allowed_methods": [],
                            "status_get": None,
                            "content_type": None,
                            "json_top_keys": [],
                            "children": [],
                        },
                    )

                    links = obj.get("links") or []
                    if isinstance(links, list):
                        R["links"].extend(links)

                    get_params = obj.get("get_params") or {}
                    if isinstance(get_params, dict):
                        for pn, pv in get_params.items():
                            if pn not in R["get_params"]:
                                R["get_params"][pn] = pv

                    forms = obj.get("forms") or []
                    if isinstance(forms, list):
                        R["forms"].extend(forms)

                    try:
                        d = obj.get("depth")
                        if isinstance(d, int):
                            if R.get("depth") is None or d < R.get("depth"):
                                R["depth"] = d
                    except:
                        pass

                    try:
                        ts = obj.get("discovered_at")
                        if isinstance(ts, str):
                            if not R.get("discovered_at") or ts < R.get("discovered_at"):
                                R["discovered_at"] = ts
                    except:
                        pass

                    for fld in ["allowed_methods", "status_get", "content_type", "json_top_keys", "children"]:
                        val = obj.get(fld)
                        if val is None:
                            continue

                        if fld in {"allowed_methods", "children"}:
                            try:
                                R[fld] = sorted(set((R.get(fld) or []) + (val or [])))
                            except:
                                pass
                        else:
                            R[fld] = val

        except Exception:
            continue

    for R in rec_by_url.values():
        R["links"] = sorted(set(R.get("links") or []))

    return rec_by_url


def _score_xss_preprobe(url: str, R: dict) -> int:

    p = urlparse(url)
    path_lower = (p.path or "/").lower()
    path_ext = _ext_of_path(path_lower)
    path_segs = [s for s in path_lower.split('/') if s]

    forms = R.get("forms") or []
    links = R.get("links") or []
    params = set((R.get("get_params") or {}).keys())
    ct = (R.get("content_type") or "").lower()

    xss = 0

    textlike = 0
    has_get_form = False
    same_action = False

    for fm in forms:

        try:
            if (fm.get("method") or "").upper() == "GET":
                has_get_form = True

            if _norm(fm.get("action") or "") == url:
                same_action = True

            for fld in fm.get("fields") or []:
                if (fld.get("type") or "text").lower() in {"text", "search", "textarea"}:
                    textlike += 1


        except:
            continue

    has_html_ui = True

    if has_html_ui and textlike >= 1:
        xss += 2

    if params & XSS_PARAM_HINTS:
        xss += 3

    if any(seg in SEG_XSS for seg in path_segs):
        xss += 2

    if len(forms) >= 2 or textlike >= 3:
        xss += 2

    if has_get_form and params:
        xss += 1

    if path_ext in HTML_EXTS:
        xss += 0.75

    if len(links) >= 10:
        xss += 0.75

    if same_action:
        xss += 0.75

    if "text/html" in ct:
        xss += 0.75

    return min(int(round(xss)), 9)


def _score_sqli_preprobe(url: str, R: dict) -> int:

    p = urlparse(url)
    path_lower = (p.path or "/").lower()
    path_ext = _ext_of_path(path_lower)
    path_segs = [s for s in path_lower.split('/') if s]

    forms = R.get("forms") or []
    params_dict = R.get("get_params") or {}
    params = set(params_dict.keys())
    ct = (R.get("content_type") or "").lower()

    sqli = 0

    if forms:
        sqli += 2

    found = False
    for fm in forms:
        if (fm.get("method") or "").upper() == "GET":
            for field in fm.get("fields") or []:
                name = field.get("name")
                if name and name.lower() in SQLI_PARAM_HINTS:
                    sqli += 3
                    found = True
                    break
        if found:
            break

    for param_name in params_dict.keys():
        if param_name.lower() in SQLI_PARAM_HINTS:
            sqli += 3
            break

    has_numeric_default = False

    try:
        for vs in params_dict.values():
            vals = vs if isinstance(vs, list) else [vs]
            if any(_is_numeric(v) for v in vals):
                has_numeric_default = True
                break
    except:
        pass

    if has_numeric_default:
        sqli += 2

    try:
        if any(m in (R.get("allowed_methods") or []) for m in ["POST", "PUT", "PATCH"]) or any(
            (fm.get("method") or "").upper() == "POST" for fm in forms
        ):
            sqli += 1
    except:
        pass

    if "application/json" in ct and set(R.get("json_top_keys") or []) & {"filter", "where", "query", "search", "sort", "orderby", "fields"}:
        sqli += 1

    if NUM_SEG.search(path_lower) or any(seg in path_segs for seg in SEG_SQLI):
        sqli += 1

    if (len(params) >= 3) or (("page" in params or "offset" in params) and ("limit" in params or "size" in params)):
        sqli += 1

    if path_ext in {".php", ".asp", ".aspx", ".jsp"}:
        sqli += 0.75

    if len(R.get("children") or []) >= 5:
        sqli += 0.75

    try:
        if (R.get("status_get") or 200) >= 500:
            sqli += 0.75
    except:
        pass

    return min(int(round(sqli)), 9)


def _unify_priority(xss: float, sqli: float) -> int:

    x = max(0, min(9, xss)) / 9
    s = max(0, min(9, sqli)) / 9

    return int(round(9 * (1 - (1 - x) * (1 - s))))


def score_and_write(inputs: list[str] | None = None, output_path: str = "scored_results.ndjson") -> str:

    if inputs is None:
        inputs = [
            "static_crawl_results.ndjson",
            "api_crawl_results.ndjson",
            "crawl_results.ndjson",
            "results.jsonl",
        ]

    rec_by_url = _merge_records(inputs)

    with open(output_path, "w", encoding="utf-8") as f:

        for url, R in rec_by_url.items():

            xss = _score_xss_preprobe(url, R)
            sqli = _score_sqli_preprobe(url, R)
            prio = _unify_priority(xss, sqli)

            out = {}
            out["schema_version"] = 1
            out["source"] = "scorer"

            try:
                out["discovered_at"] = R.get("discovered_at") or datetime.now(timezone.utc).isoformat()
            except:
                out["discovered_at"] = None

            out["page"] = R.get("page", url)
            out["depth"] = R.get("depth")
            out["links"] = R.get("links") or []
            out["get_params"] = R.get("get_params") or {}
            out["forms"] = R.get("forms") or []
            out["allowed_methods"] = R.get("allowed_methods") or []
            out["status_get"] = R.get("status_get")
            out["content_type"] = R.get("content_type")
            out["json_top_keys"] = R.get("json_top_keys") or []
            out["children"] = R.get("children") or []

            out["score_xss_preprobe"] = xss
            out["score_sqli_preprobe"] = sqli
            out["priority"] = prio

            f.write(json.dumps(out, ensure_ascii=False) + "\n")

    return output_path


def main():
    try:
        out = score_and_write()
        print(f"Wrote unified pre-probe scores to {out}")
    except Exception as e:
        print(f"Scoring failed: {e}")


if __name__ == "__main__":
    main()