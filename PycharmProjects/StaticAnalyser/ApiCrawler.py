import re
import json
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, urlunparse

import requests


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


def _normalize_url(u: str) -> str:
    parsed = urlparse(u)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, ""))


def _same_site(u: str, domain: str) -> bool:
    return urlparse(u).netloc == domain


def _extract_endpoints_from_text(text: str, base_url: str, domain: str) -> list[str]:

    candidates = set()

    for m in re.finditer(r"(?P<path>(?:/)?(?:api|v\d+)[/A-Za-z0-9_\-\.]*[^\s\"'<>])", text, flags=re.IGNORECASE):
        path = m.group("path")
        # Make absolute
        abs_url = urljoin(base_url, path)
        if _same_site(abs_url, domain):
            candidates.add(_normalize_url(abs_url))
    return sorted(candidates)


def api_crawl(session: requests.Session,
              seeds: list[str],
              rate_limit: float = 0.2,
              max_new: int = 100,
              out_path: str | None = None) -> dict:

    if not seeds:
        raise ValueError("seeds must contain at least one endpoint URL")

    # Determine crawl scope from first seed
    first = _normalize_url(seeds[0])
    parsed_first = urlparse(first)
    domain = parsed_first.netloc
    base_url = f"{parsed_first.scheme}://{parsed_first.netloc}"

    visited: set[str] = set()
    frontier: list[str] = []

    # Normalize and keep only same site seeds
    for s in seeds:
        u = _normalize_url(s)
        if _same_site(u, domain):
            frontier.append(u)

    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            pass  # truncate

    processed = 0
    discovered_total = 0

    while frontier:
        url = frontier.pop(0)
        if url in visited:
            continue
        visited.add(url)
        processed += 1

        record: dict = {
            "schema_version": 1,
            "source": "api_crawler",
            "discovered_at": _iso_now(),
            "endpoint": url,
            "allowed_methods": [],
            "status_get": None,
            "content_type": None,
            "json_top_keys": [],
            "children": [],
        }

        # Probe OPTIONS to get allowed methods
        try:
            r_opt = session.options(url, timeout=10)
            allow = r_opt.headers.get("Allow") or r_opt.headers.get("allow")
            if allow:
                record["allowed_methods"] = [m.strip() for m in allow.split(",") if m.strip()]
        except Exception:

            pass

        # Probe GET
        body_text = ""
        try:
            r_get = session.get(url, timeout=15)
            record["status_get"] = r_get.status_code
            ct = r_get.headers.get("Content-Type", "").split(";")[0].strip()
            record["content_type"] = ct or None
            body_text = r_get.text or ""
            if "json" in ct or (body_text.startswith("{") and body_text.endswith("}")):
                try:
                    data = r_get.json()
                    if isinstance(data, dict):
                        record["json_top_keys"] = sorted(list(data.keys()))
                except Exception:
                    pass
        except Exception:
            pass


        children = _extract_endpoints_from_text(body_text, base_url=base_url + "/", domain=domain)
        record["children"] = children
        discovered_total += len(children)


        for c in children:
            if len(frontier) >= max_new:
                break
            if c not in visited and c not in frontier:
                frontier.append(c)

        line = json.dumps(record, ensure_ascii=False)
        print(line)
        if out_path:
            with open(out_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

        time.sleep(rate_limit)

    summary = {
        "processed": processed,
        "unique_endpoints": len(visited),
        "discovered_children": discovered_total,
    }
    print(f"API crawl complete: processed={processed}, unique={len(visited)}, children={discovered_total}")
    return summary


if __name__ == "__main__":

    sess = requests.Session()
    seeds_example = [
        "http://localhost:3000/
    ]
    try:
        api_crawl(sess, seeds_example, out_path="api_crawl_results.ndjson")
    except Exception as e:
        print(f"API crawl failed to start: {e}")
