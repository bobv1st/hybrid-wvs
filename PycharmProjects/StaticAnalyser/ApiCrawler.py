import re
import json
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, urlunparse, unquote

import requests
from bs4 import BeautifulSoup


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


def _normalize_url(u: str) -> str:
    parsed = urlparse(u)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, ""))


def _same_site(u: str, domain: str) -> bool:
    return urlparse(u).netloc == domain


def _extract_endpoints_from_text(text: str, base_url: str, domain: str) -> list[str]:

    candidates = set()

    # 1) Absolute URLs that look like API endpoints
    for m in re.finditer(r"https?://[^\s\"'<>]+", text, flags=re.IGNORECASE):
        abs_url = m.group(0)

        if _same_site(abs_url, domain) and re.search(r"/(?:api|rest|graphql|v\d+)(?:/|$)", abs_url, re.IGNORECASE):
            candidates.add(_normalize_url(abs_url))

    # 2) Site-relative or relative paths that look like API endpoints
    for m in re.finditer(r"(?P<path>(?:/)?(?:api|rest|graphql|v\d+)[/A-Za-z0-9_\-\.]*[^\s\"'<>])", text, flags=re.IGNORECASE):
        path = m.group("path")
        abs_url = urljoin(base_url, path)
        if _same_site(abs_url, domain):
            candidates.add(_normalize_url(abs_url))

    # 3) HATEOAS-style link objects {"href": "/api/..."} or {"url": "..."}
    for m in re.finditer(r"\"(?:href|url|next|self)\"\s*:\s*\"([^\"]+)\"", text, flags=re.IGNORECASE):
        path = m.group(1)
        abs_url = urljoin(base_url, path)
        if _same_site(abs_url, domain) and re.search(r"/(?:api|rest|graphql|v\d+)(?:/|$)", abs_url, re.IGNORECASE):
            candidates.add(_normalize_url(abs_url))

    return sorted(candidates)


def _fetch_text(session: requests.Session, url: str, timeout: int = 10) -> str:
    try:
        r = session.get(url, timeout=timeout)
        return r.text or ""
    except Exception:
        return ""


# --- Directory wordlist helpers (minimal normalization) -------------------------
_ID_SEGMENT_RE = re.compile(r"^(?:\d+|[0-9a-fA-F]{8,})$")
_VER_RE = re.compile(r"^v\d+$", re.IGNORECASE)
_EDGE_JUNK_RE = re.compile(r"^[^A-Za-z0-9_-]+|[^A-Za-z0-9_-]+$")


def _build_directory_candidates(endpoints: list[str]) -> list[str]:


    API_MARKERS = {"api", "rest", "graphql"}
    out: set[str] = set()

    for u in endpoints:
        path = unquote(urlparse(u).path or "")
        if not path:
            continue
        segs = [s for s in path.split('/') if s]
        # drop leading markers
        i = 0
        while i < len(segs) and (segs[i].lower() in API_MARKERS or _VER_RE.match(segs[i])):
            i += 1
        if i >= len(segs):
            continue
        seg = _EDGE_JUNK_RE.sub('', segs[i].lower())
        if not seg or _ID_SEGMENT_RE.fullmatch(seg):
            continue
        out.add(f"/{seg}")

    return sorted(out)


def discover_initial_seeds(session: requests.Session, base: str) -> list[str]:

    parsed = urlparse(base)
    if not parsed.scheme:
        base = "http://" + base
        parsed = urlparse(base)
    site = f"{parsed.scheme}://{parsed.netloc}"
    domain = parsed.netloc

    seeds: set[str] = set()

    def add_candidates_from_text(text: str):
        for u in _extract_endpoints_from_text(text, base_url=site + "/", domain=domain):
            seeds.add(u)

    # 1) Well-known candidates
    well_known = [
        "/api",
        "/api/v1",
        "/api/v2",
        "/rest",
        "/rest/v1",
        "/graphql",
        "/openapi.json",
        "/swagger.json",
        "/v3/api-docs",
    ]
    for p in well_known:
        seeds.add(_normalize_url(urljoin(site + "/", p)))

    # 2) robots.txt
    robots = _fetch_text(session, urljoin(site + "/", "/robots.txt"))
    if robots:
        for m in re.finditer(r"Disallow:\s*([^\s#]+)", robots, flags=re.IGNORECASE):
            path = m.group(1).strip()
            abs_url = urljoin(site + "/", path)
            if _same_site(abs_url, domain):
                if re.search(r"/(?:api|rest|graphql|v\d+)(?:/|$)", abs_url, re.IGNORECASE):
                    seeds.add(_normalize_url(abs_url))

    # 3) sitemap.xml
    sitemap = _fetch_text(session, urljoin(site + "/", "/sitemap.xml"))
    if sitemap:
        for m in re.finditer(r"<loc>([^<]+)</loc>", sitemap, flags=re.IGNORECASE):
            loc = m.group(1).strip()
            if _same_site(loc, domain):
                if re.search(r"/(?:api|rest|graphql|v\d+)(?:/|$)", loc, re.IGNORECASE):
                    seeds.add(_normalize_url(loc))

    # 4) Homepage scan (HTML + linked JS)
    home = _fetch_text(session, site + "/")
    if home:
        add_candidates_from_text(home)
        try:
            soup = BeautifulSoup(home, "html.parser")
            for s in soup.find_all("script", src=True):
                js_url = urljoin(site + "/", s.get("src"))
                if _same_site(js_url, domain):
                    js_text = _fetch_text(session, js_url)
                    if js_text:
                        add_candidates_from_text(js_text)
        except Exception:
            pass

    # 5) OpenAPI documents
    for openapi_path in ["/openapi.json", "/swagger.json", "/v3/api-docs"]:
        try:
            r = session.get(urljoin(site + "/", openapi_path), timeout=8)
            if r.status_code == 200:
                doc = r.json()
                # OpenAPI v3: paths is a dict
                paths = doc.get("paths") if isinstance(doc, dict) else None
                if isinstance(paths, dict):
                    for p in paths.keys():
                        abs_url = urljoin(site + "/", p)
                        if _same_site(abs_url, domain):
                            seeds.add(_normalize_url(abs_url))
        except Exception:
            pass

    # Filter to plausible endpoints only 
    filtered = [u for u in seeds if re.search(r"/(?:api|rest|graphql|v\d+)(?:/|$)", u, re.IGNORECASE)]
    return sorted(set(filtered))


def api_crawl(session: requests.Session,
              seeds: list[str],
              rate_limit: float = 0.2,
              max_new: int = 100,
              out_path: str | None = None,
              wordlist_path: str | None = None) -> dict:

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
                        # HATEOAS links at top-level
                        for k in ["_links", "links"]:
                            if isinstance(data.get(k), dict):
                                for v in data[k].values():
                                    href = v.get("href") if isinstance(v, dict) else None
                                    if href:
                                        abs_u = urljoin(base_url + "/", href)
                                        if _same_site(abs_u, domain):
                                            record.setdefault("children", []).append(_normalize_url(abs_u))
                except Exception:
                    pass
        except Exception:
            pass

        # Extract endpoints from the body text (JSON/HTML/plain)
        children = _extract_endpoints_from_text(body_text, base_url=base_url + "/", domain=domain)


        try:
            if record["content_type"] and "html" in record["content_type"]:
                soup = BeautifulSoup(body_text, "html.parser")
                for s in soup.find_all("script", src=True):
                    js_url = urljoin(base_url + "/", s.get("src"))
                    if _same_site(js_url, domain):
                        try:
                            r_js = session.get(js_url, timeout=10)
                            js_text = r_js.text or ""
                            js_children = _extract_endpoints_from_text(js_text, base_url=base_url + "/", domain=domain)
                            if js_children:
                                children.extend(js_children)
                        except Exception:
                            pass
        except Exception:
            pass

        # Deduplicate children
        children = sorted(set(children))
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

    try:
        wl_candidates = _build_directory_candidates(sorted(visited))
        if wordlist_path is None:
            # do not overwrite existing by default unless user passes a path
            wordlist_path = "api_wordlist.txt"
        with open(wordlist_path, "w", encoding="utf-8") as f:
            for line in wl_candidates:
                f.write(line + "\n")
        summary["wordlist_path"] = wordlist_path
        summary["wordlist_size"] = len(wl_candidates)
        print(f"Wrote {len(wl_candidates)} wordlist entries to {wordlist_path}")
    except Exception as e:
        print(f"Failed to build/write wordlist: {e}")

    return summary


def main_api(seed: str):

    sess = requests.Session()

    base_site = seed
    try:
        seeds_example = discover_initial_seeds(sess, base_site)

        print(f"Discovered {len(seeds_example)} initial seeds")
        api_crawl(sess, seeds_example, out_path="api_crawl_results.ndjson", wordlist_path="api_wordlist.txt")
    except Exception as e:
        print(f"API crawl failed to start: {e}")
