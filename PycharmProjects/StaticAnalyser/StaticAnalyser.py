import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from collections import deque
import time
import json
from datetime import datetime, timezone
import os

# Disable SSL warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


def _parse_forms(soup, base_url):
    forms = []
    for form in soup.find_all("form"):
        method = (form.get("method") or "GET").upper()
        action = urljoin(base_url, form.get("action") or base_url)

        fields = []
        # input elements
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            fields.append({
                "name": name,
                "type": (inp.get("type") or "text").lower(),
                "value": inp.get("value")
            })
        # select elements
        for sel in form.find_all("select"):
            name = sel.get("name")
            if not name:
                continue
            fields.append({
                "name": name,
                "type": "select"
            })
        # textarea elements
        for ta in form.find_all("textarea"):
            name = ta.get("name")
            if not name:
                continue
            fields.append({
                "name": name,
                "type": "textarea"
            })

        forms.append({
            "action": action,
            "method": method,
            "fields": fields
        })
    return forms


def _normalize_url(u: str):
    # strip fragments and normalize
    parsed = urlparse(u)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, ""))


def _load_headless_links_simple(results_path: str) -> list[str]:

    links: set[str] = set()
    if not results_path or not os.path.exists(results_path):
        return []

    try:
        with open(results_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                raw = obj.get("final_url") or obj.get("url")
                if not raw:
                    continue
                # Keep fragments so SPA routes like #/page are preserved at enqueue time
                links.add(str(raw).strip())
    except Exception:
        # Be tolerant to file/parse issues
        return sorted(links)

    return sorted(links)


from typing import Optional, List


def crawl(session, start_url, max_depth=3, rate_limit=0.5, out_path=None, playwright_results_path: str = "crawl_results.ndjson", extra_seeds: Optional[List[str]] = None):

    if not start_url.endswith('/'):
        start_url = start_url + '/'

    visited = set()
    queue = deque([(start_url, 0)])
    domain = urlparse(start_url).netloc
    base_path = urlparse(start_url).path.rstrip('/') or '/'

    total_links_discovered = 0



    # Seed queue with links discovered by headless crawler (depth 0)h
    for hl in _load_headless_links_simple(playwright_results_path):
        if hl == start_url:
            continue
        try:
            # Normalize for comparison (strip fragments)
            norm_hl = _normalize_url(hl)
            parsed_hl = urlparse(norm_hl)
            # Enforce same domain
            if parsed_hl.netloc != domain:
                continue
            # Enforce base path scope similar to link discovery below
            link = norm_hl
            if not parsed_hl.path.startswith(base_path):
                if parsed_hl.path.startswith('/') and not parsed_hl.path.startswith(base_path + '/'):
                    corrected_path = base_path.rstrip('/') + parsed_hl.path
                    link = urlunparse((parsed_hl.scheme, parsed_hl.netloc, corrected_path, "", parsed_hl.query, ""))
                else:
                    # Skip anything outside the base path
                    continue
            queue.append((link, 0))
        except Exception:
            # Be tolerant to malformed URLs in headless results
            continue

    # Seed additional provided seeds (depth 0), respecting same domain/base_path
    if extra_seeds:
        for es in extra_seeds:
            try:
                if not es:
                    continue
                norm_es = _normalize_url(es)
                if norm_es == start_url:
                    continue
                pes = urlparse(norm_es)
                if pes.netloc != domain:
                    continue
                link = norm_es
                if not pes.path.startswith(base_path):
                    if pes.path.startswith('/') and not pes.path.startswith(base_path + '/'):
                        corrected_path = base_path.rstrip('/') + pes.path
                        link = urlunparse((pes.scheme, pes.netloc, corrected_path, "", pes.query, ""))
                    else:
                        continue
                queue.append((link, 0))
            except Exception:
                continue

    while queue:
        url, depth = queue.popleft()
        # Normalize for actual HTTP request (strips fragments)
        request_url = _normalize_url(url)
        if depth > max_depth:
            continue

        # Guard: skip any off-scope URLs that slipped into the queue (domain/base_path)
        try:
            parsed_req = urlparse(request_url)
            if parsed_req.netloc != domain:
                continue
            if not (parsed_req.path.startswith(base_path) or parsed_req.path == ""):
                # Allow exact base root as well
                if not (parsed_req.path == "/" and base_path == "/"):
                    continue
        except Exception:
            continue


        if request_url in visited:
            try:
                parsed_page = urlparse(request_url)
                get_params = parse_qs(parsed_page.query)
                fragment = urlparse(url).fragment
                mapped_record = {
                    "schema_version": 1,
                    "source": "static_crawler",
                    "discovered_at": _iso_now(),
                    "page": url,
                    "depth": depth,
                    "links": [],
                    "get_params": get_params,
                    "forms": [],
                    "mapped_to": request_url,
                    "fragment_only_mapped": bool(fragment)
                }
                line = json.dumps(mapped_record, ensure_ascii=False)
                print(line)
                if out_path:
                    with open(out_path, "a", encoding="utf-8") as f:
                        f.write(line + "\n")
            except Exception:
                pass
            continue

        visited.add(request_url)
        print("Crawling:", url)

        try:
            r = session.get(request_url, timeout=10, verify=False)
        except Exception as e:
            print(f"Request failed for {request_url}: {e}")
            continue

        # Use final URL after redirects
        final_url = _normalize_url(r.url)
        soup = BeautifulSoup(r.text, "html.parser")

        page_links = []
        for a in soup.find_all("a", href=True):
            raw_href = a["href"].strip()
            if not raw_href:
                continue

            # Resolve URL against the actual fetched page URL
            link = urljoin(final_url, raw_href)
            parsed = urlparse(link)
            if parsed.netloc != domain:
                continue

            # fix absolute paths that escape '/DVWA'
            if not parsed.path.startswith(base_path):

                if raw_href.startswith('/') and not raw_href.startswith(base_path + '/'):
                    corrected_path = base_path.rstrip('/') + parsed.path
                    link = urlunparse((parsed.scheme, parsed.netloc, corrected_path, "", parsed.query, ""))
                    parsed = urlparse(link)
                else:
                    # Skip anything outside the DVWA base path
                    continue

            link = _normalize_url(link)
            page_links.append(link)
            if link not in visited and depth + 1 <= max_depth:
                queue.append((link, depth + 1))

        total_links_discovered += len(page_links)

        parsed_page = urlparse(final_url)
        get_params = parse_qs(parsed_page.query)

        forms = _parse_forms(soup, final_url)

        record = {
            "schema_version": 1,
            "source": "static_crawler",
            "discovered_at": _iso_now(),
            "page": final_url,
            "depth": depth,
            "links": page_links,
            "get_params": get_params,
            "forms": forms
        }

        line = json.dumps(record, ensure_ascii=False)
        print(line)
        if out_path:
            with open(out_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

        time.sleep(rate_limit)

    print(f"Pages visited: {len(visited)}; Links discovered on pages: {total_links_discovered}")
    return visited

def static_main(seed:str):


    session = requests.Session()
    session.verify = False




    result = crawl(
        session,
        start_url=seed,
        max_depth=3,
        rate_limit=0.5,
        out_path="static_crawl_results.ndjson",
        playwright_results_path="static_crawl_results.ndjson"
    )


def static_main_seeds(seeds: list[str]):

    if not isinstance(seeds, list) or not seeds:
        return
    session = requests.Session()
    session.verify = False
    start = seeds[0]
    extra = seeds[1:] if len(seeds) > 1 else []
    crawl(
        session,
        start_url=start,
        max_depth=3,
        rate_limit=0.5,
        out_path="static_crawl_results.ndjson",
        playwright_results_path="static_crawl_results.ndjson",
        extra_seeds=extra,
    )
