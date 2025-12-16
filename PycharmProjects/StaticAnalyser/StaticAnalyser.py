import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from collections import deque
import time
import json
from datetime import datetime, timezone

def login(session, login_url, username, password):
    # Fetch login page first to capture CSRF token
    try:
        r_get = session.get(login_url, timeout=10)
    except Exception as e:
        print(f"Failed to load login page: {e}")
        r_get = None

    user_token = None
    if r_get is not None:
        soup = BeautifulSoup(r_get.text, "html.parser")
        token_inp = soup.find("input", attrs={"name": "user_token"})
        if token_inp:
            user_token = token_inp.get("value")

    payload = {
        "username": username,
        "password": password,
        "Login": "Login",
    }
    if user_token:
        payload["user_token"] = user_token

    # Send the POST request
    r = session.post(login_url, data=payload)



    return r

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


def crawl(session, start_url, max_depth=3, rate_limit=0.5, out_path=None):

    if not start_url.endswith('/'):
        start_url = start_url + '/'

    visited = set()
    queue = deque([(start_url, 0)])
    domain = urlparse(start_url).netloc
    base_path = urlparse(start_url).path.rstrip('/') or '/'

    total_links_discovered = 0

    # prepare output file (truncate if exists)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            pass

    while queue:
        url, depth = queue.popleft()
        if depth > max_depth or url in visited:
            continue

        visited.add(url)
        print("Crawling:", url)

        try:
            r = session.get(url, timeout=10)
        except Exception as e:
            print(f"Request failed for {url}: {e}")
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

            # Enforce base path scoping; fix absolute paths that escape '/DVWA'
            if not parsed.path.startswith(base_path):
                # If original href looked like a root-absolute path, try prefixing base_path
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
session = requests.Session()

login(session,
      login_url="http://localhost/DVWA/login.php",
      username="admin",
      password="password")

result = crawl(
    session,
    start_url="http://localhost/DVWA",
    max_depth=3,
    rate_limit=0.5,
    out_path="crawl_results.ndjson"
)
