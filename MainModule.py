import StaticAnalyser

import crawler_playwright
import scorer
import SQLprobe
import XSSprobe
import json
import urllib3
from urllib.parse import urlparse




urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _normalize_url(u: str) -> str:

    from urllib.parse import urlparse, urlunparse
    p = urlparse(u)
    return urlunparse((p.scheme, p.netloc, p.path, "", p.query, ""))


def _same_origin(u: str, base: str) -> bool:
    try:
        pu = urlparse(u)
        pb = urlparse(base)
        return bool(pu.scheme) and bool(pu.netloc) and (pu.netloc == pb.netloc)
    except Exception:
        return False


def _load_seeds_from_results(results_path: str, base_seed: str) -> list[str]:
    seeds = set()
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

                for key in ("page", "mapped_to"):
                    val = obj.get(key)
                    if isinstance(val, str) and _same_origin(val, base_seed):
                        seeds.add(_normalize_url(val))

                links = obj.get("links") or []
                if isinstance(links, list):
                    for l in links:
                        if not isinstance(l, str):
                            continue
                        if _same_origin(l, base_seed):
                            seeds.add(_normalize_url(l))
    except FileNotFoundError:
        pass
    except Exception:

        pass

    seeds.add(_normalize_url(base_seed))
    return sorted(seeds)

def main():
    input_seed = input("Input seed url:")





    crawler_playwright.playwright_main(input_seed)
    StaticAnalyser.static_main(input_seed)


    seeds = _load_seeds_from_results("static_crawl_results.ndjson", input_seed)

    max_second_pass = 500
    if len(seeds) > max_second_pass:
        seeds = seeds[:max_second_pass]




    # Headless crawler second pass
    try:
        crawler_playwright.playwright_main_seeds(seeds)
    except Exception as e:
        print(f"Second-pass headless error: {e}")

    # Static crawler second pass
    try:
        StaticAnalyser.static_main_seeds(seeds)
    except Exception as e:
        print(f"Second-pass static error: {e}")



if __name__ == '__main__':
    main()
    scorer.main()
    SQLprobe.main()
    XSSprobe.main()









