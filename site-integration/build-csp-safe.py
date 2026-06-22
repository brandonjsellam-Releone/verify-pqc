"""Generate the CSP-safe /pq pages from the working web/ originals.
Externalizes inline scripts (script-src 'self'), swaps the fetch base to the same-origin
proxy (connect-src 'self'), and vendors js-sha512. Re-run after editing web/*."""
import os, re, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, "web")
PQ = os.path.join(ROOT, "site-integration", "pq")
os.makedirs(os.path.join(PQ, "js"), exist_ok=True)

def proxy(js):
    return (js.replace("https://testnet-idx.algonode.cloud", "/api/pq/idx")
              .replace("https://throndar.ai", "/api/pq/throndar"))

INLINE = re.compile(r"<script>\s*(.*?)</script>", re.S)

for name in ["verify-live", "verify-unified", "anchor"]:
    html = open(os.path.join(WEB, name + ".html"), encoding="utf-8").read()
    import re as _re
    html = _re.sub(r'<script src="https://cdn\.jsdelivr\.net/npm/js-sha512@0\.9\.0/src/sha512\.min\.js"[^>]*></script>',
                   '<script src="vendor/sha512.min.js"></script>', html)
    m = INLINE.search(html)
    assert m, "no inline <script> in " + name
    open(os.path.join(PQ, "js", name + ".js"), "w", encoding="utf-8").write(proxy(m.group(1)))
    html = html[:m.start()] + ('<script src="js/%s.js"></script>' % name) + html[m.end():]
    open(os.path.join(PQ, name + ".html"), "w", encoding="utf-8").write(html)
    print("built", name)

# pqbadge.js is already external — just swap the default indexer to the proxy.
pj = proxy(open(os.path.join(WEB, "pqbadge.js"), encoding="utf-8").read().replace(
    "var DEF_INDEXER = 'https://testnet-idx.algonode.cloud';", "var DEF_INDEXER = '/api/pq/idx';"))
open(os.path.join(PQ, "js", "pqbadge.js"), "w", encoding="utf-8").write(pj)
demo = open(os.path.join(WEB, "pqbadge-demo.html"), encoding="utf-8").read().replace('src="./pqbadge.js"', 'src="js/pqbadge.js"')
open(os.path.join(PQ, "pqbadge-demo.html"), "w", encoding="utf-8").write(demo)

shutil.copy(os.path.join(WEB, "index.html"), os.path.join(PQ, "index.html"))
shutil.copy(os.path.join(WEB, "anchors.json"), os.path.join(PQ, "anchors.json"))
print("done — pq/ is CSP-safe")
