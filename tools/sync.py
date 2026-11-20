#!/usr/bin/env python3
"""Mirror Quantumult X remote resources listed in sources.json into this repo.

- Downloads every entry from its upstream URL (retry once with a Quantumult X UA).
- In rewrite snippets, discovers second-level script URLs (.js), mirrors them too,
  and rewrites them to this repo's raw URLs.
- On fetch failure keeps the existing copy; never exits non-zero for upstream errors.
"""
import json, os, re, sys, urllib.parse, urllib.request, posixpath

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "sources.json")
UAS = ["Mozilla/5.0 (curl-compatible mirror)",
       "Quantumult%20X/1.5.2 (iPhone; iOS 17.0; Scale/3.00)"]
URL_RE = re.compile(r"https?://[^\s,\"'<>]+")
# Second-level dependencies inside rewrite snippets: script bodies (QX "url script-xxx URL",
# Surge/Loon "script-path=URL"), echo-response mock files and jq-path files. Match patterns
# (the regex on the left of a rewrite) and 302/307 redirect targets are NOT mirrored.
DEP_RE = re.compile(r"(script-path|script-[a-z-]+|echo-response|jq-path)\s*[= ]\s*(?:[\w.+-]+/[\w.+-]+\s+echo-response\s+)?(https?://[^\s,\"'<>]+)")

def raw_base(m):
    return "https://raw.githubusercontent.com/%s/%s/" % (m["repo"], m.get("branch", "main"))

def raw_url(m, path):
    return raw_base(m) + urllib.parse.quote(path, safe="/()-_.~")

def fetch(url):
    last = None
    for ua in UAS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ua})
            with urllib.request.urlopen(req, timeout=30) as r:
                if r.status == 200:
                    data = r.read()
                    if data:
                        return data, None
                    last = "empty body"
                else:
                    last = "HTTP %s" % r.status
        except Exception as e:  # noqa
            last = "%s: %s" % (type(e).__name__, e)
    return None, last

def owner_of(url):
    p = urllib.parse.urlparse(url)
    parts = [x for x in p.path.split("/") if x]
    if p.netloc in ("raw.githubusercontent.com", "github.com", "gist.githubusercontent.com",
                    "gist.github.com", "cdn.jsdelivr.net") and parts:
        if p.netloc == "cdn.jsdelivr.net" and len(parts) > 1:
            return parts[1]
        return parts[0]
    return p.netloc

def path_for(url, category, taken):
    p = urllib.parse.urlparse(url)
    name = urllib.parse.unquote(posixpath.basename(p.path.rstrip("/"))) or "index"
    name = re.sub(r"[\\:*?\"<>|]", "_", name)
    if category == "scripts" and "." not in name:
        name += ".js"
    base = "%s/%s/%s" % (category, owner_of(url), name)
    path, i = base, 2
    while path in taken and taken[path] != url:
        stem, ext = os.path.splitext(base)
        path = "%s_%d%s" % (stem, i, ext); i += 1
    return path

def strip_comments(line):
    s = line.lstrip()
    return s.startswith("#") or s.startswith(";") or s.startswith("//")

def main():
    m = json.load(open(MANIFEST, encoding="utf-8"))
    entries = m["files"]
    taken = {e["path"]: e["url"] for e in entries}
    by_url = {e["url"]: e for e in entries}
    status = {}
    i = 0
    while i < len(entries):
        e = entries[i]; i += 1
        data, err = fetch(e["url"])
        dest = os.path.join(ROOT, e["path"])
        if data is None:
            status[e["path"]] = "FAILED (%s)%s" % (err, "; kept old copy" if os.path.exists(dest) else "")
            continue
        status[e["path"]] = "ok"
        if e.get("kind") == "rewrite":
            text = data.decode("utf-8", "replace")
            for line in text.splitlines():
                if strip_comments(line):
                    continue
                for kw, u in DEP_RE.findall(line):
                    u = u.rstrip(")];")
                    cat = "scripts" if kw.startswith("script") else "others"
                    if u not in by_url:
                        ne = {"path": path_for(u, cat, taken), "url": u,
                              "kind": "script" if cat == "scripts" else "data", "parent": e["path"]}
                        taken[ne["path"]] = u; by_url[u] = ne; entries.append(ne)
            e["_text"] = text
        else:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            if not os.path.exists(dest) or open(dest, "rb").read() != data:
                open(dest, "wb").write(data)
    # second pass: write rewrite snippets with URL substitutions (only for mirrored files)
    present = {u: raw_url(m, x["path"]) for u, x in by_url.items()
               if os.path.exists(os.path.join(ROOT, x["path"]))}
    for e in entries:
        if "_text" not in e:
            continue
        text = e.pop("_text")
        out = []
        for line in text.splitlines(keepends=True):
            if not strip_comments(line):
                for u in sorted(present, key=len, reverse=True):
                    if u in line and by_url[u].get("kind") in ("script", "data"):
                        line = line.replace(u, present[u])
            out.append(line)
        new = "".join(out).encode("utf-8")
        dest = os.path.join(ROOT, e["path"])
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if not os.path.exists(dest) or open(dest, "rb").read() != new:
            open(dest, "wb").write(new)
    for e in entries:
        e.pop("_text", None)
    m["files"] = entries
    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(m, f, ensure_ascii=False, indent=1); f.write("\n")
    with open(os.path.join(ROOT, "status.json"), "w", encoding="utf-8") as f:
        json.dump(status, f, ensure_ascii=False, indent=1, sort_keys=True); f.write("\n")
    bad = [k for k, v in status.items() if v != "ok"]
    print("mirrored %d/%d, failed %d" % (len(status) - len(bad), len(status), len(bad)))
    for k in bad:
        print("  ", k, status[k])
    return 0

if __name__ == "__main__":
    sys.exit(main())
