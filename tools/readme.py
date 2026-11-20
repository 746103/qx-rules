#!/usr/bin/env python3
"""Regenerate README.md (file list + original source URLs) from sources.json and status.json."""
import json, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
m = json.load(open(os.path.join(ROOT, "sources.json"), encoding="utf-8"))
st = {}
p = os.path.join(ROOT, "status.json")
if os.path.exists(p):
    st = json.load(open(p, encoding="utf-8"))
base = "https://raw.githubusercontent.com/%s/%s/" % (m["repo"], m.get("branch", "main"))
titles = {"rules": "分流规则 rules/", "rewrite": "重写 rewrite/", "scripts": "脚本 scripts/",
          "icons": "图标 icons/", "others": "其他 others/"}
L = ["# qx-rules", "",
     "Quantumult X 远程资源的镜像（规则、重写、脚本、图标）。由 `.github/workflows/sync.yml` 每天从原始地址重新拉取，",
     "重写文件里引用的脚本地址会自动改成本仓库的 raw 地址。拉取失败时保留旧副本。", "",
     "Raw 地址前缀：`%s`" % base, "",
     "## 版权 / License", "",
     "本仓库只是镜像，不拥有任何文件的版权。每个文件的版权和许可证归下表中原始仓库/作者所有，",
     "请遵守原项目的许可证；如原作者要求删除，请提 issue。脚本仅供个人学习使用。", ""]
for cat in ["rules", "rewrite", "scripts", "icons", "others"]:
    rows = [e for e in m["files"] if e["path"].startswith(cat + "/")]
    if not rows:
        continue
    L += ["## %s (%d)" % (titles[cat], len(rows)), "", "| 文件 | 原始地址 | 状态 |", "|---|---|---|"]
    for e in rows:
        s = st.get(e["path"], "")
        L.append("| `%s` | %s | %s |" % (e["path"], e["url"], "ok" if s == "ok" else (s or "-")))
    L.append("")
open(os.path.join(ROOT, "README.md"), "w", encoding="utf-8").write("\n".join(L))
