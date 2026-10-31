"""把 subconverter 模板（*.ini）翻译成 mihomo 配置（只含分组和规则，不含节点）。

节点由 Sub-Store「文件 → mihomo 配置」注入，OpenClash 直接订阅 Sub-Store 输出的完整配置，
不再经过在线订阅转换。

用法：python tools/ini2mihomo.py Custom_Clash_Full.ini
输出：同名的 .mihomo.yaml（例如 Custom_Clash_Full.mihomo.yaml）
"""
import json
import re
import sys
from pathlib import Path

# raw.githubusercontent.com 国内经常打不开，换成 jsDelivr 镜像
RAW = re.compile(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$")
MIRROR = r"https://testingcf.jsdelivr.net/gh/\1/\2@\3/\4"


def q(s):
    # YAML 双引号字符串（JSON 字符串就是合法的 YAML）
    return json.dumps(s, ensure_ascii=False)


def parse_group(line):
    name, kind, *items = line.split("`")
    group = {"name": name, "type": kind}
    if kind in ("url-test", "fallback", "load-balance"):
        regex, url, timing = items[0], items[1], items[2]
        interval, _timeout, tolerance = (timing.split(",") + ["", "", ""])[:3]
        group.update(include_all=True, url=url, interval=int(interval or 300))
        if regex != ".*":
            group["filter"] = regex
        if tolerance:
            group["tolerance"] = int(tolerance)
        return group
    proxies = []
    for item in items:
        if item.startswith("[]"):
            proxies.append(item[2:])
        else:
            group["include_all"] = True
            if item != ".*":
                group["filter"] = item
    if proxies:
        group["proxies"] = proxies
    return group


def parse_ruleset(line, providers):
    group, src = line.split(",", 1)
    if src.startswith("[]"):
        parts = src[2:].split(",")
        if parts[0] == "FINAL":
            return f"MATCH,{group}"
        return ",".join([parts[0], parts[1], group] + parts[2:])
    url, *rest = src.split(",")
    url = RAW.sub(MIRROR, url)
    name = re.sub(r"\W", "_", Path(url.split("?")[0]).stem)
    base, n = name, 2
    while name in providers and providers[name]["url"] != url:
        name, n = f"{base}_{n}", n + 1
    providers[name] = {"url": url, "interval": int(rest[0]) if rest and rest[0] else 86400}
    return f"RULE-SET,{name},{group}"


def convert(text):
    groups, rules, providers = [], [], {}
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("custom_proxy_group="):
            groups.append(parse_group(line.split("=", 1)[1]))
        elif line.startswith("ruleset="):
            rules.append(parse_ruleset(line.split("=", 1)[1], providers))

    out = ["proxy-groups:"]
    for g in groups:
        out.append(f"  - name: {q(g['name'])}")
        out.append(f"    type: {g['type']}")
        if "proxies" in g:
            out.append("    proxies: [" + ", ".join(q(p) for p in g["proxies"]) + "]")
        if g.get("include_all"):
            out.append("    include-all: true")
        if "filter" in g:
            out.append(f"    filter: {q(g['filter'])}")
        for key in ("url", "interval", "tolerance"):
            if key in g:
                out.append(f"    {key}: {q(g[key]) if key == 'url' else g[key]}")

    if providers:
        out.append("\nrule-providers:")
        for name, p in providers.items():
            out += [
                f"  {name}:",
                "    type: http",
                "    behavior: classical",
                "    format: text",
                f"    url: {q(p['url'])}",
                f"    path: ./rule_provider/{name}.list",
                f"    interval: {p['interval']}",
            ]

    out.append("\nrules:")
    out += [f"  - {q(r)}" for r in rules]
    return "\n".join(out) + "\n", len(groups), len(rules), len(providers)


def main():
    for arg in sys.argv[1:]:
        src = Path(arg)
        text, g, r, p = convert(src.read_text(encoding="utf-8"))
        dst = src.with_suffix(".mihomo.yaml")
        header = f"# 由 {src.name} 自动生成（tools/ini2mihomo.py），不要手改；节点由 Sub-Store 注入\n\n"
        dst.write_text(header + text, encoding="utf-8", newline="\n")
        print(f"{src.name} -> {dst.name}：分组 {g}，规则 {r}，规则集 {p}")


if __name__ == "__main__":
    main()
