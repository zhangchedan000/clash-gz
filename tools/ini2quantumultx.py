"""把 subconverter 模板（*.ini）翻译成圈X配置（只含分组和规则，不含节点）。

圈X不支持 GEOSITE，换成 blackmatrix7 的同类规则集（和 ini2shadowrocket.py 用同一张对照表）；
ini 里引用的远程 .list 是 Clash 写法，下载后转成圈X写法存到 qx/ 目录；
节点由 Sub-Store 在 [server_remote] 里加上订阅。

用法：python tools/ini2quantumultx.py Custom_Clash_Full.ini
输出：Custom_Clash_Full.quantumultx.conf 和 qx/*.list
"""
import re
import sys
import urllib.request
from pathlib import Path

from ini2mihomo import parse_group
from ini2shadowrocket import GEOIP, GEOSITE, INLINE, split_auto

BM = "https://testingcf.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/QuantumultX/{0}/{0}.list"
SELF = "https://testingcf.jsdelivr.net/gh/zhangchedan000/clash-gz@main/qx/{0}.list"
QX_DIR = Path("qx")

# Clash 规则类型 → 圈X；不在表里的（端口、进程之类）圈X不支持，跳过
TYPES = {
    "DOMAIN": "HOST",
    "DOMAIN-SUFFIX": "HOST-SUFFIX",
    "DOMAIN-KEYWORD": "HOST-KEYWORD",
    "DOMAIN-WILDCARD": "HOST-WILDCARD",
    "IP-CIDR": "IP-CIDR",
    "IP-CIDR6": "IP6-CIDR",
    "GEOIP": "GEOIP",
    "IP-ASN": "IP-ASN",
}

GENERAL = """[general]
network_check_url=http://www.gstatic.com/generate_204
server_check_url=http://cp.cloudflare.com/generate_204
server_check_timeout=3000
excluded_routes=10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 239.255.255.250/32, 255.255.255.255/32
udp_whitelist=1-442, 444-65535
fallback_udp_policy=direct

[dns]
no-ipv6
server=223.5.5.5
server=119.29.29.29
server=114.114.114.114
"""


def policy(name):
    return name.lower() if name.upper() in ("DIRECT", "REJECT") else name


def policy_line(g):
    regex = g.get("filter", ".*") if g.get("include_all") else None
    if g["type"] == "url-test":
        return (f"url-latency-benchmark={g['name']}, server-tag-regex={regex}, "
                f"check-interval={g.get('interval', 300)}, tolerance={g.get('tolerance', 50)}, alive-checking=false")
    parts = [g["name"]] + [policy(p) for p in g.get("proxies", [])]
    if regex:
        parts.append(f"server-tag-regex={regex}")
    return "static=" + ", ".join(parts)


def to_qx(lines, tag):
    out = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        kind = TYPES.get(parts[0].upper())
        if kind and len(parts) > 1:
            # 远程分流用 force-policy 指定策略，这里的策略名只是占位
            extra = [p for p in parts[2:] if p == "no-resolve"]
            out.append(",".join([kind, parts[1], tag] + extra))
    return out


def write_list(name, lines):
    QX_DIR.mkdir(exist_ok=True)
    (QX_DIR / f"{name}.list").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return SELF.format(name)


def remote(url, group, tag):
    return f"{url}, tag={tag}, force-policy={policy(group)}, update-interval=86400, opt-parser=false, enabled=true"


def ruleset_lines(line, local, warnings):
    group, src = line.split(",", 1)
    if not src.startswith("[]"):
        url = src.split(",")[0]
        name = re.sub(r"\W", "_", Path(url.split("?")[0]).stem)
        text = urllib.request.urlopen(url, timeout=60).read().decode("utf-8")
        return [remote(write_list(name, to_qx(text.splitlines(), name)), group, name)]
    parts = src[2:].split(",")
    kind, value = parts[0], parts[1] if len(parts) > 1 else ""
    if kind == "FINAL":
        local.append(f"FINAL,{policy(group)}")
        return []
    if kind == "GEOSITE":
        if value in INLINE:
            name = re.sub(r"\W", "_", value)
            return [remote(write_list(name, to_qx(INLINE[value], name)), group, name)]
        if value not in GEOSITE:
            warnings.append(f"没有对应规则集，跳过: GEOSITE,{value}")
        return [remote(BM.format(n), group, n) for n in GEOSITE.get(value, [])]
    if kind == "GEOIP":
        rule = GEOIP.get(value.lower())
        if rule:
            local.append(f"{rule},{policy(group)}")
        return []
    warnings.append(f"圈X不支持，跳过: {src}")
    return []


def convert(text):
    groups, filters, local, warnings = [], [], [], []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("custom_proxy_group="):
            groups.append(parse_group(line.split("=", 1)[1]))
        elif line.startswith("ruleset="):
            filters += ruleset_lines(line.split("=", 1)[1], local, warnings)
    # 同一个规则集被多个分类映射到时只留第一次
    seen, deduped = set(), []
    for f in filters:
        url = f.split(",", 1)[0]
        if url not in seen:
            seen.add(url)
            deduped.append(f)
    # FINAL 必须在最后
    local.sort(key=lambda r: r.startswith("FINAL"))
    groups = split_auto(groups)
    out = [GENERAL, "[policy]"] + [policy_line(g) for g in groups]
    # 圈X要求这些段落都存在，空的也要写上
    out += ["", "[server_local]", "", "[server_remote]", "", "[filter_remote]"] + deduped
    out += ["", "[filter_local]"] + local
    out += ["", "[rewrite_remote]", "", "[rewrite_local]", "", "[task_local]", "", "[http_backend]", "", "[mitm]", ""]
    return "\n".join(out), len(groups), len(deduped), warnings


def main():
    src = Path(sys.argv[1])
    text, g, r, warnings = convert(src.read_text(encoding="utf-8"))
    dst = src.with_suffix(".quantumultx.conf")
    header = f"; 由 {src.name} 自动生成（tools/ini2quantumultx.py），不要手改；节点由 Sub-Store 加到 [server_remote]\n\n"
    dst.write_text(header + text, encoding="utf-8", newline="\n")
    print(f"{src.name} -> {dst.name}：分组 {g}，远程分流 {r}")
    for w in warnings:
        print("提示:", w)


if __name__ == "__main__":
    main()
