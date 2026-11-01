"""把 subconverter 模板（*.ini）翻译成小火箭配置（只含分组和规则，不含节点）。

小火箭不支持 GEOSITE / GEOIP 分类，这里把它们换成 blackmatrix7 的同类规则集；
节点由 Sub-Store 在分组里加 policy-path 引用订阅。

用法：python tools/ini2shadowrocket.py Custom_Clash_Full.ini [额外规则 rules.yaml]
输出：同名的 .shadowrocket.conf（例如 Custom_Clash_Full.shadowrocket.conf）
额外规则：Clash 写法的 rules.yaml（openclash-rules 仓库里那份），放在最前面
"""
import sys
from pathlib import Path

from ini2mihomo import MIRROR, RAW, parse_group

BM = "https://testingcf.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Shadowrocket/{0}/{0}.list"

# GEOSITE 分类 → blackmatrix7 规则集（一个分类可能对应多个）；空列表表示小火箭里没有对应的，跳过
GEOSITE = {
    "private": ["Lan"],
    "google-cn": [],
    "category-games@cn": [],
    "category-game-platforms-download": [],
    "category-public-tracker": [],
    "category-communication": ["Telegram", "Whatsapp", "Line", "Discord"],
    "category-social-media-!cn": ["Twitter", "Facebook", "Instagram"],
    "openai": ["OpenAI"],
    "onedrive": ["OneDrive"],
    "bing": ["Copilot", "Bing"],
    "category-ai-!cn": ["Claude", "Gemini"],
    "github": ["GitHub"],
    "category-speedtest": ["Speedtest"],
    "youtube": ["YouTube"],
    "apple-tvplus": ["AppleTV"],
    "apple": ["Apple"],
    "microsoft": ["Microsoft"],
    "googlefcm": ["GoogleFCM"],
    "google": ["Google"],
    "tiktok": ["TikTok"],
    "netflix": ["Netflix"],
    "disney": ["Disney"],
    "hbo": ["HBO"],
    "primevideo": ["PrimeVideo"],
    "category-emby": ["Emby"],
    "spotify": ["Spotify"],
    "bahamut": ["Bahamut"],
    "steam": ["Steam"],
    "category-games": ["Game"],
    "category-entertainment": ["GlobalMedia"],
    "category-pt": ["PrivateTracker"],
    "paypal": ["PayPal"],
    "category-ecommerce": ["Amazon", "eBay", "Shopee"],
    "gfw": ["Global"],
    "cn": ["China"],
}
# blackmatrix7 没有的，直接写域名
INLINE = {
    "talkatone": ["DOMAIN-SUFFIX,talkatone.com", "DOMAIN-KEYWORD,talkatone"],
}
# 这些 GEOIP 已经包含在对应的规则集里（Telegram、Twitter……都带 IP 段），只保留 CN 和私有地址
GEOIP = {"cn": "GEOIP,CN", "private": None}
# Clash 规则类型在小火箭里的写法
CLASH_TYPES = {"DST-PORT": "DEST-PORT", "SRC-IP-CIDR": "SRC-IP", "IP-CIDR6": "IP-CIDR"}

GENERAL = """[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 127.0.0.1, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32, 239.255.255.250/32
dns-server = https://doh.pub/dns-query, https://dns.alidns.com/dns-query
fallback-dns-server = system
ipv6 = false
prefer-ipv6 = false
dns-direct-system = false
icmp-auto-reply = true
always-reject-url-rewrite = false
private-ip-answer = true
dns-direct-fallback-proxy = true
udp-policy-not-supported-behaviour = REJECT
# Sub-Store 会把下面这行换成这份完整配置自己的分享链接
update-url = https://example.invalid/replaced-by-sub-store
"""


def split_auto(groups):
    """小火箭/圈X 的自动测速组不能手动点节点。国家组（带筛选的自动组）拆成两个：
    同名的手动组（第一项是「xx自动」子组，下面是这个国家的全部节点）+ 自动子组，两种模式都能用。"""
    manual, autos = [], []
    for g in groups:
        if g["type"] == "url-test" and g.get("filter"):
            name = g["name"].replace("节点", "自动") if "节点" in g["name"] else g["name"] + "自动"
            autos.append(dict(g, name=name))
            manual.append({"name": g["name"], "type": "select", "proxies": [name],
                           "include_all": True, "filter": g["filter"]})
        else:
            manual.append(g)
    return manual + autos


def group_line(g):
    parts = [g["type"]]
    if g["type"] == "url-test":
        parts += [f"url={g['url']}", f"interval={g.get('interval', 300)}",
                  f"tolerance={g.get('tolerance', 50)}", "timeout=5"]
    parts += g.get("proxies", [])
    if g.get("include_all"):
        parts.append(f"policy-regex-filter={g.get('filter', '.*')}")
    return f"{g['name']} = " + ",".join(parts)


def ruleset_lines(line, warnings):
    group, src = line.split(",", 1)
    if not src.startswith("[]"):
        url = RAW.sub(MIRROR, src.split(",")[0])
        return [f"RULE-SET,{url},{group}"]
    parts = src[2:].split(",")
    kind, value = parts[0], parts[1] if len(parts) > 1 else ""
    if kind == "FINAL":
        return [f"FINAL,{group}"]
    if kind == "GEOSITE":
        if value in INLINE:
            return [f"{r},{group}" for r in INLINE[value]]
        if value not in GEOSITE:
            warnings.append(f"没有对应规则集，跳过: GEOSITE,{value}")
            return []
        return [f"RULE-SET,{BM.format(n)},{group}" for n in GEOSITE[value]]
    if kind == "GEOIP":
        rule = GEOIP.get(value.lower())
        return [f"{rule},{group}"] if rule else []
    return [",".join([kind, value, group] + parts[2:])]


def extra_rules(path):
    out = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.split(" #", 1)[0].strip()
        if line.startswith("- "):
            parts = [p.strip() for p in line[2:].strip("'\"").split(",")]
            parts[0] = CLASH_TYPES.get(parts[0].upper(), parts[0].upper())
            if parts[0] != "MATCH":
                out.append(",".join(parts))
    return out


def convert(text, extra=None):
    groups, rules, warnings = [], [], []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("custom_proxy_group="):
            groups.append(parse_group(line.split("=", 1)[1]))
        elif line.startswith("ruleset="):
            rules += ruleset_lines(line.split("=", 1)[1], warnings)
    # 同一个规则集被多个分类映射到时只留第一次
    seen, deduped = set(), []
    for r in rules:
        key = r.rsplit(",", 1)[0] if r.startswith("RULE-SET,") else r
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    groups = split_auto(groups)
    head = (["# ---- 自定义规则（openclash-rules/rules.yaml）----"] + extra_rules(extra)
            + ["# ---- 模板规则 ----"]) if extra else []
    out = [GENERAL, "[Proxy Group]"] + [group_line(g) for g in groups]
    out += ["", "[Rule]"] + head + deduped + ["", "[Host]", "localhost = 127.0.0.1", ""]
    return "\n".join(out), len(groups), len(deduped), warnings


def main():
    src = Path(sys.argv[1])
    extra = sys.argv[2] if len(sys.argv) > 2 else None
    text, g, r, warnings = convert(src.read_text(encoding="utf-8"), extra)
    dst = src.with_suffix(".shadowrocket.conf")
    header = f"# 由 {src.name} 自动生成（tools/ini2shadowrocket.py），不要手改；节点由 Sub-Store 用 policy-path 注入\n\n"
    dst.write_text(header + text, encoding="utf-8", newline="\n")
    print(f"{src.name} -> {dst.name}：分组 {g}，规则 {r}")
    for w in warnings:
        print("提示:", w)


if __name__ == "__main__":
    main()
