#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发布前自检：排版 HTML 全规则扫描 + 仓库敏感信息扫描。全绿才可交付。"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HTML = os.path.join(HERE, "公众号排版版.html")
body = open(HTML, encoding="utf-8").read()

fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (" :: " + detail if detail and not cond else ""))
    if not cond:
        fails.append(name)


# 1. 标签配对
for tag in ("section", "p", "strong"):
    o = len(re.findall(r"<%s(\s|>)" % tag, body))
    c = len(re.findall(r"</%s>" % tag, body))
    check("标签配对 <%s> %d/%d" % (tag, o, c), o == c)

# 2. 禁止双分号
check("无双分号 ;;", ";;" not in body)

# 3. 卡片统一 87% 宽 + box-sizing
cards = re.findall(r"<section[^>]*>", body)
bad_w = [c for c in cards if "width: 87%" not in c and "width:87%" not in c]
check("全部 section 卡片 87%% 宽 (%d 张)" % len(cards), not bad_w, str(bad_w[:1]))
bad_box = [c for c in cards if "box-sizing: border-box" not in c]
check("全部卡片 box-sizing", not bad_box)

# 4. 显式 text-align（所有 p 和 section）
ps = re.findall(r"<p[^>]*>", body)
bad_align = [p for p in ps if "text-align:" not in p]
check("全部 p 显式 text-align (%d 个)" % len(ps), not bad_align, str(bad_align[:1]))
bad_salign = [c for c in cards if "text-align:" not in c]
check("全部 section 显式 text-align", not bad_salign)

# 5. 章节 01-04 骨架
for n in ("01", "02", "03", "04"):
    check("章节 %s 存在" % n, ('>%s<' % n) in body)
check("章节编号橙红 rgb(255,104,39)", "rgb(255,104,39)" in body)

# 6. 正文规格：17px/2em/0.034em
check("正文 17px", "font-size: 17px" in body)
check("行高 2em", "line-height: 2em" in body)
check("字距 0.034em", "letter-spacing: 0.034em" in body)

# 7. 代码块黑底绿字
check("代码块 #0d1117 + #3fb950", "#0d1117" in body and "#3fb950" in body)

# 8. 图片：全部 gcore CDN + 是 6 张已知实拍图
imgs = re.findall(r'<img src="([^"]+)"', body)
check("图片 6 张", len(imgs) == 6, str(len(imgs)))
bad_img = [u for u in imgs if not u.startswith(
    "https://gcore.jsdelivr.net/gh/tomlen045/tokshelf@main/")]
check("全部 gcore.jsdelivr.net CDN", not bad_img, str(bad_img[:1]))
check("无 cdn.jsdelivr.net 主域", "cdn.jsdelivr.net" not in body)
check("图注 ▲ ×6", body.count("▲") == 6, str(body.count("▲")))

# 9. 文末顺序：金句暗卡 → 开源地址卡 → 互动 → 关注卡
tail = body[-2600:]
check("文末=金句暗卡(#0d1117)", "#0d1117" in tail)
check("文末=开源地址卡+阅读原文", "阅读原文" in tail and "gitee.com/tomlen/tokshelf" in tail)
check("文末=互动钩子", "点赞最高" in tail)
check("文末=关注卡", "我是小薅薅" in tail and "关注我" in tail)
pos_gold = body.find("凭据不是配置，是耗材")
pos_oss = body.find("开源地址")
pos_follow = body.find("我是小薅薅</p>", pos_oss)
check("文末顺序 金句→开源→关注", 0 < pos_gold < pos_oss < pos_follow)

# 10. 段落规模（短句段 40-60）
shortps = [p for p in re.findall(
    r'<p style="margin: 16px 8px[^"]*"[^>]*>(.*?)</p>', body, re.S)]
check("短句段 %d 个(40-60)" % len(shortps), 40 <= len(shortps) <= 60)

# 11. 敏感信息扫描（HTML + 仓内全部交付文件）
patterns = {
    "内网段 172.16.": r"172\.16\.",
    "内网段 172.18.": r"172\.18\.",
    "门牌 10.92.": r"10\.92\.",
    "完整32hex凭据": r"[0-9a-f]{32}(?![0-9a-f])",
    "完整 ghp_ token": r"ghp_[A-Za-z0-9]{20,}",
    "完整 github_pat_": r"github_pat_[A-Za-z0-9_]{20,}",
    "完整 sk- key": r"sk-[A-Za-z0-9_-]{16,}",
}
# tokshelf.py 自测 fixture 的合成假凭据（明显非真实形态）
FIXTURE_OK = {"a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8",
              "1234567890abcdef1234567890abcdef"}
targets = {"公众号HTML": body}
for fn in ("README.md", "README_EN.md", "tokshelf.py", "make_demo.py"):
    targets[fn] = open(os.path.join(HERE, fn), encoding="utf-8").read()
for tname, text in targets.items():
    for pname, pat in patterns.items():
        ms = re.findall(pat, text)
        if ms:
            # selftest 里的假凭据白名单：明显 FAKE/fake 标记或合成偶数位串
            ms = [m for m in ms
                  if "FAKE" not in m and "fake" not in m
                  and m not in FIXTURE_OK]
        check("敏感扫描 %s/%s" % (tname, pname), not ms, str(ms[:2]))

# 12. 仓库跟踪文件清单（排版文件绝不入仓）
import subprocess
GIT = "/Library/Developer/CommandLineTools/usr/bin/git"
r = subprocess.run([GIT, "ls-files"], cwd=HERE, capture_output=True, text=True)
tracked = r.stdout.split()
check("排版HTML不在git跟踪", "公众号排版版.html" not in tracked)
check("封面不入仓(封面只发后台)", "cover-900x383.png" not in tracked)
check("gitignore含排版文件",
      "公众号排版版.html" in open(os.path.join(HERE, ".gitignore"),
                                  encoding="utf-8").read())

print()
if fails:
    print("SELF-CHECK FAILED: %d 项" % len(fails))
    sys.exit(1)
print("SELF-CHECK ALL GREEN (%d sections, %d p, %d imgs)" %
      (len(cards), len(ps), len(imgs)))
