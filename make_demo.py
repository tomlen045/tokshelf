#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tokshelf 真实演示：扫描本机真实仓库树。输出已脱敏（工具不变量），仅指纹。"""
import os
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "demo-run")
os.makedirs(OUT, exist_ok=True)
PY = "/opt/homebrew/bin/python3.13"
TOK = os.path.join(HERE, "tokshelf.py")
TARGET = os.path.expanduser("~/CodeBuddy/dx")

steps = [
    ("01-scan", [PY, TOK, "scan", TARGET]),
    ("02-lease-add", [PY, TOK, "lease", "add", "--label", "gitee-发布token",
                      "--expires", "2026-12-01", "--provider", "gitee",
                      "--note", "fafa-generator remote 同款"]),
    ("03-lease-list", [PY, TOK, "lease", "list"]),
    ("04-scan-netrc", [PY, TOK, "scan", os.path.expanduser("~/.netrc")]),
]

for name, cmd in steps:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    with open(os.path.join(OUT, name + ".txt"), "w") as f:
        f.write("$ " + " ".join(cmd[2:]) + "\n\n" + r.stdout + r.stderr)
    print(name, "rc=", r.returncode)

# report 只扫一个真实仓库，控制输出规模；探活走真实网络（只读 GET）
r = subprocess.run([PY, TOK, "report", TARGET, "--warn-days", "60"],
                   capture_output=True, text=True, timeout=600)
with open(os.path.join(OUT, "05-report.txt"), "w") as f:
    f.write("$ tokshelf.py report ~/CodeBuddy/dx --warn-days 60\n\n"
            + r.stdout + r.stderr)
print("05-report rc=", r.returncode)

# 脱敏终检：demo-run 全部产物里绝不出现完整凭据
import re
bad = []
for fn in os.listdir(OUT):
    body = open(os.path.join(OUT, fn), encoding="utf-8").read()
    for m in re.finditer(r"[0-9a-f]{32}", body):
        bad.append((fn, m.group(0)))
    for m in re.finditer(r"ghp_[A-Za-z0-9]{20,}", body):
        bad.append((fn, m.group(0)))
if bad:
    print("LEAK!", bad[:3])
    sys.exit(1)
print("redact-check: all demo outputs clean (no full tokens)")
