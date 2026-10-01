#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tokshelf —— 凭据寿命哨兵（零依赖单文件，Python 3.8+）

四命令：
  scan    扫描指定路径的凭据形态（git remote token / .env KEY=VALUE / .netrc）
  probe   对可探活凭据发最小只读请求（Gitee GET api/v5/user、GitHub GET api.github.com/user）
  lease   登记凭据预期寿命，到期前 N 天告警
  report  汇总 alive/dead/unknown + 建议动作

四不变量：
  1. 只读探测：probe 绝不带凭据做写操作（全部 GET，无 POST/PATCH/PUT/DELETE）
  2. 输出脱敏：一律指纹（前4后4，如 ghp_x…9f2），绝不明文
  3. 网络失败 ≠ 凭据坏：单独 unknown 类，不与 dead 混淆
  4. 审计不落明文：日志/JSONL 只记指纹与计数

背景：2026-09-30，Gitee 旧仓库 remote 里的 token 已 401，发布卡壳半小时。
凭据不是配置，是耗材——有寿命，需要台账。
"""
import argparse
import concurrent.futures
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime

VERSION = "1.0.0"
PROG = "tokshelf"

# ---------------------------------------------------------------- 基础设施

def data_home():
    """审计与台账的存储根目录（可用 TOKSHELF_HOME 覆盖，selftest 用临时目录隔离）。"""
    return os.environ.get("TOKSHELF_HOME") or os.path.join(
        os.path.expanduser("~"), ".tokshelf")

AUDIT_NAME = "audit.jsonl"
SHELF_NAME = "shelf.json"

SENSITIVE_KEY_RE = re.compile(r"(TOKEN|KEY|SECRET|PASS|AUTH)", re.I)
HEX32_RE = re.compile(r"^[0-9a-fA-F]{32}$")
GH_TOKEN_RE = re.compile(r"^(gh[posur]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})$")
SK_RE = re.compile(r"^sk-[A-Za-z0-9_-]{8,}$")
ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")
GIT_URL_RE = re.compile(r"^\s*url\s*=\s*(\S+)\s*$", re.M)
NETRC_RE = re.compile(
    r"machine\s+(\S+)\s+login\s+(\S+)\s+password\s+(\S+)")
SCHEMES = ("github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk-")

SKIP_DIRS = {"node_modules", "__pycache__", ".venv", "venv", ".tox",
             ".mypy_cache", ".pytest_cache", "site-packages"}


def redact(token):
    """指纹 = 形态前缀 + 前4后4（如 ghp_ab12…ef34 / 352c…e342）。短凭据整体打码。"""
    t = (token or "").strip()
    scheme = ""
    for p in SCHEMES:
        if t.startswith(p):
            scheme = p
            break
    core = t[len(scheme):] if scheme else t
    if len(core) < 8:
        return (scheme + "…") if scheme else "…"
    return scheme + core[:4] + "…" + core[-4:]


def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def append_audit(cmd, creds, extra=None):
    """审计追加：只落指纹/计数/形态，绝不落明文（不变量④）。"""
    try:
        os.makedirs(data_home(), exist_ok=True)
        rec = {
            "ts": now_iso(),
            "cmd": cmd,
            "tokshelf": VERSION,
            "fps": [c["fp"] for c in creds],
            "providers": {},
        }
        for c in creds:
            rec["providers"][c["provider"]] = \
                rec["providers"].get(c["provider"], 0) + 1
        if extra:
            rec.update(extra)
        with open(os.path.join(data_home(), AUDIT_NAME), "a",
                  encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass  # 审计失败不阻断主流程


# ---------------------------------------------------------------- 形态分类

def classify_token(value, host="", key=""):
    """按形态分类：gitee / github / openai / hex32 / generic。"""
    v = (value or "").strip()
    if GH_TOKEN_RE.match(v):
        return "github"
    if v.startswith("sk-") or SK_RE.match(v):
        return "openai"
    if host and "gitee.com" in host.lower():
        return "gitee" if HEX32_RE.match(v) else "gitee"
    if key and "GITEE" in key.upper():
        return "gitee"
    if host and "github.com" in host.lower():
        return "github"
    if HEX32_RE.match(v):
        return "hex32"
    return "generic"


PROVIDER_LABEL = {
    "gitee": "Gitee-32hex", "github": "GitHub-ghp", "openai": "OpenAI-sk-",
    "hex32": "通用hex32", "generic": "通用凭据", "netrc": "netrc口令",
}


def make_cred(ctype, provider, where, secret, extra=None):
    c = {
        "type": ctype,          # git-remote / env / netrc
        "provider": provider,   # gitee / github / openai / hex32 / generic / netrc
        "label": PROVIDER_LABEL.get(provider, provider),
        "where": where,         # 文件:行 或 host 路径
        "fp": redact(secret),
        "_secret": secret,      # 仅内存持有，任何输出前剥离
    }
    if extra:
        c.update(extra)
    return c


def _strip_quotes(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def scan_file(path, creds):
    fn = os.path.basename(path)
    dn = os.path.basename(os.path.dirname(path))
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return

    if fn == "config" and dn == ".git":
        for i, line in enumerate(lines, 1):
            m = GIT_URL_RE.match(line)
            if not m:
                continue
            url = m.group(1)
            um = re.match(r"https?://([^/\s@]+)@([^\s/]+)(/[^\s]*)?", url)
            if not um:
                continue
            token = um.group(1).split(":")[-1]
            host = um.group(2)
            tail = (um.group(3) or "").rstrip("/")
            if not token:
                continue
            provider = classify_token(token, host=host)
            creds.append(make_cred(
                "git-remote", provider, host + tail, token,
                {"file": path, "line": i}))
        return

    if fn in (".netrc", "_netrc"):
        for i, line in enumerate(lines, 1):
            for m in NETRC_RE.finditer(line):
                machine, login, pw = m.group(1), m.group(2), m.group(3)
                creds.append(make_cred(
                    "netrc", "netrc", "%s:%d machine=%s login=%s" % (
                        path, i, machine, login), pw,
                    {"file": path, "line": i, "machine": machine,
                     "login": login}))
        return

    if fn == ".env" or fn.endswith(".env"):
        for i, line in enumerate(lines, 1):
            m = ENV_LINE_RE.match(line)
            if not m:
                continue
            key, val = m.group(1), _strip_quotes(m.group(2))
            if not val or not SENSITIVE_KEY_RE.search(key):
                continue
            provider = classify_token(val, key=key)
            creds.append(make_cred(
                "env", provider, "%s:%d %s" % (path, i, key), val,
                {"file": path, "line": i, "key": key}))
        return


def _is_cred_file(dirpath, fn):
    """凭据形态预过滤：只打开候选文件，不逐个全文读取无关文件（含二进制）。"""
    if fn == "config" and os.path.basename(dirpath) == ".git":
        return True
    if fn in (".netrc", "_netrc"):
        return True
    if fn == ".env" or fn.endswith(".env"):
        return True
    return False


MAX_FILE_BYTES = 8 * 1024 * 1024  # 超大文件不读（凭据文件不会这么大）


def scan_paths(paths, baseline=None):
    """扫描路径集合（目录递归/文件直扫），返回凭据记录列表。"""
    creds = []
    for p in paths:
        p = os.path.abspath(os.path.expanduser(p))
        if os.path.isfile(p):
            scan_file(p, creds)
        elif os.path.isdir(p):
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                for fn in filenames:
                    if not _is_cred_file(dirpath, fn):
                        continue
                    fp_ = os.path.join(dirpath, fn)
                    try:
                        if os.path.getsize(fp_) > MAX_FILE_BYTES:
                            continue
                    except OSError:
                        continue
                    scan_file(fp_, creds)
    if baseline:
        creds = mark_baseline(creds, baseline)
    return creds


def load_baseline(path):
    """--baseline 手动兜底清单：每行一个裸 token 或指纹（前4…后4）。"""
    items = []
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    items.append(s)
    except OSError:
        pass
    return items


def mark_baseline(creds, baseline_items):
    """基线命中标记：扫描发现的凭据若与基线指纹一致 → baseline=True。"""
    bset = set()
    for b in baseline_items:
        bset.add(b)
        if "…" in b:
            bset.add(b.split("…")[0][:4])
    for c in creds:
        core = c["fp"]
        hit = c["fp"] in bset or any(
            core.startswith(x) for x in bset if len(x) == 4)
        c["baseline"] = bool(hit)
    return creds


def public_cred(c):
    """剥离 _secret 后的可输出视图（不变量②：任何出口绝不带明文）。"""
    return {k: v for k, v in c.items() if not k.startswith("_")}


# ---------------------------------------------------------------- probe

GITEE_API_DEFAULT = "https://gitee.com/api/v5/user"
GITHUB_API_DEFAULT = "https://api.github.com/user"


def probe_one(cred, gitee_api=GITEE_API_DEFAULT,
              github_api=GITHUB_API_DEFAULT, timeout=6.0):
    """最小只读探活：Gitee/GitHub 发 GET。200=alive 401/403=dead 其余/失败=unknown。"""
    c = public_cred(cred)
    secret = cred["_secret"]
    if cred["provider"] == "gitee":
        url = gitee_api + "?" + urllib.parse.urlencode(
            {"access_token": secret})
        req = urllib.request.Request(url, method="GET")
    elif cred["provider"] == "github":
        req = urllib.request.Request(
            github_api, method="GET",
            headers={"Authorization": "token " + secret,
                     "User-Agent": PROG + "/" + VERSION})
    else:
        c["status"] = "unprobed"   # 无等价最小只读探针，不硬探
        c["status_note"] = "该形态无等价只读探针，未探测（不猜）"
        return c
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            c["status"] = "alive" if 200 <= r.status < 300 else "unknown"
            c["http"] = r.status
    except urllib.error.HTTPError as e:
        c["status"] = "dead" if e.code in (401, 403) else "unknown"
        c["http"] = e.code
    except (urllib.error.URLError, socket.timeout, OSError, ValueError):
        c["status"] = "unknown"    # 不变量③：网络失败 ≠ 凭据坏
        c["status_note"] = "网络失败/超时，与凭据有效性无关"
    return c


def probe_creds(creds, gitee_api=GITEE_API_DEFAULT,
                github_api=GITHUB_API_DEFAULT, timeout=6.0, workers=4):
    """小并发探活（默认 4 线程），保持输入顺序。"""
    out = [None] * len(creds)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe_one, c, gitee_api, github_api, timeout): i
                for i, c in enumerate(creds)}
        for fut in concurrent.futures.as_completed(futs):
            out[futs[fut]] = fut.result()
    return out


# ---------------------------------------------------------------- lease

def shelf_path(args_file):
    return os.path.abspath(os.path.expanduser(
        args_file or os.path.join(data_home(), SHELF_NAME)))


def load_shelf(path):
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            pass
    return {"entries": []}


def save_shelf(path, shelf):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(shelf, f, ensure_ascii=False, indent=2)


def parse_date(s):
    return datetime.strptime(s, "%Y-%m-%d").date()


def lease_status(entry, today=None, warn_days=14):
    """返回 (状态, 剩余天数)：EXPIRED / EXPIRING / OK。"""
    today = today or date.today()
    exp = parse_date(entry["expires"])
    days = (exp - today).days
    if days < 0:
        return "EXPIRED", days
    if days <= warn_days:
        return "EXPIRING", days
    return "OK", days


# ---------------------------------------------------------------- 输出

def print_cred_line(c, status=None):
    tag = {"git-remote": "git-remote", "env": "env      ",
           "netrc": "netrc    "}.get(c["type"], c["type"])
    star = " *基线" if c.get("baseline") else ""
    line = "[%s] %-12s %s  %s%s" % (tag, c["label"], c["where"], c["fp"], star)
    if status:
        mark = {"alive": "V alive  ", "dead": "X dead   ",
                "unknown": "? unknown", "unprobed": "- unprobed"}.get(
                    status, status)
        line += "  " + mark
    print(line)


def recommendations(rows, shelf, warn_days):
    """按判级给建议动作——报得出死的，也要给得出下一步。"""
    recs = []
    for r in rows:
        if r.get("status") == "dead":
            recs.append("① 立即轮换 %s（%s）：生成新 token → 更新 remote/env "
                        "→ lease close 旧指纹，别让下次发布再卡 401"
                        % (r["fp"], r["where"]))
        elif r.get("status") == "unknown" and r.get("status_note"):
            recs.append("稍后重探 %s：网络失败 ≠ 凭据坏，先查代理/VPN 再下结论"
                        % r["fp"])
    for e in shelf.get("entries", []):
        st, days = lease_status(e, warn_days=warn_days)
        if st == "EXPIRED":
            recs.append("② 台账 %s 已过期 %d 天（%s）：确认已轮换就 close，"
                        "仍在用立刻换" % (e["label"], -days, e["expires"]))
        elif st == "EXPIRING":
            recs.append("③ 台账 %s 还有 %d 天到期（%s）：现在排期续期，"
                        "别等发布前夜" % (e["label"], days, e["expires"]))
    return recs


# ---------------------------------------------------------------- 命令

def cmd_scan(args):
    creds = scan_paths(args.paths, baseline=load_baseline(args.baseline)
                       if args.baseline else None)
    for c in creds:
        print_cred_line(c)
    print("# %d 项凭据 / 扫描 %s" % (len(creds), " ".join(args.paths)))
    if not creds:
        print("# 未发现凭据形态——正常（多数文件本来就没有凭据）")
    append_audit("scan", creds, {"paths": args.paths})
    if args.json:
        print("# json-begin")   # 机器解析标记：此后为一整段 JSON
        print(json.dumps([public_cred(c) for c in creds],
                         ensure_ascii=False, indent=2))
    return 0


def cmd_probe(args):
    creds = scan_paths(args.paths, baseline=load_baseline(args.baseline)
                       if args.baseline else None)
    rows = probe_creds(creds, gitee_api=args.gitee_api,
                       github_api=args.github_api,
                       timeout=args.timeout, workers=args.workers)
    for r in rows:
        print_cred_line(r, status=r.get("status"))
    alive = sum(1 for r in rows if r["status"] == "alive")
    dead = sum(1 for r in rows if r["status"] == "dead")
    unk = sum(1 for r in rows if r["status"] == "unknown")
    unp = sum(1 for r in rows if r["status"] == "unprobed")
    print("# 探活 %d 项: alive=%d dead=%d unknown=%d unprobed=%d" %
          (len(rows), alive, dead, unk, unp))
    append_audit("probe", creds,
                 {"alive": alive, "dead": dead, "unknown": unk})
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 1 if dead else 0


def cmd_lease(args):
    path = shelf_path(args.file)
    shelf = load_shelf(path)
    if args.lease_cmd == "add":
        fp = args.fp or ""
        entry = {
            "label": args.label,
            "expires": args.expires,
            "fp": fp and redact(fp),
            "provider": args.provider or "generic",
            "note": args.note or "",
            "created": now_iso(),
        }
        parse_date(args.expires)  # 日期格式前置校验
        shelf["entries"] = [e for e in shelf["entries"]
                            if e["label"] != args.label]
        shelf["entries"].append(entry)
        save_shelf(path, shelf)
        st, days = lease_status(entry, warn_days=args.warn_days)
        print("已登记: %s 到期 %s（剩 %d 天，%s）" %
              (entry["label"], entry["expires"], days, st))
        append_audit("lease-add", [], {"label": entry["label"],
                                       "expires": entry["expires"]})
        return 0
    if args.lease_cmd == "close":
        before = len(shelf["entries"])
        shelf["entries"] = [e for e in shelf["entries"]
                            if e["label"] != args.label]
        save_shelf(path, shelf)
        print("已结案: %s（%d → %d 条）" %
              (args.label, before, len(shelf["entries"])))
        append_audit("lease-close", [], {"label": args.label})
        return 0
    # list
    warn = args.warn_days
    rows = []
    for e in shelf["entries"]:
        st, days = lease_status(e, warn_days=warn)
        rows.append((e, st, days))
    rows.sort(key=lambda x: x[2])
    for e, st, days in rows:
        mark = {"OK": "V", "EXPIRING": "!", "EXPIRED": "X"}[st]
        print("%s [%s] %s  到期 %s  剩 %d 天  %s" %
              (mark, st, e["label"], e["expires"], days,
               e.get("note") or ""))
    if not rows:
        print("# 台账为空：lease add --label <名> --expires 2026-12-01 登记")
    n_exp = sum(1 for _, s, _ in rows if s == "EXPIRED")
    n_expd = sum(1 for _, s, _ in rows if s == "EXPIRING")
    print("# 台账 %d 条: EXPIRED=%d EXPIRING(≤%d天)=%d" %
          (len(rows), n_exp, warn, n_expd))
    append_audit("lease-list", [], {"entries": len(rows)})
    if args.json:
        print(json.dumps(
            [{"label": e["label"], "expires": e["expires"], "status": s,
              "days_left": d} for e, s, d in rows],
            ensure_ascii=False, indent=2))
    return 1 if n_exp else 0


def cmd_report(args):
    creds = scan_paths(args.paths, baseline=load_baseline(args.baseline)
                       if args.baseline else None)
    if args.no_probe:
        rows = [dict(public_cred(c), status="unprobed",
                     status_note="--no-probe 跳过探活") for c in creds]
    else:
        rows = probe_creds(creds, gitee_api=args.gitee_api,
                           github_api=args.github_api,
                           timeout=args.timeout, workers=args.workers)
    shelf = load_shelf(shelf_path(None))
    alive = sum(1 for r in rows if r["status"] == "alive")
    dead = sum(1 for r in rows if r["status"] == "dead")
    unk = sum(1 for r in rows if r["status"] == "unknown")
    unp = sum(1 for r in rows if r["status"] == "unprobed")
    n_exp = sum(1 for e in shelf["entries"]
                if lease_status(e, warn_days=args.warn_days)[0] == "EXPIRED")
    n_expd = sum(1 for e in shelf["entries"]
                 if lease_status(e, warn_days=args.warn_days)[0] == "EXPIRING")
    print("tokshelf v%s report —— %s" % (VERSION, now_iso()))
    print("  凭据 %d 项: alive=%d dead=%d unknown=%d unprobed=%d"
          % (len(rows), alive, dead, unk, unp))
    print("  台账 %d 条: 已过期=%d 临期(≤%d天)=%d"
          % (len(shelf["entries"]), n_exp, args.warn_days, n_expd))
    for r in rows:
        print_cred_line(r, status=r.get("status"))
    recs = recommendations(rows, shelf, args.warn_days)
    if recs:
        print("# 建议动作：")
        for r in recs:
            print("  - " + r)
    else:
        print("# 全绿：凭据可用、台账无临期。保持节奏。")
    append_audit("report", creds,
                 {"alive": alive, "dead": dead, "unknown": unk,
                  "expired": n_exp, "expiring": n_expd})
    if args.json:
        print(json.dumps({"summary": {"total": len(rows), "alive": alive,
                                      "dead": dead, "unknown": unk,
                                      "unprobed": unp,
                                      "lease_expired": n_exp,
                                      "lease_expiring": n_expd},
                          "creds": rows}, ensure_ascii=False, indent=2))
    return 1 if (dead or n_exp) else 0


# ---------------------------------------------------------------- selftest

def _selftest():
    """26 例自测：分类/redact/审计/只读/probe三态(本地mock)/lease/基线/端到端。"""
    import io
    import tempfile
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    cases = []

    def case(name):
        def deco(fn):
            cases.append((name, fn))
            return fn
        return deco

    def capture(fn, *a, **kw):
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = fn(*a, **kw)
        finally:
            sys.stdout = old
        return rc, buf.getvalue()

    tmp = tempfile.TemporaryDirectory()
    home = os.path.join(tmp.name, "home")
    os.environ["TOKSHELF_HOME"] = home

    # ---- 构造偏态演示树：34 个文件里只有 4 个带凭据（真实世界形态）
    root = os.path.join(tmp.name, "demo")
    proj = os.path.join(root, "proj-a")
    os.makedirs(os.path.join(proj, ".git"))
    secrets = {
        "gitee": "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8",      # 假 token，仅测试
        "github": "ghp_FAKE1234567890abcdefFAKE9876efgh",
        "openai": "sk-fake1234567890abcdef1234567890ab",
        "netrc": "fakepass2026",
    }
    with open(os.path.join(proj, ".git", "config"), "w") as f:
        f.write('[remote "origin"]\n'
                "\turl = https://tomlen:%s@gitee.com/tomlen/demo.git\n"
                % secrets["gitee"])
        f.write('[remote "github"]\n'
                "\turl = https://oauth2:%s@github.com/tomlen045/demo.git\n"
                % secrets["github"])
    with open(os.path.join(proj, ".env"), "w") as f:
        f.write("OPENAI_API_KEY=%s\nDB_HOST=127.0.0.1\n"
                "GITEE_TOKEN=%s\n" % (secrets["openai"], secrets["gitee"]))
    with open(os.path.join(proj, "readme.md"), "w") as f:
        f.write("clean file\n" * 10)
    projb = os.path.join(root, "proj-b")
    os.makedirs(projb)
    with open(os.path.join(projb, "_netrc"), "w") as f:
        f.write("machine gitlab.com login tom password %s\n"
                % secrets["netrc"])
    for i in range(30):  # 30 个无凭据文件：凭据是少数（偏态）
        with open(os.path.join(projb, "log%02d.txt" % i), "w") as f:
            f.write("no secrets here\n")

    # ---- mock HTTP server：200 / 401 / 挂起三态
    class Mock(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/ok"):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"login":"mock"}')
            elif self.path.startswith("/deny"):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{"message":"Bad credentials"}')
            elif self.path.startswith("/gone"):
                self.send_response(403)
                self.end_headers()
            else:
                time.sleep(3)   # 挂起，配合 0.6s 超时 → unknown

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Mock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_port

    def cred(provider, secret):
        return make_cred("git-remote", provider, "mock/cred", secret)

    def run_case(i, name, fn):
        try:
            fn()
            cases.append(("PASS", i, name))
            print("PASS %02d %s" % (i, name))
        except AssertionError as e:
            cases.append(("FAIL", i, name))
            print("FAIL %02d %s :: %s" % (i, name, e))
        except Exception as e:  # noqa: BLE001
            cases.append(("FAIL", i, name))
            print("FAIL %02d %s :: %s: %s" % (i, name, type(e).__name__, e))

    # ========== 01-06 redact 脱敏 ==========
    def t01():
        r = redact(secrets["gitee"])
        assert r == "a1b2…a7b8", r
        assert secrets["gitee"] not in r
    def t02():
        r = redact(secrets["github"])
        assert r.startswith("ghp_") and r.endswith("efgh") and "…" in r, r
        assert secrets["github"] not in r
    def t03():
        r = redact(secrets["openai"])
        assert r.startswith("sk-") and "…" in r, r
        assert secrets["openai"] not in r
    def t04():
        assert redact("short") == "…", redact("short")   # 短凭据整体打码
        assert redact("") == "…"
    def t05():
        r = redact(secrets["netrc"])
        assert "…" in r and secrets["netrc"] not in r, r
    def t06():
        # 任何 redact 输出长度不得超过明文（不回显）
        for s in secrets.values():
            assert len(redact(s)) < len(s)

    # ========== 07-11 形态分类 ==========
    def t07():
        assert classify_token(secrets["gitee"], host="gitee.com") == "gitee"
        assert classify_token(secrets["gitee"], key="GITEE_TOKEN") == "gitee"
    def t08():
        assert classify_token(secrets["github"]) == "github"
        assert classify_token("ghp_" + "a" * 30) == "github"
    def t09():
        assert classify_token(secrets["openai"]) == "openai"
    def t10():
        assert classify_token("a" * 32) == "hex32"
        assert classify_token("hello-world-token") == "generic"
    def t11():
        assert classify_token("dbpass123", key="DB_PASSWORD") == "generic"
        assert classify_token("1234567890abcdef1234567890abcdef",
                              host="gitlab.com") == "hex32"

    # ========== 12-15 端到端扫描（偏态树） ==========
    def t12():
        creds = scan_paths([root])
        provs = sorted(c["provider"] for c in creds)
        assert provs == ["gitee", "gitee", "github", "netrc", "openai"], provs
    def t13():
        creds = scan_paths([root])
        assert creds[0]["type"] in ("git-remote", "env", "netrc")
        g = [c for c in creds if c["provider"] == "gitee"]
        assert len(g) == 2      # .git/config 一处 + .env 一处
        assert g[0]["fp"] == "a1b2…a7b8"
    def t14():
        rc, out = capture(cmd_scan, type("A", (), {
            "paths": [root], "json": False, "baseline": None})())
        for s in secrets.values():
            assert s not in out, "明文泄漏进 scan 输出!"
        assert "a1b2…a7b8" in out and "unprobed" not in out
    def t15():
        rc, out = capture(cmd_scan, type("A", (), {
            "paths": [root], "json": True, "baseline": None})())
        data = json.loads(out.split("# json-begin\n", 1)[1])
        assert len(data) == 5
        for d in data:
            assert "_secret" not in d and "secret" not in json.dumps(d)
            assert "…" in d["fp"]

    # ========== 16-17 审计与只读不变量 ==========
    def t16():
        audit = os.path.join(home, AUDIT_NAME)
        assert os.path.isfile(audit)
        body = open(audit, encoding="utf-8").read()
        for s in secrets.values():
            assert s not in body, "审计落了明文!"
        assert '"cmd": "scan"' in body
    def t17():
        def snapshot(d):
            out = {}
            for dp, dns, fns in os.walk(d):
                for fn in fns:
                    p = os.path.join(dp, fn)
                    st = os.stat(p)
                    out[p] = (st.st_size, st.st_mtime_ns)
            return out
        before = snapshot(root)
        scan_paths([root])
        probe_creds(scan_paths([root]), timeout=0.1)
        assert snapshot(root) == before, "scan/probe 写了目标目录!"

    # ========== 18-21 probe 三态（本地 mock） ==========
    def t18():
        r = probe_one(cred("gitee", secrets["gitee"]),
                      gitee_api=base + "/ok", timeout=2)
        assert r["status"] == "alive" and r["http"] == 200, r
        assert secrets["gitee"] not in json.dumps(r)
    def t19():
        r = probe_one(cred("gitee", secrets["gitee"]),
                      gitee_api=base + "/deny", timeout=2)
        assert r["status"] == "dead" and r["http"] == 401, r
        r2 = probe_one(cred("github", secrets["github"]),
                       github_api=base + "/gone", timeout=2)
        assert r2["status"] == "dead" and r2["http"] == 403, r2
    def t20():
        r = probe_one(cred("gitee", secrets["gitee"]),
                      gitee_api=base + "/hang", timeout=0.6)
        assert r["status"] == "unknown", r
        assert "网络失败" in (r.get("status_note") or ""), r
    def t21():
        # unprobed：openai/netrc/hex32 无等价只读探针，绝不硬探
        for p in ("openai", "netrc", "hex32", "generic"):
            r = probe_one(cred(p, "x" * 40))
            assert r["status"] == "unprobed", (p, r)

    # ========== 22-23 并发 + 顺序稳定 ==========
    def t22():
        cs = [cred("gitee", secrets["gitee"]) for _ in range(6)]
        rows = probe_creds(cs, gitee_api=base + "/ok", timeout=2, workers=4)
        assert len(rows) == 6 and all(r["status"] == "alive" for r in rows)
    def t23():
        rc, out = capture(cmd_probe, type("A", (), {
            "paths": [root], "json": False, "baseline": None,
            "gitee_api": base + "/ok", "github_api": base + "/ok",
            "timeout": 2, "workers": 4})())
        assert "alive=3" in out, out
        assert "dead=0" in out
        assert "unprobed=2" in out
        for s in secrets.values():
            assert s not in out

    # ========== 24 lease 到期计算 ==========
    def t24():
        today = date(2026, 10, 1)
        assert lease_status({"expires": "2026-09-20"}, today)[0] == "EXPIRED"
        assert lease_status({"expires": "2026-10-10"}, today)[0] == "EXPIRING"
        assert lease_status({"expires": "2026-12-01"}, today) == ("OK", 61)
        assert lease_status({"expires": "2026-10-15"}, today,
                            warn_days=14) == ("EXPIRING", 14)
    def t25():
        p = os.path.join(tmp.name, "shelf.json")
        ns = type("A", (), {"lease_cmd": "add", "label": "gitee-demo",
                            "expires": "2026-10-05", "fp": secrets["gitee"],
                            "provider": "gitee", "note": "demo",
                            "file": p, "warn_days": 14})
        rc, out = capture(cmd_lease, ns())
        assert "EXPIRING" in out and "剩" in out, out
        ns2 = type("A", (), {"lease_cmd": "add", "label": "old-one",
                             "expires": "2026-09-01", "fp": "", "provider":
                             "gitee", "note": "", "file": p, "warn_days": 14})
        capture(cmd_lease, ns2())
        nsl = type("A", (), {"lease_cmd": "list", "file": p,
                             "warn_days": 14, "json": False})
        rc, out = capture(cmd_lease, nsl())
        assert "EXPIRED=1" in out and "EXPIRING(≤14天)=1" in out, out
        assert rc == 1
        shelf = load_shelf(p)
        assert shelf["entries"][0]["fp"] == "a1b2…a7b8"  # 台账也脱敏

    # ========== 26 基线兜底 + report 汇总 ==========
    def t26():
        bl = os.path.join(tmp.name, "baseline.txt")
        with open(bl, "w") as f:
            f.write("a1b2…a7b8\n")
        creds = scan_paths([root], baseline=load_baseline(bl))
        marks = [c.get("baseline") for c in creds if c["provider"] == "gitee"]
        assert any(marks), marks
        rows = probe_creds(creds, gitee_api=base + "/ok",
                           github_api=base + "/deny", timeout=2)
        alive = sum(1 for r in rows if r["status"] == "alive")
        dead = sum(1 for r in rows if r["status"] == "dead")
        assert (alive, dead) == (2, 1), (alive, dead)
        rc, out = capture(cmd_report, type("A", (), {
            "paths": [root], "json": False, "baseline": None,
            "gitee_api": base + "/ok", "github_api": base + "/deny",
            "timeout": 2, "workers": 4, "no_probe": False,
            "warn_days": 14})())
        assert "alive=2" in out and "dead=1" in out, out
        assert "建议动作" in out and "轮换" in out, out
        for s in secrets.values():
            assert s not in out, "report 泄漏明文!"

    tests = [
        ("redact: 32hex 前4后4指纹", t01),
        ("redact: ghp_ 前缀形态指纹", t02),
        ("redact: sk- 前缀形态指纹", t03),
        ("redact: 短凭据整体打码", t04),
        ("redact: netrc 口令脱敏", t05),
        ("redact: 输出恒短于明文(不回显)", t06),
        ("分类: Gitee-32hex(host/key双路)", t07),
        ("分类: GitHub-ghp_/gho_", t08),
        ("分类: OpenAI-sk-", t09),
        ("分类: 通用hex32/纯generic", t10),
        ("分类: env口令键/gitlab host", t11),
        ("端到端: 偏态树5项凭据全发现", t12),
        ("端到端: 同token多位置各记一笔", t13),
        ("端到端: scan人读输出零明文", t14),
        ("端到端: scan --json 零明文字段", t15),
        ("审计: JSONL只落指纹不落明文", t16),
        ("只读: scan/probe不写目标目录", t17),
        ("probe: mock 200 → alive", t18),
        ("probe: mock 401/403 → dead", t19),
        ("probe: mock 超时 → unknown(网络失败≠凭据坏)", t20),
        ("probe: 无等价探针形态 → unprobed不硬探", t21),
        ("probe: 4线程小并发×6顺序稳定", t22),
        ("probe: 全链路mock零明文+计数正确", t23),
        ("lease: 到期/临期/安全三态计算", t24),
        ("lease: 台账增查+指纹脱敏+退出码", t25),
        ("基线: --baseline兜底标记+report汇总建议", t26),
    ]
    print("tokshelf v%s selftest" % VERSION)
    for i, (name, fn) in enumerate(tests, 1):
        run_case(i, name, fn)
    srv.shutdown()
    tmp.cleanup()
    npass = sum(1 for c in cases if c[0] == "PASS")
    nfail = sum(1 for c in cases if c[0] == "FAIL")
    print("selftest: %d/%d 绿" % (npass, npass + nfail))
    if nfail:
        print("selftest: %d 例失败，禁止放行" % nfail)
        return 2
    print("四不变量+mock三态+偏态端到端全部通过。")
    return 0


# ---------------------------------------------------------------- 入口

def build_parser():
    ap = argparse.ArgumentParser(
        prog=PROG, description="凭据寿命哨兵：扫描/探活/台账/汇总，只读+脱敏")
    ap.add_argument("--version", action="version",
                    version="%s v%s" % (PROG, VERSION))
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("scan", help="扫描凭据形态（git remote/.env/.netrc）")
    p.add_argument("paths", nargs="+", help="文件或目录（目录递归）")
    p.add_argument("--json", action="store_true", help="追加机器可读输出")
    p.add_argument("--baseline", help="手动兜底基线文件（每行裸token或指纹）")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("probe", help="对可探活凭据发最小只读 GET")
    p.add_argument("paths", nargs="+")
    p.add_argument("--gitee-api", default=GITEE_API_DEFAULT)
    p.add_argument("--github-api", default=GITHUB_API_DEFAULT)
    p.add_argument("--timeout", type=float, default=6.0)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--json", action="store_true")
    p.add_argument("--baseline")
    p.set_defaults(fn=cmd_probe)

    p = sub.add_parser("lease", help="凭据寿命台账")
    p.add_argument("lease_cmd", choices=["add", "list", "close"])
    p.add_argument("--label")
    p.add_argument("--expires", help="YYYY-MM-DD")
    p.add_argument("--fp", help="裸 token（入库即脱敏为指纹）")
    p.add_argument("--provider", default="generic")
    p.add_argument("--note", default="")
    p.add_argument("--file", help="台账文件（默认 ~/.tokshelf/shelf.json）")
    p.add_argument("--warn-days", type=int, default=14)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_lease)

    p = sub.add_parser("report", help="汇总 alive/dead/unknown + 建议动作")
    p.add_argument("paths", nargs="+")
    p.add_argument("--gitee-api", default=GITEE_API_DEFAULT)
    p.add_argument("--github-api", default=GITHUB_API_DEFAULT)
    p.add_argument("--timeout", type=float, default=6.0)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--warn-days", type=int, default=14)
    p.add_argument("--no-probe", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--baseline")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("selftest", help="26 例自测（含 mock 三态与偏态端到端）")
    p.set_defaults(fn=lambda a: _selftest())
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if not getattr(args, "fn", None):
        ap.print_help()
        return 2
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
