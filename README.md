# tokshelf

[中文](README.md) | [English](README_EN.md)

**凭据寿命哨兵** —— git remote 里的 token 不会过期提醒，只会在发布前夜 401。
cronguard 盯任务（[cronguard](https://github.com/tomlen045/cronguard)），capguard 盯磁盘（[capguard](https://github.com/tomlen045/capguard)），bakcheck 盯备份（[bakcheck](https://github.com/tomlen045/bakcheck)），**tokshelf 盯你凭据的死活**。

tokshelf 只做四件事：扫出来 / 探明白 / 记台账 / 给动作。

[![tests](https://img.shields.io/badge/self--tests-26%2F26-green)]() [![deps](https://img.shields.io/badge/deps-zero-yellow)]() [![license](https://img.shields.io/badge/license-MIT-blue)]()

---

## 解决什么问题

* 发布前一刻才发现 remote 里的 token 早已 401 → **probe 一条命令验活**：Gitee/GitHub 各发一个最小只读 GET，200=alive / 401·403=dead，当场现形
* token 散落在 .git/config、.env、.netrc 里，自己都数不清 → **scan 按形态盘点**：Gitee-32hex / GitHub-ghp_ / OpenAI-sk- / 通用hex32，一处不漏
* 换了新 token，旧的是"大概还能用"还是"已经死了"？没证据 → **指纹台账**：输出一律前4后4（`ghp_x…9f2`），有据可查且不怕截图
* 网络抖动误判"token 坏了"，白白轮换一轮 → **unknown 单列**：超时/断网绝不与 dead 混淆，网络失败 ≠ 凭据坏
* 「这 token 什么时候到期」全靠回忆 → **lease 寿命台账**：登记到期日，临期自动点名，别等发布前夜
* 报得出死的，给不出下一步？→ **report 汇总建议动作**：轮换顺序、排期续期、重探清单一次给全

## 安装

```bash
# 方式一：直接拉单文件（仅标准库，Python 3.8+）
curl -fsSLO https://gitee.com/tomlen/tokshelf/raw/main/tokshelf.py

# 方式二：GitHub
curl -fsSLO https://raw.githubusercontent.com/tomlen045/tokshelf/main/tokshelf.py
```

## 30 秒上手

```bash
# 1) 扫描：这个目录里到底埋了多少凭据、什么形态
python3 tokshelf.py scan ~/CodeBuddy

# 2) 探活：哪些还活着，哪些早就 401 了（只读 GET，小并发）
python3 tokshelf.py probe ~/CodeBuddy

# 3) 登记寿命：给每个 token 记上到期日，临期自动点名
python3 tokshelf.py lease add --label gitee-主token --expires 2026-12-01

# 4) 汇总：alive/dead/unknown + 建议动作（cron 友好，dead 退出码 1）
python3 tokshelf.py report ~/CodeBuddy --json
```

## 判级规则

| 状态 | 触发 | 含义 |
|---|---|---|
| alive | 探针 HTTP 200 | 凭据当前可用 |
| dead | 探针 HTTP 401/403 | 凭据已被服务端拒绝，立即轮换 |
| unknown | 超时/断网/5xx | **网络失败 ≠ 凭据坏**，查代理后重探 |
| unprobed | 无等价只读探针的形态 | 不硬探、不猜，如实标注 |
| EXPIRING | 距台账到期日 ≤ N 天（默认 14） | 排期续期 |
| EXPIRED | 已过台账到期日 | 确认轮换则 close，仍在用立刻换 |

## 四不变量

1. **只读探测** —— probe 全部 GET，绝不带凭据做任何写操作
2. **输出脱敏** —— 一律指纹（前4后4），绝不明文；审计 JSONL 同样只落指纹
3. **网络失败 ≠ 凭据坏** —— unknown 独立一类，不与 dead 混淆
4. **审计不落明文** —— 日志/JSONL 只记指纹、计数与形态

## 设计边界（说在前面）

* probe 只覆盖 Gitee / GitHub 两家（有等价最小只读 GET）；OpenAI key、netrc 口令等标注 unprobed，**不硬探**——用一条写请求去验活本身就是事故
* lease 是你自己的台账：工具提醒到期，续期动作在人
* scan 按文件名/形态识别（`config`+`.git`、`.env`、`.netrc`），不做内容全量熵扫描——那是另一个工具的事
* 偏态数据友好：凭据在文件堆里是极少数，scan 不做任何统计外推，逐项如实报告；可用 `--baseline` 挂手动兜底清单对照

## 自测

```bash
python3 tokshelf.py selftest   # 26/26 绿（含 mock 三态、偏态端到端、脱敏断言）
```

## LICENSE

MIT
