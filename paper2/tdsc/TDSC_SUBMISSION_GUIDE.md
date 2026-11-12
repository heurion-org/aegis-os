# Paper 2 — IEEE TDSC (CCF-A / SCI Q1) 投稿操作指南

本目录（`paper2/tdsc/`）已为您准备好符合 **IEEE Transactions on Dependable and Secure Computing (TDSC)** 官方规范的全套投稿文件。整篇正刊排版共 **13 页**（严格控制在 TDSC 常规论文 **14 页免费上限** 以内），选择传统订阅出版模式（Traditional Subscription）可实现 **$0 审稿费、$0 APC 版面费、$0 超页费**，且完全兼容您已发布的 CERN Zenodo 预印本（Green Open Access）。

---

## 一、本版针对 IEEE TDSC 审稿标准的实质性升级

相比 Zenodo `v1` 预印本，本目录中的 [`main_tdsc.pdf`](main_tdsc.pdf) 完成了三项针对 CCF-A 安全顶刊审稿人的核心升级：

1. **新增 Table 2（真实世界 NIST NVD 漏洞映射表，§2.2）**：
   - 将 `V1`–`V6` 六大绕过类与 30 个基准载荷（`v1_1`–`v6_5`）系统映射到 2021–2026 年公开披露的真实高危漏洞：包括 Anthropic Claude Code（`CVE-2025-59536`、`CVE-2026-21852` Check Point *"Caught in the Hook"*、`CVE-2026-55607` Worktree 沙箱逃逸）、官方 MCP 生态（`CVE-2025-53109` / `CVE-2025-53110` 文件系统前缀与符号链接逃逸、`CVE-2025-6514` `mcp-remote` RCE、`CVE-2025-49596` Loopback 控制面未授权 RCE、Cursor `CVE-2025-54135/54136`）、Nous Hermes 与 Git（`CVE-2026-71963` `core.fsmonitor` RCE、`CVE-2025-48384`）以及 *Trojan Source* Bidi 欺骗（`CVE-2021-42574`，USENIX Security '23）。
   - 直接用客观历史漏洞证明：厂商针对单一入口打点补丁（如 `claude v2.1.163`、`hermes v0.21.1`）后，最新生产版本在运行项目脚本或 `git status` 时依然失守，只有 `execve()` 之前的父进程内核隔离能根治。
2. **新增 Table 9（RQ5 六大领域冻结暂存区校验与哈希链审计表，§6.3）**：
   - 完整展示 `code`、`docs`、`data`、`binary`、`app_state`、`memory` 六类 `DomainProfile` 在 `commit_frozen_stage` 上的 `60/60 (100%)` 拦截率（均值 `67.47 μs`）与 500 条 SHA-256 哈希链审计账本构建/校验开销（`64.52 ms` / `8.87 ms`）。
3. **切换官方 `IEEEtran` (`10pt,journal,compsoc`) 排版与零警告编译**：
   - 包含 IEEE Computer Society 标准抬头、结构化摘要、`IEEEkeywords`、首段 `\IEEEPARstart` 下沉首字母、`IEEEtran.bst` 参考文献样式（共 36 篇真实文献）、伦理与开源声明、作者简介（`IEEEbiographynophoto`）及首页预印本透明披露脚注。
   - 经 Tectonic 完整编译验证：**共 13 页，0 Warning、0 Overfull Box、0 Undefined Citation**。

---

## 二、IEEE Author Portal 投稿步骤（全程约 10 分钟，$0 费用）

### 1. 打开 IEEE TDSC 新版官方投稿入口
- 访问 IEEE Author Portal（Atypon Rex 新系统，已替代旧版 ScholarOne）：
  👉 **[https://ieee.atyponrex.com/journal/tdsc-cs](https://ieee.atyponrex.com/journal/tdsc-cs)**
- 点击 **Submit a Manuscript**，使用您的 IEEE 账号（绑定邮箱 `huizhao@heurion.org` 与您的 ORCID）登录。

### 2. 选择稿件类型与 $0 免费出版选项（关键）
- **Article Type（稿件类型）**：选择 **`Regular Paper`**。
- **Publication / Open Access Option（出版模式）**：
  - 选择 **`Traditional / Subscription`（传统订阅模式，非金色 OA）**。
  - **费用核对**：IEEE TDSC 对传统订阅模式收取 **$0 APC**；常规论文免费页数上限为 **14 页**，本稿件为 **13 页**，因此超页费（Mandatory Overlength Page Charges）同样为 **$0**。
- **Review Model（审稿模式）**：保持默认的 **Single-Anonymous（单盲审稿）** 即可。

### 3. 上传文件清单（全部位于 `paper2/tdsc/` 目录）
1. **Manuscript PDF（主文档 PDF）**：上传 [`paper2/tdsc/main_tdsc.pdf`](main_tdsc.pdf)（或让系统从下面的源码包自动编译并核对生成的 PDF）。
2. **LaTeX Source Files（LaTeX 源码包）**：上传 [`paper2/tdsc/tdsc_submission_source.zip`](tdsc_submission_source.zip)（内含 `main_tdsc.tex`、`main_tdsc.bbl` 与 `references.bib`；若系统偏好 `.tar.gz` 亦可上传同目录下的 [`tdsc_submission_source.tar.gz`](tdsc_submission_source.tar.gz)）。
3. **Cover Letter（投稿附信）**：复制 [`paper2/tdsc/COVER_LETTER_TDSC.txt`](COVER_LETTER_TDSC.txt) 全文粘贴到 Cover Letter 栏（或直接上传该 `.txt` 文件）。

### 4. 网页表单必填项速查（直接复制粘贴）

- **Title**:
  `Why Agent Plugins Are Not a Security Boundary: Inverting Control from In-Process Hooks to a Kernel-Enforced Agent Runtime`

- **Abstract**（纯 ASCII 无特殊字符，241 词）:
  ```text
  Autonomous CLI coding agents -- Claude Code (claude), OpenCode (opencode), Google Antigravity (agy), and Nous Hermes (hermes) -- rely on in-process governance plugins (PreToolUse hooks, additive MCP servers, and prompt rules). We show that treating an in-process plugin as a security boundary violates Anderson's Reference Monitor guarantees of complete mediation, tamper-resistance, and verifiability whenever the agent runs under the developer's UNIX UID. Auditing four production CLI agents and mapping recent disclosed vulnerabilities across the CLI/MCP ecosystem reveals six structural bypass classes (V1-V6): workspace escape and unapproved host writes (V1); unconfined socket egress (V2); host credential, Keychain, and environment key theft (V3); hook/config self-tampering (V4); repository code execution during read-only git status/diff via core.fsmonitor (V5); and same-UID self-approval or post-diff TOCTOU swaps (V6). We present Aegis Enforced Runtime (aegis-os run -- <agent>), which inverts control so the OS supervisor confines the unmodified agent inside Linux bubblewrap (--bind-fd) or macOS Seatbelt before execve(). Aegis combines Copy-on-Write shadows with a read-only .git view and .aegis-bin/git shim, read-only config over-mounts, a split-plane L4/L7 egress proxy that injects API keys at the host boundary without TLS MITM, dual-token SessionBroker isolation, and frozen-stage SHA-256 commit pinning. Across 30 deterministic payloads on macOS and Linux plus 54 executed live runs (60-cell matrix) of all four agents, Aegis reduces bypass coverage from 73.3%-93.3% (and 80.0% in OCI/nerdctl devcontainers) to 0.0% and live repository-trap compromises from 100% to 0%, while saving 99.05% of APFS disk allocation on 500 MB packed Git repos, adding +0.221 ms loopback TTFT overhead, and preserving 100% multi-file coding pass rates.
  ```

- **Keywords / Index Terms**:
  - `Autonomous coding agents`
  - `Operating system security`
  - `Reference monitor`
  - `Kernel sandboxing`
  - `Copy-on-write shadow workspace`
  - `Boundary secret injection`
  - `TOCTOU protection`
  - `Model Context Protocol (MCP)`

- **Preprint Disclosure（预印本声明，若表单询问是否发过 Preprint，选 Yes 并填）**:
  `Archived as a preprint on CERN Zenodo: https://doi.org/10.5281/zenodo.24170505 (DOI: 10.5281/zenodo.24170505)`

- **Companion / Related Submission Disclosure（关联工作说明，如表单询问）**:
  `Companion manuscript arXiv:2611.08516 studies cooperative multi-agent MCP/A2A workspace coordination and Diff3 merging; this TDSC manuscript addresses the distinct OS kernel security problem of confining adversarial/untrusted CLI agent binaries prior to execve(), with zero shared figures, tables, or datasets.`

- **Code & Data Availability URL**:
  `https://github.com/heurion-org/aegis-os`

---

## 三、后续进阶路线图（审稿期间 / R1 备战 & arXiv 解锁）

1. **审稿等待期（可选储备实验）**：TDSC 首轮外审通常约 2.5–4 个月。若希望提前为 Major/Minor Revision 储备弹药，可在本地空闲时用 `scripts/p2_live/harness.py` 扩展跑一组 20 题 SWE-bench Lite 切片（$n=3$ 重复），审稿人一旦问及更大规模良性任务效用，可在一周内秒回 Rebuttal。
2. **录用后解锁 arXiv `cs.CR`**：拿到 IEEE TDSC 正式录用 DOI 后，既可在 Zenodo 发布关联期刊号的更新说明，也可直接点击此前 arXiv 邮件中的 `appeal` 链接提交 TDSC DOI，一举上架 arXiv `cs.CR` 主分类。
