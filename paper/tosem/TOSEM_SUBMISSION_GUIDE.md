# Aegis OS — arXiv `v2` 更新与 ACM TOSEM (CCF-A) 投稿操作指南

本目录（`paper/tosem/`）与上级目录（`paper/`）已为您准备好全套开箱即用的文件。整个流程分为 **两步**，总耗时约 **10–15 分钟**，且 **全程 0 费用**。

---

## 第一步：在 arXiv 上将 `v1` 更新为 `v2`（约 2 分钟）

> **为什么要先做这一步**：ACM TOSEM 是单盲审稿（Single-Blind），副主编（AE）和外审专家拿到稿件后会在 Google Scholar / arXiv 上检索标题。先将 arXiv 更新为包含 **28,087 次真实会话调用、Linux 四种文件系统评测、L7/DLP 防护与 9 行消融矩阵** 的 `v2`，能让审稿人看到完整一致的强版本。

1. 登录 [https://arxiv.org/user](https://arxiv.org/user)。
2. 在您已发表的 `Aegis OS` 条目右侧，点击 **`Replace`**（替换/更新版本）。
3. **上传源码包**：直接上传仓库中的 [`paper/arxiv_submission.tar.gz`](../arxiv_submission.tar.gz)（已内含预编译的 `main.bbl` 与去注释的 `main.tex`，无需 `.bib`，已在隔离沙箱中通过 4 遍 XeTeX 编译验证）。
4. **更新 Metadata**：打开 [`paper/ARXIV_METADATA.txt`](../ARXIV_METADATA.txt)：
   - 将 `[Comments]` 替换为：
     `19 pages, 3 TikZ figures, 13 tables. Open-source Rust implementation and reproducible benchmark suite available at https://github.com/heurion-org/aegis-os`
   - 将 `[Abstract]` 替换为 `paper/ARXIV_METADATA.txt` 中的纯文本摘要（共 **1,914 字符**，严格控制在 arXiv 的 1,920 字符上限以内）。
5. 预览生成的 PDF 无误后，点击 **Submit** 即可完成 `v2` 更新。

---

## 第二步：投稿至 ACM TOSEM（CCF-A 顶刊，0 版面费）

### 1. 投稿入口
- 打开 ACM TOSEM 官方投稿系统（ScholarOne Manuscripts）：
  👉 **[https://mc.manuscriptcentral.com/tosem](https://mc.manuscriptcentral.com/tosem)**
- 使用您的邮箱（`huizhao@heurion.org`）注册/登录并关联 ORCID。

### 2. 稿件类型与费用选项（重要：如何选 0 元免费出版）
- **Manuscript Type（稿件类型）**：选择 **`Research Article`**（常规研究长文）。
- **Open Access / Publication Mode（出版模式）**：
  - 在投稿系统的版权/出版选项中，选择 **Traditional Subscription Model（传统订阅模式 / Non-Open Access）**。
  - ACM 对选择传统订阅模式的作者 **不收取任何版面费或审稿费（$0 APC, $0 Page Charge）**，且允许您在个人主页和 **arXiv** 上永久公开作者预印本（Green Open Access）。

### 3. 上传文件清单（全部位于 `paper/tosem/` 目录）
在 ScholarOne 的 `File Upload` 步骤中上传以下文件：
1. **Main Document - PDF（主文档 PDF）**：上传 [`paper/tosem/main_tosem.pdf`](main_tosem.pdf)（采用 ACM 官方 `acmart` `acmsmall` 期刊排版，带行号与审稿视图，共含 13 张表、3 张 TikZ 图与完整参考文献）。
2. **LaTeX Source Files（源码压缩包）**：上传 [`paper/tosem/tosem_submission_source.tar.gz`](tosem_submission_source.tar.gz)（包含 `main_tosem.tex`、`main_tosem.bbl` 与 `references.bib`）。
3. **Cover Letter（投稿附信）**：直接复制 [`paper/tosem/COVER_LETTER_TOSEM.txt`](COVER_LETTER_TOSEM.txt) 的全文粘贴到系统的 Cover Letter 文本框中（或作为 Cover Letter 附件上传）。

### 4. 表单必填字段速查（直接复制粘贴）
- **Title**：
  `Aegis OS: A Transactional Multi-Tenant Operating System Runtime for Eliminating Authorization Fatigue in Autonomous Coding Agents`
- **Abstract**：
  直接复制 [`paper/ARXIV_METADATA.txt`](../ARXIV_METADATA.txt) 中的 `[Abstract]` 段落。
- **Keywords**：
  `Autonomous Coding Agents, Agent Operating System Runtime, Authorization Fatigue, Copy-on-Write Shadow Workspace, Three-Way Merge, OS Kernel Sandbox, Model Context Protocol (MCP), Agent2Agent (A2A) Protocol`
- **CCS Concepts（ACM 分类号，已在 `main_tosem.tex` 中内嵌）**：
  - `Software and its engineering -> Software development Environments`
  - `Security and privacy -> Operating systems security`
  - `Computing methodologies -> Multi-agent systems`
- **Data / Replication Package Availability Link**：
  `https://github.com/heurion-org/aegis-os`

---

## 备选方案（Plan B）：若需转投 JSS 或 IEEE TDSC
- 若首轮遇到不熟悉 OS 沙箱的副主编未送审，无需气馁，可直接将稿件投往：
  1. **Journal of Systems and Software (JSS, Elsevier, CCF-B / JCR Q1)**：同样支持 **0 元传统订阅出版**，审稿周期仅 2–3 个月，录用把握 **80%–90%**。
  2. **IEEE Transactions on Dependable and Secure Computing (TDSC, CCF-A)**：安全与可信计算顶刊。
