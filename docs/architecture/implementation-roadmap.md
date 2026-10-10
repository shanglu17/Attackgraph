# ASTRA 通用适航安保平台实施路线图（Phase 0–7）

- 状态：Accepted
- 提出日期：2026-10-08
- 接受日期：2026-10-09
- 代码基线：`06ff8c6`（已包含特征规则预览与离线拓扑路径追踪）
- 目标标准基线：DO-326A + DO-356A
- 前向兼容目标：DO-326B

## 1. 路线图目的

本路线图指导 ASTRA 从当前 F3532/ZG-ONE 与研究原型并存的实现，演进为标准无关、项目隔离、证据可追溯、分析可重现的适航安保工程辅助平台。

路线图描述工程能力和实施顺序，不构成标准符合性声明。任何符合性主张仍需关联项目适用性、经授权的标准版本、受控证据和有资质人员的评审决定。

## 2. 固定实施原则

所有阶段共同遵守以下约束：

1. 通用核心不依赖 DO-326A、DO-356A、F3532、ZG-ONE 或某份工作簿的专用字段。
2. 标准差异由版本化 `StandardProfile` 和 adapter 表达；分析算法由版本化 analysis method 表达。
3. 所有业务读写显式携带 Project、Model、Revision 或 Baseline 上下文。
4. 源事实、派生结果、人工评审和批准基线不得混为同一语义。
5. 自动生成只产生 Draft/Experimental/Candidate 结果，不能产生人工 Reviewed/Approved 决定。
6. 已评审结果不被重新生成、导入或批量替换静默覆盖。
7. 迁移显式、可预检、可验证、可恢复；应用启动不得修改业务数据。
8. 每个分析结果保留输入摘要、方法/规则版本、范围、截断信息和解释证据。
9. 向后兼容通过 adapter、compatibility projection 和迁移完成，不通过长期复制应用实现。
10. 每阶段都必须通过构建、自动化测试、数据不变量和文档一致性检查后才能进入下一阶段。

## 3. 目标结构

```text
通用领域核心
  Project / Model / Revision / Baseline
  System Model / Security Assessment / Assurance
  Provenance / Review / Traceability / Audit

标准适配
  DO-326A process profile
  DO-356A method/work-product profile
  F3532 compatibility adapter
  future DO-326B profile

分析方法扩展
  Legacy DFS/DPS
  F3532 deterministic generation
  Experimental feature-rule preview
  Evidence-scoped topology tracing

项目配置
  tailoring / numbering / approved policies / report layout
```

标准适配和分析方法是两个不同扩展维度。标准 profile 可以选择允许的方法，但某个研究算法不能反向定义通用资产、证据、审核或攻击路径模型。

## 4. 阶段总览与可停止增量

“用户”按阶段可以是适航安保分析工程师、评审人员、项目管理员或平台运维人员。表中的停止状态用于明确：如果后续投资终止，当前成果究竟能否独立交付，以及不得对外声称什么。

| 阶段 | 名称 | 主要受益者 | 用户可见结果 | 如果只做到本阶段就停止 | 当前状态 |
| --- | --- | --- | --- | --- | --- |
| Phase 0 | 合并后基线与治理校准 | 架构师、开发与项目负责人 | 可审阅的路线图、领域边界、ADR 和能力差距 | 只有经过治理的实施蓝图，没有新增可运行产品能力 | Complete |
| Phase 1 | 项目化与写入治理基础 | 项目管理员、开发与运维 | 项目隔离、revision/baseline、显式迁移和审计成为可验证的数据安全能力；旧读取保留，未作用域化的旧写入口被隔离 | 可交付为安全的平台基础，但不是新的适航分析产品流程 | Complete |
| Phase 2 | 标准无关系统模型与契约 | 集成开发者、建模工程师 | 可通过版本化契约建立通用资产、接口、数据流、来源和追踪关系 | 通用建模 API 可试用，但尚无完整、用户可验收的适航安保闭环 | Ready |
| VG-1 | 首条可交付纵向链路 | 分析工程师、评审人员、演示与试点用户 | 在一个项目内查看一条 DO-356A 追踪链，并导出带来源、版本和状态的报告 | 至少保留一个可运行、可演示、可复现、可导出的试点产品切片 | Blocked by Phase 2 |
| Phase 3 | DO-326A/DO-356A 工程闭环 | 分析工程师、适航安保评审人员 | TC/TS、风险、目标、要求、验证和证据形成 profile 驱动闭环 | 可交付首个正式工程闭环版本，但高级分析、影响传播和完整工作台仍受限 | Planned |
| Phase 4 | 可插拔分析与结果晋级 | 分析工程师、方法开发者、评审人员 | 可重现分析运行、候选解释及人工晋级流程 | 可交付受控分析平台，但完整变更影响与工作产品能力仍不完备 | Planned |
| Phase 5 | 追踪、变更影响与工作产品 | 项目负责人、评审人员、报告编制人员 | 基线差异、stale 传播、追踪矩阵和 profile 驱动报告 | 可交付主要工程与报告能力，但角色治理、运维质量和发布切换尚未完成 | Planned |
| Phase 6 | 评审工作台、质量与运维 | 全部日常用户及平台运维 | 完整评审工作台、角色审计、E2E 证据和备份恢复能力 | 可进入受控试运行，但遗留数据正式切换和发布证据尚未完成 | Planned |
| Phase 7 | 遗留迁移与发布验收 | 项目组织、运维、质量与发布负责人 | 遗留数据完成受控切换，并形成可审计发布证据包 | 达到本路线图定义的正式发布状态，但仍不自动构成适航批准声明 | Planned |

## 5. Phase 0：合并后基线与治理校准

### 目标

以合并后的 `06ff8c6` 为现状基线，确认通用核心、标准适配器、分析方法和项目配置的边界，并冻结 Phase 1–7 的顺序与验收方式。

### 交付物

- Phase 0 架构基线和术语表；
- 目标领域模型及现有类型映射；
- DO-326A/DO-356A 能力差距矩阵；
- [特征规则/拓扑追踪到目标模型的 crosswalk](./experimental-analysis-crosswalk.md)；
- ADR-0001 至 ADR-0006；
- 遗留迁移设计；
- 本路线图和阶段级验收门槛。

### 出口门槛

- `FeatureRule`、`Evidence`、`Scope`、`Policy` 明确属于实验方法契约，不是核心持久化模型；
- 拓扑路径候选与正式 `AttackPath` 的晋级门槛明确；
- Phase 1 不再依赖未决的核心身份、版本或写入治理决策；
- 本阶段只有文档变更，构建和测试基线无退化。
- workspace 级测试命令在支持的开发环境中可直接运行；已知跨平台缺口必须修复或显式推迟。

## 6. Phase 1：项目化与写入治理基础

### 目标

先消除全库单版本、全局业务编号和隐式数据修复三个基础风险，建立后续模型重构的安全承载层。

### 主要工作

- 引入 MigrationRecord、迁移命令、dry-run、pre/post-condition；
- 创建 Project、Model、Revision、Baseline 和 StandardProfileVersion；
- 将 `GraphVersion` 收敛为 revision 内乐观并发版本；
- 引入内部 UUID 和项目内 `business_id`；
- 建立 scoped unit of work、command idempotency 和 AuditEvent；
- 将现有数据挂接到受控的遗留项目和工作 revision；
- 禁止启动时业务删除以及无项目范围的 seed/reset/replace。
- 关闭 `PH1-TOOLING-001`：修复前端 workspace test script 在 Windows 下的 glob 可移植性。

### 出口门槛

- 两个项目能够使用相同业务编号而不冲突；
- 所有新增写入要求 project/revision/expected-version；
- Approved Baseline 不存在更新入口；
- 迁移和回滚演练通过；
- F3532、特征预览和现有查询仍能通过兼容层运行。
- `npm test -w @attackgraph/frontend` 在支持的开发环境中无需手工展开文件名即可运行。

## 7. Phase 2：标准无关系统模型与契约

### 目标

把资产、接口、数据流、边界、来源和追踪从专用模板字段中解耦，形成稳定的核心应用接口。

### 主要工作

- 建立 Function、Asset、Interface、DataFlow、SecurityBoundary、ExternalEntity；
- 统一 `AssetEdge`、BoundaryInterface 和 SystemDataFlow 的核心语义；
- 引入 SourceRecord、EvidenceRecord、TraceLink 及字段级定位能力；
- 拆分核心、application service、adapter、infrastructure 模块；
- 建立版本化 API 和共享/生成的前后端契约；
- 将导入统一为 parse → preview → scoped commit；
- 保留 F3532 extension 和旧 API compatibility projection。

### 出口门槛

- 关闭 F3532 adapter 后核心系统仍能构建并完成通用建模；
- 通用 Asset 无需 F3532 字段；
- 导入实体均可追溯到 SourceRecord；
- 批量 SDF 写入不再以全局 ID 或静默 last-write-wins 处理重复业务对象。

## 8. VG-1：首条可交付纵向链路

### 定位

VG-1 是 Phase 3 的硬前置价值门槛，不是扩大领域模型的新阶段。Phase 2 通过后，必须先用已完成的 Project、Revision、StandardProfileVersion、通用系统模型、来源和 TraceLink 跑通一条用户可见的纵向链路，再继续铺开 Phase 3 的完整工程对象。

### 最小链路

```text
Project → Model → Revision → DO-326A/DO-356A StandardProfileVersion
        → SourceRecord → 最小系统对象 → Draft Threat/TraceLink
        → Frozen Baseline → 可查看、可导出的追踪报告
```

### 实施约束

- 只提前抽取形成纵向切片所需的最小 Threat、报告和界面能力，不在此展开 Phase 3、5、6 的完整广度；
- 提前实现的能力必须从后续阶段范围中扣除，不建立第二套临时模型或报告实现；
- 使用有授权的标准元数据、条款标识或项目引用，不复制受限标准正文；
- 自动生成内容保持 Draft/Candidate，报告明确标记状态，不作完整符合性或适航批准声明；
- 链路必须可在空数据库上通过显式迁移和受控示例数据重复构建。

### 通过条件

- 用户能在界面中打开一个项目及 revision/baseline，并查看一条 DO-356A 追踪链；
- 报告可导出，且包含 project、revision/baseline、profile、来源、actor、状态和生成版本；
- 从受控输入到报告的关键对象可双向追踪，不依赖个人绝对路径或隐式数据库状态；
- 端到端自动化测试覆盖创建、查看、冻结和导出；
- 关闭 F3532 adapter 后，该链路仍可运行；
- VG-1 未通过时，不得开始 Phase 3 的大规模领域铺开。

## 9. Phase 3：DO-326A/DO-356A 工程闭环

### 目标

用标准 profile 驱动完整但不越权的工程链路，而不是把标准编号固化到核心类型中。

### 主要工作

- 建立 ThreatPoint、ThreatCondition、ThreatScenario 的清晰边界；
- 建立 RiskAssessment、SecurityObjective、SecurityRequirement、Control；
- 建立 VerificationCase、EvidenceRecord 和 ReviewDecision；
- 实现 DO-326A 项目过程/活动/工作产品 profile；
- 实现 DO-356A 方法、数据字段和工作产品 profile；
- 将 F3532 01/02/03/04 映射为兼容 adapter；
- 支持项目裁剪、适用性和标准引用追踪。

### 出口门槛

- Appendix D 示例能够形成端到端追踪链；
- F3532 adapter 可启用/关闭且核心不受污染；
- 算法结果与人工工程判断分开存储；
- 报告能够解析到确切 profile、revision/baseline 和来源。

## 10. Phase 4：可插拔分析与结果晋级

### 目标

将现有 DFS/DPS、F3532 确定性生成、特征规则预览和拓扑追踪纳入统一且可重现的分析框架。

### 主要工作

- 建立 AnalysisMethodDefinition、AnalysisRun 和 DerivedResult；
- 记录输入 revision/baseline、方法/规则版本、配置、哈希和执行边界；
- 为 DFS/DPS 提供核心路径方法适配；
- 将 FeatureRule 契约保持为版本化 method-specific DTO；
- 将拓扑追踪结果保持为 `topology_only` 候选；
- 建立 Candidate → Reviewed → Promoted/Rejected 的显式晋级命令；
- 为截断、未知、冲突、无证据和未映射结果保留结构化状态；
- 使用领域特定 canonicalizer，禁止对有顺序意义的路径步骤通用排序。

### 出口门槛

- 相同输入、方法和规则版本产生相同摘要；
- 旧结果不会被重跑覆盖，上游变化会标记 stale；
- 未经人工晋级，特征规则和拓扑结果不会生成正式 ThreatPoint/ThreatScenario/AttackPath；
- asserted reviewer metadata 不会被当作平台 ReviewDecision。

## 11. Phase 5：追踪、变更影响与工作产品

### 目标

让基线变化、工程结论和报告单元都能够反向追溯并进行影响处置。

### 主要工作

- 比较 revision/baseline 并沿依赖与 TraceLink 传播影响；
- 标记受影响的分析、风险、目标、要求、验证和证据；
- 支持影响接受、重分析、豁免和推迟决定；
- 生成追踪矩阵、缺口报告和覆盖率视图；
- 使用 profile 驱动 DO-326A/DO-356A/F3532 工作产品；
- 报告保留生成版本、来源和批准状态。

### 出口门槛

- 修改上游对象能够得到确定的 stale/impact 集；
- 历史报告仍可解析原始 baseline；
- 每个正式报告结论可追溯到来源、分析和人工决定；
- 报告不产生超出证据能力的符合性声明。

## 12. Phase 6：评审工作台、质量与运维

### 目标

把后端治理能力落实为可用的评审工作流、稳定界面和可恢复运行环境。

### 主要工作

- 在四工作区信息架构上增加项目、revision、profile 和 baseline 上下文；
- 提供候选结果比较、证据查看、意见、退回和批准界面；
- 建立最小角色模型并为未来职责分离预留扩展；
- 完成 API、仓储、前端和 E2E 测试金字塔；
- 增加结构化日志、指标、健康检查、备份与恢复演练；
- 执行依赖、安全、性能、可访问性和响应式检查。

### 出口门槛

- 关键闭环具有 E2E 自动化证据；
- 评审决定包含真实 actor、role、timestamp 和 subject version；
- 备份恢复与迁移恢复演练通过；
- 前端满足 `docs/frontend-development-standard.md` 的验证清单。

## 13. Phase 7：遗留迁移与发布验收

### 目标

将现有授权遗留数据和 Appendix D 示例安全切换到目标模型，并形成可审计的发布证据包。被忽略的合作项目保密资料不属于默认发布迁移输入。

### 主要工作

- 执行 M0–M6 迁移流程和 MigrationIssue 人工处置；
- 运行新旧双读、数量/关系/报告/Golden 差异核对；
- 验证多项目隔离、回滚、基线冻结和影响传播；
- 使用明确授权或脱敏样例验证所需的兼容 adapter、DO-326A/DO-356A 闭环和实验方法隔离；
- 停止旧模型写入，保留兼容读取窗口；
- 形成发布说明、操作手册、已知限制和验收记录。

### 出口门槛

- 无未解释的数据丢失、跨项目关系或 Golden 差异；
- 所有高风险 MigrationIssue 已解决或由责任人显式接受；
- 旧写入入口关闭，回退方案经过验证；
- 发布证据包完整，但不自动生成适航批准声明。

## 14. 阶段推进规则

- 阶段允许交叠开展设计和测试准备，但不得绕过前置架构门槛提交正式持久化实现。
- 紧急兼容修复可以进入当前代码，但必须补充差异记录，不得形成新的核心依赖。
- 每个阶段开始前维护任务清单、风险和测试基线；结束时记录实现偏差和遗留项。
- ADR 发生变化时优先更新决策，再修改代码和路线图。
- Phase 0 重新 Accepted 之前，不启动 Phase 1 的数据库结构修改。
- Phase 2 完成后必须先通过 VG-1；不得以“后续 Phase 3/5/6 会补齐”为理由跳过用户可见的端到端验收。
