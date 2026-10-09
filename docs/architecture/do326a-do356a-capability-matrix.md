# DO-326A / DO-356A 能力差距矩阵

- 状态：Accepted（已纳入 `06ff8c6` 新增能力）
- 重新接受日期：2026-10-09
- 日期：2026-10-08
- 用途：架构规划与实施验收

## 1. 使用边界

本矩阵评估 ASTRA 的工程辅助能力，不构成标准符合性判定，也不复制标准正文。正式项目仍需使用经授权的标准版本、项目认证基础和主管当局/申请人的裁剪结论。

状态定义：

- `已有`：存在可运行实现和至少一种验证证据；
- `部分`：存在数据结构或局部流程，但不能形成完整工程闭环；
- `缺失`：尚无可用的一等能力；
- `需重构`：已有能力，但当前结构会阻碍多项目或标准通用化。

## 2. 能力矩阵

| 能力域 | 当前状态 | 当前证据 | 主要问题 | 目标能力 | 计划阶段 |
| --- | --- | --- | --- | --- | --- |
| 项目与评估范围 | 缺失 | 导入请求只有 `aircraft_model` 字符串 | 没有 Project、评估层级、范围、假设和参与者 | 项目、模型、范围、假设和角色成为一等实体 | Phase 1/3 |
| 标准版本与适用性 | 部分 | `StandardKnowledgeBase`、`standard_id` | 默认值和入口写死 F3532/DO326A；无 edition/tailoring | `StandardProfile` 显式记录标准版本、适用性和裁剪 | Phase 1/2 |
| 模型修订与基线 | 需重构 | 全局 `GraphVersion`、ChangeSet 冲突检查 | 全库单版本；无不可变基线和批准记录 | Project/Model/Revision/Baseline 隔离和冻结 | Phase 1 |
| 功能模型 | 部分 | `FunctionNode`、SUPPORTS_FUNCTION | 主要由导入驱动；无层级、范围和版本上下文 | 通用功能实体及层级/分配关系 | Phase 2/3 |
| 资产模型 | 已有/需重构 | `AssetNode`、ReactFlow 图 | `AssetNode` 被 F3532 BDF 字段污染；类型枚举过窄 | 通用 Asset + 可扩展分类和 adapter 扩展 | Phase 2 |
| 接口和数据流 | 部分/需重构 | `AssetEdge`、`BoundaryInterface`、`SystemDataFlow` | 通用边、BI、SDF 多套表达；端点语义不统一 | Interface/DataFlow 一等实体和专用视图 | Phase 2/3 |
| 安保边界 | 部分 | `TrustBoundary`、BI/SB 报表 | 命名和关系受当前模板影响；没有版本/来源闭环 | 通用 SecurityBoundary 与成员、跨越和责任关系 | Phase 2/3 |
| 外部实体和威胁主体 | 部分 | `ThreatActor`、外部资产 | ExternalEntity、ThreatSource、ThreatActor 边界不清 | 分离外部实体、来源分类和威胁主体 | Phase 2/3 |
| 来源与数据谱系 | 部分 | 部分实体有 source sheet/row | 字段零散；缺文件 hash、转换版本和字段级来源 | `SourceRecord` 和统一 Provenance | Phase 1/2 |
| Threat Point | 已有/需重构 | `ThreatPoint` | 示例把完整 TS 放入 ThreatPoint；字段混合入口与威胁描述 | 仅表达可利用入口/暴露点 | Phase 2/3 |
| Threat Condition | 部分 | `ThreatCondition` 类型、F3532 04 | 只走 F3532 仓储；全局替换；无通用生命周期 | 项目级 TC、影响、来源、评审和追踪 | Phase 3 |
| Threat Scenario | 部分 | `ThreatScenario` 类型、F3532 04 | 与 ThreatPoint/AttackPath 重叠；缺结构化步骤和版本 | 主体、入口、动作、目标、TC、路径的完整场景 | Phase 3 |
| 攻击路径搜索 | 已有 | DFS/DPS、循环和范围剪枝 | 算法与工程结论边界不清；配置和输入摘要不足 | 可插拔路径引擎、AnalysisRun、可重现结果 | Phase 4 |
| 特征规则预览 | 已有/实验性 | 严格 Zod 契约、四值逻辑、scope/policy/evidence 门控、input hash | 使用研究侧 Asset/Feature/Evidence/Scope/Policy DTO；无项目/revision 上下文；调用方审核声明未认证 | 注册为 `AnalysisMethodDefinition`（`maturity=experimental`）并接入 AnalysisRun，保留专用 DTO | Phase 4 |
| 拓扑候选追踪 | 已有/实验性 | 显式资产映射、allowed edges、方向语义、搜索上限和 mapping hash | 使用全局 graph_version；边缺逐边证据；拓扑可达不等于攻击可行 | project/revision-scoped、evidence-aware 的 `topology_only` DerivedResult 和显式晋级 | Phase 4 |
| 路径解释 | 部分 | explanations、F3532 evidence | 主要是字符串；缺统一证据结构 | 结构化规则命中、事实引用和决策依据 | Phase 4 |
| 风险评估 | 部分 | likelihood/complexity/DPS/priority | 单一启发式评分；缺评估方法、接受准则和人工决定 | `RiskAssessment` 绑定方法、对象、结果和批准 | Phase 3/4 |
| Security Objective | 缺失 | 仅有 mitigation/reference 文本 | 无法从风险结论追踪到目标 | 一等目标、分配、状态和追踪 | Phase 3 |
| Security Requirement | 缺失/弱 | 示例 SR 仅存为文本/link | 没有要求实体、版本、分配和验证准则 | 一等要求与目标、设计元素、验证项关联 | Phase 3 |
| 安保控制/措施 | 部分 | `security_mechanism`、existing measures 文本 | 不能复用、分配、评审或验证 | `Control` 及其实现和有效性状态 | Phase 3 |
| 验证策划 | 缺失 | 无 | 无验证方法、接受准则和状态 | `VerificationCase` 支持分析/测试/检查/评审 | Phase 3 |
| 符合性证据 | 部分/弱 | `evidence_reference` 字符串 | 不受控、无 hash、版本、所有者和适用范围 | `EvidenceRecord` + 文件/链接元数据 + 评审 | Phase 3/6 |
| 标准条款知识 | 部分 | Clause/Artifact/Stage 知识图谱 | 导入接口写死 F3532；标准全文授权边界未治理 | 通用标准元数据与授权导入 profile | Phase 2 |
| 标准追踪 | 部分/需重构 | `DO326ALink`、`StandardMapping` | 两套模型；关系类型有限；目标类型硬编码 | 统一有类型 `TraceLink` | Phase 2/3 |
| 评审与批准 | 部分 | Draft/Reviewed/Approved | 无意见、退回、角色、独立性和批准事件 | ReviewSession、Comment、Decision、角色校验 | Phase 3/6 |
| 变更影响分析 | 缺失 | GraphVersion 只能拒绝旧提交 | 不知道哪些分析/要求/证据受影响 | 基线差异、依赖传播和 stale 标记 | Phase 4/5 |
| 审计 | 部分 | `CommitAudit` | 摘要有限；不同仓储绕开审计；无防篡改策略 | 覆盖全部状态变化的 AuditEvent | Phase 1/6 |
| 导入预览 | 已有 | 单表、CXF、F3532 preview/commit | 多套错误结构和模板逻辑 | adapter 导入契约、统一诊断和幂等提交 | Phase 2 |
| 报告和导出 | 部分 | JSON、F3532 03/04、第四章 Excel | 报告与 F3532/ZG-ONE 紧耦合；字段缺来源链接 | profile 驱动工作产品与追踪矩阵 | Phase 3/5 |
| 多项目隔离 | 缺失 | 全局唯一约束 | ID 冲突、查询和删除均可能跨项目 | 所有读写强制 project/revision scope | Phase 1 |
| 用户与权限 | 缺失 | `x-user-id` 固定文本 | 无身份真实性和职责分离 | 单用户兼容 + 可扩展 RBAC | Phase 6 |
| API 契约 | 部分 | Zod + TS 类型 | 后端、前端、schema 三份定义；无 API 版本 | 版本化 API 和生成客户端类型 | Phase 2 |
| 自动化测试 | 部分 | F3532 Golden；feature evaluator/API/CLI/path trace；SDF integration；前端导入测试 | 缺通用核心、项目隔离、迁移、完整仓储和 E2E 测试；前端 workspace test glob 在 Windows 不可移植 | 测试金字塔、跨平台命令和标准样例 Golden 集 | Phase 0-6 持续 |
| 运维和恢复 | 缺失/弱 | Docker + health | 无迁移账本、备份演练、指标和告警 | 明确部署、备份、恢复和可观测性 | Phase 6 |

## 3. MVP 必须闭环的追踪链

DO-326A/DO-356A 第一版 MVP 至少必须支持以下链路：

```text
StandardReference
  -> ProjectScope / Activity / WorkProduct
  -> ModelElement
  -> ThreatCondition
  -> ThreatScenario
  -> AttackPath / RiskAssessment
  -> SecurityObjective
  -> SecurityRequirement
  -> VerificationCase
  -> EvidenceRecord
  -> ReviewDecision
```

允许某些节点在经过裁剪后为空，但裁剪理由必须作为受控记录存在，不能通过缺数据隐含表达。

## 4. MVP 验收用例

### 4.1 多项目隔离

- 创建两个项目；
- 两个项目都使用业务编号 `SI.1`、`TC.1`；
- 读取、提交、删除、报告和审计均不跨项目；
- 项目 A 的 stale revision 不影响项目 B。

### 4.2 Appendix D 示例闭环

- 将现有 AMS 示例迁移为项目、模型和 revision；
- ThreatPoint、ThreatCondition、ThreatScenario 和 AttackPath 独立存在；
- 至少一条风险结论追踪到目标、要求、验证项和证据；
- 可以冻结基线并导出追踪矩阵；
- 不再把 TS 文本直接存为 ThreatPoint 名称来代替场景。

### 4.3 F3532 回归

- 现有 01/02 数据能够迁移；
- 03 的确定性生成结果和 Golden 对比不发生未解释变化；
- 04 的 TC/TS 进入通用实体，但报告输出保持兼容；
- F3532 adapter 不被启用时，核心系统不加载其规则或界面。

### 4.4 可重现与过期传播

- 相同 baseline、规则和生成器版本产生相同结果摘要；
- 修改上游模型后，关联派生结果标记为 stale；
- 原结果和审批历史继续可读；
- 未经人工决定，不自动把新结果标记为 Approved。

### 4.5 实验分析隔离与晋级

- 相同 FeatureRule 输入与方法版本产生相同 `input_sha256` 和判定摘要；
- 外部 JSON 中的 APPROVED/reviewer/verified 不自动创建平台 ReviewDecision；
- `topology_candidate` 在晋级前保持 `topology_only`，不出现在正式 AttackPath 集合中；
- 截断、未映射、证据未验证、无路径和搜索未完成保持不同状态；
- 禁用实验方法后，核心建模、F3532 回归和 DO-326A/DO-356A 闭环仍可运行。

## 5. Phase 1 优先问题

Phase 1 不应先补齐全部标准工作产品，而应先解决五个结构性风险：

1. 全库单 `GraphVersion`；
2. 全局业务 ID 唯一约束；
3. 启动时隐式数据修复；
4. 部分仓储绕开 ChangeSet、版本和审计直接覆盖数据。
5. 新旧分析入口缺少 Project/Revision/AnalysisRun 的统一执行外壳。

这些问题不解决，继续增加标准实体只会扩大后续迁移范围。
