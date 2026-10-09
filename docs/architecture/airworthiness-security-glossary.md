# ASTRA 适航安保领域术语表

- 状态：Accepted（已补充实验分析与结果晋级术语）
- 日期：2026-10-08
- 重新接受日期：2026-10-09

本术语表用于统一后端、前端、数据库、导入模板、API 和报告中的语言。英文名称是代码和 API 的首选规范名称；中文名称用于界面和文档。

## 1. 项目与版本

| 规范名称 | 中文 | 定义 | 不应混同 |
| --- | --- | --- | --- |
| `Project` | 项目 | 一项独立的适航安保工程工作范围，拥有自己的参与者、标准配置、模型和基线 | aircraft model 字符串、数据库实例 |
| `Model` | 模型 | 项目内一个明确范围的被评估对象，如 aircraft、system 或 item 模型 | 某次修改、某张报告 |
| `Revision` | 修订 | 模型的可变工作版本，是变更、分析和评审的并发控制边界 | 已冻结的基线 |
| `Baseline` | 基线 | 从某个 Revision 冻结得到的不可变快照，具有状态、批准记录和内容摘要 | 全局 GraphVersion |
| `StandardProfile` | 标准配置 | 标准标识、版本、适用范围、裁剪项和启用适配器的组合 | 标准全文、硬编码 feature flag |
| `ProjectConfiguration` | 项目配置 | 项目特定编号、模板、映射和已批准规则 | 通用核心规则 |

## 2. 来源、状态与审计

| 规范名称 | 中文 | 定义 |
| --- | --- | --- |
| `SourceRecord` | 来源记录 | 输入资料的可审计描述，包括文件、sheet/行、版本、hash、提交者和时间 |
| `SourceFact` | 源事实 | 由输入资料或人工录入形成、尚未经过分析推导的业务事实 |
| `DerivedResult` | 派生结果 | 可由确定输入、规则和生成器重新计算的结果 |
| `ReviewDecision` | 评审决定 | 人对事实或派生结果作出的接受、拒绝、修改、退回或批准决定 |
| `AuditEvent` | 审计事件 | 对业务状态产生影响的不可变事件记录 |
| `Provenance` | 来源链 | 一个实体或字段从资料、转换、生成到评审的完整来源描述 |
| `Stale` | 已过期 | 上游输入或规则已经变化，现有派生结果仍被保留但不可作为最新结论 |

建议的通用评审状态为：

```text
Draft -> Generated -> InReview -> Reviewed -> Approved
                     \-> Rejected
任一派生状态可因上游变化变为 Stale
```

`Approved` 只能由具有批准权限的人工操作产生，生成器不得直接写入。

## 3. 系统模型

| 规范名称 | 中文 | 定义 |
| --- | --- | --- |
| `Function` | 功能 | 被评估对象提供或支持的功能 |
| `Asset` | 资产 | 对安全、运行或适航有意义并需要建模保护的对象 |
| `SystemAsset` | 系统资产 | 系统、子系统、设备、软件或平台类资产 |
| `InformationAsset` | 信息资产 | 数据、配置、软件载荷、密钥、消息或记录等信息对象 |
| `Interface` | 接口 | 两个模型元素发生物理、逻辑或人员交互的位置 |
| `DataFlow` | 数据流 | 信息或控制在两个端点间的有方向传递 |
| `SecurityBoundary` | 安保边界 | 安保属性、控制责任或信任条件发生变化的边界 |
| `ExternalEntity` | 外部实体 | 处于当前模型范围外但与模型交互的人员、系统、设备或组织 |

`BoundaryInterface`、BDF、SDF、BI、SI 等可以作为适配器或项目词汇，但不得强迫所有标准使用同样的编号和数据结构。

## 4. 威胁与分析

| 规范名称 | 中文 | 定义 | 关键边界 |
| --- | --- | --- | --- |
| `ThreatSource` | 威胁来源 | 可能发起或促成威胁行为的来源分类 | 不等于一次具体攻击 |
| `ThreatActor` | 威胁主体 | 具有能力、动机或访问机会的具体或抽象主体 | 不等于 Threat Scenario |
| `ThreatPoint` | 威胁入口点 | 拓扑中可以被威胁利用或施加影响的位置 | 不得承载完整场景、影响和评审结论 |
| `ThreatCondition` | 威胁条件 | 对资产或功能施加未授权作用后可能形成的安保相关状态及影响 | 不等于攻击步骤 |
| `ThreatScenario` | 威胁场景 | 描述主体、入口、前置条件、攻击动作/路径和目标结果的情景 | 不等于单个入口点 |
| `AttackPath` | 攻击路径 | 场景在系统拓扑中的一条候选或已评审传播路径 | 算法路径不自动成为批准场景 |
| `RiskAssessment` | 风险评估 | 对明确分析对象、方法、输入和假设形成的风险判断 | 不等于单一 DPS 分数 |
| `AnalysisMethodDefinition` | 分析方法定义 | 版本化描述算法身份、输入输出契约、规则配置、规范化和运行限制 | 不等于 StandardProfile，也不定义核心 Asset |
| `AnalysisRun` | 分析运行 | 一次可复现的算法执行，绑定输入基线、配置、规则和生成器版本 | 不等于最终工程判断 |
| `DerivedResult` | 派生结果 | AnalysisRun 基于明确输入产生的版本化结果 | Experimental/Candidate 不等于人工接受结论 |
| `TopologyCandidate` | 拓扑候选 | 在给定图快照、映射和搜索边界内找到的可达序列 | 不等于已证实攻击可行的 AttackPath |
| `Promotion` | 结果晋级 | 经人工评审把派生候选显式转换为核心 Draft 实体的受审命令 | 不得由生成器自动执行 |

## 5. 安保保证与符合性工作产品

| 规范名称 | 中文 | 定义 |
| --- | --- | --- |
| `SecurityObjective` | 安保目标 | 为控制已识别风险而需要达到的目标性陈述 |
| `SecurityRequirement` | 安保要求 | 可分配、可实现并可验证的约束或能力要求 |
| `Control` | 安保控制 | 为满足要求而实施的技术、物理、人员或过程措施 |
| `VerificationCase` | 验证项 | 定义验证对象、方法、预期结果和接受准则的工作项 |
| `EvidenceRecord` | 证据记录 | 支撑验证、评审或符合性结论的受控证据及其来源信息 |
| `ComplianceClaim` | 符合性主张 | 对某个标准目标或项目准则的明确主张，必须由追踪和证据支撑 |
| `ChangeImpactAssessment` | 变更影响评估 | 比较基线并判断哪些分析、要求、验证和证据需要重新评估的活动 |

## 6. 追踪

`TraceLink` 是通用的、有类型的追踪关系。最少包含：

- link id；
- project/revision context；
- source entity type/id；
- target entity type/id；
- trace type；
- rationale；
- source reference；
- review status；
- created/updated actor and time。

建议的追踪类型包括：

- `DERIVED_FROM`
- `ALLOCATED_TO`
- `MITIGATES`
- `SATISFIES`
- `VERIFIED_BY`
- `SUPPORTED_BY`
- `MAPS_TO_STANDARD`
- `AFFECTED_BY_CHANGE`

关系名称表达工程语义；不得把所有关系退化为一个无法解释的 “link”。

## 7. 当前名称到目标名称的过渡

| 当前名称 | 目标处理 | 说明 |
| --- | --- | --- |
| `GraphVersion` | 迁移为 Revision 的版本字段 | 不再是全库唯一版本 |
| `DO326ALink` | 迁移为 `TraceLink` + 标准引用 | 保留原始 link id 和评审信息 |
| `StandardMapping` | 合并到 `TraceLink` | 避免两套映射体系 |
| `ThreatPoint` 中的 TS 文本 | 拆分为 ThreatPoint + ThreatScenario | 保留旧 ID 作为 legacy alias |
| `FunctionPropagationPath` | 作为适配器派生结果或通用 AnalysisPath 的专门视图 | 不作为所有标准的统一路径实体 |
| F3532 `ThreatCondition`/`ThreatScenario` | 映射到通用实体并记录 adapter/source profile | 不再由 F3532 仓储全局替换 |
| FeatureRule `Asset/Feature/Evidence/Scope/Policy` | 保持为版本化 method-specific DTO | 通过 crosswalk 引用核心对象，不按同名字段直接合并 |
| FeatureRule decision | 映射为实验性 `DerivedResult` | 不直接创建 ThreatPoint 或 ThreatScenario |
| Offline topology trace | 映射为 `topology_only` DerivedResult | 经证据核验和 promotion 后才可形成核心 Draft AttackPath |
| `ReviewStatus` | 扩展为统一生命周期 | 迁移时保留 Draft/Reviewed/Approved 语义 |

## 8. 命名规则

- 通用领域类型不得包含标准编号或项目名。
- 标准专用 DTO、导入器和报告可以带 `Do326a`、`Do356a`、`F3532` 前缀。
- 数据库存储的 `id` 是内部身份；`business_id` 是项目内可读编号；`legacy_id` 只用于迁移追踪。
- API 字段使用稳定英文名称；中文表头在 adapter/export 层转换。
- “生成”“评审”“批准”“提交”“冻结”必须作为不同动作和状态，不得混用。
