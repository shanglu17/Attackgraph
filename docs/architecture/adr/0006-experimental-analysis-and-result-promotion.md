# ADR-0006：实验性分析方法与结果晋级

- 状态：Accepted
- 提出日期：2026-10-08
- 接受日期：2026-10-09

## 背景

当前代码已经包含证据感知的特征规则预览和离线拓扑路径追踪。特征规则契约以 `EXP`、`TRU`、`PCX`、`EXE`、`INF`、`FUN` 六维特征模型为方法层输入，并增加 evidence、scope、policy 和 reviewer metadata 等运行治理信息。这些能力具有严格输入契约、确定性哈希、四值逻辑、范围门控、路径截断状态和显式研究限制，应作为一等分析方法继续演进。

但六维方法的 `Asset`、`FeatureRecord`、`Evidence`、`Scope`、`Policy` 和 reviewer metadata 构成方法自己的领域语言及传输契约；拓扑追踪仍使用全局 `graph_version` 和原型资产映射。若直接把这些 DTO 持久化为通用核心，或者把 `topology_candidate` 当作正式 AttackPath，会混淆研究候选、工程事实与人工批准。

本 ADR 在 ADR-0004 的来源、派生结果、评审与追踪规则，以及 ADR-0005 的统一写入治理之上，定义分析方法、运行外壳和结果晋级的附加约束。

## 决策

### 1. 分离标准 profile 与分析方法

- `StandardProfile` 描述标准版本、适用性、裁剪和工作产品要求；
- `AnalysisMethodDefinition` 描述算法身份、成熟度、输入输出契约、规则包、配置 schema、canonicalization、运行限制和输出种类；
- profile 可以允许、要求或禁止某种方法，但方法 DTO 不定义 Project、Asset、EvidenceRecord、ReviewDecision 或 AttackPath 等通用核心实体；
- 六维特征模型是 FeatureRule 方法的一等方法领域模型；`feature-preview-0.1` 是其当前版本化传输/运行契约，二者不得混称为平台通用 schema。

特征规则预览和拓扑追踪分别注册为 `AnalysisMethodDefinition`，并设置 `maturity = experimental`。F3532 生成和 DFS/DPS 后续也通过相同方法端口接入，但可以具有不同成熟度与可用状态。

### 2. 统一核心 AnalysisRun 外壳

`AnalysisRun` 和 `DerivedResult` 是标准无关核心实体，可以被追踪、评审、晋级和审计。方法专用输入输出是版本化 DTO 或 extension payload，不是通用核心领域实体，也不能替代核心实体。

任何需要保存或晋级的运行至少必须记录或可解析到：

- project、model、revision 或 baseline，以及不可变输入快照引用和内容摘要；
- `StandardProfileVersion`；
- method definition id/version 和 implementation artifact digest；
- contract version；
- rule-pack version（适用时）；
- method-config version；
- canonicalizer id/version；
- SourceRecord/Provenance 入口；
- graph snapshot reference/hash（适用时）；
- mapping snapshot reference/hash（适用时）；
- started/completed at and actor；
- creation command/idempotency id 和对应 AuditEvent；
- execution limits、truncation、completeness、termination reason 和 diagnostics；
- result status 和 supersession relation。

“可解析”允许通过字段、受控关系或审计索引实现，不要求全部复制为 AnalysisRun 的平面属性。只有 hash、没有可检索的输入/图/映射快照，不足以支撑可重放承诺。

### 3. 两阶段评审与显式晋级

```text
Experimental/Imported Output
  -> Candidate DerivedResult
  -> ReviewDecision A（subject = DerivedResult version）
  -> Idempotent Promotion Command
  -> Core Draft Entity + DERIVED_FROM TraceLink
  -> ReviewDecision B（subject = Core Draft version）
  -> Engineering Acceptance / Baseline Approval
```

- 规则预览结果默认只产生 method-specific `DerivedResult`；
- ReviewDecision A 只判断明确版本的 DerivedResult 是否具备晋级资格；
- promotion command 必须显式选择目标类型、目标 revision、来源结果和目标业务身份，并遵循 ADR-0005 的幂等写入与审计约束；
- ReviewDecision B 对晋级后 Core Draft 的工程内容作出决定，不能复用 ReviewDecision A；
- 是否允许同一人执行两次评审由项目 ReviewPolicy/ProjectConfiguration 决定；首版可以不强制职责分离，但必须保留两个独立 subject version、角色和决定；
- Core Draft 被退回或拒绝时，原 DerivedResult、ReviewDecision A 和 promotion 审计历史不回滚、不删除；
- 再次晋级必须通过新命令产生新 Draft/version，并使用 supersedes/superseded-by 表达替代关系；
- 生成器、导入器和 CLI 不能产生 Reviewed/Approved 状态。

### 4. 晋级后来源不可洗白

- `topology_candidate` 在源 DerivedResult 中始终保留 `topology_only=true`，不自动成为正式 AttackPath；
- 晋级后的核心实体必须记录 `origin`，并通过 `DERIVED_FROM` TraceLink 指向源 DerivedResult，进而解析到原 AnalysisRun、输入、映射、证据、截断和完整性状态；
- 这些来源信息必须在 API、评审界面、导出和报告中可见，不得只保存在内部审计日志；
- 晋级为 Draft AttackPath 前，必须验证逐段拓扑语义与证据，并记录为何拓扑可达能够支持该 Draft 的攻击可行性判断；
- 经逐段验证后，Core Draft AttackPath 不要求继续声明自身为 `topology_only=true`，但不得删除或隐藏源结果的 topology-only 属性和证据缺口；
- 重跑方法不得覆盖源 DerivedResult、晋级后的 Draft 或任一 ReviewDecision。

### 5. 原型资产与范围映射

- research/prototype asset、scope 和 topology mapping 必须在 AnalysisRun 所属 project 及 revision/baseline 快照内显式解析；
- 不得跨项目匹配，不得仅凭名称、显示文本或参考答案猜测映射；
- 未映射、映射歧义或映射证据未验证时必须保持 unresolved/issue 状态，不得通过扩大允许边集规避；
- mapping 必须具有版本、内容 hash、来源证据和适用快照；映射变化产生新运行或使旧结果 stale；
- 具体映射遵循[实验性特征分析 Crosswalk](../experimental-analysis-crosswalk.md)，其实现不得削弱本 ADR 的约束。

### 6. 证据和审核语义

通用 SourceRecord、DerivedResult、ReviewDecision 和 TraceLink 要求遵循 ADR-0004；所有持久化、晋级和状态变化遵循 ADR-0005。本节只规定实验方法的附加限制：

- 输入 JSON 中的 `verified`、`APPROVED`、reviewer 等字段仅表示调用方断言；
- 未经过平台身份、角色、对象版本和证据完整性校验，不得映射为正式 `ReviewDecision`；
- method evidence 通过 crosswalk 映射到 SourceRecord/EvidenceRecord，原始定位、版本和 hash 必须保留；
- 缺证据、冲突、未知、未映射、搜索未完成和完整无路径是不同状态，不得合并为“无威胁”或“无路径”。

### 7. 确定性、重放与方法生命周期

- 每个方法定义自己的 canonicalization 规则，canonicalizer id/version 参与运行身份和结果摘要；
- FeatureRule 中语义为集合的数组可以按方法规则排序；AttackPath steps、事件历史和评审序列等有序数据不得使用通用数组排序；
- `maturity` 与运行可用状态分离：experimental/qualified/deprecated 表达成熟度，enabled/disabled/archived 等表达是否允许新运行；
- deprecated 不等于不可重放。产生过持久化 AnalysisRun 的方法实现、规则包、canonicalizer 和必要运行制品必须按保留策略归档；
- 输入、图和映射必须保存不可变快照或可内容寻址的可检索引用，不能只保存 hash；
- 在规定保留期内，使用归档实现、输入/图/映射快照、规则包、配置和 canonicalizer，应能重算相同的规范化结果摘要；
- 若所需制品不再可用，历史结果必须标记为不可重放但可验证，不得继续宣称可重现；原输出、hash、来源和审计记录仍必须保留。

### 8. 搜索完整性

- 路径方法必须在 AnalysisMethodDefinition 中定义“搜索完成”的判定及其适用范围；
- diagnostics 至少表达 completeness（complete/partial/unknown）和 termination reason；
- termination reason 至少能够区分搜索空间穷尽、hop/path/expansion 上限、取消和错误；
- 只有未截断、`completeness=complete`、因允许搜索空间穷尽而结束且未找到路径时，才能输出 `no_path_in_snapshot`；
- 达到任何资源上限但未找到路径时必须输出 `search_incomplete` 或等价的不完整状态。

## 结果

- 六维特征研究能力作为一等分析方法保留，同时实验 DTO 不污染通用 Asset、Evidence、Review 和 AttackPath；
- 同一项目可以在不同 StandardProfileVersion、方法、规则包或配置版本下运行和比较结果；
- AnalysisRun/DerivedResult 成为稳定的核心接缝，method-specific payload 可以独立演进；
- 机器候选到工程结论的责任边界清晰，晋级后仍能看到原始来源和局限；
- 历史运行的重放、验证、退役和不可重放状态具有明确语义；
- 后续 DO-356A 方法扩展无需复制项目、证据、评审和审计基础设施。

## 未采用方案

### 直接把 FeatureRule schema 变成核心领域模型

未采用。六维特征模型是重要的方法领域模型，但其分类、特征和 policy 语义不能覆盖平台全部通用适航安保实体。

### 直接将拓扑候选写入 AttackPath

未采用。拓扑可达性不等于攻击可行性，当前原型边也没有逐边工程证据。

### 方法直接创建 Core Draft，再由人工事后否决

未采用。该反向流程会让未映射、截断、未知或证据不足的机器结果提前进入正式工程对象空间，弱化候选隔离和责任边界。

### 只保留导出的 JSON，不建立 AnalysisRun

未采用。它无法提供项目范围、输入版本、方法身份、过期传播、审计和评审晋级关系。

## Phase 4 待定实现项

下列内容由 Phase 4 详细设计决定，但不得违反上述架构不变量：

- Neo4j 标签、关系、索引以及 method payload 的物理存储；
- AnalysisRun/DerivedResult 的最终 API 字段名和 JSON Schema；
- 完整的候选、晋级、退回、拒绝和 supersession 状态机；
- ReviewPolicy 的角色矩阵及职责分离强制规则；
- 方法实现制品、快照和规则包的归档技术及保留周期；
- 搜索 diagnostics 的最终 schema 和各方法的完整性算法；
- promotion command 的 API 形状和业务编号分配方式。

## 验收约束

- 特征规则预览和拓扑追踪使用 `AnalysisMethodDefinition` 且 `maturity=experimental`，不存在第二套实验方法类型；
- AnalysisRun 和 DerivedResult 属于核心实体，method-specific payload 不替代核心领域实体；
- 每个持久化结果可解析到 StandardProfileVersion、方法/实现版本、canonicalizer、输入快照、SourceRecord、创建命令和 AuditEvent；
- 未经 ReviewDecision A 和显式幂等 promotion command，实验结果不会创建核心 ThreatPoint、ThreatScenario、AttackPath 或 RiskAssessment；
- ReviewDecision A 与 ReviewDecision B 具有不同 subject version，前者不能自动批准晋级后的 Core Draft；
- 晋级实体保留 origin 和到源 DerivedResult/AnalysisRun 的 `DERIVED_FROM` 追踪，并在评审、导出和报告中可见；
- asserted reviewer metadata 不会成为平台 ReviewDecision；
- asset/scope/mapping 仅在运行所属 project/revision/baseline 内解析，未解析状态不会被名称猜测消除；
- 在声明的保留范围内，相同快照、方法实现、规则、配置和 canonicalizer 可重算相同规范化结果摘要；
- 不满足重放条件的历史运行明确标记为不可重放，不继续宣称可重现；
- 截断、部分或未知完整性的搜索不能被标为完整无路径；
- 方法被禁用或 deprecated 时，核心建模、评审、历史读取和报告能力仍可运行。

## 关联决策

- ADR-0002：标准无关核心与适配器边界；
- ADR-0003：项目、模型、修订与基线；
- ADR-0004：数据来源、生成、评审与追踪；
- ADR-0005：显式迁移与写入治理。
