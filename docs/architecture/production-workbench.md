# 正式工作台契约与映射 v1

基线：43df6f8；与原 analysis-run.v1（浏览器提供输入）的兼容语义分离。

## 路由

* GET `/api/v2/governance/workspaces`：项目、模型、修订、状态与版本。
* POST `/api/v2/governance/workspaces`：沿用现有创建命令。
* GET `/api/v2/system-model`：沿用核心实体与来源读取。
* POST `/api/v2/system-model/import/preview|commit`：原 system-model.v2 create-only；另支持 `contract_version: inventory-import.v1`、`inventory`、`conversion_profile: do356a-ams/v1`、原始文件 SHA256。
* GET `/api/v2/system-model/workbench?project_id&revision_id`：核心模型、分析配置、服务端推导图与实际目标。
* POST `/api/v2/system-model/changes/preview|commit`：`model-edit.v1`；完整核心实体候选、分析配置、expected_revision_version。预览返回字段差异与引用诊断，提交在 RevisionUnitOfWork 内再次校验并原子更新，不调用旧全局 ChangeSet。
* POST `/api/v2/analysis/runs`：新增 `saved-model-analysis.v1`，只接受范围、版本、命令及 max_hops/dps_hop_decay/scope_asset_ids；不接受浏览器图。旧请求按原契约处理。
* POST `/api/v2/analysis/runs/export`：范围、run_id 与参数；服务端检查模型/配置摘要、参数、运行状态和读取期间的版本稳定性，返回经核验的模型与运行。冲突或失败运行返回 409。
* GET `/api/v2/analysis/runs?...&view=workbench.v1`：显式工作台读取视图，附加由服务端 AuditEvent 回执推导的 input_origin。默认读取保持旧 DTO，避免改变已有冻结报告的内容摘要。

所有新写命令包含 actor、command_id、project_id、revision_id、expected_revision_version；复用现有幂等指纹、冻结与审计事务。版本冲突返回 409，禁止覆盖。重试必须使用相同请求和 command_id。

## 数据位置

核心资产、接口、数据流、边界和候选威胁存储在 SystemModelElement。新增 `analysis` 元数据仅描述该实体的 DPS 映射（Neo4j 中保存为 JSON），不是另一份浏览器图。资产 ID 使用核心 business_id，数据流 ID 映射 edge_id，DraftThreat 映射候选 ThreatPoint。

AnalysisConfiguration 节点位于项目/修订内：保存转换版本、原始清单、自动威胁参数和人工覆盖；配置更新与核心编辑共享同一版本事务和审计事件。自动威胁仍是 Draft，界面必须标注待核对。

转换规则 `do356a-ams/v1` 只适用于经人工选择的 DO356A-AMS 输入。内部复用 CxfImportService 的现有规则；不声称适用于任意机型。通用核心模型通过 `core-dps/v1` 映射，不猜测 AMS 拓扑。

分析在修订事务锁内读取核心及配置并构造不可变输入快照，调用原 AnalysisService；保存映射版本、参数、配置摘要、耗时及结果。算法公式、目标推断、路径顺序不变。运行本身递增修订审计版本，因此结果当前性以模型/配置摘要及参数判断，不能简单比较 input_revision_version 与最新事务版本。

| 核心事实 | DPS 映射 | 来源与限制 |
| --- | --- | --- |
| Asset.business_id / name | asset_id / asset_name | 核心字段为准，不信任浏览器算法图 |
| Asset.category / criticality / analysis | 类型、重要性、安全域、分类、占位标记与原标签 | Catastrophic 映射 High；通用类别默认 Terminal，不新增目标算法 |
| DataFlow.business_id / producer / consumer | edge_id / source / target | link_type、direction、trust_level、安全机制等由实体 analysis 元数据映射；dps_enabled=false 明确排除 |
| Interface 的两个资产 | 显式派生 Logical 边 | 仅双向或明确指定有序单向；不重复已有 DataFlow 接口连接，不对未知方向猜测 |
| DraftThreat | 候选 ThreatPoint | ID、名称和关联资产来自核心；参数来自分析配置，未配置时使用明确的 Medium/Medium/external/Tampering/Network 默认候选 |
| 原始功能/边界/主体/接口/系统流 | v2 Function / SecurityBoundary / ExternalEntity / Interface / DataFlow | 原始清单还保存在修订配置来源记录中；未知或不唯一的端点阻止转换 |

AMS 包装层保持原 CxfImportService 产生的资产、连接及威胁集合和顺序。mapping_order 保留转换顺序；补充边界接口与独立系统流不会默默变成额外的 DPS 边，标记 dps_enabled=false 并在预览告知。原始 Sheet、行号和字段坐标随记录保存，包括旧格式的原列坐标。

编辑提交使用候选核心实体及完整配置。事务内重新检查重复身份、全部核心引用、配置威胁引用及其他工程实体的删除引用，再更新实体和语义关系。AuditEvent 的 result_json 保存逐字段 before/after 差异及变更数；来源节点保留，新增实体继续关联来源。相同 command_id 与内容重放返回原结果，内容变化拒绝复用。

## 结果语义

评分统一说明：用于相对排序的启发式评分，不代表实际攻击成功概率。
原 DFS 仅保证配置跳数范围，输出标注 bounded；超时为明确错误，不返回空路径。当前导出必须校验模型/配置摘要及参数；历史导出必须标明历史版本。模型变更后保留历史运行，并标记 stale。

工作线程限制 10 秒及 256 MB 老生代内存。超时或执行错误保存 Failed 运行、输入与配置快照、耗时、错误诊断，termination_reason 为 execution_error；不创建攻击路径候选，也不能导出为当前成果。正常零路径运行仍保存 search_summary，明确说明只在配置范围内未发现路径。本轮只提供历史查看，不提供历史文件导出。

“已保存模型输入”由审计回执中的 request_canonicalizer=workbench.saved-analysis/v1 核验，而不是由调用方可填写的 method_config_version 或 model_hash 自行声明。兼容 API 即使伪造相同配置标记，input_origin 仍为 caller-provided，前端及导出均不得认作当前正式成果。默认旧读取不增加这个派生字段，历史 TraceabilityReport 摘要保持兼容。
