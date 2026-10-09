# ASTRA 遗留数据迁移设计

- 状态：Accepted（已纳入实验分析能力，尚未实施）
- 日期：2026-10-08
- 重新接受日期：2026-10-09
- 目标阶段：Phase 1 至 Phase 2

## 1. 目标

将当前全局 Neo4j 图安全迁移到 Project/Model/Revision/Baseline 架构，同时保留：

- 当前数据库中经过授权的遗留业务编号；
- DO-356A Appendix D 示例；
- 已导入源数据和可恢复的来源定位；
- AttackPath、FP、TC、TS 和标准映射；
- 评审状态和审计信息；
- 现有报告输出所需字段；
- F3532 03 Golden 对比能力。

迁移不得把当前模型清空后重新 seed 作为正式方案。

## 2. 迁移原则

1. 先复制/挂接，后切换读取，最后弃用旧字段。
2. 每个步骤可 dry-run，输出预计节点/关系/冲突数量。
3. 原始 ID 和属性在迁移验证完成前不删除。
4. 业务编号不作为新内部主键。
5. 迁移期间双读可以接受，长期双写不可接受。
6. 无法自动判断的语义进入 migration issue，不猜测批准状态。
7. 迁移成功以不变量和 Golden 结果验证，不以脚本退出码单独判断。
8. 仓库外研究资料必须通过逻辑 source id、版本、hash 和受控位置登记，个人绝对路径不作为可迁移标识。
9. 方法专用 JSON/DTO 原样留存并记录 contract version，不通过字段同名猜测映射为核心实体。

## 3. 默认遗留上下文

若运行迁移时没有提供项目配置，则创建中性的未分类遗留上下文：

```text
Project
  business_id: legacy-unclassified
  name: Generic Legacy Migration

Model
  business_id: legacy-primary-model
  level: system

Revision
  business_id: legacy-import-r1
  status: Draft
```

实际实施前允许通过迁移参数替换这些值。DO-356A Appendix D 示例必须迁移为独立 Project，不能与未分类数据继续共享全局图。仓库已忽略的 ZG-ONE/F3532 保密资料不属于本阶段迁移输入；若未来兼容回归确有需要，只能由资料责任人明确提供经过授权或脱敏的受控样例，不得从忽略目录自动恢复或提交。

## 4. 遗留对象映射

| 当前对象 | 目标对象 | 保留策略 |
| --- | --- | --- |
| `GraphVersion` | Revision.version + legacy metadata | 保留原值作为 `legacy_graph_version` |
| `AssetNode` | Asset/InformationAsset/adapter extension | 保留 `asset_id` 为 legacy id 或 business id |
| `AssetEdge` | Relationship/DataFlow/Connection | 按 link_type 分类；不能判断时保留 generic connection |
| `FunctionNode` | Function | 保留 function id |
| `BoundaryInterface` | Interface + adapter extension | BI 编号保留为 business id |
| `SystemDataFlow` | DataFlow + F3532 extension | SDF 编号保留；解析 producer/consumer endpoint |
| `TrustBoundary` | SecurityBoundary | 原 boundary id 保留 |
| `ThreatActor` | ThreatActor | 保留 actor id 和类型 |
| `ThreatPoint` | ThreatPoint；必要时拆出 ThreatScenario | 自动拆分只能生成 Draft migration candidate |
| `AttackPath` | AttackPath + AnalysisRun | 根据 batch 生成 AnalysisRun，保存旧 score/config |
| FeatureRule preview bundle | SourceRecord + AnalysisRun method input | 保留 contract/input hash；研究 Asset/Evidence/Scope/Policy 不直接创建核心同名对象 |
| FeatureRule decision | Experimental DerivedResult | 保留四值 checks、执行门控和来源索引；不自动创建 ThreatPoint/ThreatScenario |
| Offline topology trace | `topology_only` DerivedResult | 保留图/映射 hash、有序节点边、截断和 edge evidence 状态；不自动创建 AttackPath |
| `FunctionPropagationPath` | AdapterDerivedResult/AnalysisPath view | 保留 FP 编号和成员关系 |
| `FailureCondition` | ExternalSafetyReference/FailureCondition | 保留 FHA 来源和关系 |
| `ThreatCondition` | ThreatCondition | 绑定项目/revision，保留 review status |
| `ThreatScenario` | ThreatScenario | 绑定 TC、actor 和路径；缺关系产生 issue |
| `DO326A_Link` | TraceLink + StandardReference | 保留 link id、linkage type 和 evidence text |
| `StandardMapping` | TraceLink + StandardReference | 与 DO326A link 去重但不丢原始记录 |
| `CommitAudit` | AuditEvent | 标记 `legacy=true`，不伪造缺失字段 |

## 5. 迁移步骤

### M0：盘点与备份

- 检查数据库版本和现有约束；
- 导出节点/关系数量、孤立引用、重复 ID 和空关键字段；
- 创建可验证备份并记录 backup id/hash；
- 记录 Appendix D 导出摘要；只有明确提供授权或脱敏兼容样例时才记录对应 Golden；
- 盘点已保存的 feature preview/path trace 输入输出、contract version 和 hash；
- 将仓库外资料路径转换为待解析的 SourceRecord 清单，不复制或假定资料内容；
- 若存在未知 schema 或未完成迁移，停止。

### M1：建立迁移基础设施

- 创建 MigrationRecord；
- 创建 Project/Model/Revision/StandardProfile；
- 添加新的内部 UUID 和 scope 字段；
- 暂不删除旧约束和字段。

### M2：挂接通用模型

- 将现有实体关联到目标 project/model/revision；
- 生成内部 UUID；
- 为重复业务编号生成冲突报告；
- 建立 SourceRecord，无法定位的标记为 `legacy-unknown-source`。

### M3：语义归一化

- 将 BDF/SDF/BI 等专用属性映射到 adapter extension；
- 将通用 Asset/Interface/DataFlow 字段从专用字段中分离；
- 将 DO326ALink/StandardMapping 映射为 TraceLink；
- 创建迁移候选，而不是自动批准 TC/TS 拆分结果。

### M4：生成与评审历史

- 按 analysis batch 创建 AnalysisRun；
- 为 F3532 生成结果保存 generator/rule version；
- 为已保存的 feature preview/path trace 创建实验 AnalysisRun 和 DerivedResult；没有原始输入或 hash 时产生 MigrationIssue；
- 保留 `topology_only`、truncated、unknown/conflict、mapping/evidence 状态；
- 保留原 review status；
- 缺少 actor/timestamp 的旧记录明确标记为 unknown，不使用当前用户补写。

### M5：兼容读取与验证

- 新 API 从目标模型读取；
- 旧 API 通过 compatibility mapper 返回旧响应；
- 比较旧/新图数量、业务 ID、关系、报告和 Golden 输出；
- 执行双读差异报告。

### M6：切换与弃用

- 停止旧模型写入；
- 新写入只经过 scoped application service；
- 旧字段进入 deprecated 状态；
- 至少经过一个稳定版本后，才提交删除旧字段/约束的独立迁移。

## 6. 必须保持的不变量

- 每个迁移业务实体恰好属于一个 Project 和一个工作 Revision；
- 所有关系两端属于相容的 project/model/revision；
- 每个业务编号都能反查旧 ID；
- Approved 记录数量不能在无迁移 issue 的情况下减少；
- AttackPath 的 hop sequence 和 edge membership 不发生无解释变化；
- topology trace 的节点/边顺序不得因集合规范化而重排；
- 外部 reviewer/APPROVED/verified 声明不得自动增加平台 Reviewed/Approved 数量；
- 对纳入迁移范围的授权 Golden，差异为零或每项差异均有批准的迁移说明；
- 现有报告所需数据不得变为空；
- 新旧总量差异能够由拆分、合并或过滤规则解释。

## 7. 冲突与人工确认

下列情况不得自动决定：

- 一个遗留 TS 文本究竟是 ThreatPoint 名称还是完整 ThreatScenario；
- `DO326ALink` 与 `StandardMapping` 是否表达同一工程关系；
- 同一业务编号在混合数据集中属于哪个项目；
- 现有 Reviewed/Approved 状态是否满足未来角色和独立性要求；
- F3532 专用 FunctionPropagationPath 是否应升级为通用 AttackPath。
- 研究侧 Asset 是否与核心 Asset 表达同一对象，以及其 `prototype_asset_id` 映射是否仍有效；
- 调用方声明的 reviewer、APPROVED 或 verified 是否具有正式工程审核效力；
- topology candidate 是否具备逐边证据并可以晋级为核心 AttackPath。

这些情况进入 MigrationIssue，包含候选方案、影响对象和人工决定。

## 8. 回滚策略

- M1-M5 期间保留旧字段和旧读取路径；
- 任一步失败时停止后续 migration id，不自动继续；
- 数据修复优先通过补偿迁移完成；
- 若不变量无法恢复，使用 M0 备份恢复到独立数据库，再重新执行；
- 切换后不得通过删除新数据来“回滚”，应恢复备份或执行已审查的反向迁移。

## 9. 完成标准

- 迁移 dry-run、apply 和 verify 都有机器可读报告；
- 新应用能够读取遗留项目并生成等价报告；
- 旧 API 兼容测试通过；
- 多项目相同 business id 验证通过；
- 不存在未归属实体和跨项目关系；
- 所有 MigrationIssue 已解决、接受或显式推迟；
- 经确认后才能进入旧字段清理阶段。
