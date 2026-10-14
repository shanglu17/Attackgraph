# Change Impact v1 与 Assurance Work Product v1 API 契约

状态：Implemented（Phase 5）

影响契约：`change-impact.v1`

工作产品契约：`assurance-work-product.v1`

## 作用域与比较边界

每次比较必须显式提供 `project_id`，并为起点和终点各指定且只指定一个 `revision_id` 或 `baseline_id`。Baseline 解析到冻结时的原始 revision；服务不会跨项目猜测同名对象。

比较对象是该 revision 中的 `CoreEntity` 与 `SourceRecord`。差异按 `entity_type + business_id` 对齐，区分 Added、Removed、Modified，并记录变更字段与规范化摘要。结果使用稳定排序和 `change-impact/v1` 规范化规则生成 `preview_hash`。

## 影响传播

- 直接变化对象标记为 `Direct`、距离为 0；
- 显式依赖按工程方向传播；
- `DERIVED_FROM_SOURCE` 与 `DERIVED_FROM` 从来源/派生结果传播到依赖对象；
- `PRODUCED` 从生产者传播到产物；
- TraceLink 保守地双向连接两端，但报告保留经过的 TraceLink 业务标识；
- 传播结果记录距离、触发对象和经过的追踪链，不把“可能受影响”自动写成人工结论。

## HTTP 接口

- `POST /api/v2/impact-assessments/preview`：预览确定性差异与影响集，不写库；
- `POST /api/v2/impact-assessments`：保存 ChangeImpactAssessment 与 ImpactItem；
- `GET /api/v2/impact-assessments?project_id=&revision_id=&assessment_id=`：读取评估、影响项和人工作出决定；
- `POST /api/v2/impact-assessments/dispositions`：记录 Accept、Reanalyze、Waive 或 Defer；
- `GET /api/v2/impact-assessments/work-product`：生成 profile 驱动的追踪矩阵、缺口和工作产品；
- `GET /api/v2/impact-assessments/work-product/export`：导出相同内容的 JSON 文件。

所有写入都要求 `actor`、`command_id`、`expected_revision_version`，经过 RevisionUnitOfWork，并产生 AuditEvent。同一命令和相同请求安全重放；同一命令但请求内容不同返回 `COMMAND_PAYLOAD_MISMATCH`。Defer 必须指定期限，Waive 必须给出豁免依据。

## 工作产品边界

工作产品根据 StandardProfileVersion 的标准引用生成 DO-326A 和 DO-356A 区段；只有 profile 显式启用 F3532 adapter 时才生成 F3532 兼容附录。它包含：

- profile、revision/baseline 与生成器版本；
- 追踪矩阵中的来源、评审和覆盖状态；
- 缺少来源、未评审结论、stale 分析、未追踪实体和未处置影响；
- 已保存的影响评估与人工作出决定；
- 内容摘要以及 Draft/Reviewable 状态。

每条非空工作产品结论都列出参与计算的 TraceLink 业务标识；没有追踪矩阵时不生成结论。`Reviewable` 只表示已达到平台定义的送审条件，不表示符合性成立。导出固定包含如下责任边界：覆盖率和评审状态不构成符合性判定或适航批准。

## 历史可解析性

使用 `baseline_id` 生成报告时，实体、来源、profile 和追踪链均从 Baseline 的原始 revision 读取。后续 revision 的写入、影响评估和处置不会修改历史 baseline 内容。
