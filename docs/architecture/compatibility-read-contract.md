# 兼容读取与遗留写隔离契约

- 状态：Implemented（P1.6）
- 日期：2026-10-10
- 依据：ADR-0003、ADR-0005、作用域身份契约

## 1. 目标

P1.6 在不改变旧读取响应 DTO 的前提下，阻止旧 API 对多个项目执行全库查询。兼容层只负责把旧读取绑定到一个明确的 Project/Revision；它不是 Phase 2 scoped command API 的替代品。

## 2. Scope 输入与解析

调用方可以通过以下任一方式同时提供 scope：

- 查询参数：`project_id`、`revision_id`；
- 请求头：`X-Project-Id`、`X-Revision-Id`。

两者必须成对出现。解析器验证 Project → Model → Revision 关系以及 `revision.project_id`，成功后得到唯一的 `project_id`、`model_id` 和 `revision_id`。
若请求头与查询参数同时提供但值不同，请求返回 400，不按任一来源静默覆盖。

未提供 scope 的旧客户端仅使用固定 compatibility projection：

```text
dataset_kind = do356a-appendix-d
project.business_id = legacy-do356a-appendix-d
model.business_id = appendix-d-ams-model
revision.business_id = legacy-import-r1
```

默认对象不存在或不唯一时请求失败。禁止退回“数据库中第一个项目”“唯一 revision”、相同名称或相同旧业务编号。

## 3. Scope 输出

成功的兼容读取保留原 JSON 响应，并增加：

- `X-ASTRA-Project-Id`；
- `X-ASTRA-Revision-Id`；
- `X-ASTRA-Scope-Source: explicit | legacy-default`。

这样旧前端不需要修改 DTO，新客户端和审计日志仍可识别实际读取范围。

## 4. 受保护读取

以下数据全部按 `project_id + revision_id` 过滤：

- 图快照中的 Asset、Edge、ThreatPoint、Function、Boundary、Interface、SDF、FP 和 DO-326A link；
- 章节 4 报表和 F3532 03 生成事实；
- FHA/FailureCondition 上下文、F3532 04 TC/TS 报告；
- AttackPath 与建模结果导出；
- StandardMapping；
- 旧 CommitAudit 列表。

StandardClause、ArtifactType、ArtifactField、PipelineStage 和 StandardKnowledgeBase 是共享参考知识，继续按标准版本全局读取。

## 5. 遗留写隔离

以下旧端点仍使用全局 GraphVersion 或无 scope 的 MERGE/DELETE，P1.6 起返回 HTTP 409 和稳定错误码 `LEGACY_GLOBAL_WRITE_QUARANTINED`：

- graph ChangeSet validate/commit；
- Excel、CXF、F3532 input、FHA commit；
- sample/generic seed；
- AttackPath persist、FunctionPropagation run；
- F3532 03/04 commit 或隐式写入式 generation；
- DO-326A link 创建/评审；
- StandardMapping 创建。
- `npm run seed:sample`、`npm run seed:generic` 和 `npm run clear` 全库 CLI。

preview、只读分析、报告和导出继续可用。Phase 2 必须以 `RevisionUnitOfWork`、expected revision version、command id 和 AuditEvent 为基础提供替代命令；不得简单解除本隔离清单。

## 6. 错误语义

| 情况 | HTTP | 行为 |
| --- | --- | --- |
| project/revision 仅提供一个 | 400 | 拒绝，不推断另一个字段 |
| scope 不存在或关系不匹配 | 404 | 拒绝，不回退默认项目 |
| 调用已隔离旧写入口 | 409 | 返回 `LEGACY_GLOBAL_WRITE_QUARANTINED`，不写数据库 |
| 默认遗留 workspace 不存在 | 404 | 拒绝，不选择其他 Project |

## 7. 回归要求

- 用两个包含相同旧业务编号的项目验证所有兼容投影；
- 错误 scope 的结果必须为空或显式失败，不能返回另一项目对象；
- 隔离写入口调用前后数据库节点数保持一致；
- FeatureRule/path trace 继续验证显式 scope、input hash、mapping hash 和截断诊断；
- 每次 Phase 1 数据迁移变更均需执行独立 dump 恢复与 migration replay。
