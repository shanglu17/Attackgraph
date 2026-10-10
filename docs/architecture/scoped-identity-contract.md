# 作用域身份契约

- 状态：Implemented（P1.5）
- 日期：2026-10-09
- 依据：ADR-0003、ADR-0005

## 1. 目的

ASTRA 不再把 `asset_id`、`TC.1`、`SI.1` 等用户可读编号当作全库主键。内部引用使用不可变 UUID；用户可读编号只在明确的项目与 revision 范围内解释。这样不同项目可以使用相同工程编号，同时不牺牲引用稳定性和迁移可追溯性。

## 2. 字段职责

| 字段 | 语义 | 规则 |
| --- | --- | --- |
| `id` | 系统内部身份 | UUID、不可变、全局唯一；新关系和持久引用优先保存它 |
| `business_id` | 用户可读工程编号 | 普通实体在 project/revision 内唯一；不可脱离 scope 解析 |
| `legacy_id` | 迁移反查编号 | 保留旧系统编号，不作为新主键，不用于无 scope 查询 |
| 原 legacy key | 旧结构兼容字段 | 如 `asset_id`、`edge_id`、`tc_id`；暂时保留，后续通过 compatibility projection 返回 |
| `project_id` / `revision_id` | 身份解释范围 | 所有工程实体和工程关系必填 |

`AttackPath` 是分析运行结果，其业务唯一范围为 `(project_id, revision_id, analysis_batch_id, business_id)`；相同路径编号可以出现在不同分析运行中。

## 3. 约束规则

每类已登记节点具有两个约束：

1. `id` 全局唯一；
2. scope 与 `business_id` 组合唯一。

`ASSET_EDGE` 同样具有 UUID 唯一约束和 `(project_id, revision_id, business_id)` 组合唯一约束。旧的 `asset_unique`、`edge_unique`、`path_unique` 等全局业务编号约束由显式迁移退出，不能由应用启动重新创建。

标准知识库中的 Clause、ArtifactType、ArtifactField、PipelineStage 和 KnowledgeBase 属于共享参考知识，不是项目工程实体，继续使用其标准库自然键约束。`StandardMapping` 属于工程映射，使用项目/revision 作用域身份。

## 4. 兼容解析

兼容仓储解析旧编号时必须提供：

- `project_id`；
- `revision_id`；
- 实体类型；
- 旧编号、`business_id` 或内部 UUID；
- 查询 AttackPath 时额外提供 `analysis_batch_id`。

解析只在上述范围内进行，成功后返回规范内部 UUID。零结果、同范围多结果、未知类型或缺少 AttackPath 运行范围均显式失败；禁止通过名称相同、编号相同或全库搜索猜测对象。

## 5. 写入和迁移边界

- 新业务写入通过 `RevisionUnitOfWork`，在同一事务中处理 scope、revision version、命令幂等和 AuditEvent；
- schema 变更只通过显式 migration CLI；应用启动只做只读兼容性检查；
- 删除旧全局约束前必须先建立新约束、验证所有实体身份，并提供可验证备份；
- P1.5 保留旧字段和响应；P1.6 已完成旧读取入口的 scope 接入，并隔离仍依赖全局身份的旧写端点；
- identity 回填不能自动补造来源证据、评审决定或标准语义。
