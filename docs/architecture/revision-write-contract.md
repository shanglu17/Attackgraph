# Revision 范围写入契约

- 状态：Accepted（P1.4）
- 日期：2026-10-09
- 适用范围：P1.4 之后新增的业务写入

## 1. 强制入口

所有新增的 Revision 内容写入必须通过 `RevisionUnitOfWork`。调用方必须提供：

- `project_id`；
- `revision_id`；
- `expected_revision_version`；
- `actor`；
- `command_id`；
- 稳定 `event_type`；
- 以 `/vN` 结尾的命令专用 `request_canonicalizer`；
- 参与请求摘要计算的语义 payload；
- 可审阅的变更摘要。

不得为新增能力读取或更新全局 `GraphVersion`，也不得直接创建自己的 AuditEvent 来模拟受控写入。

## 2. 原子事务顺序

`RevisionUnitOfWork` 在一个 Neo4j 写事务内按以下顺序执行：

1. 按 command id 查询既有 AuditEvent；
2. 校验事件类型、request hash、摘要算法和 canonicalizer；
3. 对目标 Revision 获取写锁；
4. 在锁内重新校验 Project 归属、`Draft` 状态和 expected version；
5. 将 Revision version 单调增加 1；
6. 执行业务 mutation；
7. 写入包含版本前后值、请求指纹、结果摘要和结果回执的 AuditEvent；
8. 一并提交版本、业务变更和审计事件。

任一步失败时整笔回滚，包括已经预占的 Revision version。两个并发命令使用相同 expected version 时只能有一个成功。

## 3. 幂等与回执

- command id 不参与请求摘要，因此同一语义请求可用原 command id 重放；
- actor、project、revision、expected version、event type 和语义 payload 均参与摘要；
- 相同 command id、事件类型和规范请求摘要返回原结果，不再次调用 mutation；
- 相同 command id 对应不同事件或不同摘要时拒绝；
- 缺少兼容指纹或结果字段的历史回执不可重放；
- payload 只能使用确定性的 JSON 值；非有限数字、函数、`undefined` 等值不得进入命令契约；
- 数组默认保持顺序。只有调用方的命令专用 canonicalizer 明确声明为集合的字段才可排序或去重。

## 4. Mutation 开发约束

- mutation 只能使用 unit of work 提供的 transaction，不得再打开 session 或嵌套写事务；
- 所有创建、匹配、更新、删除和关系解析必须使用回调上下文中的 project/revision scope；
- mutation 返回值必须是可 JSON 序列化的最小回执，不得返回 Neo4j Node、Relationship、Integer 或 driver 对象；
- mutation 不创建 AuditEvent、不直接修改 Revision version、不提交事务；
- 业务实体的字段校验、引用完整性和跨范围检查在进入 mutation 前完成，必要的最终存在性检查仍在同一事务内完成；
- 关闭的 Revision 不允许以新命令写入；应从受控 baseline/revision 派生新的 Draft Revision。

## 5. 结构化失败语义

| 失败 | 语义 |
| --- | --- |
| `RevisionWriteScopeError` | Revision 不存在或不属于指定 Project |
| `RevisionNotWritableError` | Revision 不是 Draft |
| `RevisionWriteConflictError` | expected version 已过期 |
| `CommandReuseError` | command id 已用于另一事件类型 |
| `CommandPayloadMismatchError` | command id 已用于不同语义请求 |
| `CommandReceiptUnverifiableError` | 历史回执缺少可验证指纹或结果 |

HTTP/API 层在 Phase 2 建立版本化契约时负责把这些错误映射为稳定错误码；repository 不拼装 HTTP 响应。

## 6. Legacy 隔离清单

下列入口在 P1.4 后只允许维持现有兼容行为，不得成为新增功能的依赖：

- `GraphRepository.commitChangeSet()` 与 `getGraphVersion()`；
- 现有单表/CXF/F3532 导入对全局 GraphChangeSet 的提交；
- F3532 03/04、AttackPath、DO326A_Link 和标准知识仓储中的专用直写；
- sample/generic seed 的全库 reset；
- `CommitAudit` 作为旧 GraphChangeSet 的审计记录。

P1.5 已完成内部 UUID 与项目内业务编号约束切换；P1.6 已完成兼容读取 scope 接入，并将仍绕过本契约的 legacy 写端点隔离为 `LEGACY_GLOBAL_WRITE_QUARANTINED`。Phase 2 将导入统一为 parse → preview → scoped commit，并以版本化命令替代这些端点；不得直接解除隔离。

## 7. 代码评审检查

- 是否显式传入 project/revision/expected version/actor/command id？
- 是否使用命令专用且版本化的 canonicalizer？
- payload 是否覆盖所有会改变业务结果的字段？
- 是否只在 unit of work 的 transaction 中写库？
- 所有查找与关系两端是否均限制在同一 project/revision？
- 失败时业务变化、Revision version 和 AuditEvent 是否共同回滚？
- 是否具有同载荷重放、异载荷拒绝、stale version、跨项目、Closed Revision 和并发测试？
