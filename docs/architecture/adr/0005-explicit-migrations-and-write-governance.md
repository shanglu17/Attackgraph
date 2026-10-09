# ADR-0005：显式迁移与写入治理

- 状态：Accepted
- 日期：2026-10-08

## 背景

当前启动流程会创建/删除约束并对重复 AttackPath 执行删除；seed 会清空全库；F3532 04 会全局替换 TC/TS。部分写入经过 GraphChangeSet，部分直接进入专用仓储，版本和审计保障不一致。

## 决策

### 显式迁移

- 数据结构变化通过有编号、可审计、可重复的迁移执行；
- 应用启动只检查 schema compatibility，不执行破坏性迁移；
- 每次迁移写入 MigrationRecord；
- destructive migration 必须要求备份标识和显式确认；
- 迁移提供 dry-run、precondition、postcondition 和恢复说明。

### 统一写入入口

所有业务写入经过 application service/unit of work，并强制：

- project scope；
- revision scope；
- expected version；
- actor；
- command/idempotency id；
- 版本化的命令专用 canonicalizer 和规范请求摘要；
- validation；
- transaction；
- AuditEvent。

adapter、导入器和生成器只能提交命令或 change set，不能持有全局删除权限。

幂等重放只对“相同 command id、相同事件类型、相同规范请求摘要”成立。AuditEvent 必须记录请求摘要、摘要算法和 canonicalizer id/version；相同 command id 的请求语义发生变化时必须拒绝，不得返回第一次调用的结果。缺少这些指纹字段的历史回执不可验证，调用方必须使用新的 command id，不能把它当作安全重放。

Revision 内容写入遵循 [Revision 范围写入契约](../revision-write-contract.md)：在同一事务内获取 Revision 写锁、重新校验 scope/status/expected version、递增 Revision version、执行业务 mutation 并写入 AuditEvent。全局 GraphVersion 只作为遗留兼容入口保留，不得被新增能力依赖。

### 删除规则

- 业务删除默认使用 archive/retire；
- 确需物理删除时必须先解析确切 project/revision 范围；
- 禁止业务路径执行无项目条件的 `MATCH (n) DETACH DELETE n`；
- seed/demo reset 必须使用隔离的 demo project，不得清空共享数据库；
- 批量替换必须以 generator scope、revision 和 expected version 限定。

## 结果

- 部署启动不会改变业务数据；
- 所有写操作具有一致的并发和审计语义；
- 迁移失败可以定位、停止并从备份/检查点恢复；
- F3532 和后续 adapter 不能绕开核心治理。

## 未采用方案

### 继续通过 `ensureConstraints()` 演进生产 schema

未采用。它适合最初原型，但不能安全表达数据回填、约束切换、失败恢复和多版本兼容。

### 保留专用仓储的全局 replace 方法

未采用。即使使用事务，也缺少项目范围、旧结果保留和并发控制。

## 验收约束

- 应用启动路径不包含业务 `DELETE`；
- 写 API 没有 project/revision scope 时拒绝执行；
- 相同 command id 与相同规范请求重放时不产生重复业务结果；
- 相同 command id 对应不同事件类型或不同规范请求时明确拒绝；
- command receipt 记录请求摘要、摘要算法和 canonicalizer id/version，缺少指纹的历史回执不可重放；
- stale expected version 返回结构化冲突；
- 每次成功写入都有对应 AuditEvent；
- 每个迁移都有可自动检查的后置条件。
