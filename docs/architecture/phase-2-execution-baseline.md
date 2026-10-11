# Phase 2 执行基线：标准无关系统模型与契约

- 状态：Complete
- 完成日期：2026-10-10
- 分支：`Airworthiness-326A/356A`
- 前置：Phase 1 Complete
- 下一门槛：VG-1 Ready

## 1. 已交付能力

1. 新增共享契约 workspace `@attackgraph/contracts`，同时供后端 Zod 运行时校验和前端 TypeScript API 使用。
2. 建立通用 `Asset`、`Function`、`Interface`、`DataFlow`、`SecurityBoundary`、`ExternalEntity`。
3. 建立 `SourceRecord`、`EvidenceRecord`、`TraceLink`，并为所有导入实体保留字段级 `source_locator`。
4. 新增 `/api/v2/system-model` 的 preview、scoped commit 和 read API。
5. 所有提交经过 `RevisionUnitOfWork`，继承 project/revision scope、乐观并发、command idempotency、request hash 和 `AuditEvent`。
6. v2 导入使用 create-only 语义：重复业务身份或悬空引用导致整批回滚，不发生静默 last-write-wins。
7. 新增迁移 `0007_system_model_core` 与 `0008_system_model_element_identity`，为所有通用实体和来源记录建立内部 UUID 与 project/revision 范围业务身份约束。
8. F3532 代码继续作为独立兼容实现存在；Phase 2 核心仓储、应用服务和 v2 路由无 F3532 import。

## 2. 模块边界

| 层 | 实现 | 责任 |
| --- | --- | --- |
| 共享核心契约 | `packages/contracts` | 核心术语、运行时 schema、前后端共享类型 |
| application service | `systemModelImportService.ts` | 预览、引用校验、确定性摘要、提交编排 |
| infrastructure | `systemModelRepository.ts` | Neo4j scoped read/write 和关系持久化 |
| API adapter | `routes/systemModel.ts` | v2 HTTP、稳定错误码、契约解析 |
| compatibility adapter | 既有 legacy/F3532 repositories/routes | 保留旧读取投影；旧全局写继续隔离 |

## 3. 数据不变量

- 每个通用实体具有内部 UUID、`project_id`、`revision_id`、`business_id` 和 `entity_type`。
- 业务身份只在 `(label, project_id, revision_id, business_id)` 内唯一。
- 所有语义引用只能解析到同一 project/revision。
- 所有导入实体都有且只有本次导入来源的 `DERIVED_FROM_SOURCE` 关系。
- TraceLink 的 source/target 均显式记录类型和业务编号，并由图关系连接到真实端点。
- 导入成功只递增一次 revision version；失败事务不留下部分节点。

## 4. 验收结果

| 检查 | 结果 |
| --- | --- |
| 共享契约构建 | 通过 |
| 后端 TypeScript 构建 | 通过 |
| 前端 TypeScript/Vite 构建 | 通过；仅保留既有 chunk-size warning |
| 后端单元测试 | 67/67 通过 |
| Neo4j 集成测试 | 11/11 通过 |
| 迁移 0001–0008 verify | 全部通过 |
| 通用建模且无 F3532 adapter import | 自动化边界测试通过 |
| SourceRecord/字段定位 | 真实 Neo4j 集成测试通过 |
| 幂等重放/请求体错配 | 真实 Neo4j 集成测试通过 |

集成测试使用临时 project/revision，并在完成后清理；未修改 Appendix D/F3532 现有项目数据。迁移 0007、0008 均为非破坏性约束迁移，已应用到当前开发数据库。

## 5. Phase 2 出口判定

- **核心脱离 F3532：通过。** 通用核心构建与测试不引用 F3532 adapter。
- **通用 Asset 无专用字段：通过。** 仅要求通用 `business_id/name/category`。
- **导入实体追溯来源：通过。** 所有实体建立 `DERIVED_FROM_SOURCE` 并保存定位 JSON。
- **批量写入不使用全局 ID/LWW：通过。** v2 在 revision scope 内 create-only；旧 SDF 全局写仍被 P1.6 隔离。

Phase 2 完成。下一步只能进入 VG-1 的最小纵向链路，不应直接铺开 Phase 3 的完整领域广度。

## 6. 保留问题

Phase 1 登记的 3 条 legacy provenance `MigrationIssue` 仍保持 Open：现有 Appendix D/F3532 节点缺少可验证的来源定位。Phase 2 已提供 `SourceRecord` 和字段级定位承载机制，但不会用文件名、节点名称或个人路径猜测来源，也不会为通过验收而伪造溯源。VG-1 若选用这些遗留节点，必须先补充经确认的来源记录；若使用 v2 受控示例导入，则不受这些遗留问题影响。
