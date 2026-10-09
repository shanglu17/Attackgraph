# Phase 1 执行计划：项目化与写入治理基础

- 状态：In Progress
- 开始日期：2026-10-09
- 前置基线：Phase 0 Accepted，代码基线 `7574362`

## 1. 目标

Phase 1 不扩展新的适航分析功能，先建立后续通用化所需的安全承载层：显式迁移、项目/模型/修订/基线、项目范围写入、稳定内部身份、兼容读取和回归保护。

## 2. 实施批次

| 批次 | 内容 | 主要出口条件 | 状态 |
| --- | --- | --- | --- |
| P1.1 | 迁移账本、显式 CLI、跨平台测试入口 | dry-run/status 不写库；apply 有 actor/idempotency/audit 状态；测试入口跨平台 | Complete |
| P1.2 | Project/Model/Revision/Baseline 最小核心 | 两项目可复用业务编号；Approved Baseline 无更新入口 | Complete |
| P1.3 | 遗留数据挂接与来源盘点 | 现有全局数据可 dry-run 挂接到默认遗留项目；冲突生成 MigrationIssue | Ready |
| P1.4 | Revision 版本与统一写入入口 | 新写入强制 project/revision/expected-version/command/audit | Planned |
| P1.5 | 内部 UUID 与项目内业务编号 | 全局业务 ID 约束退出；兼容 API 保留 legacy id | Planned |
| P1.6 | 兼容读取、隔离与回归验收 | F3532/FeatureRule 回归、多项目隔离、迁移/回滚验证通过 | Planned |

## 3. P1.1 范围

### 实施

- 新增只在显式命令下运行的迁移注册表和 MigrationRecord 账本；
- 支持 `status`、`plan`、`apply`、`verify`；
- 每个迁移具有稳定 checksum、风险等级、可读步骤和机器验证；
- destructive migration 必须提供显式开关和 backup id；
- 失败迁移保留失败状态，不自动跳过或继续；
- 应用启动暂时维持现状，但本批次不得新增任何启动时迁移；
- 修复 `PH1-TOOLING-001` 前端测试命令的 Windows glob 问题。

### 不实施

- 不创建 Project/Model/Revision/Baseline 业务数据；
- 不迁移现有 Neo4j 节点和关系；
- 不删除或替换现有 GraphVersion；
- 不改变现有 API、F3532 生成或 FeatureRule 判定；
- 不把当前 `ensureConstraints()` 立即移出启动路径；该切换在迁移覆盖现有 schema 后单独完成。

## 4. P1.1 验收

- `status`、`plan` 和 `verify` 不产生业务写入；
- `apply` 缺少 actor 时拒绝；
- destructive migration 缺少确认或 backup id 时拒绝；
- 已应用迁移 checksum 改变时拒绝继续；
- apply 失败写入失败状态并停止后续迁移；
- migration runner 单元测试、后端测试、前端测试和完整构建通过；
- 所有 Phase 1 代码变更不依赖 F3532 配置。

## 5. P1.1 操作入口

```powershell
npm run db:migrate -- status
npm run db:migrate -- plan
npm run db:migrate -- apply --actor <actor-id>
npm run db:migrate -- verify
```

`apply` 是唯一会写入 MigrationRecord 或执行迁移的入口。P1.1 首个迁移只建立 MigrationRecord 唯一约束，不触碰业务节点。

## 6. P1.1 完成记录（2026-10-09）

- `0001_migration_ledger` 已通过显式 CLI 应用；
- MigrationRecord checksum：`f54436456b0c99585771b835fc08598b028ceba60a63f38c8cf1d030a52cd5fa`；
- 后置验证通过，唯一约束存在；
- 后端测试 47/47 通过，其中迁移 runner 新增 4 项单元测试；
- 前端测试 5/5 通过，`PH1-TOOLING-001` 已关闭；
- 后端和前端完整构建通过；
- 前端既有大 chunk 告警未增加，仍按 Phase 6 技术债处理；
- 本批次没有创建或修改 Project、Model、Revision、Baseline 或其他业务节点。

## 7. P1.2 范围

### 实施

- 建立独立于遗留图类型的 Project Governance 领域类型：Project、Model、Revision、Baseline 和 StandardProfileVersion；
- 通过单一事务原子创建 Project、Model、Draft Revision 和绑定的 StandardProfileVersion；
- 使用系统 UUID 作为内部身份，并对 Model、Revision、Baseline 和 StandardProfileVersion 建立带 project/model 上下文的业务编号约束；
- 新增专用 `freezeRevision` 命令，将 Draft Revision 关闭并产生内容摘要固定的 Frozen Baseline；
- 新增专用 `approveBaseline` 命令，只允许 Frozen Baseline 进入 Approved 状态；
- 所有成功命令写入带 actor、command id、subject version 和结果引用的 AuditEvent；
- 相同 command id 重放既有结果，不产生重复业务节点或审计事件；
- 新增非破坏性迁移 `0002_governance_core_constraints`，由 P1.1 显式迁移入口执行。

### 边界

- Baseline 的快照身份、来源 revision、standard profile version 和 content hash 不提供更新方法；批准命令只改变生命周期与批准审计元数据；
- 本批次不把遗留图数据挂接到新 Revision，该工作属于 P1.3；
- 本批次不替换全局 GraphVersion、旧仓储或旧 API，该工作属于 P1.4-P1.6；
- 本批次不提前暴露 HTTP API；版本化 API 和共享契约仍按 Phase 2 实施。

## 8. P1.2 验收

- 两个不同 Project 可各自创建相同 Model `business_id`，内部 UUID 保持不同；
- Revision 必须携带 project/model/profile scope 和单调整数 version；
- freeze 要求 Draft 状态和 expected revision version，成功后 Revision 进入 Closed；
- Baseline 创建时固定来源 Revision、StandardProfileVersion 和 SHA-256 content hash；
- approve 要求 Frozen 状态和 expected baseline version；
- Approved Baseline 不存在通用更新入口，再次使用新命令批准会返回冲突；
- 相同 command id 的 create/freeze/approve 重放不产生重复结果；
- 每次首次成功写入产生且只产生一个 AuditEvent；
- 迁移后置检查、后端回归、Neo4j 集成测试、前端回归和完整构建通过。

## 9. P1.2 完成记录（2026-10-09）

- `0002_governance_core_constraints` 已通过显式 CLI 应用并验证；
- MigrationRecord checksum：`43e744327580d58f5d26c7c3491a78493a911622811ee0dac5d9f0b7e43a3452`；
- 新增 12 个治理核心唯一约束，均通过自动后置检查；
- 后端单元与回归测试共 50 项断言通过；
- Neo4j 集成测试 2/2 通过，其中治理核心测试覆盖跨项目业务编号复用、幂等重放、冻结、批准和 Approved 状态保护；
- 前端回归测试 5/5 通过，前后端完整构建通过；
- 集成测试创建的数据已按测试 Project 范围清理；迁移约束和 MigrationRecord 保留；
- 前端既有大 chunk 告警未增加，仍按 Phase 6 技术债处理。
