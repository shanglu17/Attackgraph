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
| P1.2 | Project/Model/Revision/Baseline 最小核心 | 两项目可复用业务编号；Approved Baseline 无更新入口 | Ready |
| P1.3 | 遗留数据挂接与来源盘点 | 现有全局数据可 dry-run 挂接到默认遗留项目；冲突生成 MigrationIssue | Planned |
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
