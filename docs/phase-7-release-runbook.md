# Phase 7 发布与回退手册

## 1. 使用范围

本手册用于 DO-326A/DO-356A 通用分支的技术发布候选验收。默认输入仅包括已授权的 DO-356A Appendix D 项目及仓库内通用/脱敏样例；不得扫描或恢复被忽略的合作项目资料。

## 2. 发布前检查

1. 将 Neo4j 数据卷或项目级恢复快照保存到受控位置，并记录外部 backup id；
2. 确认 `.env` 使用部署密钥，不能直接使用 `.env.example` 的示例值；
3. 执行迁移计划和 checksum 核验：

```powershell
npm run db:migrate -- plan
npm run db:migrate -- verify
```

4. 只读检查 Appendix D 挂接状态：

```powershell
npm run legacy:attach -- dry-run --dataset do356a-appendix-d
npm run legacy:attach -- verify --dataset do356a-appendix-d
```

5. 生成技术证据，不写发布记录：

```powershell
npm run phase7:acceptance -- verify --actor <technical-runner> --release-id <release-id> --output <controlled-path>\phase7-evidence.json
```

任何检查为 `fail` 时停止，不得通过修改 Golden 数量来消除差异；应先定位数据变更、scope 错误或 MigrationIssue。

## 3. 记录技术验收

只有在证据 `overall_status=passed` 后执行：

```powershell
npm run phase7:acceptance -- record --actor <technical-runner> --command-id <unique-command-id> --release-id <release-id> --output <controlled-path>\phase7-record.json
```

同一 command id 和 release id 的重放返回原记录；任一标识被不同证据复用时拒绝。记录包含 `human_release_authorization=not_asserted`，组织放行应在外部受控流程中完成。

## 4. 切换状态

- 新写入仅允许 project/revision-scoped application service；
- `/admin/seed/*`、旧 Excel commit、旧 changeset commit 等全局 GraphVersion 写入继续返回 `409 LEGACY_GLOBAL_WRITE_QUARANTINED`；
- 旧读取仍通过明确的 compatibility scope 服务现有调用方；不得根据当前数据库内容猜测 project/revision；
- 物理删除旧字段或兼容读取不属于本次切换。

## 5. 回退

1. 停止新写请求，保留日志和失败证据；
2. 若只是应用发布失败，回退应用版本，数据库保持向前兼容；
3. 若数据不变量被破坏，恢复到独立 Neo4j 实例，先运行 `db:migrate -- verify` 和 `phase7:acceptance -- verify`；
4. 比较 backup semantic hash、Golden 数量和 MigrationIssue，再决定是否切回；
5. 不得通过删除新数据、重跑全局 seed 或修改 MigrationRecord checksum 伪造回退。

项目恢复演练会创建临时项目，持久化临时快照，执行真实删除和恢复，比较语义 SHA-256 后清理临时项目。它不会删除目标 Appendix D 项目。

## 6. 已知限制

- 浏览器本地解析的 Excel/DOCX 继续受 Phase 6 文件类型与大小限制；只接受可信来源文件；
- API key 适合受控部署，不替代企业身份提供方和外部密钥服务；
- 兼容读取仍存在，计划在至少一个稳定版本后通过单独、可回退的破坏性迁移移除；
- 平台输出是工程辅助证据，不是合规声明或适航批准。
