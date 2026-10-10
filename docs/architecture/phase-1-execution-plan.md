# Phase 1 执行计划：项目化与写入治理基础

- 状态：Complete
- 开始日期：2026-10-09
- 完成日期：2026-10-10
- 前置基线：Phase 0 Accepted，代码基线 `7574362`

## 1. 目标

Phase 1 不扩展新的适航分析功能，先建立后续通用化所需的安全承载层：显式迁移、项目/模型/修订/基线、项目范围写入、稳定内部身份、兼容读取和回归保护。

## 2. 实施批次

| 批次 | 内容 | 主要出口条件 | 状态 |
| --- | --- | --- | --- |
| P1.1 | 迁移账本、显式 CLI、跨平台测试入口 | dry-run/status 不写库；apply 有 actor/idempotency/audit 状态；测试入口跨平台 | Complete |
| P1.2 | Project/Model/Revision/Baseline 最小核心 | 两项目可复用业务编号；Approved Baseline 无更新入口 | Complete |
| P1.3 | 遗留数据挂接与来源盘点 | 现有全局数据可 dry-run 挂接到默认遗留项目；冲突生成 MigrationIssue | Complete |
| P1.4 | Revision 版本与统一写入入口 | 新写入强制 project/revision/expected-version/command/audit | Complete |
| P1.5 | 内部 UUID 与项目内业务编号 | 全局业务 ID 约束退出；兼容 API 保留 legacy id | Complete |
| P1.6 | 兼容读取、隔离与回归验收 | F3532/FeatureRule 回归、多项目隔离、迁移/回滚验证通过 | Complete |

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
- 相同 command id 且规范请求一致的 create/freeze/approve 重放不产生重复结果；
- 相同 command id 对应不同事件或不同规范请求时拒绝；AuditEvent 记录请求摘要、SHA-256 算法和命令专用 canonicalizer id/version；
- 缺少请求指纹的历史 command receipt 不可验证，必须换用新的 command id；
- 每次首次成功写入产生且只产生一个 AuditEvent；
- 迁移后置检查、后端回归、Neo4j 集成测试、前端回归和完整构建通过。

## 9. P1.2 完成记录（2026-10-09）

- `0002_governance_core_constraints` 已通过显式 CLI 应用并验证；
- MigrationRecord checksum：`43e744327580d58f5d26c7c3491a78493a911622811ee0dac5d9f0b7e43a3452`；
- 新增 12 个治理核心唯一约束，均通过自动后置检查；
- 后端单元与回归测试共 56 项通过，其中命令指纹测试覆盖字段顺序、集合规范化、身份、版本和批准理由；
- Neo4j 集成测试 2/2 通过，其中治理核心测试覆盖跨项目业务编号复用、同载荷幂等重放、异载荷拒绝、旧回执拒绝、冻结、批准和 Approved 状态保护；
- 前端回归测试 5/5 通过，前后端完整构建通过；
- 集成测试创建的数据已按测试 Project 范围清理；迁移约束和 MigrationRecord 保留；
- 前端既有大 chunk 告警未增加，仍按 Phase 6 技术债处理。

## 10. P1.3 范围

### 实施

- 新增只读 `dry-run`，盘点已知遗留标签、数量、scope、旧业务编号、来源定位和数据集分类；
- 默认使用中性的 `generic-legacy` 上下文，不再把未分类数据预设为某个合作项目；
- 通过显式 Appendix D 标记识别仓库示例；若使用默认上下文，计划必须以 `DATASET_CLASSIFICATION_MISMATCH` 阻止执行；
- 应用命令必须显式指定数据集、actor 和 command id；
- 建立 LegacyAttachmentRun、MigrationIssue 和 AuditEvent，重复 command id 只重放既有结果；
- 对可安全挂接的已知实体增加内部 UUID、project/model/revision scope、legacy id/label 和 Revision 成员关系；
- 将全局 GraphVersion 原值保留为 Revision 的 `legacy_graph_version`，不删除原节点；
- 对未知 schema、scope 冲突、重复/缺失旧 ID 和缺失来源定位生成结构化诊断；
- 新增非破坏性迁移 `0003_legacy_attachment_support`，只创建运行账本和 MigrationIssue 约束。

### 边界

- 本批次只挂接和盘点，不执行 Asset/DataFlow/Threat/TraceLink 的语义归一化；
- 来源缺失保持为 MigrationIssue，不通过节点名称、文件名或个人绝对路径猜测；SourceRecord 在 Phase 2 建立；
- 已忽略的 ZG-ONE/F3532 保密资料不自动恢复、不扫描且不作为 P1.3 输入；未来如需兼容回归，必须由资料责任人明确提供授权或脱敏样例；
- 不删除旧字段、旧节点或旧关系，不改变旧 API 的响应结构；
- 完整遗留切换、双读和旧写入关闭仍属于 Phase 7。

## 11. P1.3 操作入口

```powershell
# 默认中性上下文；若检测到 Appendix D 会阻止执行
npm run legacy:attach -- dry-run

# 显式盘点和挂接 Appendix D 示例
npm run legacy:attach -- dry-run --dataset do356a-appendix-d
npm run legacy:attach -- apply --dataset do356a-appendix-d --actor <actor-id> --command-id <command-id>
npm run legacy:attach -- verify --dataset do356a-appendix-d
```

支持的数据集配置为 `generic-legacy` 和 `do356a-appendix-d`。`apply` 不接受隐式默认数据集，避免把混合数据错误归入一个项目。

## 12. P1.3 验收

- dry-run 不写数据库，并输出机器可读 inventory、issue、plan hash 和 blocked 状态；
- Appendix D 数据使用默认上下文时被阻止，显式选择独立项目后才能执行；
- 未知 schema 阻止执行，已知但不可安全覆盖的 scope 冲突生成 MigrationIssue；
- 重复/缺失旧业务编号和缺失来源定位不被静默修复；
- 每个已挂接遗留实体具有有效内部 UUID 和唯一 project/model/revision scope；
- 每个已挂接实体存在到目标 Revision 的成员关系；
- 关系两端不存在跨项目 scope；
- 重复 command id 不产生重复项目、关系、问题或审计事件；
- 不删除或覆盖遗留业务字段，迁移约束具有自动后置检查。

## 13. P1.3 完成记录（2026-10-09）

- `0003_legacy_attachment_support` 已通过显式 CLI 应用并验证；
- MigrationRecord checksum：`d4f59f9453dca09cbd01a8f2bb8e3d7ed9f56e74c4bf6573a2f6348e646923c3`；
- 默认 dry-run 正确识别当前图为 Appendix D，并以 1 条阻塞性分类问题拒绝挂接到中性遗留项目；
- 显式 Appendix D dry-run 识别 27 个可挂接实体、0 个 scope 冲突；
- 已创建独立 Project、Model、Draft Revision 和 Draft StandardProfileVersion，并非破坏性挂接 27 个遗留实体；
- 挂接运行 id：`9afa1cb3-6010-4593-8201-27041d917504`，首次 plan hash：`553dc2e431923ec5f1a13fc5e0ff48da331462e0ea20ce36ce82a15cebf37dd7`；
- 相同 command id 重放返回同一运行 id，未产生重复结果；
- 当前保留 3 条 Open MigrationIssue：17 个 AssetNode、4 个 ThreatPoint、5 个 DO326A_Link 缺少可靠来源定位，留待 Phase 2 的 SourceRecord 处置；
- 1 条不适用于 CommitAudit 的来源问题经受审计重检标记为 Superseded，未删除历史；
- 最终验证：27 个实体已挂接、3 条 Open MigrationIssue、0 个未归属已知实体、0 个无效 UUID、0 个缺失 Revision 成员关系、0 个跨项目关系；
- 后端单元与回归测试 56/56、Neo4j 集成测试 2/2、前端回归测试 5/5 通过，前后端完整构建通过；
- `apps/frontend/tsconfig.tsbuildinfo` 已在 `.gitignore` 中，现从版本控制移除，避免构建缓存继续污染阶段提交；
- 前端既有大 chunk 告警未增加，仍按 Phase 6 技术债处理。

## 14. P1.4 范围

### 实施

- 新增 `RevisionUnitOfWork`，作为 P1.4 后所有新增 Revision 内容写入的强制事务入口；
- 统一要求 project/revision/expected revision version/actor/command id、稳定事件类型和命令专用 canonicalizer；
- 在 Neo4j 写锁内重新校验 Revision 的项目归属、Draft 状态和 expected version，成功写入时单调递增 Revision version；
- 业务 mutation、Revision version 和 AuditEvent 在同一事务提交或共同回滚；
- AuditEvent 保存版本前后值、请求摘要、摘要算法、canonicalizer、变更摘要和最小结果回执；
- 提取共享 command receipt 校验，使 Project Governance 和 Revision 写入使用相同的事件复用、载荷冲突和旧回执规则；
- 建立 [Revision 范围写入契约](./revision-write-contract.md) 和 legacy 隔离清单；
- 将 `GraphRepository.commitChangeSet()` 与 `getGraphVersion()` 标记为 legacy compatibility API。

### 边界

- P1.4 不删除全局 GraphVersion，也不改变现有 UI 和导入请求格式；现有终端工作流继续走兼容入口；
- P1.4 不提前切换 Asset/Threat/DataFlow 等实体的全局业务 ID 约束，该工作属于 P1.5；
- P1.4 不一次性重写 F3532、标准知识、分析结果和 seed 的专用仓储；这些路径不得被新增能力继续引用，并在 P1.5-P1.6/Phase 2 分批收口；
- P1.4 不暴露新的 HTTP API；版本化 API 与稳定错误响应属于 Phase 2。

## 15. P1.4 验收

- 缺少合法 project/revision scope、actor、command id 或正整数 expected version 时拒绝；
- Revision 不属于指定 Project 时拒绝；
- Closed/InReview Revision 不接受普通内容写入；
- stale expected version 返回带 expected/current version 的结构化冲突；
- 两个并发命令使用同一 expected version 时只有一个提交成功；
- mutation 抛错时业务实体、Revision version 和 AuditEvent 全部回滚；
- 相同 command id 和规范请求返回原结果且不再次执行 mutation；
- command id 对应不同事件或请求摘要时拒绝；
- 成功写入只产生一个包含 request fingerprint 和版本前后值的 AuditEvent；
- 全局 GraphVersion 不被 `RevisionUnitOfWork` 读取或修改。

## 16. P1.4 完成记录（2026-10-09）

- `RevisionUnitOfWork` 已实现，并以数据库集成测试验证 scope、Draft 状态、乐观并发、显式写锁、事务回滚、幂等回执和审计；
- 集成测试首次捕获“固定赋值导致两个并发事务都成功”的 lost update，现改为先获取 Revision 写锁并在锁内重新判断 version；
- 后端单元与回归测试增至 58 项，Neo4j 集成测试增至 3/3；
- 本批次不需要 schema migration：Revision version 和 AuditEvent 唯一约束已由 `0002_governance_core_constraints` 提供；
- 集成测试业务数据按测试 Project 清理，没有修改已挂接的 Appendix D 项目；
- P1.5 可开始处理内部 UUID、项目内业务编号和全局唯一约束退出。

## 17. P1.5 范围

### 实施

- 建立 [作用域身份契约](./scoped-identity-contract.md)，统一 `id`、`business_id` 和 `legacy_id` 的职责；
- 为 15 类已登记遗留节点和 `ASSET_EDGE` 关系补齐不可变内部 UUID、project/revision scope、业务编号与 legacy 反查字段；
- 普通工程实体的业务编号在 `(project_id, revision_id, business_id)` 内唯一；`AttackPath` 额外包含 `analysis_batch_id`，避免不同运行的结果互相覆盖；
- 新增 `0004_scoped_entity_identity`，先执行前置条件检查、字段回填、新约束建立和 postcondition 验证；
- 新增 `0005_retire_global_business_constraints`，只有提供 destructive 确认与已验证 backup id 时才退出旧全局业务编号约束；
- 新增非破坏性 `0006_legacy_graph_version_compatibility`，保证全新数据库显式迁移后仍可运行尚未退役的旧 GraphVersion 兼容入口，但不允许新写入依赖它；
- 应用启动与仓储 `ensureConstraints()` 改为只读 schema compatibility 检查，不再创建、删除、去重或修复数据；
- 新增显式 scope 的 legacy identity repository API，同时接受内部 UUID、`business_id`、`legacy_id` 和原 legacy key，但只返回规范内部 UUID；
- 修复 Windows + Docker Desktop 下 `localhost` 解析为 IPv6 时的 Bolt 连接重置，连接配置统一规范到 IPv4 loopback。

### 边界

- 保留 `asset_id`、`edge_id`、`threatpoint_id` 等旧字段，不在 P1.5 删除旧字段或旧响应形状；
- P1.5 只提供兼容身份解析边界，不一次性改写全部旧查询、导入、seed、F3532 和前端调用；这些入口的隔离与双读回归属于 P1.6；
- `GraphVersion` 兼容入口仍保留，但新写入不得继续使用它作为全库并发边界；
- 3 条缺少可靠来源定位的 Open MigrationIssue 不因身份迁移而自动关闭，仍由 Phase 2 SourceRecord 处理。

## 18. P1.5 验收

- 每个已登记遗留节点和 `ASSET_EDGE` 具有有效 UUID、project/revision scope、`business_id` 和 `legacy_id`；
- 两个不同项目/revision 可复用同一个 Asset 和 ASSET_EDGE 业务编号，内部 UUID 不同；
- legacy resolver 缺少 scope、跨 scope 或未知实体类型时不得猜测或全库查询；
- 旧全局业务编号约束全部退出，新 UUID 与 scope 组合约束全部存在；
- 迁移前必须生成可恢复 dump，并将 backup id/hash 写入破坏性迁移账本；
- 迁移 `verify` 对 0001–0006 全部返回成功；
- 应用启动只验证 schema，不执行 DDL 或业务数据修复。

## 19. P1.5 完成记录（2026-10-09）

- 迁移前 Neo4j dump 保存于被 `.gitignore` 排除的本地目录 `.tmp/neo4j-backups/p1.5-20261009-231509/neo4j.dump`；文件大小 131,075 字节，SHA-256 为 `B2B57F5A0321C59C2CCECD55940419EBE7198AD96523CEEA96D7B67079E8D441`；
- `0004_scoped_entity_identity` checksum 为 `c3054e09f15898f4b0997b8e97fec3c9e77e3c83a0e2fe381b2da3f2e3dc03ac`，`0005_retire_global_business_constraints` checksum 为 `4c2f844cb9b302d77f301f3619e3998e2e35c2dc3b0d65a1b97fc93c25ce0f7b`，`0006_legacy_graph_version_compatibility` checksum 为 `bb8b129f9e9eacd5d1783a00d693c413cde33b07a3fd099990d238754f49610b`，均已 Applied 且 postcondition 通过；
- 数据盘点确认 17 个 AssetNode、4 个 ThreatPoint、5 个 DO326A_Link、1 个 CommitAudit 和 14 条 ASSET_EDGE 均已具有 P1.5 作用域身份；
- 15 个旧全局业务编号约束剩余数量为 0；新约束同时保护内部 UUID 和作用域业务编号；
- 新增跨项目重复 `ASSET-001`/`EDGE-001` 集成用例，验证显式 scope 可解析到不同内部 UUID，错误 scope 不产生结果；
- 后端单元与回归测试增至 60 项，Neo4j 集成测试增至 4/4；迁移 0001–0006 验证全部通过；
- P1.6 进入 Ready，下一批次负责把现有读取入口系统性接入 scope/compatibility projection，并执行 F3532、FeatureRule、隔离和恢复回归。

## 20. P1.6 范围

### 实施

- 建立 [兼容读取与遗留写隔离契约](./compatibility-read-contract.md)；
- 新增唯一的 `CompatibilityScopeRepository`：显式 `project_id + revision_id` 优先；旧客户端未传 scope 时只解析已登记的 `do356a-appendix-d` 遗留 revision；
- 图快照、章节 4 报表、F3532 03/04 上下文、攻击路径、建模导出、DO-326A 链接、StandardMapping 和旧 CommitAudit 读取全部强制携带 project/revision scope；
- 旧 JSON 响应形状保持不变，响应头返回 `X-ASTRA-Project-Id`、`X-ASTRA-Revision-Id` 和 `X-ASTRA-Scope-Source`；
- 缺少一半 scope、跨项目 revision 或不存在的 scope 显式拒绝，不按业务编号、名称或“唯一项目”猜测；
- 将仍依赖全局 GraphVersion、无 scope MERGE/DELETE 的遗留业务写端点统一隔离为 `409 LEGACY_GLOBAL_WRITE_QUARANTINED`；纯 preview、分析运行和报告读取继续可用；
- 基线实验脚本默认不再执行全局 seed；`--seed-sample` 被隔离，防止实验命令替换受控项目数据；
- 修复 `getF353204()` 在同一个 Neo4j session 并发运行查询导致的 open transaction 错误。

### 边界

- P1.6 不建立 Phase 2 的版本化 scoped command HTTP API，因此不把旧全局写实现包装成伪作用域接口；
- 共享标准知识库 Clause/Artifact/Pipeline 读取仍按 standard id 全局复用；项目工程映射 `StandardMapping` 必须按 project/revision 读取；
- FeatureRule preview/path trace 是显式输入包驱动的实验方法，不从 Neo4j 全库读取，继续按其 contract/scope/hash 规则回归；
- 3 条来源定位 MigrationIssue 保持 Open，不在读取兼容层补造 SourceRecord。

## 21. P1.6 验收

- 两个项目/revision 中相同 Asset、Edge、Path、Mapping、TC/TS、DO-326A link 和 CommitAudit 编号的读取结果完全隔离；
- 默认兼容 scope 精确解析到已登记 Appendix D revision，并在响应头公开解析结果；
- 部分 scope、错误 project/revision 组合和未知 scope 不产生回退或跨项目结果；
- 所有列入清单的旧全局写端点返回稳定 409 错误，数据库节点数不变；
- Appendix D 挂接仍为 27 个实体、3 条 Open MigrationIssue；迁移 0001–0006 验证通过；
- P1.5 dump 能在独立环境恢复，恢复后可重放 0004–0006，实体数量、作用域读取和约束状态与主库一致；
- F3532、FeatureRule、前后端构建和既有测试无退化。

## 22. P1.6 完成记录（2026-10-10）

- HTTP 集成验证：默认 `/graph` 返回 17 个 Appendix D 资产并公开 scope 响应头；仅提供 `project_id` 返回 400；调用 `/admin/seed/sample` 返回 `409 LEGACY_GLOBAL_WRITE_QUARANTINED` 且数据库节点数不变；
- 多项目隔离矩阵在两个项目中复用 `ASSET-001`、`EDGE-001`、`PATH-001`、`LINK-001`、`MAP-001`、`FC-001`、`TC-001`、`TS-001` 和 `COMMIT-001`，所有兼容投影均只返回所属 revision 数据；
- Appendix D 真实数据只读回归得到 17 个 AssetNode、14 条 ASSET_EDGE、4 个 ThreatPoint；LegacyAttachment verify 为 27 个挂接实体、3 条 Open MigrationIssue、0 条诊断；
- 默认 scope 双读计数与迁移前兼容全库视图一致：AssetNode 17/17、ThreatPoint 4/4、DO326A_Link 5/5、CommitAudit 1/1、ASSET_EDGE 14/14，差异为 0；
- 使用 SHA-256 `B2B57F5A0321C59C2CCECD55940419EBE7198AD96523CEEA96D7B67079E8D441` 的 P1.5 dump 在临时卷恢复；初始状态为 0001–0003 Applied、0004–0006 Pending，重放后 0001–0006 全部验证通过；
- 恢复库验证为 17 个资产、14 条边、4 个威胁点、55 个约束、0 个旧全局业务编号约束；临时容器和卷已清理，主库持续运行；
- 前后端完整构建通过；后端单元/F3532/FeatureRule 回归 62/62、数据库与 HTTP 集成测试 10/10、前端测试 5/5 通过；前端既有大 chunk 告警未增加；
- Phase 1 出口门槛已满足。Phase 2 进入 Ready，下一阶段提供标准无关模型契约和 scoped command API；VG-1 仍需等待 Phase 2 完成。
