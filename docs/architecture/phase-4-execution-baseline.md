# Phase 4 执行基线：可插拔分析与结果晋级

状态：Complete  
完成日期：2026-10-14  
前置：Phase 3 Complete，ADR-0006 Accepted

## 交付结果

Phase 4 已建立标准无关、项目隔离且可重现的分析外壳：

    scoped SourceRecord + Revision + StandardProfileVersion
      → AnalysisMethodDefinition
      → immutable input/config/graph/mapping snapshots
      → AnalysisRun → DerivedResult (Experimental/Candidate)
      → human ReviewDecision A
      → explicit Promotion → Core Draft + DERIVED_FROM TraceLink
      → independent Engineering ReviewDecision B
      → traceability report

DFS/DPS、F3532 确定性生成、六维特征规则预览和拓扑候选追踪通过适配器进入同一框架。方法专用 DTO 没有进入核心领域模型。

## 已实现能力

1. `analysis-run.v1` 共享契约覆盖方法定义、运行、快照、结果、人审和晋级；
2. 迁移 `0011_analysis_framework` 建立方法、运行、结果、快照和晋级身份约束，并注册四个方法版本；`0012_engineering_legacy_identity_compatibility` 非破坏性补齐复用旧标签的工程实体兼容身份；
3. 输入、配置、图和映射保存完整快照及哈希，同时记录方法配置、规则包、实现指纹和 canonicalizer 版本；
4. 相同输入/配置/方法版本产生相同结果摘要，另一次运行建立新历史记录，不覆盖旧结果；
5. 所有写命令经过 revision 乐观锁、command payload hash、AuditEvent 和幂等回执；
6. 分析输入中的核心资产必须解析到同 project/revision；F3532 运行受 profile adapter 开关约束；
7. topology-only 候选保留有序路径、结构化完整性、终止原因和诊断；只有穷尽允许搜索空间才能声明完整无路径；
8. topology-only AttackPath 晋级要求可行性说明、逐边语义和同作用域证据，防止晋级后“洗白”来源；
9. 晋级 Core Draft 保留 `origin`、源 AnalysisRun/DerivedResult 与可见 `DERIVED_FROM` 链；ReviewDecision A 与 Engineering ReviewDecision B 相互独立；
10. 追踪报告包含运行、候选、晋级、来源和状态；受控分析工作台支持加载、执行、审查和晋级；
11. 上游系统模型或工程案例后续写入会将旧运行标记 stale，不修改历史 payload/hash；
12. 外部规则数据中的 reviewer 声明只保留在方法快照，不会生成平台 ReviewDecision。

## 出口门槛结论

| 门槛 | 结论 | 证据 |
|---|---|---|
| 同输入、方法和规则版本产生同摘要 | 通过 | canonicalizer 单测、两次独立运行集成测试、phase4:demo |
| 旧结果不覆盖，上游变化标记 stale | 通过 | append-only AnalysisRun/DerivedResult、集成测试 |
| 无人审不得写入核心实体 | 通过 | Reviewed 状态前置条件、事务回滚测试 |
| topology-only 晋级不丢失来源 | 通过 | origin + DERIVED_FROM + 报告可见性、逐边证据门禁 |
| asserted reviewer metadata 不成为 ReviewDecision | 通过 | 方法适配器单测、独立人审命令 |
| project/revision/profile/source 隔离 | 通过 | 作用域查询、资产解析、ProfileConfiguration 方法开关 |
| 截断与无路径语义可判定 | 通过 | completeness/termination_reason、path trace 测试 |

## 验证记录

- `npm test -w @attackgraph/backend`：75 项通过；
- `npm run build -w @attackgraph/backend`：通过；
- `npm run build -w @attackgraph/frontend`：通过；
- 前端 `1440×900`、`1280×800`、`390×844`：无页面级横向滚动，局部标签一次只显示一个任务；
- `npm run db:migrate -- apply --actor phase4-acceptance`：`0001`–`0012` 已应用；
- `npm run db:migrate -- verify`：`0001`–`0012` 全部通过，演示写入后复验仍通过；
- `npm run test:integration -w @attackgraph/backend`：14 项通过；`analysisFramework.integration.test.ts` 覆盖幂等/冲突、确定性、两级评审、逐边证据、报告来源和 stale；
- `npm run phase4:demo`：确定性摘要、命令重放、结果晋级、独立批准和可见 `DERIVED_FROM` 均通过。

## 明确不属于 Phase 4

- 全依赖图的 impact 传播、处置决定和 baseline 差异属于 Phase 5；
- profile 驱动正式工作产品和覆盖率矩阵属于 Phase 5；
- ReviewSession、评论协作、强制职责分离/RBAC 和完整 E2E 运维证据属于 Phase 6。

Phase 4 已通过出口门槛，Phase 5 转为 Ready。
