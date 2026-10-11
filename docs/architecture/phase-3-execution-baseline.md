# Phase 3 执行基线：DO-326A/DO-356A 工程闭环

状态：Complete  
完成日期：2026-10-11  
前置：Phase 2 Complete，VG-1 Passed

## 交付结果

Phase 3 已形成标准 profile 驱动、可审计且不越权的工程闭环：

    SourceRecord / System Model
      → ThreatPoint → ThreatCondition → ThreatScenario
      → RiskAssessment
      → SecurityObjective → SecurityRequirement → Control
      → VerificationCase → EvidenceRecord
      → human ReviewDecision
      → traceability report → Frozen Baseline

核心类型未固化 F3532 表格结构。DO-326A 过程/活动/工作产品与 DO-356A 方法/字段/工作产品由 ProfileConfiguration 声明，项目差异由 TailoringDecision 表达。

## 已实现能力

1. 共享 engineering-case.v1 契约覆盖 Phase 3 核心实体、TraceLink 和 ReviewDecision；
2. 新写入统一经过 Draft revision、乐观版本、command id、请求摘要与 AuditEvent；
3. 导入只能建立 Draft；人工作出的 ReviewDecision 是状态晋升或退回的唯一入口；
4. RiskAssessment 的 computed_result 与 engineering_judgement 分栏保存；
5. 所有工程实体与追踪关系绑定同 revision 的 SourceRecord；
6. 追踪报告 v2 合并系统模型和工程闭环，并将其纳入 baseline 内容摘要；
7. F3532 01/02/03/04 注册为可开关 compatibility adapter；04 映射只输出核心 Draft，不接受外部批准断言；
8. 报告工作区新增“工程闭环”视图，可读取全链并提交人审决定；
9. 迁移 0010_engineering_case_core 建立统一 CoreEntity 和 ReviewDecision 作用域身份；
10. 受控 Appendix D 示例可从空白项目重复生成、评审、报告和冻结。

## Appendix D 验收

数据来源按项目决定确认为 DO-356A Appendix D。仓库中的 examples/phase3-appendix-d-source.json 仅保存项目控制的合成描述、来源标识和定位信息，不复制标准正文。

执行：

    npm run db:migrate -- apply --actor <actor-id>
    npm run phase3:demo

2026-10-11 实测结果：

- 1 个 profile configuration、1 个 tailoring decision；
- ThreatPoint、ThreatCondition、ThreatScenario、RiskAssessment、SecurityObjective、SecurityRequirement、Control、VerificationCase 各 1 个；
- 8 条跨阶段 TraceLink；
- SecurityRequirement 经人工作出决定后为 Reviewed；
- baseline 报告完整性为 matched；
- 相同命令再次执行返回既有结果，无重复写入。

## 出口门槛结论

| 门槛 | 结论 | 证据 |
|---|---|---|
| Appendix D 端到端追踪 | 通过 | phase3:demo，8 条工程链 |
| F3532 adapter 可开关且核心不受污染 | 通过 | profile adapter binding、纯预览映射、核心边界测试 |
| 算法结果与工程判断分开 | 通过 | computed_result / engineering_judgement |
| 报告解析 profile、revision/baseline、来源 | 通过 | traceability report v2，冻结后 matched |
| 人审不可由导入冒充 | 通过 | Draft-only schema、独立 ReviewDecision command |
| 写入幂等且可审计 | 通过 | RevisionUnitOfWork、request hash、AuditEvent、演示重放 |

## 验证记录

- npm test -w @attackgraph/backend：通过；
- npm run build：通过；
- npm run db:migrate -- verify：迁移 0001–0010 全部通过；
- npm run phase3:demo：首次执行和重放通过；
- 既有 Neo4j 集成测试在完成前执行。

## 明确不属于 Phase 3

- AnalysisMethodDefinition、AnalysisRun、DerivedResult 和结果晋级属于 Phase 4；
- 变更影响传播、覆盖率矩阵和 profile 驱动正式工作产品属于 Phase 5；
- ReviewSession、评论协作、职责分离策略和完整权限模型属于 Phase 6。

Phase 3 完成后，Phase 4 状态转为 Ready。
