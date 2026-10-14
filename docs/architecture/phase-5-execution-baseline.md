# Phase 5 执行基线：追踪、变更影响与工作产品

状态：Complete

完成日期：2026-10-14

前置：Phase 4 Complete

## 交付结果

Phase 5 已建立从批准 baseline 到目标 revision 的确定性影响分析、人工处置和 profile 驱动工作产品链：

    approved Baseline / source Revision
      → deterministic Added / Removed / Modified comparison
      → dependency and TraceLink propagation
      → ChangeImpactAssessment + ImpactItem
      → human Accept / Reanalyze / Waive / Defer disposition
      → traceability matrix + gaps + coverage
      → DO-326A / DO-356A work-product sections

这条链保留 project/revision/profile/source 边界，不会把机器传播结果伪装成人工工程结论，也不会产生适航符合性声明。

## 已实现能力

1. `change-impact.v1` 契约支持 revision/baseline 两端显式比较、确定性摘要、影响保存和人工作出决定；
2. `assurance-work-product.v1` 契约提供矩阵、缺口、覆盖率、影响评估、profile 区段和受限状态；
3. 迁移 `0013_change_impact_and_work_products` 建立评估、影响项和处置决定的全局及作用域身份约束；
4. Added、Removed、Modified 差异记录变更字段及前后摘要；直接与传播影响记录距离、触发对象和经过的 TraceLink；
5. TraceLink 采用保守双向传播，来源、派生和产物关系保留工程方向，结果稳定排序并生成 `preview_hash`；
6. 所有保存和处置写入经过 revision 乐观锁、command payload hash、AuditEvent 和幂等回执；
7. Accept、Reanalyze、Waive、Defer 均为独立人工作出决定；Defer 要求期限，Waive 要求依据；
8. 报告识别缺少来源、未评审结论、stale 分析、未追踪实体和未处置影响；
9. DO-326A/DO-356A 区段由 StandardProfileVersion 生成，F3532 只在 adapter 显式开启时出现；
10. 每条非空报告结论列出实际参与计算的 TraceLink，空矩阵不生成无依据结论；
11. 工作产品只标记 Draft 或 Reviewable，固定声明不构成符合性判定或适航批准；
12. 报告工作区新增“影响与工作产品”局部任务，支持预览、保存、读取、处置、生成和导出；
13. 使用 baseline 读取历史报告时解析原始 revision，后续 revision 不会洗掉历史内容。

## 出口门槛结论

| 门槛 | 结论 | 证据 |
|---|---|---|
| 上游修改产生确定影响集 | 通过 | 纯函数单测、跨 baseline/revision 集成测试、phase5:demo |
| 历史报告解析原始 baseline | 通过 | 集成测试验证 baseline 返回原资产而非目标 revision 资产 |
| 正式报告结论可反向追踪 | 通过 | 结论携带完整参与矩阵的 TraceLink 标识；来源/评审/影响处置随包导出 |
| 不超出证据作符合性声明 | 通过 | 仅 Draft/Reviewable；固定免责声明；无 compliance/approval 自动判定 |
| project/revision/profile 隔离 | 通过 | 显式作用域解析、跨项目拒绝、profile 驱动区段 |
| 写入可审计且可安全重放 | 通过 | RevisionUnitOfWork、AuditEvent、payload mismatch 集成测试 |

## 验证记录

- `npm test -w @attackgraph/backend`：78 项通过；
- `npm run build -w @attackgraph/backend`：通过；
- `npm run build -w @attackgraph/frontend`：通过；
- `npm run test:integration -w @attackgraph/backend`：15 项通过；
- `npm run db:migrate -- verify`：`0001`–`0013` 全部通过；
- `npm run phase5:demo`：直接/传播影响、命令重放、人工作出决定、DO-326A/DO-356A 工作产品和责任边界均通过；
- 前端 `1440×900`、`1280×800`、`390×844`：实际渲染均无页面级横向滚动，主工作区与报告子页签各只有一个选中项，影响与工作产品面板可见且窄屏正确折行。

## 明确不属于 Phase 5

- ReviewSession、评论协作、真实身份认证、强制职责分离和完整 RBAC 属于 Phase 6；
- 备份恢复演练、可观测性、性能、安全和完整 E2E 证据属于 Phase 6；
- 遗留数据正式切换、双读退出和发布证据包属于 Phase 7；
- 平台生成的工作产品不能替代申请人、主管当局或授权标准的符合性判断。

Phase 5 已通过出口门槛，Phase 6 转为 Ready。
