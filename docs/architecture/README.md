# ASTRA 架构基线索引

本目录记录 ASTRA 从 F3532/ZG-ONE 专用实现演进为通用适航安保工程辅助平台的目标架构。

**Phase 0：合并后基线与治理校准** 已于 2026-10-09 重新接受，**Phase 1：项目化与写入治理基础**、**Phase 2：标准无关系统模型与契约** 已于 2026-10-10 完成，**VG-1 首条可交付纵向链路** 已于 2026-10-11 通过，**Phase 3：DO-326A/DO-356A 工程闭环** 已于 2026-10-11 完成，**Phase 4：可插拔分析与结果晋级** 与 **Phase 5：追踪、变更影响与工作产品** 已于 2026-10-14 完成，**Phase 6：评审工作台、质量与运维** 和 **Phase 7：遗留迁移与发布验收** 已于 2026-10-15 完成。系统达到路线图定义的正式发布候选状态，但不自动构成适航批准声明。

## 阅读顺序

1. [Phase 0–7 实施路线图](./implementation-roadmap.md)
2. [Phase 1 执行计划](./phase-1-execution-plan.md)
3. [Phase 2 执行基线](./phase-2-execution-baseline.md)
4. [VG-1 执行基线](./vg1-execution-baseline.md)
5. [Phase 3 执行基线](./phase-3-execution-baseline.md)
6. [Phase 4 执行基线](./phase-4-execution-baseline.md)
7. [Phase 5 执行基线](./phase-5-execution-baseline.md)
8. [Change Impact v1 与 Assurance Work Product v1 API 契约](./change-impact-v1-api.md)
9. [Phase 6 执行基线](./phase-6-execution-baseline.md)
10. [Phase 6 评审与运维手册](../phase-6-operations-runbook.md)
11. [Phase 7 执行基线](./phase-7-execution-baseline.md)
12. [Phase 7 发布与回退手册](../phase-7-release-runbook.md)
13. [Analysis Run v1 API 契约](./analysis-run-v1-api.md)
14. [Engineering Case v1 API 契约](./engineering-case-v1-api.md)
15. [System Model v2 API 契约](./system-model-v2-api.md)
16. [Revision 范围写入契约](./revision-write-contract.md)
17. [作用域身份契约](./scoped-identity-contract.md)
18. [兼容读取与遗留写隔离契约](./compatibility-read-contract.md)
19. [Phase 0 架构基线](./phase-0-baseline.md)
20. [目标领域模型](./target-domain-model.md)
21. [适航安保领域术语表](./airworthiness-security-glossary.md)
22. [DO-326A / DO-356A 能力差距矩阵](./do326a-do356a-capability-matrix.md)
23. [实验性特征分析 Crosswalk](./experimental-analysis-crosswalk.md)
24. [遗留数据迁移设计](./legacy-migration-plan.md)
25. 架构决策记录：
   - [ADR-0001：产品定位与标准版本策略](./adr/0001-product-positioning-and-standard-versioning.md)
   - [ADR-0002：标准无关核心与适配器边界](./adr/0002-standard-neutral-core-and-adapters.md)
   - [ADR-0003：项目、模型、修订与基线](./adr/0003-project-model-revision-baseline.md)
   - [ADR-0004：数据来源、生成、评审与追踪](./adr/0004-provenance-review-and-traceability.md)
   - [ADR-0005：显式迁移与写入治理](./adr/0005-explicit-migrations-and-write-governance.md)
   - [ADR-0006：实验性分析方法与结果晋级](./adr/0006-experimental-analysis-and-result-promotion.md)

## 文档状态约定

- `Accepted`：已经确认，后续实现必须遵守。
- `Proposed`：待讨论，不能作为实施依据。
- `Reopened`：曾经接受，但因代码基线或约束发生变化而重新评审。
- `Superseded`：已被新的 ADR 替代，但保留决策历史。
- `Deprecated`：不再推荐使用，仍可能描述遗留行为。

## 适用范围

这些文档约束后续对以下区域的改造：

- `apps/backend/src/types`
- `apps/backend/src/repositories`
- `apps/backend/src/services`
- `apps/backend/src/routes`
- `apps/frontend/src`
- Neo4j 标签、关系、约束与迁移脚本
- 导入模板、分析结果、标准映射与报告导出

当前实现行为以仓库代码和阶段执行基线为准。Phase 0–7 与 VG-1 均已通过技术验收；组织放行和适航批准仍必须由对应责任方在平台外或受控流程中作出。
