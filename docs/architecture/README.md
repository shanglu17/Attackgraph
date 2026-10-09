# ASTRA 架构基线索引

本目录记录 ASTRA 从 F3532/ZG-ONE 专用实现演进为通用适航安保工程辅助平台的目标架构。

**Phase 0：合并后基线与治理校准** 已于 2026-10-09 重新接受。当前处于 **Phase 1：项目化与写入治理基础**；Phase 1 的实现不得绕过本目录已经接受的身份、版本、来源、分析和晋级约束。Phase 2 完成后必须通过 **VG-1 首条可交付纵向链路**，才能大规模进入 Phase 3。

## 阅读顺序

1. [Phase 0–7 实施路线图](./implementation-roadmap.md)
2. [Phase 1 执行计划](./phase-1-execution-plan.md)
3. [Revision 范围写入契约](./revision-write-contract.md)
4. [作用域身份契约](./scoped-identity-contract.md)
5. [Phase 0 架构基线](./phase-0-baseline.md)
6. [目标领域模型](./target-domain-model.md)
7. [适航安保领域术语表](./airworthiness-security-glossary.md)
8. [DO-326A / DO-356A 能力差距矩阵](./do326a-do356a-capability-matrix.md)
9. [实验性特征分析 Crosswalk](./experimental-analysis-crosswalk.md)
10. [遗留数据迁移设计](./legacy-migration-plan.md)
11. 架构决策记录：
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

当前实现行为仍以仓库现有代码和 `docs/project-baseline.md` 为准；本目录描述下一阶段的目标结构。目标模型尚未实现前，不得把目标文档误写为已有能力。
