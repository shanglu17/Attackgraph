# ADR-0002：标准无关核心与适配器边界

- 状态：Accepted
- 日期：2026-10-08

## 背景

当前通用 `AssetNode` 已承载 BDF、F3532 topic 和 continuation policy，`GraphRepository` 也直接导入 F3532 别名和排序逻辑。这使标准专用规则能够影响通用查询、存储和报告。

## 决策

采用标准无关核心、标准适配器和项目配置三层结构。

### 核心负责

- Project、Model、Revision、Baseline；
- Function、Asset、Interface、DataFlow、SecurityBoundary；
- ThreatPoint、ThreatCondition、ThreatScenario、AttackPath、RiskAssessment；
- SecurityObjective、SecurityRequirement、Control；
- VerificationCase、EvidenceRecord、ReviewDecision；
- TraceLink、SourceRecord、AuditEvent；
- 生命周期、不变量、权限端口和仓储端口。

### 标准适配器负责

- 标准术语到核心实体的映射；
- 标准专用导入模板和校验；
- 标准专用生成规则；
- 工作产品 schema；
- 报告布局和列名；
- 适用性、裁剪和版本差异。

### 项目配置负责

- 业务编号规则；
- 组织认可的别名和枚举映射；
- 经批准的路径/分类规则；
- 项目模板和报告品牌信息。

## 依赖规则

- 核心不得 import `config/f3532/*`；
- adapter 可以依赖核心公开接口；
- Neo4j、Express、Excel 和前端组件属于外层，不得成为核心实体的必需依赖；
- adapter 不得直接执行全局数据库删除或绕过核心写入服务；
- 项目规则必须经过 schema 校验和版本控制。

## 结果

- F3532 可继续使用，但成为可开关的 adapter；
- DO-326A/DO-356A 可以共享同一核心；
- ZG-ONE 项目规则不再作为全行业默认规则；
- 前端可根据启用的 adapter 动态提供导入器和报告。

## 未采用方案

### 继续扩展单一 `domain.ts` 和 `GraphRepository`

未采用。文件规模和循环依赖风险已经超过可持续范围，并且无法表达 adapter 边界。

### 为每个标准复制一套完整应用

未采用。共享的项目、模型、审计、权限和追踪能力会重复实现并产生不一致。

## 验收约束

- 关闭 F3532 adapter 后，后端和前端仍能构建并运行核心流程；
- 通用资产不需要 F3532 字段才能创建；
- adapter 只通过公开 application service 写入核心；
- adapter 的导入/导出 DTO 不直接成为持久化实体。
