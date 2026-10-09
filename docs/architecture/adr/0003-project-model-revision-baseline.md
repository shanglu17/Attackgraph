# ADR-0003：项目、模型、修订与基线

- 状态：Accepted
- 日期：2026-10-08

## 背景

当前 Neo4j 约束要求资产、接口、TC、TS 等业务编号在全库唯一，并使用一个全局 `GraphVersion` 控制提交。这样无法同时存储两个都包含 `SI.1` 或 `TC.1` 的项目，也无法保留可复审的历史基线。

## 决策

采用以下层级：

```text
Project 1 --- n Model 1 --- n Revision
                         Revision 0..1 --- 1 BaselineSnapshot
Project 1 --- n StandardProfile
Revision n --- 1 StandardProfileVersion
```

### Project

工程管理和数据隔离边界。项目删除、导出、权限和审计均以此为最高业务范围。

### Model

项目内一个被评估对象。记录模型层级、范围描述、父模型和当前工作 revision。

### Revision

可变工作副本和乐观并发边界。拥有单调递增的 revision version，不使用时间戳作为唯一并发语义。

### Baseline

由 Revision 冻结产生的不可变快照。记录内容摘要、标准 profile 版本、批准信息和来源 revision。

## 身份规则

每个业务实体至少具有：

- `id`：系统生成、不可变的内部 UUID；
- `project_id`；
- `model_id`；
- `revision_id` 或 `baseline_id`；
- `business_id`：项目/模型范围内稳定、用户可读；
- `legacy_id`：迁移期可选；
- `created_at/by`、`updated_at/by`。

唯一约束以内部 UUID 为主。需要校验业务编号时，约束范围至少包含 project/model/revision 上下文。

## 生命周期约束

- Draft Revision 可修改；
- Frozen/Approved Baseline 不可原地修改；
- 修改已冻结内容必须从 baseline 派生新 revision；
- 分析运行绑定 revision 或 baseline 的内容摘要；
- 报告绑定 baseline 或明确标记为 draft；
- 项目内删除采用受控归档或显式级联计划，不允许无范围的全库删除。

## 结果

- 多项目可以重用相同业务编号；
- 能够比较基线和执行变更影响分析；
- 历史报告能够解析到原始模型状态；
- `GraphVersion` 迁移为 revision 版本，不再承担全库版本角色。

## 未采用方案

### 每个项目使用独立 Neo4j 数据库

首版不采用。它可以提供物理隔离，但会增加部署、标准知识复用和跨项目管理成本。领域模型仍需项目上下文，未来可在高隔离部署中增加数据库级分片。

### 继续使用时间戳 GraphVersion

未采用。时间戳不能完整表达父 revision、冻结状态和内容身份，也不便于确定性测试。

## 验收约束

- 两个项目可创建相同 `business_id`；
- 所有仓储方法显式接收 project 和 revision/baseline scope；
- stale version 只在所属 revision 内冲突；
- baseline 内容摘要在导出和重新加载后保持一致；
- Approved baseline 没有更新 API。

## 实施记录

- P1.2 已实现 Project/Model/Revision/Baseline 和 StandardProfileVersion 的治理核心身份；
- P1.4 已实现 Revision 范围统一写入、乐观并发、命令幂等和 AuditEvent；
- P1.5 已通过显式迁移为登记的工程节点与 `ASSET_EDGE` 建立内部 UUID 和 project/revision 作用域业务编号约束，并退出旧全局业务编号约束；
- 旧业务字段作为 compatibility projection 输入继续保留，旧读取入口的全面 scope 接入与差异验证属于 P1.6。
