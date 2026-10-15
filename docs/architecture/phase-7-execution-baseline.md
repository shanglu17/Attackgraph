# Phase 7 执行基线：遗留迁移与发布验收

状态：Complete

完成日期：2026-10-15

前置：Phase 6 Complete

## 交付结果

Phase 7 将 Phase 1 已开始的遗留挂接、Phase 2–6 的目标模型和运维能力收束为一次可重复、失败即关闭的 M0–M6 技术发布验收：

    授权的 DO-356A Appendix D 遗留项目
      → M0 盘点与内容哈希快照
      → M1 迁移账本和约束校验
      → M2 project/revision 归属与跨项目检查
      → M3 来源确认
      → M4 正式评审历史完整性检查
      → M5 scoped/compatibility/Golden 三方比较
      → M6 旧写隔离和真实删除/恢复演练
      → 不可变 ReleaseAcceptanceRun + AuditEvent

本阶段没有读取或恢复被 `.gitignore` 排除的 ZG-ONE/F3532 合作资料；兼容检查只使用已授权的 Appendix D 数据和仓库内通用/脱敏测试夹具。

## M0–M6 结论

| 阶段 | 结论 | 证据 |
| --- | --- | --- |
| M0 | 通过 | 目标项目 41 个节点、106 条内部关系；项目快照语义 SHA-256 已记录 |
| M1 | 通过 | `0001`–`0015` 均为 Applied，checksum 与迁移账本一致 |
| M2 | 通过 | 27 个遗留节点已挂接；未归属节点 0；跨项目关系 0 |
| M3 | 通过 | 1 个 `DO356A-APPENDIX-D-SOURCE`；26 个来源关系；不复制标准正文 |
| M4 | 通过 | 当前发布 scope 中缺 actor/role/time/version 的正式 ReviewDecision 为 0 |
| M5 | 通过 | 直接读取、兼容读取与 Golden 均为 Asset 17、Edge 14、ThreatPoint 4、DO326A Link 5、CommitAudit 1 |
| M6 | 通过 | 旧全局写入口保持 409 隔离；高风险 Open MigrationIssue 为 0；临时项目删除/恢复后 5 节点、8 关系及语义哈希一致 |

技术验收记录 `ASTRA-PHASE7-2026-10-15` 已写入 `ReleaseAcceptanceRun`，并由 `TECHNICAL_RELEASE_ACCEPTANCE_RECORDED` AuditEvent 引用。证据 hash 为 `3d3c69a7aafc84a230f990a7f7e938932d5f08edd6c9c56bbfcdf7e1d2724431`。

## 实现边界

- `phase7-release-evidence.v1` 只记录计数、状态、迁移 checksum、语义 hash 和技术检查结论，不包含受限标准正文；
- `human_release_authorization` 固定为 `not_asserted`。技术通过不冒充组织放行、适航批准或主管当局判断；
- M6 停止的是旧 GraphVersion 全局写入。兼容读取窗口保留，旧字段本阶段不物理删除；
- `0015_release_acceptance` 只增加发布证据身份约束，是非破坏性迁移；
- `AnalysisMethodDefinition` 和技术发布记录是平台级对象，遗留盘点不得把它们误报为未归属业务数据；project/revision 已完整的目标模型对象也不得因没有 `model_id` 被误报为 scope 冲突。

## 验证记录

- 后端单元测试：82 项通过；
- 数据库/HTTP 集成测试：16 项通过，覆盖多项目隔离、冻结、影响传播、评审、旧写隔离和兼容读取；
- 前端测试：8 项通过；前后端生产构建通过；
- `legacy:attach dry-run --dataset do356a-appendix-d`：0 个阻断或非阻断问题；
- `db:migrate apply/verify`：`0001`–`0015` 全通过；
- `phase7:acceptance verify` 与 `record`：M0–M6 全部通过；
- Phase 1–6 的多项目隔离、基线冻结、影响传播、旧写 409、评审和恢复集成测试继续作为发布回归门槛。

## 仍需部署组织决定的事项

- 生产放行人、批准时间、部署窗口和外部备份位置不由仓库自动填写；
- 企业 OIDC、密钥托管、集群告警和异地灾备属于部署增强；
- `xlsx@0.18.5` 无上游修复的公告风险与 `mammoth` 传递中风险继续按运行手册限制输入并跟踪替代；
- 兼容读取何时物理移除必须至少经过一个稳定发布版本，并另立破坏性迁移与备份审批。

Phase 7 已通过路线图定义的技术出口门槛；系统达到本路线图的正式发布候选状态，但不自动构成适航批准声明。
