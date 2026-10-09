# 实验性特征分析到通用领域模型的 Crosswalk

- 状态：Accepted
- 日期：2026-10-08
- 接受日期：2026-10-09
- 当前契约：`feature-preview-0.1`

## 1. 目的

本文件规定现有 FeatureRule preview 和 offline topology trace 如何接入目标架构。它是边界映射，不要求修改当前实验契约，也不把研究数据自动认定为正式工程事实。

## 2. 输入映射

| 当前实验对象/字段 | 目标归属 | 映射规则 |
| --- | --- | --- |
| `scenario_id` | AnalysisRun 外部相关标识 | 保留原值；不能代替核心 ThreatScenario id |
| research `Asset` | method-specific input subject | 通过显式 mapping 引用核心 Asset；没有映射时保持 unresolved |
| `prototype_asset_id` | AnalysisRun input mapping | 必须在所属 project/revision 的图快照中解析；不得跨项目猜测 |
| `FeatureRecord` | method-specific fact set | 保留 feature/version/scope 语义；必要时用 TraceLink 引用核心对象 |
| feature `Fact` | method-specific assertion | present/absent/unknown/conflict 语义保留，不直接写为核心 Asset 属性 |
| research `Evidence` | SourceRecord/EvidenceRecord candidate | source locator/hash 可映射来源；`verified` 仅是调用方断言，需平台评审后才具有正式证据状态 |
| `Scope` | AnalysisRun scope extension | boundary、operational phase、attacker profile 必须显式解析到项目上下文或保持 unresolved |
| `Rule` | AnalysisMethod rule-pack item | rule id/version/enabled/maturity 随方法版本保存，不成为 StandardReference |
| `Policy` | method configuration candidate | 只有经项目 ReviewDecision 接受后才可成为受控项目配置 |
| input `reviewer`/`APPROVED` | external review assertion | 仅保留来源元数据；不能直接创建平台 ReviewDecision |
| `input_sha256` | AnalysisRun.input_content_hash | 使用契约版本对应的 canonicalizer 复算并校验 |

## 3. 输出映射

| 当前输出 | 目标对象 | 限制 |
| --- | --- | --- |
| `rule_not_executed` | Experimental DerivedResult | 不解释为“没有威胁” |
| `not_applicable` | Experimental DerivedResult | 只对本次 scope/profile/method 输入成立 |
| `needs_evidence` | Experimental DerivedResult + evidence gap | 不自动补全事实或来源 |
| `requirements_not_met` | Experimental DerivedResult | 不等于全局规则失效 |
| `blocked` | Experimental DerivedResult | 只表达输入 policy 下的机器判断，不等于风险已接受 |
| `candidate_scoped` | Candidate DerivedResult | 保留 downgrade effect，不自动量化风险 |
| `candidate_protection_unresolved` | Candidate DerivedResult | 必须保留未知/冲突原因 |
| `candidate` | Candidate DerivedResult | 不自动创建 ThreatPoint/ThreatScenario |
| `topology_candidate` | `topology_only` DerivedResult | 不自动创建 AttackPath；保留 ordered nodes/edges 和反向遍历标记 |
| `no_path_in_snapshot` | DerivedResult | 仅在未截断且完整搜索允许范围后成立 |
| `search_incomplete` | DerivedResult | 不得改写为 no-path 结论 |
| `asset_unmapped`/`scope_unmapped` | Mapping issue | 不得通过名称或参考答案自动猜测映射 |
| `mapping_evidence_unverified` | Evidence issue | 不能扩大可遍历边集合来规避问题 |
| graph/mapping hash | AnalysisRun snapshot metadata | 与 revision/baseline 内容摘要共同保存 |

## 4. 晋级规则

### 晋级为核心 Draft 前必须具备

- 明确的 Project、Model 和 Revision/Baseline；
- 可解析的核心 subject 和 scope；
- 原 AnalysisRun、方法版本、输入 hash 和结果 id；
- 满足目标核心类型所需的工程字段；
- 对关键证据、未知、冲突和截断状态的处置；
- 真实平台 actor/role 对明确 subject version 作出的 ReviewDecision；
- 显式且幂等的 promotion command。
- 晋级产生的核心 Draft 必须记录 origin，并通过 `DERIVED_FROM` TraceLink 指向源 DerivedResult/AnalysisRun；
- 核心 Draft 的后续工程评审必须形成针对 Draft version 的第二个 ReviewDecision，不得复用候选评审决定。

### 目标类型附加要求

| 晋级目标 | 附加要求 |
| --- | --- |
| ThreatPoint | 证明它表达可利用入口/暴露点，而非完整场景文本 |
| ThreatScenario | 补全主体、前置条件、动作、目标和关联 ThreatCondition |
| AttackPath | 验证逐段语义与证据；确认拓扑可达能够支撑攻击可行性判断 |
| RiskAssessment | 绑定受控风险方法、输入依据、工程判断和接受决定 |

## 5. 不允许的隐式映射

- 不因字段同名把 research Asset 与核心 Asset 合并；
- 不因 `APPROVED` 字符串创建 Approved ReviewDecision；
- 不因 `verified=true` 把来源升级为已验证证据；
- 不因存在节点/边序列创建正式 AttackPath；
- 不因找不到路径生成“无威胁”结论；
- 不以输入数组重排改变 AttackPath step sequence；
- 不用个人电脑绝对路径作为长期 SourceRecord 身份。
