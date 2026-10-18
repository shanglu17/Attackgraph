# 九类 Sheet 系统资产清单填写指南

契约：cxf_asset_inventory_v1。字段定义来源：packages/contracts/src/inventory.ts 与 inventoryFields.ts；解析器、模板下载、字段帮助及后端诊断共用这些定义。本文件通过 scripts/generate-inventory-guide.mjs 生成。

下载当前模板会生成全部九类工作表。功能资产、边界数据流表、数据资产是旧模板也必须包含的三类 Sheet，其他旧模板缺失的 Sheet 按空表兼容。空模板可解析，但功能资产、边界数据流和数据资产至少各有一条记录才能提交。不要删除表头，编号不允许重复；正文中的空行保留真实行号。布尔值只能填写 是/否、true/false、yes/no、1/0 等明确值，不能填写“可能”。

首次使用请下载填写示例，再通过正常上传、预览和提交保存。保留原始工作簿，转换仅在内存中处理副本，不原地改写。

AMS 转换必须明确使用 DO356A-AMS。字段枚举通过后仍需满足版本化转换规则的适用性；不能据此宣称支持其他机型。

## 功能资产

| 字段键 | 中文表头 | 必填 | 类型 | 枚举 | 别名 | 引用 | 示例 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| id | 编号 | 是 | text | — | — | — | FA01 |
| name | 功能资产名称 | 是 | text | — | — | — | 温度控制 |
| description | 资产说明 | 否 | text | — | — | — | 文本 |

## 边界数据流表

| 字段键 | 中文表头 | 必填 | 类型 | 枚举 | 别名 | 引用 | 示例 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| id | 边界数据流编号 | 是 | text | — | 接口编号 | — | SI.1 |
| producer | 产生者 | 是 | text | — | — | — | 文本 |
| consumer | 用户 | 是 | text | — | — | — | 文本 |
| data_flow_description | 数据流描述 | 否 | text | — | — | — | 文本 |
| data_flow_type | 数据流类型 | 否 | text | CMD / CONFIG / STATE / DATA / LOAD / ALERT / SENSOR | — | — | DATA |
| target_function | 目标功能 | 否 | text | — | — | 功能资产 | 引用对应工作表编号 |
| boundary_interface_id | 所属边界接口 | 否 | text | — | — | 边界接口表 | 引用对应工作表编号 |
| enters_internal_propagation | 进入内部传播 | 否 | boolean | 是 / 否 / true / false | — | — | 是 |
| physical_interface | 物理接口 | 否 | text | — | — | — | 文本 |
| logical_interface | 逻辑接口 | 否 | text | — | — | — | 文本 |
| network_domain | 网络域 | 否 | text | — | — | 域属性表 | 引用对应工作表编号 |
| zone | 区域 | 否 | text | — | — | — | 文本 |
| purpose | 目的 | 否 | text | — | — | — | 文本 |

## 支持资产

| 字段键 | 中文表头 | 必填 | 类型 | 枚举 | 别名 | 引用 | 示例 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| id | 编号 | 是 | text | — | — | — | SSA.1 |
| name | 名称 | 是 | text | — | — | — | 温度控制 |
| linked_interfaces | 交联接口 | 否 | references | — | — | 边界数据流表 | 引用对应工作表编号 |
| security_domain | 安全域 | 否 | text | Internal / Shared / DMZ / External | — | — | Internal |
| criticality | 重要性 | 否 | text | Low / Medium / High | — | — | High |

## 数据资产

| 字段键 | 中文表头 | 必填 | 类型 | 枚举 | 别名 | 引用 | 示例 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| id | 编号 | 是 | text | — | — | — | DA01 |
| name | 数据名称 | 是 | text | — | — | — | 温度控制 |
| data_type | 数据类型 | 否 | text | — | — | — | 文本 |
| data_flow_type | 数据流类型 | 否 | text | CMD / CONFIG / STATE / DATA / LOAD / ALERT / SENSOR | — | — | DATA |
| linked_interfaces | 对应接口 | 否 | text | — | — | 边界数据流表 | 引用对应工作表编号 |
| domain_id | 所属域 | 否 | text | — | — | 域属性表 | 引用对应工作表编号 |
| description | 说明 | 否 | text | — | 资产说明 | — | 文本 |
| target_function | 目标功能 | 否 | text | — | — | 功能资产 | 引用对应工作表编号 |
| load_description | 加载描述 | 否 | text | — | — | — | 通过维护链路加载签名配置 |

## 域属性表

| 字段键 | 中文表头 | 必填 | 类型 | 枚举 | 别名 | 引用 | 示例 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| id | 域编号 | 是 | text | — | — | — | D.1 |
| name | 域名称 | 是 | text | — | — | — | 温度控制 |
| trust_level | 信任程度 | 是 | text | Trusted / Semi-Trusted / Untrusted | — | — | Trusted |
| security_domain | 安全域 | 是 | text | Internal / Shared / DMZ / External | — | — | Internal |
| description | 描述 | 否 | text | — | — | — | 文本 |

## 信任边界表

| 字段键 | 中文表头 | 必填 | 类型 | 枚举 | 别名 | 引用 | 示例 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| id | 边界编号 | 是 | text | — | — | — | SB1 |
| name | 边界名称 | 是 | text | — | — | — | 温度控制 |
| description | 边界说明 | 否 | text | — | — | — | 文本 |
| covered_domain_ids | 覆盖域 | 否 | references | — | — | 域属性表 | 引用对应工作表编号 |
| threat_actor_ids | 威胁主体 | 否 | references | — | — | 威胁主体表 | 引用对应工作表编号 |
| enters_internal_propagation | 进入内部传播 | 否 | boolean | 是 / 否 / true / false | — | — | 是 |

## 威胁主体表

| 字段键 | 中文表头 | 必填 | 类型 | 枚举 | 别名 | 引用 | 示例 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| id | 主体编号 | 是 | text | — | — | — | TA-E-1 |
| name | 名称 | 是 | text | — | — | — | 温度控制 |
| actor_type | 类型 | 否 | text | — | — | — | 文本 |
| description | 描述 | 否 | text | — | — | — | 文本 |

## 边界接口表

| 字段键 | 中文表头 | 必填 | 类型 | 枚举 | 别名 | 引用 | 示例 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| id | 接口编号 | 是 | text | — | — | — | BI01 |
| interface_class | 接口类别 | 否 | text | — | — | — | 文本 |
| external_entity | 外部实体 | 否 | text | — | — | — | 文本 |
| access_object | 接入对象 | 否 | text | — | — | — | 文本 |
| physical_interconnect | 物理互联 | 否 | text | — | — | — | 文本 |
| logical_protocol | 逻辑协议 | 否 | text | — | — | — | 文本 |
| direction | 方向 | 否 | text | — | — | — | 文本 |
| boundary_id | 边界编号 | 否 | text | — | — | 信任边界表 | 引用对应工作表编号 |
| description | 描述 | 否 | text | — | — | — | 文本 |

## 系统数据流表

| 字段键 | 中文表头 | 必填 | 类型 | 枚举 | 别名 | 引用 | 示例 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| id | 数据流编号 | 是 | text | — | — | — | SDF01 |
| producer | 产生者 | 否 | text | — | — | — | 文本 |
| consumer | 用户 | 否 | text | — | — | — | 文本 |
| content | 内容 | 否 | text | — | — | — | 文本 |
| data_flow_type | 数据流类型 | 否 | text | CMD / CONFIG / STATE / DATA / LOAD / ALERT / SENSOR | — | — | DATA |
| target_function | 目标功能 | 否 | text | — | — | 功能资产 | 引用对应工作表编号 |

## 旧模板适配与来源

- 识别已知旧表头“接口资产”：物理接口、逻辑接口、网络域、区域和目的按名称映射，不把物理接口当作数据流类型。
- 识别旧五列“数据资产”：加载描述来自原 D 列，资产说明来自原 E 列。
- 不猜测未知列顺序。错误表头、非法值及重复编号定位到原 Sheet、行、字段和编号。原始字段坐标随记录保存；旧格式转换不会将新列号冒充旧列号。
- 引用采用对应表编号。网络域和目标功能也兼容旧格式描述，AMS 解释仍受版本化转换限制；无法唯一绑定系统数据流或边界接口端点时会给出诊断。
- 自动资产、连接、候选威胁和目标推断与原始清单分开展示。自动威胁不会升级为人工确认事实。
- 边界接口和系统数据流补充记录进入 v2 核心；原 DPS 未使用的额外连接标记 dps_enabled=false。预览显示此边界，保留原算法输入边集合。
- 模板中的“必填”描述单条记录的字段要求，转换规则可能要求更多业务信息。例如边界接口需要通过接入对象或引用绑定 1–2 个资产，系统数据流的产生者和用户必须唯一定位到资产。
