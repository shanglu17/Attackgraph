# CXF Excel 导入对接契约

## 1. 目标

本文档定义“CXF 飞机信息系统资产清单”与 Attackgraph 后端之间的对接 JSON 契约。

设计原则：

- 对外契约贴近 Excel 原模板结构，便于业务方生成和校验
- 后端内部再将该 JSON 映射为图谱模型与 `GraphChangeSet`
- `preview` 与 `commit` 使用同一份请求体
- 未来如需支持 Excel 导出，可复用同一份字段定义做反向映射

## 2. 接口定义

建议提供以下接口：

- `POST /imports/cxf-asset-inventory/preview`
- `POST /imports/cxf-asset-inventory/commit`

可选导出接口：

- `GET /exports/cxf-asset-inventory.xlsx`

## 3. 请求 JSON 模板

```json
{
  "template_version": "cxf_asset_inventory_v1",
  "source": {
    "aircraft_model": "CXF",
    "file_name": "附件1：CXF飞机信息系统资产清单-示例.xls",
    "submitted_by": "partner-system",
    "submitted_at": "2026-03-19T21:35:23Z"
  },
  "workbook": {
    "functional_assets": [
      {
        "id": "SF.1",
        "name": "提供数据交换和网络连接管理",
        "description": "为系统内设备间和交联系统间的数据交换提供连接和网络管理服务"
      }
    ],
    "interface_assets": [
      {
        "id": "SI.1",
        "producer": "信息系统（提供驾驶舱打印）",
        "consumer": "驾驶舱打印机",
        "data_flow_description": "打印任务下发",
        "physical_interface": "Ethernet",
        "logical_interface": "ARINC664P7",
        "network_domain": "信息服务域",
        "zone": "驾驶舱",
        "purpose": "打印"
      }
    ],
    "support_assets": [
      {
        "id": "SD.1",
        "name": "GIPC",
        "linked_interfaces": ["SI.1", "SI.2"]
      }
    ],
    "data_assets": [
      {
        "id": "ACD.1",
        "name": "飞机构型数据",
        "data_type": "配置数据",
        "load_description": "地面加载",
        "description": "供机载信息系统使用"
      }
    ]
  }
}
```

## 4. 请求字段说明

### 4.1 顶层字段

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `template_version` | string | 是 | 模板版本，固定先使用 `cxf_asset_inventory_v1` |
| `source` | object | 是 | 导入来源信息 |
| `workbook` | object | 是 | 对应 Excel 工作簿内容 |

### 4.2 `source`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `aircraft_model` | string | 是 | 机型标识，例如 `CXF` |
| `file_name` | string | 否 | 原始 Excel 文件名 |
| `submitted_by` | string | 是 | 调用方系统或用户标识 |
| `submitted_at` | string | 是 | ISO 8601 时间 |

### 4.3 `workbook`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `functional_assets` | array | 是 | 对应 sheet `功能资产` |
| `interface_assets` | array | 是 | 对应 sheet `接口资产` |
| `support_assets` | array | 是 | 对应 sheet `支持资产` |
| `data_assets` | array | 是 | 对应 sheet `数据资产` |

说明：

- 四个数组必须始终出现
- 没有数据时传空数组 `[]`
- 不允许缺省整个 sheet 字段

### 4.4 `functional_assets[]`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | string | 是 | Excel 列 `编号`，如 `SF.1` |
| `name` | string | 是 | Excel 列 `功能资产名称` |
| `description` | string | 否 | Excel 列 `资产说明` |

### 4.5 `interface_assets[]`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | string | 是 | Excel 列 `接口编号`，如 `SI.1` |
| `producer` | string | 是 | Excel 列 `产生者` |
| `consumer` | string | 是 | Excel 列 `用户` |
| `data_flow_description` | string | 否 | Excel 列 `数据流描述` |
| `physical_interface` | string | 否 | Excel 列 `物理接口` |
| `logical_interface` | string | 否 | Excel 列 `逻辑接口` |
| `network_domain` | string | 否 | Excel 列 `网络域` |
| `zone` | string | 否 | Excel 列 `区域` |
| `purpose` | string | 否 | Excel 列 `目的` |

### 4.6 `support_assets[]`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | string | 是 | Excel 列 `编号`，如 `SD.1` |
| `name` | string | 是 | Excel 列 `名称` |
| `linked_interfaces` | array[string] | 否 | Excel 列 `交联接口`，建议调用方拆成数组 |

### 4.7 `data_assets[]`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | string | 是 | Excel 列 `编号`，如 `ACD.1` |
| `name` | string | 是 | Excel 列 `数据名称` |
| `data_type` | string | 否 | Excel 列 `数据类型` |
| `load_description` | string | 否 | Excel 列 `加载描述` |
| `description` | string | 否 | Excel 列 `资产说明` |

## 5. 调用约束

建议双方约定以下规则：

- 所有字符串默认去首尾空格
- 空值统一使用 `null` 或字段省略，不使用 `" "` 这类伪空值
- `submitted_at` 必须为 ISO 8601
- 每个数组内部 `id` 必须唯一
- `linked_interfaces` 必须传数组，不建议传逗号拼接字符串
- 若调用方仍以 Excel 上传，建议由调用方或网关先解析为上述 JSON 再调用接口

## 6. Preview 响应

`preview` 只做模板校验、字段校验、映射校验和绑定校验，不写库。

### 6.1 成功示例

```json
{
  "ok": true,
  "accepted": {
    "functional_assets": 12,
    "interface_assets": 18,
    "support_assets": 6,
    "data_assets": 9
  },
  "summary": {
    "asset_nodes_to_add": 45,
    "asset_edges_to_add": 28,
    "warnings": []
  },
  "errors": []
}
```

### 6.2 失败示例

```json
{
  "ok": false,
  "accepted": {
    "functional_assets": 12,
    "interface_assets": 17,
    "support_assets": 6,
    "data_assets": 9
  },
  "summary": {
    "asset_nodes_to_add": 44,
    "asset_edges_to_add": 27,
    "warnings": []
  },
  "errors": [
    {
      "type": "field",
      "sheet": "interface_assets",
      "row": 5,
      "field": "consumer",
      "message": "consumer is required"
    },
    {
      "type": "binding",
      "sheet": "support_assets",
      "row": 3,
      "field": "linked_interfaces",
      "message": "referenced interface does not exist: SI.99"
    }
  ]
}
```

## 7. Commit 响应

`commit` 在 `preview` 通过后执行原子提交。任意绑定失败或语义校验失败，整批拒绝。

### 7.1 成功示例

```json
{
  "committed": true,
  "commit_id": "4b7a43f4-7f18-4e3a-9d89-99c66d3c4b15",
  "new_version": "v_1773912456789",
  "summary": {
    "asset_nodes_added": 45,
    "asset_edges_added": 28
  },
  "errors": []
}
```

### 7.2 失败示例

```json
{
  "committed": false,
  "errors": [
    {
      "type": "binding",
      "sheet": "support_assets",
      "row": 3,
      "field": "linked_interfaces",
      "message": "referenced interface does not exist: SI.99"
    }
  ]
}
```

## 8. Excel 四个 Sheet 到内部图谱的映射建议

以下是推荐的第一版映射，目的是先把“资产清单模板”接入现有图谱模型。

### 8.1 `功能资产`

建议映射为 `AssetNode`：

- `id` -> 外部业务编号，保留在扩展字段或标签中
- 系统内部 `asset_id` -> 由后端生成，例如 `SYS-SF-001`
- `name` -> `asset_name`
- `description` -> `description`
- `asset_type` -> 固定映射为 `Terminal`

### 8.2 `接口资产`

建议拆成两部分：

1. 作为 `AssetNode`
- `id` -> 外部业务编号
- 内部 `asset_id` -> 例如 `IF-SI-001`
- `producer + consumer + purpose` 可拼成 `asset_name`
- `logical_interface`、`physical_interface`、`network_domain`、`zone` 写入 `description` 或扩展字段
- `asset_type` -> 固定映射为 `Interface`

2. 生成 `AssetEdge`
- 若 `producer` 和 `consumer` 可解析到已存在资产，则生成一条边
- `link_type` 可固定为 `DataFlow` 或 `Logical`
- `protocol_or_medium` 优先取 `logical_interface`，其次取 `physical_interface`
- `description` 写入 `data_flow_description`

说明：

- 这一部分是整个设计里最需要提前冻结的，因为 Excel 中的 `producer/consumer` 是业务名称，不一定天然等于系统里的主键

### 8.3 `支持资产`

建议映射为 `AssetNode`：

- 内部 `asset_id` -> 例如 `SYS-SD-001`
- `name` -> `asset_name`
- `asset_type` -> 可先映射为 `Terminal`
- `linked_interfaces` -> 为该支持资产与接口资产生成关系边

### 8.4 `数据资产`

建议映射为 `AssetNode`：

- 内部 `asset_id` -> 例如 `SYS-ACD-001`
- `name` -> `asset_name`
- `asset_type` -> 固定映射为 `Data`
- `data_type` -> 映射到 `data_classification` 或扩展字段
- `load_description` 与 `description` -> 写入 `description`

## 9. 需要双方提前确认的关键规则

真正对接前，建议把下面几条先定死：

### 9.1 主键规则

- Excel 中的 `SF.1 / SI.1 / SD.1 / ACD.1` 是否直接作为系统主键
- 还是仅作为外部业务编号，系统内部另行生成 `asset_id`

推荐：

- Excel 编号作为 `external_id`
- 系统内部继续使用现有规范化 `asset_id`

### 9.2 名称匹配规则

`interface_assets.producer` 与 `consumer` 如何匹配到系统资产：

- 严格按名称完全匹配
- 按 `external_id` 匹配
- 由调用方额外提供 `producer_ref` / `consumer_ref`

推荐：

- 第一版直接增加 `producer_ref` 与 `consumer_ref` 可选字段
- 当存在 `*_ref` 时优先按引用匹配
- 只有没有引用时才退回名称匹配

建议增强后的 `interface_assets`：

```json
{
  "id": "SI.1",
  "producer": "信息系统（提供驾驶舱打印）",
  "producer_ref": "SF.4",
  "consumer": "驾驶舱打印机",
  "consumer_ref": "SD.3",
  "data_flow_description": "打印任务下发",
  "physical_interface": "Ethernet",
  "logical_interface": "ARINC664P7",
  "network_domain": "信息服务域",
  "zone": "驾驶舱",
  "purpose": "打印"
}
```

### 9.3 枚举映射规则

需提前约定：

- `network_domain` -> `security_domain`
- `data_type` -> `data_classification`
- `physical_interface / logical_interface` -> `protocol_or_medium`

推荐第一版：

- 未能稳定映射的字段先保留到 `description`
- 等业务方给出正式枚举表后，再做结构化枚举收敛

### 9.4 导入范围

这份模板只适合承载：

- AssetNode
- 部分 AssetEdge

它不适合直接承载：

- ThreatPoint
- AttackPath
- DO326A_Link

因此建议把它定义为“资产清单导入模板”，不要定义为“完整建模结果模板”。

## 10. 推荐的最终对外契约

如果你要和对方正式对接，我建议你给他下面这份更稳的版本：

```json
{
  "template_version": "cxf_asset_inventory_v1",
  "source": {
    "aircraft_model": "CXF",
    "file_name": "附件1：CXF飞机信息系统资产清单-示例.xls",
    "submitted_by": "partner-system",
    "submitted_at": "2026-03-19T21:35:23Z"
  },
  "workbook": {
    "functional_assets": [],
    "interface_assets": [],
    "support_assets": [],
    "data_assets": []
  }
}
```

在 `interface_assets[]` 中额外支持：

- `producer_ref?: string`
- `consumer_ref?: string`

这样后端做边生成时会稳很多。

## 11. 下一步建议

如果你准备真的开始开发，建议按这个顺序推进：

1. 先冻结“对外 JSON 契约”
2. 再冻结 “sheet -> 内部实体” 映射
3. 再实现 `preview`
4. 最后实现 `commit`
5. 导出 Excel 放在导入稳定之后做

如果需要，我下一步可以继续把这份文档再细化成：

- Zod schema 草案
- `preview/commit` 的后端接口设计
- 字段到 `AssetNode/AssetEdge` 的详细映射表
