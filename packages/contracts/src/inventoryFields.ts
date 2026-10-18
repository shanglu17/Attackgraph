import { cxfImportRequestSchema } from "./inventory.js";
import { z } from "zod";
export type InventorySheet =
  keyof import("./inventory.js").Inventory["workbook"];
export const sheetNames: Record<InventorySheet, string> = {
  functional_assets: "功能资产",
  interface_assets: "边界数据流表",
  support_assets: "支持资产",
  data_assets: "数据资产",
  domain_properties: "域属性表",
  trust_boundaries: "信任边界表",
  threat_actors: "威胁主体表",
  boundary_interfaces: "边界接口表",
  system_data_flows: "系统数据流表",
};
const columns: Record<InventorySheet, Array<[string, string, string?]>> = {
  functional_assets: [
    ["id", "编号"],
    ["name", "功能资产名称"],
    ["description", "资产说明"],
  ],
  interface_assets: [
    ["id", "边界数据流编号"],
    ["producer", "产生者"],
    ["consumer", "用户"],
    ["data_flow_description", "数据流描述"],
    ["data_flow_type", "数据流类型"],
    ["target_function", "目标功能", "functional_assets"],
    ["boundary_interface_id", "所属边界接口", "boundary_interfaces"],
    ["enters_internal_propagation", "进入内部传播"],
    ["physical_interface", "物理接口"],
    ["logical_interface", "逻辑接口"],
    ["network_domain", "网络域", "domain_properties"],
    ["zone", "区域"],
    ["purpose", "目的"],
  ],
  support_assets: [
    ["id", "编号"],
    ["name", "名称"],
    ["linked_interfaces", "交联接口", "interface_assets"],
    ["security_domain", "安全域"],
    ["criticality", "重要性"],
  ],
  data_assets: [
    ["id", "编号"],
    ["name", "数据名称"],
    ["data_type", "数据类型"],
    ["data_flow_type", "数据流类型"],
    ["linked_interfaces", "对应接口", "interface_assets"],
    ["domain_id", "所属域", "domain_properties"],
    ["description", "说明"],
    ["target_function", "目标功能", "functional_assets"],
    ["load_description", "加载描述"],
  ],
  domain_properties: [
    ["id", "域编号"],
    ["name", "域名称"],
    ["trust_level", "信任程度"],
    ["security_domain", "安全域"],
    ["description", "描述"],
  ],
  trust_boundaries: [
    ["id", "边界编号"],
    ["name", "边界名称"],
    ["description", "边界说明"],
    ["covered_domain_ids", "覆盖域", "domain_properties"],
    ["threat_actor_ids", "威胁主体", "threat_actors"],
    ["enters_internal_propagation", "进入内部传播"],
  ],
  threat_actors: [
    ["id", "主体编号"],
    ["name", "名称"],
    ["actor_type", "类型"],
    ["description", "描述"],
  ],
  boundary_interfaces: [
    ["id", "接口编号"],
    ["interface_class", "接口类别"],
    ["external_entity", "外部实体"],
    ["access_object", "接入对象"],
    ["physical_interconnect", "物理互联"],
    ["logical_protocol", "逻辑协议"],
    ["direction", "方向"],
    ["boundary_id", "边界编号", "trust_boundaries"],
    ["description", "描述"],
  ],
  system_data_flows: [
    ["id", "数据流编号"],
    ["producer", "产生者"],
    ["consumer", "用户"],
    ["content", "内容"],
    ["data_flow_type", "数据流类型"],
    ["target_function", "目标功能", "functional_assets"],
  ],
};
const enums: Record<string, string[]> = {
  security_domain: ["Internal", "Shared", "DMZ", "External"],
  criticality: ["Low", "Medium", "High"],
  trust_level: ["Trusted", "Semi-Trusted", "Untrusted"],
  data_flow_type: ["CMD", "CONFIG", "STATE", "DATA", "LOAD", "ALERT", "SENSOR"],
  enters_internal_propagation: ["是", "否", "true", "false"],
};
const examples: Record<string, string> = {
  id: "FA01",
  name: "温度控制",
  enters_internal_propagation: "是",
  security_domain: "Internal",
  criticality: "High",
  data_flow_type: "DATA",
  trust_level: "Trusted",
  load_description: "通过维护链路加载签名配置",
};
export const inventoryFields = Object.fromEntries(
  Object.entries(columns).map(([sheet, values]) => {
    const schema =
      cxfImportRequestSchema.shape.workbook.shape[sheet as InventorySheet];
    const array =
      schema instanceof z.ZodDefault ? schema.removeDefault() : schema;
    const shape = array.element.shape as Record<string, z.ZodTypeAny>;
    return [
      sheet,
      values.map(([key, header, reference]) => ({
        key,
        header,
        required: !shape[key].isOptional(),
        type:
          key === "enters_internal_propagation"
            ? "boolean"
            : key.endsWith("_ids") ||
                (key === "linked_interfaces" && sheet === "support_assets")
              ? "references"
              : "text",
        enum: enums[key] ?? [],
        aliases:
          sheet === "interface_assets" && key === "id"
            ? ["接口编号"]
            : sheet === "data_assets" && key === "description"
              ? ["资产说明"]
              : [],
        reference,
        example: key === "id" ? ({functional_assets:"FA01",interface_assets:"SI.1",support_assets:"SSA.1",data_assets:"DA01",domain_properties:"D.1",trust_boundaries:"SB1",threat_actors:"TA-E-1",boundary_interfaces:"BI01",system_data_flows:"SDF01"} as Record<string,string>)[sheet] : examples[key] ?? (reference ? "引用对应工作表编号" : "文本"),
      })),
    ];
  }),
) as Record<
  InventorySheet,
  Array<{
    key: string;
    header: string;
    required: boolean;
    type: string;
    enum: string[];
    aliases: string[];
    reference?: string;
    example: string;
  }>
>;
export const fullSheetHeaders = Object.fromEntries(
  Object.entries(inventoryFields).map(([sheet, fields]) => [
    sheet,
    fields.map((f) => f.header),
  ]),
) as Record<InventorySheet, string[]>;
export const sheetAliases = { 接口资产: "边界数据流表" };
