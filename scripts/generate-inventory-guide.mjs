import { writeFile, mkdir } from "node:fs/promises";
import { inventoryFields, sheetNames } from "@attackgraph/contracts";
let content=`# 九类 Sheet 系统资产清单填写指南\n\n契约：cxf_asset_inventory_v1。字段定义来源：packages/contracts/src/inventory.ts 与 inventoryFields.ts；解析器、模板下载、字段帮助及后端诊断共用这些定义。本文件通过 scripts/generate-inventory-guide.mjs 生成。\n\n下载当前模板会生成全部九类工作表。功能资产、边界数据流表、数据资产是旧模板也必须包含的三类 Sheet，其他旧模板缺失的 Sheet 按空表兼容。空模板可解析，但功能资产、边界数据流和数据资产至少各有一条记录才能提交。不要删除表头，编号不允许重复；正文中的空行保留真实行号。布尔值只能填写 是/否、true/false、yes/no、1/0 等明确值，不能填写“可能”。\n\n首次使用请下载填写示例，再通过正常上传、预览和提交保存。保留原始工作簿，转换仅在内存中处理副本，不原地改写。\n\nAMS 转换必须明确使用 DO356A-AMS。字段枚举通过后仍需满足版本化转换规则的适用性；不能据此宣称支持其他机型。\n\n`;
const escape=value=>String(value??"—").replaceAll("|","/").replaceAll("\n"," ");
for(const [key,fields] of Object.entries(inventoryFields)){
  content+=`## ${sheetNames[key]}\n\n| 字段键 | 中文表头 | 必填 | 类型 | 枚举 | 别名 | 引用 | 示例 |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n`;
  for(const f of fields)content+=`| ${[f.key,f.header,f.required?"是":"否",f.type,f.enum.join(" / ")||"—",f.aliases.join(" / ")||"—",f.reference?sheetNames[f.reference]:"—",f.example].map(escape).join(" | ")} |\n`;
  content+="\n";
}
content+=`## 旧模板适配与来源\n\n- 识别已知旧表头“接口资产”：物理接口、逻辑接口、网络域、区域和目的按名称映射，不把物理接口当作数据流类型。\n- 识别旧五列“数据资产”：加载描述来自原 D 列，资产说明来自原 E 列。\n- 不猜测未知列顺序。错误表头、非法值及重复编号定位到原 Sheet、行、字段和编号。原始字段坐标随记录保存；旧格式转换不会将新列号冒充旧列号。\n- 引用采用对应表编号。网络域和目标功能也兼容旧格式描述，AMS 解释仍受版本化转换限制；无法唯一绑定系统数据流或边界接口端点时会给出诊断。\n- 自动资产、连接、候选威胁和目标推断与原始清单分开展示。自动威胁不会升级为人工确认事实。\n- 边界接口和系统数据流补充记录进入 v2 核心；原 DPS 未使用的额外连接标记 dps_enabled=false。预览显示此边界，保留原算法输入边集合。\n- 模板中的“必填”描述单条记录的字段要求，转换规则可能要求更多业务信息。例如边界接口需要通过接入对象或引用绑定 1–2 个资产，系统数据流的产生者和用户必须唯一定位到资产。\n`;
await mkdir(new URL("../docs/production/",import.meta.url),{recursive:true});
await writeFile(new URL("../docs/production/inventory-template.md",import.meta.url),content);
