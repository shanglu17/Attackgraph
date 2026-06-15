"""
Generate docs/资产清单_v3_可导入.xlsx
Sample data uses ZG-ONE PSRA report (202605150007) Table 5-3 / Table 5-4 real data.
Row ID = SD data-flow ID; 接口编号 field carries SD + SI reference.
"""
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

wb = Workbook()
thin = Side(border_style="thin", color="CCCCCC")


def bdr():
    return Border(left=thin, right=thin, top=thin, bottom=thin)


def bold_w():
    return Font(bold=True, size=10, color="FFFFFF")


def norm():
    return Font(size=10)


def ctr():
    return Alignment(horizontal="center", vertical="center", wrap_text=True)


def lft():
    return Alignment(horizontal="left", vertical="center", wrap_text=True)


def fill(c):
    return PatternFill("solid", fgColor=c)


def apply_hdr(ws, headers, widths, color):
    for col, (h, w) in enumerate(zip(headers, widths), 1):
        c = ws.cell(row=1, column=col, value=h)
        c.font = bold_w()
        c.fill = fill(color)
        c.alignment = ctr()
        c.border = bdr()
        ws.column_dimensions[get_column_letter(col)].width = w
    ws.row_dimensions[1].height = 28


def style_row(ws, ri, nc, alt):
    bg = "FFEBF4FF" if alt else "FFFFFFFF"
    for col in range(1, nc + 1):
        c = ws.cell(row=ri, column=col)
        c.font = norm()
        c.alignment = lft()
        c.border = bdr()
        c.fill = fill(bg)


def add_rows(ws, data, nc):
    for ri, row in enumerate(data, 2):
        for ci, v in enumerate(row, 1):
            ws.cell(row=ri, column=ci, value=v)
        style_row(ws, ri, nc, ri % 2 == 0)


def freeze(ws):
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions


# ─── Column definitions ────────────────────────────────────────────────────
# 接口资产: 接口编号 | 产生者 | 用户 | 数据流描述 | 数据流类型 | 物理接口 | 逻辑接口 | 网络域 | 区域 | 目的 | 目标功能
IF_H = ["接口编号", "产生者", "用户", "数据流描述", "数据流类型",
        "物理接口", "逻辑接口", "网络域", "区域", "目的", "目标功能"]
IF_W = [10, 20, 20, 32, 12, 16, 16, 14, 20, 20, 12]

STOP = "以下是样例，请勿填写此行以下内容"

# ─────────────────────────────────────────────────────────────────────────────
# Sheet 1: 接口资产  (rows = one data-flow per row, ID = SD/ACD number)
# Source: ZG-ONE Table 5-4 (系统级数据流) + Table 5-2 (飞机级数据流)
# Physical/Logical interface from Table 5-3 cross-ref where unambiguous
# ─────────────────────────────────────────────────────────────────────────────
ws1 = wb.active
ws1.title = "接口资产"
apply_hdr(ws1, IF_H, IF_W, "FF2B6CB0")

dv1 = DataValidation(type="list",
                     formula1='"CMD,CONFIG,STATE,DATA,LOAD,ALERT"',
                     allow_blank=True, showDropDown=False)
ws1.add_data_validation(dv1)
dv1.sqref = "E2:E500"

# fmt: [接口编号, 产生者, 用户, 数据流描述, 数据流类型,
#        物理接口, 逻辑接口, 网络域, 区域, 目的, 目标功能]
#
# SI ref (Table 5-3):
#  SI01: RCS→DLS, 1.4G射频, 私有协议, 双向
#  SI02: 转发服务器→DLS, 4G/5G, QUIC, 双向
#  SI03: DLS→ICP, CAN, 标准CAN, 双向
#  SI04: DLS→ICP, RS422, 私有协议, 单向
#  SI05: AVCS→DLS, ETH, UDP/RTSP, 双向
#  SI06: DAAS→ICP, CAN, 标准CAN, 双向
#  SI07: EPS→ICP, CAN, 标准CAN, 双向
#  SI08: ES→ICP, CAN, 标准CAN, 双向
#  SI09: HVDS→ICP, CAN, 标准CAN, 双向
#  SI10: PACKS→ICP, CAN, 标准CAN, 双向
#  SI11: NAVS→ICP, RS422, 私有协议, 单向
#  SI12: PES→ICP, CAN, 标准CAN, 双向
#  SI13: GNSS→NAVS, 卫星天线, 模拟信号, 单向
#  SI14: 维护→DLS, ETH, 私有协议, 双向
#  SI15: 维护→EPS, CAN, 标准CAN, 双向
#  SI16: 维护→PACKS, CAN, 标准CAN, 双向
#  SI17: 维护→HVDS, CAN (细节未完全列出)
#  SI18: 维护→ICP, ETH, 双向
#  SI19: 维护→DAAS, USB3.0, 私有协议, 双向
#  SI20: 维护→AVCS, RS232/ETH, 私有协议, 双向
#  SI21: 维护→NAVS, RS422, 私有协议, 双向
#  SI22: 维护→ES, SWD, 单向
#  SI23: 维护→PES, RS232, 私有协议, 双向
#
# Note: Table 5-4 SD20-SD55 uses SI09-SI23 with different producers/consumers
# than what Table 5-3 shows for those SI numbers — known numbering discrepancy
# in the ZG-ONE report. Physical/logical values below reflect Table 5-3 where
# matched; otherwise inferred from connection type.

rows_if = [
    # ── GROUP A: 跨安保边界数据流 (外部→机载) ─────────────────────────────
    # Table 5-4 SD01-SD11 / Table 5-2 ACD01-ACD09
    ["SD01", "RCS", "ACU", "航线规划与任务配置数据（电子围栏/航线/备降点）",
     "CONFIG", "1.4G/4G/5G射频无线", "私有协议/QUIC", "空地数据链(D.2)", "外部非信任域→机载边界域",
     "飞行管理配置", "F3"],

    ["SD02", "RCS", "ACU", "飞机任务与运行控制请求（起飞/悬停/恢复任务/备降等）",
     "CMD", "1.4G/4G/5G射频无线", "私有协议/QUIC", "空地数据链(D.2)", "外部非信任域→机载边界域",
     "飞行控制", "F2,F3,F5"],

    ["SD03", "RCS", "ACU", "地面至机载语音通信数据",
     "DATA", "1.4G/4G/5G射频无线", "私有协议/QUIC", "空地数据链(D.2)", "外部非信任域→机载边界域",
     "语音通信", "F8"],

    ["SD04", "ACU", "RCS", "飞机运行状态（遥测）",
     "STATE", "1.4G/4G/5G射频无线", "私有协议/QUIC", "空地数据链(D.2)", "机载边界域→外部非信任域",
     "状态监控", "F7"],

    ["SD05", "ACU", "RCS", "飞机告警信息",
     "ALERT", "1.4G/4G/5G射频无线", "私有协议/QUIC", "空地数据链(D.2)", "机载边界域→外部非信任域",
     "告警通报", "F5,F7"],

    ["SD06", "ACU", "RCS", "音视频数据（机载→地面）",
     "DATA", "1.4G/4G/5G射频无线", "私有协议/QUIC", "空地数据链(D.2)", "机载边界域→外部非信任域",
     "视频回传", "F7"],

    # ── GROUP B: ACU→ICC/BICC 内部转发 ────────────────────────────────────
    # SI03: DLS→ICP, CAN, 标准CAN
    ["SD07", "ACU", "ICC/BICC", "电子围栏/航线/备降点信息（ACU内部转发）",
     "CONFIG", "CAN", "标准CAN", "机载航电域(D.4)", "机载边界域→机载核心信任域",
     "飞行管理配置", "F3"],

    ["SD08", "ACU", "ICC/BICC", "起飞/悬停/恢复任务/备降等控制指令（ACU转发）",
     "CMD", "CAN", "标准CAN", "机载航电域(D.4)", "机载边界域→机载核心信任域",
     "飞行控制执行", "F5"],

    ["SD09", "ICC/BICC", "ACU", "飞机运行状态（ICC→ACU→地面）",
     "STATE", "CAN", "标准CAN", "机载航电域(D.4)", "机载核心信任域→机载边界域",
     "状态上报", "F7"],

    ["SD10", "ICC/BICC", "ACU", "飞机告警信息（ICC→ACU→地面）",
     "ALERT", "CAN", "标准CAN", "机载航电域(D.4)", "机载核心信任域→机载边界域",
     "告警上报", "F5,F7"],

    # SI04: DLS→ICP, RS422, 私有协议, 单向
    ["SD11", "ACU", "ICC/BICC", "RTCM纠偏数据（差分导航）",
     "STATE", "RS422", "私有协议", "机载航电域(D.4)", "机载边界域→机载核心信任域",
     "差分导航修正", "F4"],

    # ── GROUP C: AVCS 音视频通信 (DATA, 较低风险) ─────────────────────────
    # SI05: AVCS↔DLS, ETH, UDP/RTSP
    ["SD12", "耳机", "CCU", "乘客语音输入",
     "DATA", "有线耳机接口", "音频协议", "机载航电域(D.4)", "机载边界域内部",
     "乘客通话", "F8"],

    ["SD13", "CCU", "耳机", "飞行机组语音输出",
     "DATA", "有线耳机接口", "音频协议", "机载航电域(D.4)", "机载边界域内部",
     "飞行机组通话", "F8"],

    ["SD16", "CCU", "ACU", "乘客语音（舱→链路）",
     "DATA", "ETH", "UDP/RTSP", "机载航电域(D.4)", "机载边界域内部",
     "语音转发", "F8"],

    ["SD19", "ACU", "CCU", "飞行机组语音（链路→舱）",
     "DATA", "ETH", "UDP/RTSP", "机载航电域(D.4)", "机载边界域内部",
     "语音转发", "F8"],

    # ── GROUP D: DAAS 探测与避让 ──────────────────────────────────────────
    # SD23/24/25 via SI06(DAAS→ICP, CAN)
    ["SD23", "DAAS", "ICC/BICC", "障碍物类型/距离等状态信息",
     "STATE", "CAN", "标准CAN", "机载航电域(D.4)", "机载核心信任域内部",
     "探测与避让感知", "F13"],

    ["SD24", "DAAS", "ICC/BICC", "障碍物类型/距离告警及刹停告警建议",
     "ALERT", "CAN", "标准CAN", "机载航电域(D.4)", "机载核心信任域内部",
     "避障告警", "F13"],

    ["SD25", "ICC/BICC", "DAAS", "姿态角/飞行速度等状态数据",
     "STATE", "CAN", "标准CAN", "机载航电域(D.4)", "机载核心信任域内部",
     "姿态同步", "F4"],

    # ── GROUP E: EPS/MCU 推力控制闭环 (Catastrophic 风险) ─────────────────
    # SI07: EPS→ICP, CAN, 标准CAN
    ["SD26", "MCU", "ICC/BICC", "转速等电机状态信息",
     "STATE", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "动力状态监控", "F1,F2,F3,F7"],

    ["SD27", "MCU", "ICC/BICC", "温度/电压/电流等电机状态信息",
     "STATE", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "动力健康监控", "F1,F3,F7"],

    ["SD28", "MCU", "ICC/BICC", "转速/温度/电压/电流/故障代码告警",
     "ALERT", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "动力故障告警", "F1,F2,F7"],

    ["SD29", "ICC/BICC", "MCU", "转速控制指令",
     "CMD", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "推力控制执行", "F1,F2"],

    # ── GROUP F: 电气系统 ES 状态/控制 ────────────────────────────────────
    # SI08: ES→ICP, CAN / SI09: HVDS→ICP, CAN / SI15/SI16
    ["SD30", "DCDC", "ICC/BICC", "电源变换器状态信息",
     "STATE", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "电源状态监控", "F2,F3,F7,F9"],

    ["SD31", "DCDC", "ICC/BICC", "电源变换器告警信息",
     "ALERT", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "电源故障告警", "F2,F7,F9"],

    ["SD32", "LPDU", "ICC/BICC", "低压配电盒状态信息",
     "STATE", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "低压配电监控", "F2,F3,F7,F9"],

    ["SD33", "LPDU", "ICC/BICC", "低压配电盒告警信息",
     "ALERT", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "低压配电告警", "F2,F7,F9"],

    ["SD36", "HPDU", "ICC/BICC", "高压配电盒状态信息",
     "STATE", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "高压配电监控", "F1,F2,F3,F7,F9"],

    ["SD37", "HPDU", "ICC/BICC", "高压配电盒告警信息",
     "ALERT", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "高压配电告警", "F1,F2,F7,F9"],

    ["SD38", "ICC/BICC", "HPDU", "空地状态等信息下发",
     "STATE", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "高压配电控制", "F1,F9"],

    ["SD38a", "ICC/BICC", "LPDU", "通道开关/复位指令",
     "CMD", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "低压配电控制", "F2,F9"],

    ["SD38b", "ICC/BICC", "DCDC", "电源变换器复位指令",
     "CMD", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "电源复位控制", "F2,F9"],

    # ── GROUP G: BMS 动力电池控制闭环 (Catastrophic 风险) ─────────────────
    # SI10: PACKS→ICP, CAN / SI18(ETH, 维护→ICP)
    ["SD39", "BMS", "ICC/BICC", "动力电池BMS状态信息",
     "STATE", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "电池状态监控", "F1,F2,F3,F7,F9"],

    ["SD40", "BMS", "ICC/BICC", "动力电池BMS告警信息",
     "ALERT", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "电池故障告警", "F1,F2,F7,F9"],

    ["SD41", "ICC/BICC", "BMS", "航空器空地状态信息",
     "STATE", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "空地状态同步", "F1,F9"],

    ["SD42", "ICC/BICC", "BMS", "高压上下电指令",
     "CMD", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "动力电池控制", "F1,F9"],

    # ── GROUP H: 导航系统 (Major/Hazardous 风险) ──────────────────────────
    # SI11: NAVS→ICP, RS422, 私有协议 / SI13: GNSS→NAVS, 卫星天线
    ["SD43", "高精度光纤组合导航", "ICC/BICC", "导航计算机/卫星接收机等状态信息",
     "STATE", "RS422", "私有协议", "机载控制域(D.5)", "机载核心信任域内部",
     "导航系统健康监控", "F2,F3,F4,F7"],

    ["SD43b", "高精度光纤组合导航", "ICC/BICC", "航向/姿态/速度/加速度/位置数据",
     "DATA", "RS422", "私有协议", "机载控制域(D.5)", "机载核心信任域内部",
     "导航融合输入", "F2,F3,F4,F7"],

    ["SD44", "高精度光纤组合导航", "ICC/BICC", "航向/姿态/速度/加速度/GNSS位置告警",
     "ALERT", "RS422", "私有协议", "机载控制域(D.5)", "机载核心信任域内部",
     "导航异常告警", "F2,F3,F4,F7"],

    ["SD45", "ICC/BICC", "高精度光纤组合导航", "RTCM纠偏数据",
     "DATA", "RS422", "私有协议", "机载控制域(D.5)", "机载核心信任域内部",
     "差分导航修正", "F4"],

    ["SD46", "MEMS组合导航", "ICC/BICC", "导航计算机/卫星接收机等状态信息",
     "STATE", "RS422", "私有协议", "机载控制域(D.5)", "机载核心信任域内部",
     "备份导航状态", "F2,F3,F4,F7"],

    ["SD47", "MEMS组合导航", "ICC/BICC", "航向/姿态/速度/加速度/GNSS位置告警",
     "ALERT", "RS422", "私有协议", "机载控制域(D.5)", "机载核心信任域内部",
     "备份导航告警", "F2,F4,F7"],

    ["SD48", "ICC/BICC", "MEMS组合导航", "RTCM纠偏数据",
     "STATE", "RS422", "私有协议", "机载控制域(D.5)", "机载核心信任域内部",
     "备份导航修正", "F2,F3,F4,F7"],

    ["SD49", "无线电高度表", "ICC/BICC", "无线电高度表状态信息及相对高度数据",
     "STATE", "RS422", "私有协议", "机载控制域(D.5)", "机载核心信任域内部",
     "高度感知", "F2,F3,F4,F7"],

    ["SD50", "无线电高度表", "ICC/BICC", "相对高度告警信息",
     "ALERT", "RS422", "私有协议", "机载控制域(D.5)", "机载核心信任域内部",
     "低高度告警", "F2,F3,F4,F7"],

    # ── GROUP I: PES 伞降应急系统 (Catastrophic/Hazardous 风险) ───────────
    # SI12: PES→ICP, CAN, 标准CAN
    ["SD51", "PES", "ICC/BICC", "伞降系统状态信息",
     "STATE", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "伞降系统状态", "F5,F7"],

    ["SD52", "PES", "ICC/BICC", "伞降系统告警信息",
     "ALERT", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "伞降系统告警", "F5,F7"],

    ["SD53", "ICC/BICC", "PES", "开伞指令",
     "CMD", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "应急开伞控制", "F5,F2"],

    ["SD54", "ICC/BICC", "PES", "加解锁指令",
     "CMD", "CAN", "标准CAN", "机载控制域(D.5)", "机载核心信任域内部",
     "伞降安保控制", "F5"],

    # SI13: GNSS→NAVS, 卫星天线, 模拟信号, 单向
    ["SD55", "GNSS", "PES", "GNSS卫星数据（PES定位用）",
     "STATE", "卫星天线", "射频信号", "外部信号", "外部非信任域→机载核心信任域",
     "应急定位", "F4"],

    # ── GROUP J: 维护接口 (Catastrophic 风险, LOAD类最高) ─────────────────
    # SI14: 维护→DLS, ETH; SI18: 维护→ICP, ETH; SI19: 维护→DAAS, USB3.0
    # SI21: 维护→NAVS, RS422; SI23: 维护→PES, RS232; SI15: 维护→EPS, CAN
    # Note: 报告Table 5-4使用SI24-SI31, Table 5-3只到SI23; 下方使用Table 5-4的编号
    ["SD56", "地面维护设备", "ACU", "ACU配置文件",
     "CONFIG", "ETH", "私有协议", "地面维护域(D.6)", "外部非信任域→机载边界域",
     "链路系统配置维护", "F8"],

    ["SD57", "地面维护设备", "ACU", "ACU管理软件",
     "LOAD", "ETH", "私有协议", "地面维护域(D.6)", "外部非信任域→机载边界域",
     "链路系统软件维护", "F8"],

    ["SD58", "地面维护设备", "ACU", "ACU日志数据",
     "DATA", "ETH", "私有协议", "地面维护域(D.6)", "机载边界域→外部非信任域",
     "链路系统日志导出", "F10"],

    ["SD59", "地面维护设备", "MCU", "电机控制器配置文件",
     "CONFIG", "CAN", "标准CAN", "地面维护域(D.6)", "外部非信任域→机载核心信任域",
     "动力系统配置维护", "F1,F2"],

    ["SD60", "地面维护设备", "MCU", "电机控制器管理软件/引导加载软件",
     "LOAD", "CAN", "标准CAN", "地面维护域(D.6)", "外部非信任域→机载核心信任域",
     "动力系统软件维护", "F1,F2"],

    ["SD61", "地面维护设备", "BMS", "电池管理系统管理软件/引导加载软件",
     "LOAD", "CAN", "标准CAN", "地面维护域(D.6)", "外部非信任域→机载核心信任域",
     "电池系统软件维护", "F1,F3,F9"],

    ["SD62", "地面维护设备", "ICC/BICC", "综合控制计算机配置/诊断/控制指令",
     "CONFIG", "ETH", "私有协议", "地面维护域(D.6)", "外部非信任域→机载核心信任域",
     "核心计算机配置维护", "F1,F2,F3"],

    ["SD63", "地面维护设备", "ICC/BICC", "综合控制计算机管理软件/引导加载软件",
     "LOAD", "ETH", "私有协议", "地面维护域(D.6)", "外部非信任域→机载核心信任域",
     "核心计算机软件维护", "F1,F2,F3"],

    ["SD64", "地面维护设备", "ICC/BICC", "日志/运行记录/备份导出数据",
     "DATA", "ETH", "私有协议", "地面维护域(D.6)", "机载核心信任域→外部非信任域",
     "核心计算机数据导出", "F10"],

    ["SD65", "地面维护设备", "ICC/BICC", "BICC管理软件/引导加载软件",
     "LOAD", "ETH", "私有协议", "地面维护域(D.6)", "外部非信任域→机载核心信任域",
     "备份计算机软件维护", "F1,F2,F3"],

    ["SD66", "地面维护设备", "DAAS", "探测与避让系统配置文件",
     "CONFIG", "USB3.0", "私有协议", "地面维护域(D.6)", "外部非信任域→机载核心信任域",
     "探测避让系统配置", "F2,F3,F11"],

    ["SD67", "地面维护设备", "DAAS", "探测与避让系统日志",
     "DATA", "USB3.0", "私有协议", "地面维护域(D.6)", "机载核心信任域→外部非信任域",
     "探测避让日志导出", "F10"],

    ["SD68", "地面维护设备", "AVCS", "音视频通信系统配置/诊断/控制指令",
     "CONFIG", "RS232/ETH", "私有协议", "地面维护域(D.6)", "外部非信任域→机载边界域",
     "音视频系统配置维护", "F7,F8"],

    ["SD69", "地面维护设备", "AVCS", "音视频通信系统管理软件/引导加载软件",
     "LOAD", "RS232/ETH", "私有协议", "地面维护域(D.6)", "外部非信任域→机载边界域",
     "音视频系统软件维护", "F7,F8"],

    ["SD71", "地面维护设备", "导航系统", "导航系统（光纤/MEMS组合导航）管理软件/引导加载软件",
     "LOAD", "RS422", "私有协议", "地面维护域(D.6)", "外部非信任域→机载核心信任域",
     "导航系统软件维护", "F2,F3,F4"],

    ["SD72", "地面维护设备", "导航系统", "导航系统软件维护配置",
     "CONFIG", "RS422", "私有协议", "地面维护域(D.6)", "外部非信任域→机载核心信任域",
     "导航系统参数维护", "F2,F3,F4"],

    [STOP, "", "", "", "", "", "", "", "", "", ""],
]

add_rows(ws1, rows_if, len(IF_H))
freeze(ws1)

# ─────────────────────────────────────────────────────────────────────────────
# Sheet 2: 数据资产  (key data items from ZG-ONE)
# ─────────────────────────────────────────────────────────────────────────────
ws2 = wb.create_sheet("数据资产")
DA_H = ["编号", "数据名称", "数据类型", "数据流类型", "对应接口", "所属域", "说明", "目标功能"]
DA_W = [10, 26, 22, 12, 20, 10, 36, 14]
apply_hdr(ws2, DA_H, DA_W, "FF2F855A")

dv2 = DataValidation(type="list",
                     formula1='"CMD,CONFIG,STATE,DATA,LOAD,ALERT"',
                     allow_blank=True, showDropDown=False)
ws2.add_data_validation(dv2)
dv2.sqref = "D2:D200"

rows_da = [
    # 外场可加载软件/配置 (LOAD/CONFIG - Catastrophic)
    ["DA.01", "ICC_APP",       "外场可加载软件", "LOAD",   "SD63",       "D.6", "综合控制计算机(ICC)主应用软件",       "F1,F2,F3"],
    ["DA.02", "BICC_APP",      "外场可加载软件", "LOAD",   "SD65",       "D.6", "备份综合控制计算机(BICC)应用软件",    "F1,F2,F3"],
    ["DA.03", "MCU_APP",       "外场可加载软件", "LOAD",   "SD60",       "D.6", "电机控制器(MCU)管理软件",             "F1,F2"],
    ["DA.04", "BMS_APP",       "外场可加载软件", "LOAD",   "SD61",       "D.6", "电池管理系统(BMS)全功能软件",         "F1,F3,F9"],
    ["DA.05", "NAVS_FW",       "外场可加载软件", "LOAD",   "SD71",       "D.6", "组合导航系统固件（光纤/MEMS）",       "F2,F3,F4"],
    ["DA.06", "DAAS_CONFIG",   "可加载配置文件", "CONFIG", "SD66",       "D.6", "探测与避让系统（DAA）配置参数",       "F2,F3,F11"],
    ["DA.07", "ICC_PARAM",     "可加载配置文件", "CONFIG", "SD62",       "D.6", "ICC飞行参数/导航参数/系统配置",       "F1,F2,F3"],
    ["DA.08", "MCU_PARAM",     "可加载配置文件", "CONFIG", "SD59",       "D.6", "电机控制器配置参数",                  "F1,F2"],
    # 控制指令 (CMD - Catastrophic)
    ["DA.09", "FCS_CMD",       "飞行控制指令",   "CMD",    "SD29",       "D.5", "ICC→MCU转速控制指令",                 "F1,F2"],
    ["DA.10", "BMS_PWR_CMD",   "上下电控制指令", "CMD",    "SD42",       "D.5", "ICC→BMS高压上下电指令",               "F1,F9"],
    ["DA.11", "PES_OPEN_CMD",  "开伞控制指令",   "CMD",    "SD53",       "D.5", "ICC→PES开伞指令（应急）",             "F5,F2"],
    ["DA.12", "RCS_CTRL_CMD",  "运行控制请求",   "CMD",    "SD02",       "D.2", "RCS→ACU任务与运行控制请求",           "F2,F3,F5"],
    # 导航数据 (STATE - Major/Hazardous)
    ["DA.13", "INS_NAV_DATA",  "导航融合数据",   "STATE",  "SD43,SD43b", "D.5", "高精度光纤组合导航 航向/姿态/速度/位置", "F2,F3,F4,F7"],
    ["DA.14", "MEMS_NAV_DATA", "备份导航数据",   "STATE",  "SD46",       "D.5", "MEMS组合导航 航向/姿态/速度/位置",    "F2,F3,F4,F7"],
    ["DA.15", "GNSS_SIGNAL",   "GNSS导航信号",   "STATE",  "SD55",       "D.1", "GNSS卫星定位/时间信号（开放环境）",   "F4"],
    ["DA.16", "RTCM_DATA",     "差分纠偏数据",   "STATE",  "SD11,SD48",  "D.4", "RTK差分纠偏数据",                     "F4"],
    # 遥测状态 (STATE - 监控)
    ["DA.17", "AC_STATE",      "飞机运行状态",   "STATE",  "SD04,SD09",  "D.2", "飞机综合运行状态遥测数据",             "F7"],
    ["DA.18", "MCU_STATE",     "电机状态数据",   "STATE",  "SD26,SD27",  "D.5", "MCU转速/温度/电压/电流状态",          "F1,F3,F7"],
    ["DA.19", "BMS_STATE",     "电池状态数据",   "STATE",  "SD39",       "D.5", "动力电池BMS状态信息",                 "F1,F2,F3,F9"],
    # 任务配置 (CONFIG - Hazardous)
    ["DA.20", "MISSION_CFG",   "任务配置数据",   "CONFIG", "SD01,SD07",  "D.2", "航线/电子围栏/备降点配置",            "F3"],
    # 日志/诊断数据 (DATA - InformationDisclosure)
    ["DA.21", "ICC_LOG",       "诊断日志数据",   "DATA",   "SD64",       "D.6", "ICC运行日志/故障记录/备份数据",       "F10,F11"],
    ["DA.22", "ACU_LOG",       "链路系统日志",   "DATA",   "SD58",       "D.6", "ACU运行日志数据",                     "F10"],
    [STOP, "", "", "", "", "", "", ""],
]
add_rows(ws2, rows_da, len(DA_H))
freeze(ws2)

# ─────────────────────────────────────────────────────────────────────────────
# Sheet 3: 域属性表  (ZG-ONE trust domains per Section 4.2)
# ─────────────────────────────────────────────────────────────────────────────
ws3 = wb.create_sheet("域属性表")
DM_H = ["域编号", "域名称", "信任程度", "安全域", "描述"]
DM_W = [10, 22, 14, 14, 52]
apply_hdr(ws3, DM_H, DM_W, "FF6B46C1")

dv3a = DataValidation(type="list", formula1='"Trusted,Semi-Trusted,Untrusted"', allow_blank=False)
ws3.add_data_validation(dv3a)
dv3a.sqref = "C2:C100"

dv3b = DataValidation(type="list", formula1='"Internal,External,DMZ,Shared"', allow_blank=False)
ws3.add_data_validation(dv3b)
dv3b.sqref = "D2:D100"

# ZG-ONE trust domains (Section 4.2 & 4.3)
rows_dm = [
    ["D.1", "外部非信任域",       "Untrusted",    "External",
     "RCS遥控站/转发服务器/GNSS/RTK/地面维护设备/大数据平台等外部实体。来自此域的数据不默认可信。"],
    ["D.2", "空地数据链",         "Untrusted",    "External",
     "ACU与地面GCU/转发服务器间的射频通信链路（1.4G/4G/5G）。可能经过公网/运营商网络。"],
    ["D.3", "机载边界域",         "Semi-Trusted", "Shared",
     "ACU/GCU/AVCS/CCU等机载边界与通信系统，承担对外音视频业务及链路接入功能。"],
    ["D.4", "机载航电域",         "Trusted",      "Internal",
     "ACU/CCU/DAAS/NAVS等航空电子设备。部分依赖开放环境输入（GNSS/DAA），需一致性校验。"],
    ["D.5", "机载核心信任域",     "Trusted",      "Internal",
     "ICP(ICC/BICC)/FCS/FMS/IMS/EPS/ES/PACKS/HVDS/NAVS/DAAS/PES。直接决定飞行安全，内部通信假定在受控环境。"],
    ["D.6", "地面维护域",         "Semi-Trusted", "External",
     "地面维护设备接入接口（CAN/ETH/RS422/USB等）。具备软件加载/参数配置/诊断权限，属高权限安保入口。"],
    [STOP, "", "", "", ""],
]
add_rows(ws3, rows_dm, len(DM_H))
freeze(ws3)

# ─────────────────────────────────────────────────────────────────────────────
# Sheet 4: 功能资产  (ZG-ONE F1-F13)
# ─────────────────────────────────────────────────────────────────────────────
ws4 = wb.create_sheet("功能资产")
FN_H = ["编号", "功能资产名称", "资产说明"]
FN_W = [8, 24, 54]
apply_hdr(ws4, FN_H, FN_W, "FF975A16")

rows_fn = [
    ["SF.F1",  "提供飞行动力",           "F1: 动力推进控制（EPS/MCU）"],
    ["SF.F2",  "提供飞行控制",           "F2: 姿态控制与飞行执行（FCS/MCU）"],
    ["SF.F3",  "提供飞行管理功能",       "F3: 航迹规划/导航管理/任务管理（FMS）"],
    ["SF.F4",  "提供导航功能",           "F4: 多源导航融合/GNSS/INS（NAVS）"],
    ["SF.F5",  "应急处置",               "F5: 伞降激活/应急供电切换（PES/EPS）"],
    ["SF.F6",  "提供乘员环境支撑",       "F6: 客舱环境监控与支撑功能"],
    ["SF.F7",  "提供飞行组界面显示",     "F7: 状态/告警/视频等显示（IMS/AVCS）"],
    ["SF.F8",  "提供通信",               "F8: DLS链路管理/音视频通信（ACU/AVCS）"],
    ["SF.F9",  "提供电能",               "F9: 供配电管理（ES/BMS/HVDS/PACKS）"],
    ["SF.F10", "提供数据记录功能",       "F10: 飞行日志/运行数据记录"],
    ["SF.F11", "提供维护功能",           "F11: 地面维护/软件加载/参数配置"],
    ["SF.F12", "提供安全保障",           "F12: 系统安全保障功能"],
    ["SF.F13", "提供探测与避让功能",     "F13: DAA 障碍物探测与主动避让（DAAS）"],
    [STOP, "", ""],
]
add_rows(ws4, rows_fn, len(FN_H))
freeze(ws4)

# ─────────────────────────────────────────────────────────────────────────────
# Sheet 5: 支持资产  (ZG-ONE external/support entities)
# ─────────────────────────────────────────────────────────────────────────────
ws5 = wb.create_sheet("支持资产")
SA_H = ["编号", "名称", "交联接口"]
SA_W = [10, 28, 36]
apply_hdr(ws5, SA_H, SA_W, "FF975A16")

rows_sa = [
    ["ASA.01", "RCS遥控站终端",                   "SD01, SD02, SD03, SD04, SD05, SD06"],
    ["ASA.02", "GCU地面通信单元",                 "SD01, SD02, SD04, SD05"],
    ["ASA.03", "转发服务器",                       "SD01, SD02, SD04, SD05"],
    ["ASA.04", "GNSS/RTK服务",                    "SD55"],
    ["ASA.05", "地面维护设备",                     "SD56, SD57, SD59, SD60, SD61, SD62, SD63, SD66, SD71"],
    [STOP, "", ""],
]
add_rows(ws5, rows_sa, len(SA_H))
freeze(ws5)

# ─────────────────────────────────────────────────────────────────────────────
# Sheet 6: STRIDE映射表  (reference only – not parsed)
# Mapping: data_flow_type → STRIDE category, per ZG-ONE threat analysis
# ─────────────────────────────────────────────────────────────────────────────
ws6 = wb.create_sheet("STRIDE映射表")
ST_H = ["数据流类型", "主要STRIDE类别", "典型攻击模式(ZG-ONE TC)", "安保措施方向", "FHA严重度参考"]
ST_W = [14, 26, 42, 48, 20]
apply_hdr(ws6, ST_H, ST_W, "FF9B2C2C")

stride_data = [
    ["CMD",
     "Spoofing + Tampering",
     "TC1未授权指令注入 / TC2指令篡改 / TC3指令重放\nTC11推力指令异常 / TC14非法上下电 / TC15伞降误触发",
     "双向认证(双向TLS或等效) + 完整性保护(MAC/签名)\n序列号+时间窗校验 + 运行状态门控",
     "Catastrophic / Hazardous"],
    ["CONFIG",
     "Tampering",
     "TC4配置数据恶意修改(航线/围栏)\nTC9未授权维护访问 + 参数篡改",
     "签名 + 语义约束检查 + 版本控制\n强认证 + RBAC访问控制",
     "Hazardous / Major"],
    ["LOAD",
     "Tampering",
     "TC8恶意软件加载(维护接口)\nTC9未授权维护访问",
     "Secure Boot + 软件签名验证\n完整性链 + 强认证 + RBAC",
     "Catastrophic"],
    ["STATE",
     "Spoofing",
     "TC5 GNSS欺骗 / TC7 RTCM注入\nTC12 MCU状态反馈伪造 / TC20导航融合异常",
     "多源融合一致性校验 + 异常检测\n可信度评估 + INS/RAIM冗余",
     "Major / Hazardous"],
    ["ALERT",
     "Tampering + DenialOfService",
     "TC16控制闭环DoS(总线阻塞)\nTC18避障告警抑制 / TC22告警信息篡改",
     "完整性保护 + 实时调度 + 带宽隔离\n告警超时检测 + 失效安全策略",
     "Hazardous / Catastrophic"],
    ["DATA",
     "InformationDisclosure",
     "TC21状态数据泄露 / TC23视频流劫持\n维护日志导出数据暴露",
     "加密传输(TLS) + 访问控制\n流媒体加密",
     "Minor / Major"],
]
bgs = ["FFFFF5F5", "FFF0FFF4", "FFFFF5F5", "FFEBF8FF", "FFFFF5F5", "FFF0FFF4"]
for ri, (row, bg) in enumerate(zip(stride_data, bgs), 2):
    for ci, v in enumerate(row, 1):
        c = ws6.cell(row=ri, column=ci, value=v)
        c.font = norm()
        c.alignment = lft()
        c.border = bdr()
        c.fill = fill(bg)
    ws6.row_dimensions[ri].height = 52

note = ws6.cell(
    row=9, column=1,
    value="[说明] 此表为参考，不参与系统解析。接口资产/数据资产填写数据流类型后，系统按此映射自动生成STRIDE威胁节点及攻击路径分析。威胁状态编号(TC)参见 ZG-ONE 202605150007 第6章。",
)
note.font = Font(italic=True, size=9, color="555555")
note.alignment = lft()
ws6.merge_cells("A9:E9")
ws6.row_dimensions[1].height = 28
ws6.freeze_panes = "A2"

# ─────────────────────────────────────────────────────────────────────────────
# Finalize
# ─────────────────────────────────────────────────────────────────────────────
wb._sheets = [ws1, ws2, ws3, ws4, ws5, ws6]

out = r"E:/document/airness/project/Attackgraph/docs/资产清单_v3_可导入.xlsx"
wb.save(out)
print("Saved:", out)
print(f"  接口资产 rows: {len(rows_if) - 1}")
print(f"  数据资产 rows: {len(rows_da) - 1}")
print(f"  域属性表 rows: {len(rows_dm) - 1}")
print(f"  功能资产 rows: {len(rows_fn) - 1}")
print(f"  支持资产 rows: {len(rows_sa) - 1}")
