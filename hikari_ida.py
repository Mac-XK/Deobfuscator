"""
Hikari 混淆还原插件 - IDA Pro
功能: CFF 去平坦化、不透明谓词消除、字符串解密标注、Hook 目标提取

安装: 复制到 IDA plugins 目录
使用: Edit -> Plugins -> Hikari 混淆还原  (或 Ctrl+Shift+H)
"""

import os
import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_name
import ida_ua
import ida_nalt
from collections import defaultdict

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QCheckBox, QGroupBox, QFileDialog,
    QMessageBox, QFrame, QApplication,
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def get_arm64_insn(ea):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) > 0:
        return insn
    return None


def patch_nop(ea):
    ida_bytes.patch_dword(ea, 0xD503201F)


def read_dword(ea):
    return ida_bytes.get_dword(ea)


# ---------------------------------------------------------------------------
# 不透明谓词求值器
# ---------------------------------------------------------------------------

class OpaquePredResolver:

    def find_and_resolve(self, func_ea):
        results = []
        func = ida_funcs.get_func(func_ea)
        if not func:
            return results

        ea = func.start_ea
        while ea < func.end_ea:
            insn = get_arm64_insn(ea)
            if insn and insn.itype == idaapi.ARM_cset:
                chain_start = self._find_chain_start(ea, func.start_ea)
                if chain_start:
                    result = self._evaluate_chain(chain_start, ea)
                    if result is not None:
                        results.append({
                            "chain_start": chain_start,
                            "cset_ea": ea,
                            "result": result,
                        })
            ea = idc.next_head(ea, func.end_ea)
        return results

    def _find_chain_start(self, cset_ea, func_start):
        ea = cset_ea
        for _ in range(40):
            ea = idc.prev_head(ea, func_start)
            if ea == idaapi.BADADDR:
                break
            mnem = idc.print_insn_mnem(ea)
            if mnem == "LDR":
                op_str = idc.print_operand(ea, 1)
                if "0x14" in op_str or "#0x" in op_str:
                    return ea
        return None

    def _evaluate_chain(self, start_ea, cset_ea):
        regs = {}
        ea = start_ea
        while ea <= cset_ea:
            mnem = idc.print_insn_mnem(ea)
            insn = get_arm64_insn(ea)
            if not insn:
                ea = idc.next_head(ea, cset_ea + 4)
                continue

            if mnem == "LDR" and insn.ops[0].type == idaapi.o_reg:
                reg = insn.ops[0].reg
                if insn.ops[1].type == idaapi.o_displ:
                    base = insn.ops[1].reg
                    disp = insn.ops[1].addr
                    if base in regs:
                        addr = regs[base] + disp
                        val = read_dword(addr)
                        if val is not None:
                            regs[reg] = val & 0xFFFFFFFF


            elif mnem == "MOV" and insn.ops[0].type == idaapi.o_reg:
                reg = insn.ops[0].reg
                if insn.ops[1].type == idaapi.o_imm:
                    regs[reg] = insn.ops[1].value & 0xFFFFFFFF
                elif insn.ops[1].type == idaapi.o_reg:
                    src = insn.ops[1].reg
                    if src in regs:
                        regs[reg] = regs[src]

            elif mnem == "MOVK" and insn.ops[0].type == idaapi.o_reg:
                reg = insn.ops[0].reg
                if reg in regs and insn.ops[1].type == idaapi.o_imm:
                    val = insn.ops[1].value & 0xFFFF
                    shift = insn.ops[1].specflag1 if hasattr(insn.ops[1], 'specflag1') else 0
                    op_str = idc.print_operand(ea, 1)
                    if "LSL#16" in op_str.replace(" ", "").upper() or "LSL #16" in op_str.upper():
                        shift = 16
                    mask = ~(0xFFFF << shift) & 0xFFFFFFFF
                    regs[reg] = (regs[reg] & mask) | (val << shift)

            elif mnem == "EOR" and insn.ops[0].type == idaapi.o_reg:
                dst = insn.ops[0].reg
                v1 = regs.get(insn.ops[1].reg) if insn.ops[1].type == idaapi.o_reg else None
                v2 = regs.get(insn.ops[2].reg) if insn.ops[2].type == idaapi.o_reg else None
                if v1 is not None and v2 is not None:
                    regs[dst] = (v1 ^ v2) & 0xFFFFFFFF

            elif mnem == "ORR" and insn.ops[0].type == idaapi.o_reg:
                dst = insn.ops[0].reg
                v1 = regs.get(insn.ops[1].reg) if insn.ops[1].type == idaapi.o_reg else None
                v2 = regs.get(insn.ops[2].reg) if insn.ops[2].type == idaapi.o_reg else None
                if v1 is not None and v2 is not None:
                    regs[dst] = (v1 | v2) & 0xFFFFFFFF

            elif mnem == "ADD" and insn.ops[0].type == idaapi.o_reg:
                dst = insn.ops[0].reg
                v1 = regs.get(insn.ops[1].reg) if insn.ops[1].type == idaapi.o_reg else None
                v2 = (insn.ops[2].value if insn.ops[2].type == idaapi.o_imm
                      else regs.get(insn.ops[2].reg) if insn.ops[2].type == idaapi.o_reg
                      else None)
                if v1 is not None and v2 is not None:
                    regs[dst] = (v1 + v2) & 0xFFFFFFFF


            elif mnem in ("SUB", "SUBS") and insn.ops[0].type == idaapi.o_reg:
                dst = insn.ops[0].reg
                v1 = regs.get(insn.ops[1].reg) if insn.ops[1].type == idaapi.o_reg else None
                v2 = regs.get(insn.ops[2].reg) if insn.ops[2].type == idaapi.o_reg else None
                if v1 is not None and v2 is not None:
                    result = (v1 - v2) & 0xFFFFFFFF
                    regs[dst] = result
                    regs["_c"] = 1 if v1 >= v2 else 0
                    regs["_z"] = 1 if result == 0 else 0
                    regs["_n"] = 1 if result & 0x80000000 else 0

            elif mnem == "MUL" and insn.ops[0].type == idaapi.o_reg:
                dst = insn.ops[0].reg
                v1 = regs.get(insn.ops[1].reg) if insn.ops[1].type == idaapi.o_reg else None
                v2 = regs.get(insn.ops[2].reg) if insn.ops[2].type == idaapi.o_reg else None
                if v1 is not None and v2 is not None:
                    regs[dst] = (v1 * v2) & 0xFFFFFFFF

            elif mnem == "UDIV" and insn.ops[0].type == idaapi.o_reg:
                dst = insn.ops[0].reg
                v1 = regs.get(insn.ops[1].reg) if insn.ops[1].type == idaapi.o_reg else None
                v2 = regs.get(insn.ops[2].reg) if insn.ops[2].type == idaapi.o_reg else None
                if v1 is not None and v2 is not None and v2 != 0:
                    regs[dst] = v1 // v2

            elif mnem == "ADRP" and insn.ops[0].type == idaapi.o_reg:
                reg = insn.ops[0].reg
                if insn.ops[1].type == idaapi.o_imm:
                    regs[reg] = insn.ops[1].value

            elif mnem == "CSET":
                cc = idc.print_operand(ea, 1).strip().upper()
                c, z, n = regs.get("_c", 0), regs.get("_z", 0), regs.get("_n", 0)
                result = None
                if cc == "HI":    result = 1 if (c == 1 and z == 0) else 0
                elif cc == "EQ":  result = 1 if z == 1 else 0
                elif cc == "NE":  result = 1 if z == 0 else 0
                elif cc == "GE":  result = 1 if n == 0 else 0
                elif cc == "LT":  result = 1 if n == 1 else 0
                elif cc in ("LO", "CC"): result = 1 if c == 0 else 0
                elif cc in ("HS", "CS"): result = 1 if c == 1 else 0
                elif cc == "LS":  result = 1 if (c == 0 or z == 1) else 0
                return result

            ea = idc.next_head(ea, cset_ea + 4)
        return None


# ---------------------------------------------------------------------------
# CFF 去平坦化器
# ---------------------------------------------------------------------------

class CFFDeflattener:

    def __init__(self):
        self.resolver = OpaquePredResolver()
        self.stats = defaultdict(int)

    def process_function(self, func_ea):
        func = ida_funcs.get_func(func_ea)
        if not func:
            return
        predicates = self.resolver.find_and_resolve(func_ea)
        patched = 0
        for pred in predicates:
            if pred["result"] is not None:
                if self._patch_predicate(pred):
                    patched += 1
        self.stats["predicates_found"] += len(predicates)
        self.stats["predicates_patched"] += patched
        br_count = self._count_br_x8(func)
        self.stats["br_x8_total"] += br_count

    def _patch_predicate(self, pred):
        cset_ea = pred["cset_ea"]
        next_ea = idc.next_head(cset_ea, cset_ea + 32)
        stur_ea = None
        while next_ea != idaapi.BADADDR and next_ea < cset_ea + 32:
            mnem = idc.print_insn_mnem(next_ea)
            if mnem in ("STUR", "STR"):
                stur_ea = next_ea
                break
            next_ea = idc.next_head(next_ea, cset_ea + 32)
        if stur_ea is None:
            return False
        ldr_table_ea = idc.next_head(stur_ea, stur_ea + 16)
        ldrsw_ea = idc.next_head(ldr_table_ea, ldr_table_ea + 16) if ldr_table_ea != idaapi.BADADDR else idaapi.BADADDR
        ldr_target_ea = idc.next_head(ldrsw_ea, ldrsw_ea + 16) if ldrsw_ea != idaapi.BADADDR else idaapi.BADADDR
        if ldr_target_ea == idaapi.BADADDR:
            return False
        idc.set_cmt(pred["chain_start"], f"[Hikari] 不透明谓词: 恒等于 {pred['result']}", 0)
        idc.set_cmt(cset_ea, f"[Hikari] cset 结果 = {pred['result']} (常量)", 0)
        for nop_ea in range(pred["chain_start"], cset_ea, 4):
            mnem = idc.print_insn_mnem(nop_ea)
            if mnem in ("LDR", "MOV", "MOVK", "EOR", "ORR", "AND", "ADD", "SUB", "SUBS", "MUL", "UDIV"):
                op0 = idc.print_operand(nop_ea, 0).upper()
                if op0 in ("W8", "W9", "W10") and "SP" not in idc.print_operand(nop_ea, 1).upper():
                    patch_nop(nop_ea)
        return True

    def _count_br_x8(self, func):
        count = 0
        ea = func.start_ea
        while ea < func.end_ea:
            if idc.print_insn_mnem(ea) == "BR" and idc.print_operand(ea, 0).upper() == "X8":
                count += 1
            ea = idc.next_head(ea, func.end_ea)
        return count


# ---------------------------------------------------------------------------
# 函数包装内联器
# ---------------------------------------------------------------------------

class WrapperInliner:

    def process(self):
        count = 0
        for ea in idautils.Functions():
            name = ida_name.get_name(ea)
            if name and "MacXKFunctionWrapper" in name:
                target = self._resolve_chain(ea)
                if target:
                    target_name = ida_name.get_name(target) or f"sub_{target:x}"
                    idc.set_cmt(ea, f"[Hikari] 包装器 -> {target_name} (0x{target:x})", 0)
                    count += 1
                    for xref in idautils.CodeRefsTo(ea, 0):
                        idc.set_cmt(xref, f"[Hikari] 实际调用: {target_name}", 0)
        return count

    def _resolve_chain(self, ea, depth=0):
        if depth > 10:
            return ea
        func = ida_funcs.get_func(ea)
        if not func:
            return ea
        cur = func.start_ea
        while cur < func.end_ea:
            if idc.print_insn_mnem(cur) == "BL":
                target = idc.get_operand_value(cur, 0)
                target_name = ida_name.get_name(target) or ""
                if "MacXKFunctionWrapper" in target_name:
                    return self._resolve_chain(target, depth + 1)
                return target
            cur = idc.next_head(cur, func.end_ea)
        return ea


# ---------------------------------------------------------------------------
# 字符串解密标注器
# ---------------------------------------------------------------------------

class StringAnnotator:

    def process(self):
        seg = idaapi.get_segm_by_name("__data")
        if not seg:
            return 0
        count = 0
        ea = seg.start_ea
        while ea < seg.end_ea - 32:
            chunk = ida_bytes.get_bytes(ea, 32)
            if chunk:
                non_zero = sum(1 for b in chunk if b != 0)
                high_bytes = sum(1 for b in chunk if b > 0x7e)
                if non_zero > 24 and high_bytes > 4:
                    idc.set_cmt(ea, "[Hikari] 加密字符串数据", 0)
                    count += 1
                    ea += 32
                    continue
            ea += 8
        return count


# ---------------------------------------------------------------------------
# Hook 目标提取器
# ---------------------------------------------------------------------------

class HookExtractor:

    @staticmethod
    def extract():
        hooks = []
        seen = set()
        for func_ea in idautils.Functions():
            name = ida_name.get_name(func_ea) or ""
            if "_logos_method$" in name or "_logos_meta_method$" in name:
                is_meta = "_logos_meta_method$" in name
                parts = name.split("$")
                cls_name, sel_name = None, None
                for j, p in enumerate(parts):
                    if p == "_ungrouped" and j + 1 < len(parts):
                        cls_name = parts[j + 1]
                        if j + 2 < len(parts):
                            sel_name = parts[j + 2]
                        break
                if cls_name:
                    prefix = "+" if is_meta else "-"
                    sel_display = sel_name or "?"
                    key = (prefix, cls_name, sel_display)
                    if key not in seen:
                        seen.add(key)
                        hooks.append({
                            "class": cls_name,
                            "selector": sel_display,
                            "method_type": prefix,
                            "addr": func_ea,
                        })
                    comment = f"[Hikari] Hook: {prefix}[{cls_name} {sel_display}]"
                    idc.set_func_cmt(func_ea, comment, 1)

            elif "_logosLocalInit" in name:
                idc.set_func_cmt(func_ea, "[Hikari] Logos 初始化: 注册 hook (MSHookMessageEx)", 1)
            elif "_logosLocalCtor" in name:
                idc.set_func_cmt(func_ea, "[Hikari] %ctor 构造函数", 1)
        return hooks

    @staticmethod
    def extract_selectors():
        sels = []
        for func_ea in idautils.Functions():
            name = ida_name.get_name(func_ea) or ""
            if name.startswith("_objc_msgSend$"):
                sels.append(name.split("$", 1)[1])
        return sels


# ---------------------------------------------------------------------------
# PyQt5 自定义对话框
# ---------------------------------------------------------------------------

class HikariDialog(QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Hikari 混淆还原")
        self.setMinimumWidth(520)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # --- 标题 ---
        title = QLabel("Hikari 混淆还原分析")
        title.setFont(QFont("", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        layout.addWidget(sep)

        # --- 输出路径 ---
        path_group = QGroupBox("输出路径")
        path_layout = QHBoxLayout(path_group)
        self.path_edit = QLineEdit()
        idb_path = ida_nalt.get_input_file_path() or ""
        default_dir = os.path.dirname(idb_path) if idb_path else os.path.expanduser("~")
        self.path_edit.setText(default_dir)
        self.path_edit.setPlaceholderText("选择报告输出目录...")
        path_layout.addWidget(self.path_edit)
        browse_btn = QPushButton("浏览...")
        browse_btn.setFixedWidth(80)
        browse_btn.clicked.connect(self._browse)
        path_layout.addWidget(browse_btn)
        layout.addWidget(path_group)

        # --- 分析选项 ---
        opt_group = QGroupBox("分析选项")
        opt_layout = QVBoxLayout(opt_group)
        self.chk_wrapper = QCheckBox("函数包装器还原 (MacXKFunctionWrapper)")
        self.chk_cff = QCheckBox("控制流平坦化分析 (CFF)")
        self.chk_string = QCheckBox("加密字符串标注")
        self.chk_hook = QCheckBox("Hook 目标提取")
        for chk in (self.chk_wrapper, self.chk_cff, self.chk_string, self.chk_hook):
            chk.setChecked(True)
            opt_layout.addWidget(chk)
        layout.addWidget(opt_group)

        # --- 按钮 ---
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.btn_run = QPushButton("生成报告")
        self.btn_run.setFixedWidth(120)
        self.btn_run.setDefault(True)
        self.btn_run.clicked.connect(self._run_analysis)
        btn_layout.addWidget(self.btn_run)
        btn_cancel = QPushButton("取消")
        btn_cancel.setFixedWidth(80)
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(btn_cancel)
        layout.addLayout(btn_layout)

        # --- 状态栏 ---
        self.status_label = QLabel("就绪")
        self.status_label.setStyleSheet("color: gray;")
        layout.addWidget(self.status_label)

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "选择输出目录", self.path_edit.text())
        if d:
            self.path_edit.setText(d)

    def _set_status(self, text):
        self.status_label.setText(text)
        self.status_label.setStyleSheet("color: #333;")
        QApplication.processEvents()


    def _run_analysis(self):
        out_dir = self.path_edit.text().strip()
        if not out_dir or not os.path.isdir(out_dir):
            QMessageBox.warning(self, "错误", "请选择有效的输出目录")
            return

        self.btn_run.setEnabled(False)
        lines = []
        lines.append("=" * 60)
        lines.append("  Hikari 混淆还原分析报告")
        lines.append("=" * 60)
        lines.append("")

        # 1. 函数包装器
        wrapper_count = 0
        if self.chk_wrapper.isChecked():
            self._set_status("[1/4] 解析函数包装器...")
            inliner = WrapperInliner()
            wrapper_count = inliner.process()

        # 2. CFF
        deflattener = CFFDeflattener()
        if self.chk_cff.isChecked():
            self._set_status("[2/4] 去控制流平坦化...")
            for func_ea in idautils.Functions():
                func = ida_funcs.get_func(func_ea)
                if func and (func.end_ea - func.start_ea) > 0x100:
                    deflattener.process_function(func_ea)

        # 3. 加密字符串
        str_count = 0
        if self.chk_string.isChecked():
            self._set_status("[3/4] 标注加密字符串...")
            annotator = StringAnnotator()
            str_count = annotator.process()

        # 4. Hook 目标
        hooks = []
        selectors = []
        if self.chk_hook.isChecked():
            self._set_status("[4/4] 提取 Hook 目标...")
            hooks = HookExtractor.extract()
            selectors = HookExtractor.extract_selectors()

        # --- 生成报告内容 ---
        lines.append("=" * 60)
        lines.append("## Hook 目标")
        lines.append("=" * 60)
        lines.append("")
        if hooks:
            by_class = {}
            for h in hooks:
                by_class.setdefault(h["class"], []).append(h)
            for cls, items in by_class.items():
                lines.append(f"  Hook 类: {cls}")
                for h in items:
                    lines.append(f"    方法: {h['method_type']}[{cls} {h['selector']}]  (0x{h['addr']:x})")
                lines.append("")
        else:
            lines.append("  (未检测到 hook 目标)")
            lines.append("")
        if selectors:
            lines.append(f"  objc_msgSend 选择器: {', '.join(selectors)}")
            lines.append("")

        lines.append("=" * 60)
        lines.append("## 混淆统计")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"  函数包装器: {wrapper_count}")
        lines.append(f"  不透明谓词: {deflattener.stats['predicates_found']} (已 patch: {deflattener.stats['predicates_patched']})")
        lines.append(f"  br x8 分发器: {deflattener.stats['br_x8_total']}")
        lines.append(f"  加密字符串区域: {str_count}")
        lines.append("")

        # --- 写入文件 ---
        input_name = os.path.splitext(os.path.basename(ida_nalt.get_input_file_path() or "unknown"))[0]
        report_name = f"{input_name}_hikari_report.txt"
        report_path = os.path.join(out_dir, report_name)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        self._set_status("完成!")
        self.btn_run.setEnabled(True)
        QMessageBox.information(self, "完成", f"报告已生成:\n{report_path}")
        self.accept()


# ---------------------------------------------------------------------------
# IDA 插件入口
# ---------------------------------------------------------------------------

class HikariPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Hikari 混淆还原分析"
    help = ""
    wanted_name = "Hikari 混淆还原"
    wanted_hotkey = "Ctrl+Shift+H"

    def init(self):
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        dlg = HikariDialog()
        dlg.exec_()


def PLUGIN_ENTRY():
    return HikariPlugin()
