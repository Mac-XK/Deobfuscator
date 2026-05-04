#!/usr/bin/env python3
"""
Hikari 混淆还原工具 - 静态分析版
分析经 Hikari 混淆的 ARM64 Mach-O 二进制文件，生成还原分析报告。

支持还原: 控制流平坦化、不透明谓词、字符串加密、函数包装
"""

import sys
import struct
import json
from collections import defaultdict
from pathlib import Path

try:
    import lief
except ImportError:
    sys.exit("错误: 请先安装 lief，运行 pip3 install lief")

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_GRP_JUMP, CS_GRP_RET
    from capstone.arm64 import (
        ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM,
        ARM64_REG_X8, ARM64_REG_X9, ARM64_REG_X10, ARM64_REG_X11,
        ARM64_REG_W8, ARM64_REG_W9, ARM64_REG_W10,
        ARM64_REG_SP, ARM64_REG_X29, ARM64_REG_X19,
    )
except ImportError:
    sys.exit("错误: 请先安装 capstone，运行 pip3 install capstone")


# ---------------------------------------------------------------------------
# Mach-O 加载器
# ---------------------------------------------------------------------------

class MachOLoader:
    def __init__(self, path):
        self.path = path
        self.binary = lief.parse(path)
        if self.binary is None:
            raise ValueError(f"无法解析文件: {path}")
        self.imagebase = self.binary.imagebase
        self._section_cache = {}
        self._raw = Path(path).read_bytes()

        for sec in self.binary.sections:
            self._section_cache[sec.name] = {
                "va": sec.virtual_address,
                "offset": sec.offset,
                "size": sec.size,
                "data": bytes(sec.content),
            }

    def get_section(self, name):
        return self._section_cache.get(name)

    def read_bytes(self, va, size):
        for sec in self._section_cache.values():
            if sec["va"] <= va < sec["va"] + sec["size"]:
                off = va - sec["va"]
                return sec["data"][off:off + size]
        return None

    def read_u32(self, va):
        b = self.read_bytes(va, 4)
        return struct.unpack_from("<I", b)[0] if b else None

    def read_u64(self, va):
        b = self.read_bytes(va, 8)
        return struct.unpack_from("<Q", b)[0] if b else None

    def decode_chained_ptr(self, raw_val):
        """解码 chained fixup 指针，获取目标虚拟地址。"""
        return raw_val & 0x0000FFFFFFFFFFFF

    def get_functions(self):
        funcs = {}
        for sym in self.binary.symbols:
            if sym.value and sym.value >= 0x4000:
                name = sym.name.strip("_") if sym.name else ""
                if name and (sym.value not in funcs or not funcs[sym.value]):
                    funcs[sym.value] = name
                elif sym.value not in funcs:
                    funcs[sym.value] = name
        return dict(sorted((a, n) for a, n in funcs.items() if n))

    def get_text_range(self):
        sec = self.get_section("__text")
        if sec:
            return sec["va"], sec["va"] + sec["size"]
        return 0, 0


# ---------------------------------------------------------------------------
# ARM64 反汇编器
# ---------------------------------------------------------------------------

class Disassembler:
    def __init__(self, loader):
        self.loader = loader
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.cs.detail = True

    def disasm_range(self, start, end):
        sec = self.loader.get_section("__text")
        if not sec:
            return []
        off = start - sec["va"]
        size = end - start
        code = sec["data"][off:off + size]
        return list(self.cs.disasm(code, start))

    def disasm_function(self, addr, max_size=0x10000):
        sec = self.loader.get_section("__text")
        if not sec:
            return []
        off = addr - sec["va"]
        code = sec["data"][off:off + min(max_size, sec["size"] - off)]
        return list(self.cs.disasm(code, addr))


# ---------------------------------------------------------------------------
# 不透明谓词求值器
# ---------------------------------------------------------------------------

class OpaquePredicateEvaluator:
    """
    静态求值 Hikari 不透明谓词。
    模式: ldr w8, [data] -> eor/mul/udiv/add/sub 运算链 -> cset -> 索引
    """

    def __init__(self, loader):
        self.loader = loader

    def evaluate_predicate_chain(self, insns, start_idx):
        regs = {}
        i = start_idx
        cset_result = None

        while i < len(insns):
            ins = insns[i]

            if ins.mnemonic == "ldr" and len(ins.operands) == 2:
                dst = ins.operands[0]
                src = ins.operands[1]
                if dst.type == ARM64_OP_REG and src.type == ARM64_OP_MEM:
                    base_reg = src.mem.base
                    disp = src.mem.disp
                    if base_reg in regs and isinstance(regs[base_reg], int):
                        va = regs[base_reg] + disp
                        if dst.reg in (ARM64_REG_W8, ARM64_REG_W9, ARM64_REG_W10):
                            val = self.loader.read_u32(va)
                            if val is not None:
                                regs[dst.reg] = val & 0xFFFFFFFF

            elif ins.mnemonic == "mov" and len(ins.operands) == 2:
                dst = ins.operands[0]
                src = ins.operands[1]
                if dst.type == ARM64_OP_REG and src.type == ARM64_OP_IMM:
                    regs[dst.reg] = src.imm & 0xFFFFFFFF
                elif dst.type == ARM64_OP_REG and src.type == ARM64_OP_REG:
                    if src.reg in regs:
                        regs[dst.reg] = regs[src.reg]

            elif ins.mnemonic == "movk" and len(ins.operands) == 2:
                dst = ins.operands[0]
                src = ins.operands[1]
                if dst.type == ARM64_OP_REG and src.type == ARM64_OP_IMM:
                    if dst.reg in regs and isinstance(regs[dst.reg], int):
                        shift = ins.operands[1].shift.value if ins.operands[1].shift.value else 0
                        mask = ~(0xFFFF << shift) & 0xFFFFFFFF
                        regs[dst.reg] = (regs[dst.reg] & mask) | ((src.imm & 0xFFFF) << shift)

            elif ins.mnemonic == "eor" and len(ins.operands) == 3:
                dst, s1, s2 = ins.operands
                if all(o.type == ARM64_OP_REG for o in [dst, s1, s2]):
                    v1 = regs.get(s1.reg)
                    v2 = regs.get(s2.reg)
                    if v1 is not None and v2 is not None:
                        regs[dst.reg] = (v1 ^ v2) & 0xFFFFFFFF

            elif ins.mnemonic == "orr" and len(ins.operands) == 3:
                dst, s1, s2 = ins.operands
                if all(o.type == ARM64_OP_REG for o in [dst, s1, s2]):
                    v1 = regs.get(s1.reg)
                    v2 = regs.get(s2.reg)
                    if v1 is not None and v2 is not None:
                        regs[dst.reg] = (v1 | v2) & 0xFFFFFFFF

            elif ins.mnemonic == "and" and len(ins.operands) == 3:
                dst, s1, s2 = ins.operands
                v1 = regs.get(s1.reg) if s1.type == ARM64_OP_REG else None
                v2 = regs.get(s2.reg) if s2.type == ARM64_OP_REG else (s2.imm if s2.type == ARM64_OP_IMM else None)
                if v1 is not None and v2 is not None:
                    regs[dst.reg] = (v1 & v2) & 0xFFFFFFFF

            elif ins.mnemonic == "add" and len(ins.operands) == 3:
                dst, s1, s2 = ins.operands
                if dst.type == ARM64_OP_REG:
                    v1 = regs.get(s1.reg) if s1.type == ARM64_OP_REG else None
                    v2 = s2.imm if s2.type == ARM64_OP_IMM else regs.get(s2.reg) if s2.type == ARM64_OP_REG else None
                    if v1 is not None and v2 is not None:
                        regs[dst.reg] = (v1 + v2) & 0xFFFFFFFF

            elif ins.mnemonic in ("sub", "subs") and len(ins.operands) == 3:
                dst, s1, s2 = ins.operands
                if all(o.type == ARM64_OP_REG for o in [dst, s1, s2]):
                    v1 = regs.get(s1.reg)
                    v2 = regs.get(s2.reg)
                    if v1 is not None and v2 is not None:
                        result = (v1 - v2) & 0xFFFFFFFF
                        regs[dst.reg] = result
                        regs["_flags_c"] = 1 if v1 >= v2 else 0
                        regs["_flags_z"] = 1 if result == 0 else 0
                        regs["_flags_n"] = 1 if result & 0x80000000 else 0

            elif ins.mnemonic == "mul" and len(ins.operands) == 3:
                dst, s1, s2 = ins.operands
                if all(o.type == ARM64_OP_REG for o in [dst, s1, s2]):
                    v1 = regs.get(s1.reg)
                    v2 = regs.get(s2.reg)
                    if v1 is not None and v2 is not None:
                        regs[dst.reg] = (v1 * v2) & 0xFFFFFFFF

            elif ins.mnemonic == "udiv" and len(ins.operands) == 3:
                dst, s1, s2 = ins.operands
                if all(o.type == ARM64_OP_REG for o in [dst, s1, s2]):
                    v1 = regs.get(s1.reg)
                    v2 = regs.get(s2.reg)
                    if v1 is not None and v2 is not None and v2 != 0:
                        regs[dst.reg] = v1 // v2

            elif ins.mnemonic == "cset" and len(ins.operands) == 2:
                dst = ins.operands[0]
                cc = ins.op_str.split(",")[-1].strip()
                c_flag = regs.get("_flags_c", 0)
                z_flag = regs.get("_flags_z", 0)
                n_flag = regs.get("_flags_n", 0)

                if cc == "hi":
                    cset_result = 1 if (c_flag == 1 and z_flag == 0) else 0
                elif cc == "eq":
                    cset_result = 1 if z_flag == 1 else 0
                elif cc == "ne":
                    cset_result = 1 if z_flag == 0 else 0
                elif cc == "ge":
                    cset_result = 1 if n_flag == 0 else 0
                elif cc == "lt":
                    cset_result = 1 if n_flag == 1 else 0
                elif cc == "lo":
                    cset_result = 1 if c_flag == 0 else 0
                elif cc == "hs":
                    cset_result = 1 if c_flag == 1 else 0
                else:
                    cset_result = None

                if dst.type == ARM64_OP_REG:
                    regs[dst.reg] = cset_result
                return i, cset_result

            elif ins.mnemonic == "adrp" and len(ins.operands) == 2:
                dst = ins.operands[0]
                src = ins.operands[1]
                if dst.type == ARM64_OP_REG and src.type == ARM64_OP_IMM:
                    regs[dst.reg] = src.imm

            elif ins.mnemonic in ("str", "stur", "stp"):
                pass
            elif ins.mnemonic in ("br", "b", "ret", "bl", "blr"):
                break

            i += 1

        return i, cset_result



# ---------------------------------------------------------------------------
# 控制流平坦化分析器
# ---------------------------------------------------------------------------

class CFFAnalyzer:
    """分析并重建 Hikari 控制流平坦化 (CFF) 的真实控制流。"""

    def __init__(self, loader, disasm, evaluator):
        self.loader = loader
        self.disasm = disasm
        self.evaluator = evaluator

    def find_jump_tables(self, insns):
        """查找函数中加载的跳转表基地址。"""
        tables = []
        for i, ins in enumerate(insns):
            if ins.mnemonic == "adrp" and i + 1 < len(insns):
                next_ins = insns[i + 1]
                if next_ins.mnemonic == "add":
                    dst = ins.operands[0]
                    page = ins.operands[1].imm if ins.operands[1].type == ARM64_OP_IMM else 0
                    if next_ins.operands[1].type == ARM64_OP_REG and next_ins.operands[1].reg == dst.reg:
                        offset = next_ins.operands[2].imm if next_ins.operands[2].type == ARM64_OP_IMM else 0
                        addr = page + offset
                        data_sec = self.loader.get_section("__data")
                        if data_sec and data_sec["va"] <= addr < data_sec["va"] + data_sec["size"]:
                            tables.append({
                                "addr": addr,
                                "insn_addr": ins.address,
                                "reg": dst.reg,
                            })
        return tables

    def read_jump_table(self, addr, count=2):
        """读取并解码跳转表条目。"""
        targets = []
        for i in range(count):
            raw = self.loader.read_u64(addr + i * 8)
            if raw is not None:
                target = self.loader.decode_chained_ptr(raw)
                targets.append(target)
        return targets

    def find_dispatcher_blocks(self, insns):
        """查找所有 br x8 分发跳转点。"""
        dispatchers = []
        for i, ins in enumerate(insns):
            if ins.mnemonic == "br" and len(ins.operands) == 1:
                if ins.operands[0].type == ARM64_OP_REG and ins.operands[0].reg == ARM64_REG_X8:
                    dispatchers.append({"index": i, "addr": ins.address})
        return dispatchers

    def find_opaque_predicates(self, insns):
        """查找所有不透明谓词模式。"""
        predicates = []
        for i, ins in enumerate(insns):
            if ins.mnemonic == "cset":
                start = max(0, i - 30)
                for j in range(start, i):
                    if insns[j].mnemonic == "ldr" and "0x14" in insns[j].op_str:
                        end_idx, result = self.evaluator.evaluate_predicate_chain(insns, j)
                        predicates.append({
                            "start_addr": insns[j].address,
                            "cset_addr": ins.address,
                            "start_idx": j,
                            "end_idx": i,
                            "result": result,
                            "condition": ins.op_str.split(",")[-1].strip(),
                        })
                        break
        return predicates

    def analyze_function(self, func_addr, func_name, func_end=None):
        """对单个函数进行完整的 CFF 分析。"""
        if func_end is None:
            func_end = func_addr + 0x10000
        text_start, text_end = self.loader.get_text_range()
        func_end = min(func_end, text_end)

        insns = self.disasm.disasm_range(func_addr, func_end)
        if not insns:
            return None

        jump_tables = self.find_jump_tables(insns)
        dispatchers = self.find_dispatcher_blocks(insns)
        predicates = self.find_opaque_predicates(insns)

        all_targets = set()
        table_info = []
        for jt in jump_tables:
            targets = self.read_jump_table(jt["addr"])
            valid_targets = [t for t in targets if text_start <= t < text_end]
            all_targets.update(valid_targets)
            table_info.append({
                "table_addr": jt["addr"],
                "ref_addr": jt["insn_addr"],
                "targets": [f"0x{t:x}" for t in valid_targets],
                "raw_targets": targets,
            })

        real_blocks = []
        for i, ins in enumerate(insns):
            if ins.mnemonic in ("bl", "blr"):
                target_str = ins.op_str
                real_blocks.append({
                    "addr": ins.address,
                    "type": "call",
                    "target": target_str,
                    "mnemonic": f"{ins.mnemonic} {ins.op_str}",
                })
            elif ins.mnemonic == "ret":
                real_blocks.append({
                    "addr": ins.address,
                    "type": "return",
                    "mnemonic": "ret",
                })

        stack_size = 0
        for ins in insns[:5]:
            if ins.mnemonic == "sub" and "sp" in ins.op_str:
                for op in ins.operands:
                    if op.type == ARM64_OP_IMM:
                        stack_size = op.imm
                        break

        return {
            "name": func_name,
            "addr": func_addr,
            "size": (insns[-1].address - func_addr + 4) if insns else 0,
            "insn_count": len(insns),
            "stack_size": stack_size,
            "jump_tables": table_info,
            "dispatcher_count": len(dispatchers),
            "opaque_predicates": predicates,
            "real_operations": real_blocks,
            "br_x8_count": len(dispatchers),
        }


# ---------------------------------------------------------------------------
# 函数包装分析器
# ---------------------------------------------------------------------------

class WrapperAnalyzer:
    def __init__(self, loader, disasm):
        self.loader = loader
        self.disasm = disasm

    def analyze_wrappers(self, functions):
        wrappers = {}
        for addr, name in functions.items():
            if "MacXKFunctionWrapper" not in name:
                continue
            insns = self.disasm.disasm_range(addr, addr + 20)
            target = None
            for ins in insns:
                if ins.mnemonic == "bl":
                    target = ins.op_str
                    break
            wrappers[name] = {
                "addr": addr,
                "target": target,
                "is_chain": target and "MacXKFunctionWrapper" in target,
            }

        resolved = {}
        for name, info in wrappers.items():
            chain = [name]
            current = info
            while current and current["is_chain"] and current["target"]:
                t = current["target"].strip()
                if t in wrappers:
                    chain.append(t)
                    current = wrappers[t]
                else:
                    break
            final_target = current["target"] if current else info["target"]
            resolved[name] = {
                "addr": info["addr"],
                "chain": chain,
                "final_target": final_target,
            }
        return resolved



# ---------------------------------------------------------------------------
# 字符串加密分析器
# ---------------------------------------------------------------------------

class StringAnalyzer:
    def __init__(self, loader):
        self.loader = loader

    def find_encrypted_strings(self):
        """在 __DATA 段中查找加密字符串数据。"""
        data_sec = self.loader.get_section("__data")
        if not data_sec:
            return []

        results = []
        data = data_sec["data"]
        base = data_sec["va"]

        objc_sec = self.loader.get_section("__objc_methname")
        preserved = set()
        if objc_sec:
            raw = objc_sec["data"]
            s = b""
            for b_val in raw:
                if b_val == 0:
                    if s:
                        preserved.add(s.decode("utf-8", errors="replace"))
                    s = b""
                else:
                    s += bytes([b_val])
            if s:
                preserved.add(s.decode("utf-8", errors="replace"))

        i = 0
        while i < len(data) - 16:
            chunk = data[i:i + 32]
            non_zero = sum(1 for b_val in chunk if b_val != 0)
            has_high = sum(1 for b_val in chunk if b_val > 0x7e) > 4
            if non_zero > 24 and has_high:
                end = i + 32
                while end < min(i + 256, len(data)):
                    if data[end:end + 8] == b"\x00" * 8:
                        break
                    end += 1
                results.append({
                    "offset": i,
                    "va": base + i,
                    "size": end - i,
                    "entropy": self._entropy(data[i:end]),
                    "hex_preview": data[i:min(i + 16, end)].hex(),
                })
                i = end
            else:
                i += 8
        return results

    def _entropy(self, data):
        from math import log2
        if not data:
            return 0
        freq = defaultdict(int)
        for b in data:
            freq[b] += 1
        length = len(data)
        return -sum((c / length) * log2(c / length) for c in freq.values())


# ---------------------------------------------------------------------------
# Hook 目标提取器
# ---------------------------------------------------------------------------

class HookExtractor:
    """从符号表、ObjC 元数据、MSHookMessageEx 调用中提取 hook 目标。"""

    def __init__(self, loader):
        self.loader = loader

    def extract(self):
        hooks = []

        # 1. 从 Logos 符号名提取: _logos_method$_ungrouped$ClassName$selector
        for sym in self.loader.binary.symbols:
            name = sym.name or ""
            if "_logos_method$" in name or "_logos_meta_method$" in name:
                is_meta = "_logos_meta_method$" in name
                parts = name.split("$")
                cls_name, sel_name = None, None
                for j, p in enumerate(parts):
                    if p == "_ungrouped" and j + 1 < len(parts):
                        cls_name = parts[j + 1]
                        if j + 2 < len(parts):
                            sel_name = parts[j + 2]
                            # 去掉尾部的类型编码 (如 P16UIViewControllerP13objc_selector)
                            if sel_name:
                                for k, c in enumerate(sel_name):
                                    if c == 'P' and k > 0 and sel_name[k-1].isalpha():
                                        sel_name = sel_name[:k]
                                        break
                        break
                if cls_name:
                    prefix = "+" if is_meta else "-"
                    sel_display = sel_name.replace("$", ":") if sel_name else "?"
                    hooks.append({
                        "type": "logos_symbol",
                        "class": cls_name,
                        "selector": sel_display,
                        "method_type": prefix,
                        "symbol": name,
                        "addr": sym.value,
                    })

            # _logos_orig$ 说明保存了原始 IMP
            elif "_logos_orig$" in name:
                parts = name.split("$")
                for j, p in enumerate(parts):
                    if p == "_ungrouped" and j + 1 < len(parts):
                        cls_name = parts[j + 1]
                        sel_name = parts[j + 2] if j + 2 < len(parts) else "?"
                        hooks.append({
                            "type": "logos_orig",
                            "class": cls_name,
                            "selector": sel_name,
                            "symbol": name,
                            "addr": sym.value,
                        })
                        break

        # 2. 从 ObjC 选择器提取
        objc_sec = self.loader.get_section("__objc_methname")
        selectors = []
        if objc_sec:
            raw = objc_sec["data"]
            s = b""
            for b_val in raw:
                if b_val == 0:
                    if s:
                        selectors.append(s.decode("utf-8", errors="replace"))
                    s = b""
                else:
                    s += bytes([b_val])
            if s:
                selectors.append(s.decode("utf-8", errors="replace"))

        # 3. 从导入符号检测 hook 框架
        hook_frameworks = []
        for sym in self.loader.binary.symbols:
            name = sym.name or ""
            if name in ("_MSHookMessageEx", "_MSHookFunction"):
                hook_frameworks.append(name.strip("_"))
            elif "substrate" in name.lower() or "fishhook" in name.lower():
                hook_frameworks.append(name.strip("_"))

        # 4. 从 objc_msgSend stub 符号提取调用的选择器
        msgSend_sels = []
        for sym in self.loader.binary.symbols:
            name = sym.name or ""
            if name.startswith("_objc_msgSend$"):
                sel = name.split("$", 1)[1]
                msgSend_sels.append(sel)
            elif name.startswith("_objc_msgSendClass$"):
                parts = name.split("$")
                if len(parts) >= 2:
                    msgSend_sels.append(parts[1])

        # 去重: lief 可能返回重复符号
        seen_hooks = set()
        unique_hooks = []
        for h in hooks:
            key = (h.get("class"), h.get("selector"), h.get("type"))
            if key not in seen_hooks:
                seen_hooks.add(key)
                unique_hooks.append(h)

        return {
            "hooks": unique_hooks,
            "selectors": selectors,
            "hook_frameworks": list(set(hook_frameworks)),
            "msgSend_selectors": msgSend_sels,
        }


# ---------------------------------------------------------------------------
# 报告生成器
# ---------------------------------------------------------------------------

class ReportGenerator:
    def __init__(self, loader):
        self.loader = loader

    def generate(self, func_analyses, wrappers, encrypted_strings, hook_info):
        lines = []
        lines.append("=" * 72)
        lines.append("  Hikari 混淆还原分析报告")
        lines.append("=" * 72)
        lines.append("")

        # ---- Hook 目标 (最重要的信息，放最前面) ----
        lines.append("=" * 72)
        lines.append("## Hook 目标")
        lines.append("=" * 72)
        lines.append("")

        if hook_info["hook_frameworks"]:
            lines.append(f"  Hook 框架: {', '.join(hook_info['hook_frameworks'])}")
            lines.append("")

        hooks = hook_info["hooks"]
        if hooks:
            by_class = {}
            for h in hooks:
                cls = h.get("class", "?")
                by_class.setdefault(cls, []).append(h)

            for cls, items in by_class.items():
                lines.append(f"  Hook 类: {cls}")
                seen = set()
                for h in items:
                    if h["type"] in ("logos_symbol",):
                        sig = f"{h.get('method_type','')}{h.get('selector','')}"
                        if sig not in seen:
                            lines.append(f"    方法: {h['method_type']}[{cls} {h['selector']}]  (0x{h['addr']:x})")
                            seen.add(sig)
                lines.append("")
        else:
            lines.append("  (未从符号中检测到明确的 hook 目标)")
            lines.append("  提示: 符号可能已被 strip，尝试从 MSHookMessageEx 调用参数还原")
            lines.append("")

        if hook_info["selectors"]:
            lines.append(f"  ObjC 选择器 (运行时可见): {', '.join(hook_info['selectors'])}")
            lines.append("")

        if hook_info["msgSend_selectors"]:
            lines.append(f"  objc_msgSend 调用的选择器: {', '.join(hook_info['msgSend_selectors'])}")
            lines.append("")

        # ---- 混淆概览 ----
        lines.append("=" * 72)
        lines.append("## 混淆概览")
        lines.append("=" * 72)
        lines.append("")

        total_insns = sum(f["insn_count"] for f in func_analyses if f)
        total_br = sum(f["br_x8_count"] for f in func_analyses if f)
        total_pred = sum(len(f["opaque_predicates"]) for f in func_analyses if f)
        total_tables = sum(len(f["jump_tables"]) for f in func_analyses if f)

        lines.append(f"  总指令数:              {total_insns}")
        lines.append(f"  br x8 分发器数量:      {total_br}")
        lines.append(f"  不透明谓词数量:        {total_pred}")
        lines.append(f"  跳转表数量:            {total_tables}")
        lines.append(f"  函数包装器数量:        {len(wrappers)}")
        lines.append(f"  加密字符串区域:        {len(encrypted_strings)}")
        lines.append("")

        # ---- 混淆技术 ----
        lines.append("-" * 72)
        lines.append("## 检测到的混淆技术")
        lines.append("-" * 72)
        lines.append("")
        if total_br > 0:
            lines.append(f"  1. 控制流平坦化 (CFF): {total_br} 个 br x8 分发器, {total_tables} 个跳转表")
        if total_pred > 0:
            lines.append(f"  2. 不透明谓词: {total_pred} 个")
            pred_results = [p["result"] for f in func_analyses if f for p in f["opaque_predicates"]]
            if pred_results:
                resolved = sum(1 for r in pred_results if r is not None)
                lines.append(f"     成功求值: {resolved}/{len(pred_results)}")
        if encrypted_strings:
            lines.append(f"  3. 字符串加密: {len(encrypted_strings)} 个加密区域")
            for es in encrypted_strings:
                lines.append(f"     0x{es['va']:x} ({es['size']} 字节, 熵值={es['entropy']:.2f})")
        if wrappers:
            lines.append(f"  4. 函数包装 (MacXKFunctionWrapper): {len(wrappers)} 个")
            for name, info in wrappers.items():
                chain_str = " -> ".join(info["chain"])
                lines.append(f"     {chain_str} -> {info['final_target']}")
        lines.append("")

        # ---- 逐函数分析 ----
        lines.append("=" * 72)
        lines.append("## 逐函数分析")
        lines.append("=" * 72)

        for f in func_analyses:
            if not f:
                continue
            lines.append("")
            lines.append("-" * 72)
            lines.append(f"### {f['name']}")
            lines.append(f"    地址: 0x{f['addr']:x}")
            lines.append(f"    大小: {f['size']} 字节 ({f['insn_count']} 条指令)")
            lines.append(f"    栈帧: 0x{f['stack_size']:x} 字节")
            lines.append(f"    CFF 分发器: {f['dispatcher_count']}")
            lines.append(f"    不透明谓词: {len(f['opaque_predicates'])}")
            lines.append(f"    跳转表: {len(f['jump_tables'])}")

            if f["real_operations"]:
                lines.append("    真实操作 (调用):")
                for op in f["real_operations"]:
                    lines.append(f"      0x{op['addr']:x}: {op['mnemonic']}")

        lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <dylib路径> [输出路径]")
        sys.exit(1)

    dylib_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else dylib_path.replace(".dylib", "_report.txt")

    print(f"[*] 加载 {dylib_path}...")
    loader = MachOLoader(dylib_path)

    print(f"[*] 镜像基址: 0x{loader.imagebase:x}")
    text_start, text_end = loader.get_text_range()
    print(f"[*] __TEXT 范围: 0x{text_start:x} - 0x{text_end:x}")

    disasm = Disassembler(loader)
    evaluator = OpaquePredicateEvaluator(loader)
    cff = CFFAnalyzer(loader, disasm, evaluator)
    wrapper_analyzer = WrapperAnalyzer(loader, disasm)
    string_analyzer = StringAnalyzer(loader)
    hook_extractor = HookExtractor(loader)

    # 提取 hook 目标
    print("[*] 提取 Hook 目标...")
    hook_info = hook_extractor.extract()
    if hook_info["hooks"]:
        print(f"    发现 {len(hook_info['hooks'])} 个 hook:")
        for h in hook_info["hooks"]:
            if h["type"] == "logos_symbol":
                print(f"      {h['method_type']}[{h['class']} {h['selector']}]")
    if hook_info["hook_frameworks"]:
        print(f"    Hook 框架: {', '.join(hook_info['hook_frameworks'])}")

    functions = loader.get_functions()
    print(f"[*] 发现 {len(functions)} 个函数")

    sorted_addrs = sorted(functions.keys())
    func_analyses = []
    for i, addr in enumerate(sorted_addrs):
        name = functions[addr]
        if "MacXKFunctionWrapper" in name:
            continue
        end = sorted_addrs[i + 1] if i + 1 < len(sorted_addrs) else text_end
        print(f"[*] 分析 {name} (0x{addr:x})...")
        analysis = cff.analyze_function(addr, name, end)
        if analysis:
            func_analyses.append(analysis)

    print("[*] 分析函数包装器...")
    wrappers = wrapper_analyzer.analyze_wrappers(functions)

    print("[*] 扫描加密字符串...")
    encrypted_strings = string_analyzer.find_encrypted_strings()
    print(f"    发现 {len(encrypted_strings)} 个加密区域")

    print("[*] 生成报告...")
    reporter = ReportGenerator(loader)
    report = reporter.generate(func_analyses, wrappers, encrypted_strings, hook_info)

    Path(output_path).write_text(report)
    print(f"[+] 报告已保存到 {output_path}")
    print()
    print(report)


if __name__ == "__main__":
    main()
