"""
# What is this all about?

Well, Hyper-V uses gs:XXXX to quickly access some important structures.
If you look at the end of `start`, you'll notice something like this:

```C
[...]
wrmsr(0xC0000101, some_addr);
[...]

That's MSR_GS_BASE and it's used to, guess what, tell the CPU where to look for
when you have something like `gs:0`.

IDA wouldn't let me force `gs`'s value so...

This hacky IDA Pro processor module is a quick way to turn
`mov reg, gs:XXXX` into `mov reg, qword ptr [rip+$(MSR_GS_BASE + XXXX - rip)]`.

I'm using capstone as a disassembler because I couldn't find a quick
way to get IDA to disasm some things for me.
This is probably my fault but whatever.

# How to use

1. Change the global `HVIX_GSBASE` to the value of your current Hyper-V binary.
2. Copy this script inside your ida `plugins/`.
3. Start ida64 from a virtualenv that has capstone in it.

# Warning

Once you put this script in `plugins/`, it's going to run for every binary you
open in IDA.
It's a quick thing to fix, but I haven't done it.

# Credits

All praise our Lord Rolf Rolles.
This is pretty much stolen from him :)

See: https://www.msreverseengineering.com/blog/2015/6/29/transparent-deobfuscation-with-ida-processor-module-extensions
"""

from __future__ import print_function

import os
import re

"""
RANT TIME:

    WHY THE FLYING FUCK DOES MOTHERFUCKING CAPSTONE COMES WITH THE GODDAMN
    DIET ENGINE WHEN YOU JFC INSTALL IT USING PIP FOR FUCK'S SAKE.

As you might have guessed... HUGE HACKS AHEAD :D
"""
import capstone

import ida_allins
import ida_offset
import ida_ua
import idaapi


# NOTE: CHANGE THIS
HVIX_GSBASE = 0xFFFFF80000603000

# Fuck capstone, really
X86_REGS = {
    "RAX": 0,
    "RCX": 1,
    "RDX": 2,
    "RBX": 3,
    "RSP": 4,
    "RBP": 5,
    "RSI": 6,
    "RDI": 7,
    "R8" : 8,
    "R9" : 9,
    "R10": 10,
    "R11": 11,
    "R12": 12,
    "R13": 13,
    "R14": 14,
    "R15": 15,
}


class hypervGsProcHook(idaapi.IDP_Hooks):
    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        # What could possibly go wrong...
        # Thanks, capstone diet and my ignorance of IDA scripting
        self.re = re.compile(r'([re][0-9a-dpxsi]+), ([a-z]+) ptr gs:\[([0-9a-fx]+)\]')

    def print_instr(self, instr):
        print('WTF: 0x{:08X} {} {}'.format(
            idaapi.cmd.ea,
            instr.mnemonic,
            instr.op_str
        ))

    def ev_ana_insn(self, insn):
        addr = insn.ea

        opcodes = idaapi.get_bytes(addr, 16)
        instrs = self.md.disasm(opcodes, addr)

        for instr in instrs:
            if instr.mnemonic != 'mov':
                if instr.op_str.find('gs') != -1:
                    self.print_instr(instr)
                return False

            m = self.re.search(instr.op_str)
            if m is None:
                return False

            reg, size, offset = m.groups()
            offset = int(offset, 16)
            # What could possibly go wrong #2...
            size = getattr(ida_ua, 'dt_' + size)

            reg = reg.upper()
            if reg[0] == 'E':
                reg = 'R' + reg[1:]
            if reg[-1] == 'D':
                reg = reg[:-1]
            if reg not in X86_REGS:
                print('Unknown reg: {}'.format(reg))
                return False
            reg = X86_REGS[reg]

            insn.itype = ida_allins.NN_mov

            # Seriously...
            # Seems to make the stuff RIP-relative
            insn.auxpref = 0x1810   # addressing mode not overwritten by prefix,
                                    # operand size not overwritten by prefix,
                                    # segment type is 64-bit
            # Seems to use cs instead of ds
            insn.Op2.specval = 0x1e0000

            insn.Op1.type = idaapi.o_reg
            insn.Op1.dtype = size
            insn.Op1.reg = reg
            insn.Op2.dtype = size
            insn.Op2.type = idaapi.o_mem
            insn.Op2.addr = HVIX_GSBASE + offset
            insn.size = instr.size
            return True

        return False


class hyperv_gs_proc_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Stolen from Rolf Rolles"
    wanted_hotkey = ""
    help = "Itsame, a stolen script"
    wanted_name = "hyperv_gs_proc"
    hook = None

    def init(self):
        self.hook = None
        hv_name = os.path.split(idaapi.get_input_file_path())[1].lower()
        if hv_name not in ('hvix64.exe', 'hvax64.exe') or idaapi.ph_get_id() != idaapi.PLFM_386:
            return idaapi.PLUGIN_SKIP
        self.hook = hypervGsProcHook()
        self.hook.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if self.hook:
            self.hook.unhook()


def PLUGIN_ENTRY():
    return hyperv_gs_proc_t()

