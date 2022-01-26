# This file is part of rainbow 
#
# rainbow is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#
# Copyright 2019 Victor Servant, Ledger SAS

import unicorn as uc
import capstone as cs
from struct import unpack
from rainbow.rainbow import rainbowBase, HookWeakMethod
from rainbow.color_functions import color


class rainbow_cortexm(rainbowBase):

    STACK_ADDR = 0x90000000
    STACK = (STACK_ADDR - 0x200, STACK_ADDR + 32)
    INTERNAL_REGS = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "cpsr", "pc", "lr"]
    TRACE_DISCARD = []

    def __init__(self, trace=True, sca_mode=False, local_vars={}):
        super().__init__(trace, sca_mode)
        self.emu = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_THUMB | uc.UC_MODE_MCLASS)
        self.disasm = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_THUMB | cs.CS_MODE_MCLASS)
        self.disasm.detail = True
        self.word_size = 4
        self.endianness = "little"
        self.page_size = self.emu.query(uc.UC_QUERY_PAGE_SIZE)
        self.page_shift = self.page_size.bit_length() - 1
        self.pc = uc.arm_const.UC_ARM_REG_PC

        known_regs = [i[len('UC_ARM_REG_'):] for i in dir(uc.arm_const) if '_REG' in i]
        self.reg_map = {r.lower(): getattr(uc.arm_const, 'UC_ARM_REG_'+r) for r in known_regs}

        self.stubbed_functions = local_vars
        self.setup(sca_mode)

        self.reset_stack()
        # Force mapping of those addresses so that
        # exception returns can be caught in the base
        # block hook rather than a code fetch hook
        self.map_space(0xfffffff0, 0xffffffff)

        self.emu.hook_add(uc.UC_HOOK_INTR, HookWeakMethod(self.intr_hook))

    def reset_stack(self):
        self.emu.reg_write(uc.arm_const.UC_ARM_REG_SP, self.STACK_ADDR)

    def intr_hook(self, uci, intno, data):
        # Hack : pretend this is all exceptions at once
        self['ipsr'] = 0xfffffff

        sp = self["sp"] - 32
        self["sp"] = sp
        for i, reg in enumerate(['r0','r1','r2','r3','r12','r14','pc', 'apsr']):
            self.emu.mem_write(sp + 4*i, self[reg].to_bytes(4, 'little'))

        self[sp + 24] = (self["pc"] | 1).to_bytes(4, 'little')
        self['control'] = 0

        # TODO: handle other software-triggered exceptions (like bkpt)
        self['pc'] = self.functions["SVC_Handler"] | 1
        return False 

    def start(self, begin, end, timeout=0, count=0):
        return self._start(begin | 1, end, timeout, count)

    def return_force(self):
        self["pc"] = self["lr"]

    def block_handler(self, uci, address, size, user_data):
        if (address & 0xfffffff0) == 0xfffffff0:
            is_psp = (address >> 2) & 1
            is_unpriv = (address >> 3) & 1
            self['control'] = (is_psp << 1) | is_unpriv

            sp = self['sp']
            nvic_stack_bytes = self[sp:sp+32]
            nvic_stack = unpack('8I', nvic_stack_bytes)

            for i, reg in enumerate(['r0','r1','r2','r3','r12','r14','pc','apsr']):
                self[reg] = nvic_stack[i]

            self['ipsr'] = 0
            self['sp'] = sp + 32
            return True

        # In a Cortex M, all code is in thumb mode
        # So all function addresses are odd
        self.base_block_handler(address | 1)
