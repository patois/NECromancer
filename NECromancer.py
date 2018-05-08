from ida_lines import COLOR_INSN, COLOR_MACRO 
from ida_idp import CUSTOM_INSN_ITYPE, IDP_Hooks, ph_get_regnames, ph_get_id, PLFM_NEC_V850X
from ida_bytes import get_bytes
from ida_idaapi import plugin_t, PLUGIN_PROC, PLUGIN_HIDE, PLUGIN_SKIP, PLUGIN_KEEP
from ida_ua import o_displ, o_reg, o_imm, dt_dword, OOF_ADDR
from struct import unpack

###############################################################################
#
#
#   _____ _____ _____                                   
#  |   | |   __|     |___ ___ _____ ___ ___ ___ ___ ___ 
#  | | | |   __|   --|  _| . |     | .'|   |  _| -_|  _|
#  |_|___|_____|_____|_| |___|_|_|_|__,|_|_|___|___|_|  
# ____________________________________________________________________________
#
# NECromancer - a NEC V850X instruction extender plugin for IDA Pro
# -----------------------------------------------------------------
#
# This plugin extends the V850E1 IDA processor module by adding support
# for certain V850E2 instructions on a per need basis. Rather than modifying
# the source code of the V850E1 IDA processor module, this script has been
# developed as an exercise in writing a processor module extension in
# IDAPython, particularly for version 7 of IDA and onwards.
#
###############################################################################

# ----------------------------------------------------------------------------
#
# necromancer: noun | nec*ro*man*cer | a supposed practice of magic involving
# communication with the diseased
#
# history and changelog:
# ----------------------
# 2017.01.31 - initial version
#              support for "divq", "divqu", shl (reg1, reg2, reg3),
#              shr (reg1, reg2, reg3) and "sar" instructions
# 2017.02.01 - support for LD.HU (disp23[reg1], reg3), "feret" and "eiret"
#              instructions
# 2017.02.02 - support for ST.H (reg3, disp23[reg1]) instruction,
#              bugfixes, cleanup
# 2017.02.03 - support for sign extending 23bit displacement values,
#              "sch1l", "sch1r", "caxi" and "fetrap" instructions
# 2017.08.20 - IDA 7 compatibility
# 2017.09.03 - Full IDA 7 compatibility (not requiring compatibility layer)
# 2017.12.03 - Bugfixes (with thanks to https://github.com/Quorth)
# 2018.05.08 - Fixed decoding of fetrap instruction
#
#
# based on V850E2S User's Manual: Architecture, available at:
# https://www.renesas.com/en-eu/doc/products/mpumcu/doc/v850/r01us0037ej0100_v850e2.pdf
#
# ------------------------------------------------------------------------------

__author__ = "Dennis Elser"

DEBUG_PLUGIN = True

NEWINSN_COLOR = COLOR_MACRO if DEBUG_PLUGIN else COLOR_INSN

# from V850 processor module
N850F_USEBRACKETS = 0x01
N850F_OUTSIGNED = 0x02


class NewInstructions:
    (NN_divq,
    NN_divqu,
    NN_sar,
    NN_shl,
    NN_shr,
    NN_feret,
    NN_eiret,
    NN_ld_hu,
    NN_st_h,
    NN_sch1l,
    NN_sch1r,
    NN_caxi,
    NN_fetrap) = range(CUSTOM_INSN_ITYPE, CUSTOM_INSN_ITYPE+13)
    
    lst = {NN_divq:"divq",
           NN_divqu:"divqu",
           NN_sar:"sar",
           NN_shl:"shl",
           NN_shr:"shr",
           NN_feret:"feret",
           NN_eiret:"eiret",
           NN_ld_hu:"ld.hu",
           NN_st_h:"st.h",
           NN_sch1l:"sch1l",
           NN_sch1r:"sch1r",
           NN_caxi:"caxi",
           NN_fetrap:"fetrap"}


#--------------------------------------------------------------------------
class v850_idp_hook_t(IDP_Hooks):
    def __init__(self):
        IDP_Hooks.__init__(self)

    def parse_r1(self, w):
        return w & 0x1F

    def parse_r2(self, w):
        return (w & 0xF800) >> 11

    def parse_r3(self, w):
        return self.parse_r2(w)

    def sign_extend(self, disp, nbits):
        val = disp
        if val & (1 << (nbits-1)):
            val |= ~((1 << nbits)-1)
        return val

    def decode_instruction(self, insn):
        buf = get_bytes(insn.ea, 2)
        hw1 = unpack("<H", buf)[0]

        op = (hw1 & 0x7E0) >> 5 # take bit5->bit10

        # Format I
        if op == 2 and (hw1 >> 11) == 0 and (hw1 & 0x1F) != 0:
            # TODO add vector4 parsing
            insn.itype = NewInstructions.NN_fetrap
            insn.size = 2
            return True

        # Format XIV
        elif op == 0x3D and ((hw1 & 0xFFE0) >> 5) == 0x3D:
            buf = get_bytes(insn.ea+2, 2)
            hw2 = unpack("<H", buf)[0]
            subop = hw2 & 0x1F
            
            if subop == 0x07: # ld.hu
                insn.itype = NewInstructions.NN_ld_hu

                insn.Op1.type = o_displ                
                insn.Op2.type = o_reg
                

                insn.Op1.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED
                insn.Op1.reg = self.parse_r1(hw1)

                buf = get_bytes(insn.ea+4, 2)
                hw3 = unpack("<H", buf)[0]
                
                insn.Op1.addr = self.sign_extend(((hw3 << 6) | ((hw2 & 0x7E0) >> 5)) << 1, 23)
                insn.Op1.dtyp = dt_dword
                insn.Op2.reg = self.parse_r2(hw2)
                insn.Op2.dtyp = dt_dword
                
                insn.size = 6
                return True

            elif subop == 0xD:  # st.h
                insn.itype = NewInstructions.NN_st_h

                insn.Op1.type = o_reg
                insn.Op2.type = o_displ                
                
                insn.Op2.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED
                insn.Op2.reg = self.parse_r1(hw1)

                buf = get_bytes(insn.ea+4, 2)
                hw3 = unpack("<H", buf)[0]
                
                insn.Op2.addr = self.sign_extend(((hw3 << 6) | ((hw2 & 0x7E0) >> 5)) << 1, 23)
                insn.Op2.dtyp = dt_dword
                insn.Op1.reg = self.parse_r2(hw2)
                insn.Op1.dtyp = dt_dword
                
                insn.size = 6
                return True

        # Format II
        elif op == 0x15: # sar imm5, reg2
            insn.itype = NewInstructions.NN_sar                    

            insn.Op1.type = o_imm
            insn.Op2.type = o_reg

            insn.Op1.value = hw1 & 0x1F
            insn.Op2.reg = self.parse_r2(hw1)

            insn.size = 2
            return True


        # Format IX, X, XI
        elif op == 0x3F:
            buf = get_bytes(insn.ea+2, 2)
            hw2 = unpack("<H", buf)[0]
            subop = hw2 & 0x7FF


            if hw1 & 0x7FF == 0x7E0:
                if hw1 == 0x7E0:
                    if hw2 == 0x14A: # feret
                        insn.itype = NewInstructions.NN_feret
                        insn.size = 4
                        return insn.size
                    elif hw2 == 0x0148: # eiret
                        insn.itype = NewInstructions.NN_eiret
                        insn.size = 4
                        return True

                elif subop == 0x366: # sch1l reg2, reg3
                    insn.itype = NewInstructions.NN_sch1l

                    insn.Op1.type = o_reg
                    insn.Op2.type = o_reg

                    insn.Op1.reg = self.parse_r2(hw1)
                    insn.Op2.reg = self.parse_r3(hw2)

                    insn.size = 4
                    return True
                
                elif subop == 0x362: # sch1r reg2, reg3    
                    insn.itype = NewInstructions.NN_sch1r

                    insn.Op1.type = o_reg
                    insn.Op2.type = o_reg

                    insn.Op1.reg = self.parse_r2(hw1)
                    insn.Op2.reg = self.parse_r3(hw2)

                    insn.size = 4
                    return True

            insn_handled = False
            
            if subop == hw2 == 0xA0: # sar reg1, reg2
                insn.itype = NewInstructions.NN_sar                    

                insn.Op1.type = o_reg
                insn.Op2.type = o_reg

                insn.Op1.reg = self.parse_r1(hw1)
                insn.Op2.reg = self.parse_r2(hw1)

                insn.size = 4
                return True

            elif subop == 0xEE: # caxi [reg1], reg2, reg3
                insn.itype = NewInstructions.NN_caxi                    

                insn.Op1.type = o_displ
                insn.Op1.addr = 0
                insn.Op2.type = o_reg
                insn.Op3.type = o_reg

                insn.Op1.reg = self.parse_r1(hw1)
                insn.Op2.reg = self.parse_r2(hw1)
                insn.Op2.reg = self.parse_r3(hw2)

                insn.size = 4
                return True
                
                
            elif subop == 0x2FC:  # divq reg1, reg2, reg3
                insn.itype = NewInstructions.NN_divq
                insn.size = 4
                insn_handled = True

            elif subop == 0x2FE: # divqu reg1, reg2, reg3
                insn.itype = NewInstructions.NN_divqu
                insn.size = 4
                insn_handled = True

            elif subop == 0xA2: # sar reg1, reg2, reg3
                insn.itype = NewInstructions.NN_sar                    
                insn.size = 4
                insn_handled = True
 
            elif subop == 0xC2: # shl reg1, reg2, reg3
                insn.itype = NewInstructions.NN_shl                    
                insn.size = 4
                insn_handled = True

            elif subop == 0x82: # shr reg1, reg2, reg3
                insn.itype = NewInstructions.NN_shr                   
                insn.size = 4
                insn_handled = True

            if insn_handled:
                insn.Op1.type = o_reg
                insn.Op2.type = o_reg
                insn.Op3.type = o_reg

                insn.Op1.reg = self.parse_r1(hw1)
                insn.Op2.reg = self.parse_r2(hw1)
                insn.Op3.reg = self.parse_r3(hw2)
                return True
            
        return False

    def ev_ana_insn(self, insn):
        if insn.ea & 1:
            return False

        return self.decode_instruction(insn)

    def ev_out_mnem(self, outctx):
        insntype = outctx.insn.itype
        global NEWINSN_COLOR

        if (insntype >= CUSTOM_INSN_ITYPE) and (insntype in NewInstructions.lst):
            mnem = NewInstructions.lst[insntype]
            outctx.out_tagon(NEWINSN_COLOR)
            outctx.out_line(mnem)
            outctx.out_tagoff(NEWINSN_COLOR)

            # TODO: how can MNEM_width be determined programatically?
            MNEM_WIDTH = 8
            width = max(1, MNEM_WIDTH - len(mnem))
            outctx.out_line(' ' * width)

            return True
        return False

    def ev_emu_insn(self, insn):
        if insn.itype in [NewInstructions.NN_eiret, NewInstructions.NN_feret]:
            return True
        return False

    def ev_out_operand(self, outctx, op):
        insn = outctx.insn
        if insn.itype in [NewInstructions.NN_ld_hu, NewInstructions.NN_st_h]:
            if op.type == o_displ:
                
                outctx.out_value(op, OOF_ADDR)
                brackets = insn.ops[op.n].specflag1 & N850F_USEBRACKETS
                if brackets:
                    outctx.out_symbol('[')
                outctx.out_register(ph_get_regnames()[op.reg])
                if brackets:
                    outctx.out_symbol(']')
                return True
        return False


#--------------------------------------------------------------------------
class NECromancer_t(plugin_t):
    flags = PLUGIN_PROC | PLUGIN_HIDE
    comment = ""
    wanted_hotkey = ""
    help = "Adds support for additional V850X instructions"
    wanted_name = "NECromancer"

    def __init__(self):
        self.prochook = None

    def init(self):
        if ph_get_id() != PLFM_NEC_V850X:
            return PLUGIN_SKIP

        self.prochook = v850_idp_hook_t()
        self.prochook.hook()
        print "%s intialized." % NECromancer_t.wanted_name
        return PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if self.prochook:
            self.prochook.unhook()

#--------------------------------------------------------------------------
def PLUGIN_ENTRY():
    return NECromancer_t() 
