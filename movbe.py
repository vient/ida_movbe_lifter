import ida_allins
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_loader
import ida_typeinf
import ida_ua


def get_reg_size(op):
  sizes = {
    ida_ua.dt_word: 2,
    ida_ua.dt_dword: 4,
    ida_ua.dt_qword: 8,
  }
  return sizes[op.dtype]


def get_helper_name(size):
  names = {
    2: '_byteswap_ushort',
    4: '_byteswap_ulong',
    8: '_byteswap_uint64',
  }
  return names[size]


def get_type_info(size):
  types = {
    2: ida_typeinf.BTF_UINT16,
    4: ida_typeinf.BTF_UINT32,
    8: ida_typeinf.BTF_UINT64,
  }
  return ida_typeinf.tinfo_t(types[size])


class MOVBELifter(ida_hexrays.microcode_filter_t):
  def __init__(self):
    super().__init__()

  def install(self):
    ida_hexrays.install_microcode_filter(self, True)
    print("MOVBE lifter installed")

  def remove(self):
    ida_hexrays.install_microcode_filter(self, False)
    print("MOVBE lifter removed")

  def match(self, cdg):
    return cdg.insn.itype == ida_allins.NN_movbe

  def apply(self, cdg):
    insn = cdg.insn
    to_reg = insn.Op1.type == ida_ua.o_reg
    if to_reg:
      size = get_reg_size(insn.Op1)
      arg = cdg.load_operand(1)
    else:
      size = get_reg_size(insn.Op2)
      arg = ida_hexrays.reg2mreg(insn.Op2.reg)

    call_arg = ida_hexrays.mcallarg_t()
    call_arg.set_regarg(arg, size, get_type_info(size))

    call_info = ida_hexrays.mcallinfo_t()
    call_info.cc = ida_typeinf.CM_CC_FASTCALL
    call_info.callee = ida_idaapi.BADADDR
    call_info.role = ida_hexrays.ROLE_UNK
    call_info.flags = ida_hexrays.FCI_SPLOK | ida_hexrays.FCI_FINAL | ida_hexrays.FCI_PROP | ida_hexrays.FCI_PURE
    call_info.solid_args = 1
    call_info.args.push_back(call_arg)
    call_info.return_type = get_type_info(size)

    call_insn = ida_hexrays.minsn_t(cdg.insn.ea)
    call_insn.opcode = ida_hexrays.m_call
    call_insn.l.make_helper(get_helper_name(size))
    call_insn.d.t = ida_hexrays.mop_f
    call_insn.d.f = call_info
    call_insn.d.size = size

    if to_reg:
      call_result = cdg.mba.alloc_kreg(size)

      mov_insn = ida_hexrays.minsn_t(cdg.insn.ea)
      mov_insn.opcode = ida_hexrays.m_mov
      mov_insn.l.t = ida_hexrays.mop_d
      mov_insn.l.d = call_insn
      mov_insn.l.size = size
      mov_insn.d.t = ida_hexrays.mop_r
      mov_insn.d.r = call_result
      mov_insn.d.size = size

      cdg.mb.insert_into_block(mov_insn, cdg.mb.tail)
      dest = ida_hexrays.reg2mreg(insn.Op1.reg)
      cdg.emit(ida_hexrays.m_mov, size, call_result, 0, dest, 0)
      cdg.mba.free_kreg(call_result, size)
    else:
      call_mop = ida_hexrays.mop_t()
      call_mop.t = ida_hexrays.mop_d
      call_mop.d = call_insn
      call_mop.size = size
      cdg.store_operand(0, call_mop)

    return ida_hexrays.MERR_OK


def PLUGIN_ENTRY():
  return MOVBE()


class MOVBE(ida_idaapi.plugin_t):
  flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE
  comment = "MOVBE support for the Hex-Rays x64 Decompiler"
  help = ""
  wanted_name = "MOVBE"
  wanted_hotkey = ""
  loaded = False

  def init(self):
    if ida_idp.ph.id != ida_idp.PLFM_386:
      return ida_idaapi.PLUGIN_SKIP

    ida_loader.load_plugin("hexx64")
    if not ida_hexrays.init_hexrays_plugin():
      return ida_idaapi.PLUGIN_SKIP
    assert ida_hexrays.init_hexrays_plugin(), "Missing Hexx64 Decompiler..."

    self.movbe_lifter = MOVBELifter()
    self.movbe_lifter.install()

    return ida_idaapi.PLUGIN_KEEP

  def run(self, arg):
    ida_kernwin.warning("%s cannot be run as a script in IDA." % self.wanted_name)

  def term(self):
    self.movbe_lifter = None
