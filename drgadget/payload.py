import idaapi
from idc import *
import pickle

class Item:
    TYPE_DATA = 0
    TYPE_CODE = 1
    
    def __init__(self, ea, _type, comment = ""):
        self.ea = ea
        self.type = _type
        self.comment = comment

class TargetProcessor:
    def __init__(self):      
        self.flags = idaapi.ph_get_flag()
        # instead of checking ph flags, should __EA64__ be used?
        self.is_64bit = (self.flags & idaapi.PR_USE64) != 0
        self.is_32bit = (self.flags & idaapi.PR_USE32) != 0
        self.is_stack_up = (self.flags & idaapi.PR_STACK_UP) != 0
        self.id = idaapi.ph_get_id()
        self.assembler = (self.flags & idaapi.PR_ASSEMBLE) != 0
        
        # processor default ret instruction (icode, not opcode!)
        self.ret_icodes = [idaapi.ph_get_icode_return()]

        # ptrsize in bytes
        self.ptrsize = 2
        if self.is_32bit:
            self.ptrsize = 4
        if self.is_64bit:
            self.ptrsize = 8

        self.ptrsize_mapper = {2:"H", 4:"I", 8:"Q"}
        self.datafmt_mapper = {2:"%04X", 4:"%08X", 8:"%016X"}
        self.endianness = idaapi.get_inf_structure().mf

    def supports_assemble(self):
        return self.assembler
    
    def add_ret_icode(self, icode):
        self.ret_icodes.append(icode)

    def get_ret_instructions(self):
        return self.ret_icodes

    def is_little_endian(self):
        return self.endianness == 0

    def get_pointer_size(self):
        return self.ptrsize

    def get_ptr_pack_fmt_string(self):
        endiannesfmt = "<" if self.is_little_endian() else ">"
        return endiannesfmt+self.ptrsize_mapper[self.get_pointer_size()]

    def get_data_fmt_string(self):
        return self.datafmt_mapper[self.ptrsize]
        

class DisasmEngine:
    def __init__(self):
        self.maxinstr = 20 # max instructions to disasm per "gadget"

    def set_max_insn(self, count):
        self.maxinstr = count

    def is_ret(self, ea):
        return idaapi.is_ret_insn(ea)
    
    def get_disasm(self, ea):
        next = ea
        disasm = []
        endEA = idaapi.BADADDR
        inscnt = 0
        while (next != endEA) and (inscnt < self.maxinstr):
            line = GetDisasmEx (next, GENDSM_FORCE_CODE)       
            disasm.append (line)
            if self.is_ret(next):
                return disasm
            inscnt += 1
            # I hope "NextHead" is the correct function to use
            next = NextHead (next, endEA)
        return disasm
    

class Payload:
    def __init__(self, items = []):
        self.init(items)

    def init(self, items = []):
        self.items = items
        self.size = 0
        self.rawbuf = ""
        self.clipboard = None
        self.nodename = "$ drgadget"
        self.proc = TargetProcessor()
        self.da = DisasmEngine()

    def load_from_idb(self):
        node = idaapi.netnode(0x41414141)
        node.create(self.nodename)
        result = node.getblob(0, "D")
        if result:
            self.items = pickle.loads(result)
        return result

    def save_to_idb(self):
        node = idaapi.netnode(0x41414141)
        node.create(self.nodename)
        node.setblob(pickle.dumps(self.items), 0, "D")

        
    def load_from_file(self, fileName):
        self.__init__()
        result = False
        f = None
        try:
            f = open(fileName, "rb")
            self.rawbuf = f.read()
            self.size = len(self.rawbuf)
            self.items = self.deserialize_items_from_buf(self.rawbuf)
            result = True
        except:
            pass
        finally:
            if f:
                f.close()
        return result


    def save_to_file(self, fileName):
        result = False
        f = None
        try:
            f = open(fileName, "wb")
            buf = self.serialize_buf_from_items()
            f.write(buf)
            result = True
        except:
            pass
        finally:
            if f:
                f.close()
        return result

    def clear_clipboard(self):
        self.clipboard = None

    def set_clipboard(self, item):
        self.clipboard = item

    def get_clipboard(self):
        return self.clipboard

    def serialize_buf_from_items(self):
        buf = ""
        for item in self.items:
            buf += struct.pack(self.proc.get_ptr_pack_fmt_string(), item.ea)
        return buf
    

    def deserialize_items_from_buf(self, buf):
        itemlist = []
        for p in xrange(0, len(buf), 4):
            try:
                ea = struct.unpack(self.proc.get_ptr_pack_fmt_string(), buf[p:p+self.proc.get_pointer_size()])[0]
            except:
                break
            itemlist.append(Item(ea, 0))
        return itemlist


    def get_number_of_items(self):
        return len(self.items)


    def get_item(self, n):
        return self.items[n]


    def insert_item(self, n, item):
        self.items.insert(n, item)


    def append_item(self, item):
        self.items.insert(len(self.items), item)


    def remove_item(self, n):
        self.items.pop(n)


    def reset_types(self):
        for n in xrange(self.get_number_of_items()):
            #self.set_type(n, 0)
            self.get_item(n).type = Item.TYPE_DATA



