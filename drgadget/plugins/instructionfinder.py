from idaapi import *
from idc import *
from idautils import Assemble
from payload import Item

# the following code was taken from
# http://hexblog.com/2009/09/assembling_and_finding_instruc.html
# -----------------------------------------------------------------------
def FindInstructions(instr, asm_where=None):
    """
    Finds instructions/opcodes
    @return: Returns a tuple(True, [ ea, ... ]) or a tuple(False, "error message")
    """
    if not asm_where:
        # get first segment
        asm_where = FirstSeg()
        if asm_where == idaapi.BADADDR:
            return (False, "No segments defined")

    # regular expression to distinguish between opcodes and instructions
    re_opcode = re.compile('^[0-9a-f]{2} *', re.I)

    # split lines
    lines = instr.split(";")

    # all the assembled buffers (for each instruction)
    bufs = []
    for line in lines:
        if re_opcode.match(line):
            # convert from hex string to a character list then join the list to form one string
            buf = ''.join([chr(int(x, 16)) for x in line.split()])
        else:
            # assemble the instruction
            ret, buf = Assemble(asm_where, line)
            if not ret:
                return (False, "Failed to assemble:"+line)
        # add the assembled buffer
        bufs.append(buf)

    # join the buffer into one string
    buf = ''.join(bufs)
    
    # take total assembled instructions length
    tlen = len(buf)

    # convert from binary string to space separated hex string
    bin_str = ' '.join(["%02X" % ord(x) for x in buf])

    # find all binary strings
    print "Searching for: [%s]" % bin_str
    ea = MinEA()
    ret = []
    while True:
        ea = FindBinary(ea, SEARCH_DOWN, bin_str)
        if ea == idaapi.BADADDR:
            break
        ret.append(ea)
        ea += tlen
    if not ret:
        return (False, "Could not match [%s]" % bin_str)
    Message("done.\n")
    return (True, ret)

# -----------------------------------------------------------------------
# Chooser class
class SearchResultChoose(Choose2):
    def __init__(self, list, title, payload, rv):
        self.list = list
        self.payload = payload
        self.rv = rv
        self.copy_item_cmd_id = self.append_item_cmd_id = None
        Choose2.__init__(self, \
                         title, \
                         [["address", 10 | Choose2.CHCOL_PLAIN], \
                          ["segment", 10 | Choose2.CHCOL_PLAIN], \
                          ["code", 30 | Choose2.CHCOL_PLAIN]], \
                         popup_names = ["Insert", "Delete", "Edit", "Copy item"])

    def OnCommand(self, n, cmd_id):
        if cmd_id == self.copy_item_cmd_id:
            self.payload.set_clipboard((0, "c", Item(self.list[n-1].ea, Item.TYPE_CODE)))

        elif cmd_id == self.append_item_cmd_id:
            self.payload.append_item(Item(self.list[n-1].ea, Item.TYPE_CODE))
            self.rv.refresh()
        return 0

    def OnClose (self):
        pass

    def OnGetLine (self, n):
        return self.list[n-1].columns

    def OnGetSize (self):
        return len (self.list)

    # dbl click / enter
    def OnSelectLine(self, n):
        Jump (self.list[n-1].ea)

    def set_copy_item_handler(self, cmd_id):
        self.copy_item_cmd_id = cmd_id

    def set_append_item_handler(self, cmd_id):
        self.append_item_cmd_id = cmd_id
        

# -----------------------------------------------------------------------
# class to represent the results
class SearchResult:
    def __init__(self, ea):
        self.ea = ea
        self.columns = []
        if not isCode(GetFlags(ea)):
            MakeCode(ea)
        t = idaapi.generate_disasm_line(ea)
        if t:
            line = idaapi.tag_remove(t)
        else:
            line = ""
        self.columns.append ("%08X" % ea)
        n = SegName(ea)
        self.columns.append (n)
        self.columns.append (line)

# -----------------------------------------------------------------------
def find(payload, ropviewer, s=None, x=False, asm_where=None):
    b, ret = FindInstructions(s, asm_where)
    if b:
        # executable segs only?
        if x:
            results = []
            for ea in ret:
                seg = idaapi.getseg(ea)
                if (not seg) or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
                    continue
                results.append(SearchResult(ea))
        else:
            results = [SearchResult(ea) for ea in ret]
        title = "Search result for: [%s]" % s
        idaapi.close_chooser(title)
        c = SearchResultChoose(results, title, payload, ropviewer)
        c.Show()
        c.set_copy_item_handler(c.AddCommand("Copy to payload clipboard"))
        c.set_append_item_handler(c.AddCommand("Append to payload"))
    else:
        print ret

class drgadgetplugin_t:
    def __init__(self, payload, rv):
        self.payload = payload
        self.rv = rv
        self.menucallbacks = [("Find instructions", self.run, "Ctrl-F3")]

    # mandatory
    # must return list of tuples
    # (label of menu, callback)
    # or None if no callbacks should be installed
    def get_callback_list(self):
        result = None
        if self.payload.proc.supports_assemble():
            result = self.menucallbacks
        return result
    
    def run(self):
        s = AskStr ("", "Find instructions (example: mov eax, 1; ret) ")
        if s:
            find (self.payload, self.rv, s, AskYN (1, "Scan executable segments only?") == 1)

    def term(self):
        pass
