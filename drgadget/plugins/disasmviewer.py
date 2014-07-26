import idaapi
from idc import *
from payload import Item

# this "plugin" is so ugly, it definitely needs fixing at some point.

class disasmviewer_t(idaapi.simplecustviewer_t):
    
    def Create(self, payload, rv):
        if not idaapi.simplecustviewer_t.Create(self, "disassembly"):
            return False

        self.showData   = True
        self.showRet    = True
        self.popStrings = False
        self.strBase    = 0
        self.payload    = payload
        self.rv         = rv

        self.code = []
        self.codetext = []
        self.disasmToRopviewerLine = {}

        self.refresh()
        return True

    def refresh(self):
        self.ClearLines()
        self.codetext = []
        self.code = []
        self.disasmToRopviewerLine = {}
        lnmapper = 0
        datafmt = self.payload.proc.get_data_fmt_string()
        for n in xrange(self.payload.get_number_of_items()):
            self.disasmToRopviewerLine[lnmapper] = n
            cln = idaapi.COLSTR("%04X " % (n*4), idaapi.SCOLOR_AUTOCMT)
            comm = ""
            item = self.payload.get_item(n)
            if len(item.comment):
                comm = "  ; %s" % item.comment
            c_comm = idaapi.COLSTR(comm, idaapi.SCOLOR_AUTOCMT)

            if item.type == Item.TYPE_CODE:
                disasm = self.payload.da.get_disasm(item.ea)
                dtog = False
                for line in disasm:
                    if not dtog:  # add comment only once in a multiline instr seq
                        self.code.append("  \t " + idaapi.COLSTR(line, idaapi.SCOLOR_CODNAME) + c_comm)
                        self.codetext.append("  \t " + line + comm + "\n")
                        dtog = True
                    else:
                        self.code.append("  \t " + idaapi.COLSTR(line, idaapi.SCOLOR_CODNAME))
                        self.codetext.append("  \t " + line + "\n")
                        lnmapper = lnmapper + 1
                        self.disasmToRopviewerLine[lnmapper] = n
                    
            elif self.showData:
                val = self.payload.get_item(n).ea
                if not self.popStrings:
                    self.code.append(cln + idaapi.COLSTR(("    "+datafmt+"h") % val, idaapi.SCOLOR_DNUM) + c_comm)
                    self.codetext.append((("%04X    "+datafmt+"h%s") %(n*4, val, comm)) + "\n")
                else:
                    if (val > self.strBase) and ((val-self.strBase) < self.payload.size):
                        off = val - self.strBase
                        ch1 = ord(self.payload.rawbuf[off:off+1])
                        if (ch1 >= 0x20 and ch1 < 0x7f):
                            eos = self.payload.rawbuf[off:].find(chr(0))
                            trailer = ""
                            if eos > 0:
                                if (eos > 50):
                                    eos = 50
                                    trailer = "..."
                                strtext = "    --> \"%s\"" % self.payload.rawbuf[off:off+eos] + trailer
                            else:
                                strtext = ""
                        else:
                            strtext = ""
                        self.code.append(cln + idaapi.COLSTR(("    "+datafmt+"h") % val, idaapi.SCOLOR_DNUM) + idaapi.COLSTR("%s" % strtext, idaapi.SCOLOR_STRING) + c_comm)
                        self.codetext.append((("%04X    "+datafmt+"h%s%s") % (n*4, val, strtext, comm)) + "\n")
                    else:
                        self.code.append(cln + idaapi.COLSTR(("    "+datafmt+"h") % val, idaapi.SCOLOR_DNUM) + c_comm)
                        self.codetext.append((("%04X    "+datafmt+"h%s") % (n*4, val, comm)) + "\n")
            lnmapper = lnmapper + 1

        for l in self.code:
            self.AddLine(l)            
        self.Refresh()


    def save_to_file(self, filename):
        result = False
        f = None
        try:
            f = open(filename, "w+")
            for l in self.codetext:
                f.write(l)
            result = True
        except Exception, err:
            print "[!] An error occurred:", err
        finally:
            if f:
                f.close()
        return result


    def add_comment(self, n):
        nlo = self.disasmToRopviewerLine[n]
        if nlo < self.payload.get_number_of_items():
            item = self.payload.get_item(nlo)
            s = AskStr(item.comment, "Enter Comment")
            if s:
                item.comment = s
            self.refresh()
            self.rv.refresh()


    def get_switch_setting(self, var):
        return "\7\t" if var else " \t"
        

    def OnKeydown(self, vkey, shift):
        # colon
        if vkey == 190:
            self.add_comment(self.GetLineNo())
            self.Refresh()         

        elif vkey == ord("R"):
            self.refresh()

        else:
            return False
        
        return True


    def OnPopup(self):
        self.ClearPopupMenu()
        self.menu_toggledata = self.AddPopupMenu(self.get_switch_setting(self.showData) + "Show data lines") 
        self.menu_populatestrings = self.AddPopupMenu(self.get_switch_setting(self.popStrings) + "Show strings referenced")
        self.menu_savetofile = self.AddPopupMenu("Export Disassembly")
        return True


    def OnPopupMenu(self, menu_id):
        if menu_id == self.menu_toggledata:
            self.showData = not self.showData
            self.refresh()
            
        elif menu_id == self.menu_populatestrings:
            self.popStrings = not self.popStrings
            if self.popStrings:
                self.strBase = idc.AskLong(self.strBase, "Base displacement to use?")
            self.refresh()

        elif menu_id == self.menu_savetofile:
            fileName = idc.AskFile(1, "", "Export ROP Disassembly")
            if fileName and self.save_to_file(fileName):
                print "disasm saved to %s" % fileName
            
        else:
            return False
        
        return True

class drgadgetplugin_t:
    def __init__(self, payload, rv):
        self.payload = payload
        self.rv = rv
        self.menucallbacks = [("Show disassembly", self.run, "Ctrl-F5")]


    # mandatory
    # must return list of tuples or None
    # (label of menu, callback)
    # or None if no callbacks should be installed    
    def get_callback_list(self):
        return self.menucallbacks
    
    def run(self):
        if self.payload.get_number_of_items() == 0:
            idc.Warning("Nothing to disassemble!")
        else:
            try:
                self.disasm
                self.disasm.refresh()
                self.disasm.Show()
                    
            except:
                self.disasm = disasmviewer_t()
                if self.disasm.Create(self.payload, self.rv):
                    self.disasm.Show()
                else:
                    del self.disasm

    def term(self):
        pass
