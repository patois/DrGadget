from idaapi import *
from idc import *
from idautils import Assemble, Modules
from payload import Item


# -----------------------------------------------------------------------
# Chooser class
class ModuleChooser(Choose2):
    def __init__(self, modules, title):
        self.modules = modules
        Choose2.__init__(self, \
                         title, \
                         [["Name", 30 | Choose2.CHCOL_PLAIN], \
                          ["Base", 10 | Choose2.CHCOL_PLAIN], \
                          ["Size", 10 | Choose2.CHCOL_PLAIN], \
                          ["ASLR", 5 | Choose2.CHCOL_PLAIN], \
                          ["DEP", 5 | Choose2.CHCOL_PLAIN]], \
                         popup_names = ["Insert", "Delete", "Edit", "Refresh"])

    def OnClose (self):
        pass

    def OnGetLine (self, n):
        return self.modules[n-1].columns

    def OnGetSize (self):
        return len(self.modules)

    # dbl click / enter
    def OnSelectLine(self, n):
        return

    def OnRefresh(self, n):
        self.modules = get_modules()
        return len(self.modules)

def get_security_flags(dllchars):
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x40
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT    = 0x100

    dynbase = dllchars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0
    nx      = dllchars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0
    return (dynbase, nx)
    

class ModuleInfo(object):   
    def __init__(self, mod):
        self.dynbase = self.nx = None
        self.name = mod.name
        self.base = mod.base
        self.size = mod.size
        self.rebase_to = mod.rebase_to
        self.dll_char = get_dll_characteristics(self.base, self.size)
        if self.dll_char:
            self.dynbase, self.nx = get_security_flags(self.dll_char)
        
        self.columns = []
        aslr = "N/A"
        dep = "N/A"
        if self.dll_char:
            aslr = "X" if self.dynbase else ""
            dep = "X" if self.dynbase else ""
        self.columns.append(self.name)
        self.columns.append("%X" % self.base)
        self.columns.append("%X" % self.size)
        self.columns.append(aslr)
        self.columns.append(dep)


# -----------------------------------------------------------------------
def get_dll_characteristics(base, size):
    # minimal, bugged pe parser
    result = None
    if size >= 0x40:
        mz = DbgWord(base)
        if mz == 0x5A4D or mz == 0x4D5A:
            offs_pe = DbgDword(base+0x3C)
            if size > offs_pe + 2:
                pe = DbgWord(base + offs_pe)
                if pe == 0x4550:
                    if size > offs_pe + 0x5E + 2:
                        result = DbgWord(base + offs_pe + 0x5E)
    return result
                    
def get_modules():
    results = []
                            
    for mod in Modules():
        results.append(ModuleInfo(mod))
    return results

def display_modules():
    mods = get_modules()
    title = "modules"
    c = ModuleChooser(mods, title)
    c.Show()

payload = None
ropviewer = None


class drgadgetplugin_t:
    def __init__(self, pl, rv):
        global payload
        global ropviewer
        
        payload = pl
        ropviewer = rv
        self.menucallbacks = [("Modinfo", self.run, "Ctrl-F6")]

    # mandatory
    # must return list of tuples
    # (label of menu, callback)
    # or None if no callbacks should be installed
    def get_callback_list(self):
        global payload
        result = self.menucallbacks
        return result
    
    def run(self):
        if GetProcessState() == DSTATE_NOTASK:
            Warning("No modules.")
        else:
            display_modules()

    def term(self):
        pass
