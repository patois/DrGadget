import idaapi
import os,sys, types
from idc import *
from payload import Item
from copy import deepcopy

drgadget_plugins_path = idaapi.idadir(os.path.join("plugins", "drgadget", "plugins"))

sys.path.append(drgadget_plugins_path)

# TODO: remove load- and save payload dialogs from context menu
# and move to IDA's File menu?
class ropviewer_t(idaapi.simplecustviewer_t):

    def __init__(self, payload):
        self.payload = payload

        # FIXME: ugly
        self.menu_loadfromfile  = None
        self.menu_savetofile    = None
        self.menu_copyitem      = None
        self.menu_cutitem       = None
        self.menu_pasteitem     = None
        self.menu_insertitem    = None
        self.menu_jumpto        = None
        self.menu_toggle        = None
        self.menu_deleteitem    = None
        self.menu_edititem      = None
        self.menu_reset         = None
 
        self.window_created      = False
        self.pluginlist         = self.load_plugins()

        self.clipboard = None

        idaapi.simplecustviewer_t.__init__(self)

    def load_plugins(self):
        global drgadget_plugins_path
        
        pluginlist = []
        print "loading extensions..."
        for (_path, _dir, files) in os.walk(drgadget_plugins_path):
            for f in files:
                name, ext = os.path.splitext(f)
                if ext == ".py":
                    print "* %s" % name
                    plugin = __import__(name)
                    # add instance of drgadgetplugin_t class to list
                    pluginlist.append(plugin.drgadgetplugin_t(self.payload, self))
        return pluginlist

    # workaround for a bug (related to IDA itself?)
    # do not allow the window to be opened more than once
    def Show(self):
        if not self.window_created:
            self.window_created = True
            return idaapi.simplecustviewer_t.Show(self)
        return
    
    def Create(self):
        if not idaapi.simplecustviewer_t.Create(self, "Dr. Gadget"):
            return False
        if self.payload:
            self.refresh()
        else:
            self.ClearLines()

        return True

    def OnClose(self):
        self.window_created = False


    def create_colored_line(self, n):
        # todo
        item = self.get_item(n)
        if item != None:
            typ = item.type

            width = self.payload.proc.get_pointer_size()
            cline = idaapi.COLSTR("%04X  " % (n*width), idaapi.SCOLOR_AUTOCMT)
            ea = item.ea
            fmt = self.payload.proc.get_data_fmt_string()
            elem = fmt % ea
            if typ == Item.TYPE_CODE:
                color = idaapi.SCOLOR_CODNAME if SegStart(ea) != BADADDR else idaapi.SCOLOR_ERROR
                elem = idaapi.COLSTR(elem, color)
            else:
                elem = idaapi.COLSTR(elem, idaapi.SCOLOR_DNUM)
            cline += elem
            
            comm = ""
            if typ == Item.TYPE_CODE and SegStart(ea) != BADADDR:
                comm += "<%s> " % (SegName(ea))
            if len(item.comment):
                comm += " %s" % item.comment
            if len(comm):
                comm = "  ; " + comm
                cline += idaapi.COLSTR(comm, idaapi.SCOLOR_AUTOCMT)
            return cline

    def clear_clipboard(self):
        self.clipboard = None

    def set_clipboard(self, item):
        self.clipboard = item

    def get_clipboard(self):
        return self.clipboard


    def create_colored_lines(self):
        lines = []
        for i in xrange(self.payload.get_number_of_items()):
            l = self.create_colored_line(i)
            lines.append(l)
        return lines

    

    def copy_item(self, n):
        item = self.get_item(n)
        if item != None:
            self.set_clipboard((n, "c", item))


    def paste_item(self, n):
        if self.get_clipboard() != None:
            _, mode, item = self.get_clipboard()
            self.insert_item(n, item)
            self.refresh()
            if mode == 'x':
                self.clear_clipboard()


    def cut_item(self, n):
        item = self.get_item_at_cur_line()
        if item != None:
            self.set_clipboard((n, "x", item))
            self.delete_item(n, False)

    def edit_item(self, n):
        item = self.get_item(n)
        if item != None:
            val = item.ea

            newVal = AskAddr(val, "Feed me!")
            if newVal != None:
                item.ea = newVal
                self.set_item(n, item)
                self.refresh()

    def get_item(self, n):
        item = None
        if n < self.payload.get_number_of_items():
            item = deepcopy(self.payload.get_item(n))
        return item            

    def get_item_at_cur_line(self):
        n = self.GetLineNo()
        return self.get_item(n)

    def inc_item_value(self, n):
        item = self.get_item(n)
        if item != None:
            item.ea += 1
            self.set_item(n, item)

    def dec_item_value(self, n):
        item = self.get_item(n)
        if item != None:
            item.ea -= 1
            self.set_item(n, item)   

    def insert_item(self, n, item=None):
        if self.Count() == 0:
            n = 0
        if item == None:
            item = Item(0, Item.TYPE_DATA)
        self.payload.insert_item(n, item)
        self.refresh()

    def set_item(self, n, item):
        self.payload.set_item(n, item)
        self.refresh()

    def delete_item(self, n, ask = True):
        item = self.get_item(n)
        if item != None:
            result = 1
            if ask:
                result = AskYN(0, "Delete item?")
            if result == 1:
                self.payload.remove_item(self.GetLineNo())
                self.refresh()


    def add_comment(self, n):
        item = self.get_item(n)
        if item != None:
            s = AskStr(item.comment, "Enter Comment")
            if s != None:
                item.comment = s
                self.set_item(n, item)
               
    def toggle_item(self, n):
        item = self.get_item(n)
        if item != None:
            if item.type == Item.TYPE_CODE:
                item.type = Item.TYPE_DATA
            else:
                ea = item.ea
                item.type = Item.TYPE_CODE

            self.set_item(n, item)
            l = self.create_colored_line(n)
            self.EditLine(n, l)
            self.Refresh()


    def refresh(self):
        self.ClearLines()
        for line in self.create_colored_lines():
            self.AddLine(line)
        self.Refresh()


    def OnDblClick(self, shift):
        n = self.GetLineNo()
        Jump(self.payload.get_item(n).ea)
        return True


    def OnKeydown(self, vkey, shift):

        n = self.GetLineNo()
        
        # ESCAPE
        if vkey == 27:
            self.Close()

        # ENTER
        elif vkey == 13:
            Jump(self.payload.get_item(n).ea)
            
        # CTRL
        elif shift == 4:
            if vkey == ord("C"):
                self.copy_item(n)

            elif vkey == ord("X"):
                self.cut_item(n)
            elif vkey == ord("V"):
                self.paste_item(n)

            elif vkey == ord("N"):
                self.erase_all()
            elif vkey == ord("L"):
                self.load_binary()
            elif vkey == ord("S"):
                self.load_binary()


        # colon
        elif vkey == 190:
            self.add_comment(self.GetLineNo())

        elif vkey == ord('O'):
            self.toggle_item(n)
            
        elif vkey == ord('D'):
            self.delete_item(n)
                
        elif vkey == ord("E"):
            self.edit_item(n)

        elif vkey == ord("I"):
            self.insert_item(n)

        elif vkey == ord("R"):
            self.refresh()

        elif vkey == ord("1"):
            self.dec_item_value(n)

        elif vkey == ord("2"):
            self.inc_item_value(n)

        else:
            return False
        
        return True


    def OnHint(self, lineno):
        if self.payload.get_item(lineno).type != Item.TYPE_CODE:
            return None
        
        ea = self.payload.get_item(lineno).ea
        dis = self.payload.da.get_disasm(ea)
        hint = ""

        for l in dis:
            hint += idaapi.COLSTR("%s\n" % l, idaapi.SCOLOR_CODNAME)

        size_hint = len(dis)

        if len(dis) == self.payload.da.get_max_insn():
            hint += idaapi.COLSTR("...", idaapi.SCOLOR_CODNAME)
            size_hint = len(hint)
        return(size_hint, hint)


    def OnPopup(self):
        self.ClearPopupMenu()
        self.pluginmenuids = {}
        
        # FIXME: ugly
        if not self.Count():
            self.menu_new = self.AddPopupMenu("New", "Ctrl-N")
            self.AddPopupMenu("-")
            self.menu_loadfromfile = self.AddPopupMenu("Import ROP binary", "Ctrl-L")
            self.AddPopupMenu("-")
            self.menu_insertitem = self.AddPopupMenu("New item", "I")
            if self.payload.get_clipboard() != None:
                self.menu_pasteitem = self.AddPopupMenu("Paste item", "Ctrl-V")
        else:
            self.menu_new = self.AddPopupMenu("New", "Ctrl-N")
            self.AddPopupMenu("-")
            self.menu_loadfromfile = self.AddPopupMenu("Import ROP binary", "Ctrl-L")
            self.menu_savetofile = self.AddPopupMenu("Export ROP binary", "Ctrl-S")
            self.AddPopupMenu("-")
            self.menu_insertitem = self.AddPopupMenu("New item", "I")
            self.menu_deleteitem = self.AddPopupMenu("Delete item", "D")
            self.menu_edititem = self.AddPopupMenu("Edit item address", "E")
            self.menu_toggle = self.AddPopupMenu("Toggle item type", "O")
            self.menu_comment = self.AddPopupMenu("Add comment", ":")
            self.menu_reset  = self.AddPopupMenu("Reset types")
            self.menu_jumpto = self.AddPopupMenu("Go to item address", "Enter")
            self.AddPopupMenu("-")
            self.menu_cutitem = self.AddPopupMenu("Cut item", "Ctrl-X")
            self.menu_copyitem = self.AddPopupMenu("Copy item", "Ctrl-C")
            self.menu_pasteitem = self.AddPopupMenu("Paste item", "Ctrl-V")
            self.AddPopupMenu("-")
            self.menu_refresh = self.AddPopupMenu("Refresh", "R")
            self.AddPopupMenu("-")

        # load dr gadget plugins
        for instance in self.pluginlist:
            result = instance.get_callback_list()
            if result != None:
                for r in result:
                    menu, cb, hotkey = r
                    self.pluginmenuids[self.AddPopupMenu(menu, hotkey)] = cb

        return True

    def load_binary(self):
        fileName = AskFile(0, "*.*", "Import ROP binary")
        if fileName and self.payload.load_from_file(fileName):
            self.refresh()

    def save_binary(self):
        fileName = AskFile(1, "*.*", "Export ROP binary")
        if fileName and self.payload.save_to_file(fileName):
            print "payload saved to %s" % fileName

    def erase_all(self):
        if AskYN(1, "Are you sure?") == 1:
            self.payload.init()
            self.refresh()
    

    def OnPopupMenu(self, menu_id):
        n = self.GetLineNo()
        
        if menu_id == self.menu_new:
            self.erase_all()
            
        elif menu_id == self.menu_loadfromfile:
            self.load_binary()

        elif menu_id == self.menu_savetofile:
            self.save_binary()
                        
        elif menu_id == self.menu_jumpto:
            n = self.GetLineNo()
            Jump(self.payload.get_item(n).ea)


        elif menu_id == self.menu_reset:
            if AskYN(1, "Are you sure?") == 1:
                self.payload.reset_types()
                self.refresh()
                              
        elif menu_id == self.menu_toggle:
            self.toggle_item(n)

        elif menu_id == self.menu_comment:
            self.add_comment(n)

        elif menu_id == self.menu_deleteitem:
            self.delete_item(n)

        elif menu_id == self.menu_insertitem:
            self.insert_item(n)

        elif menu_id == self.menu_edititem:
            self.edit_item(n)

        elif menu_id == self.menu_copyitem:
            self.copy_item(n)

        elif menu_id == self.menu_cutitem:
            self.cut_item(n)

        elif menu_id == self.menu_pasteitem:
            self.paste_item(n)

        elif menu_id == self.menu_refresh:
            self.refresh()

        elif menu_id in self.pluginmenuids.keys():
            self.pluginmenuids[menu_id]()
            
        else:
            return False
        
        return True
