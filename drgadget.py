#################################################
#
#   Dr. Gadget
#   ----------------------------------------
#
#   history:
#   2010/07/24  v0.1   - first public release
#   2010/07/26  v0.1.1 - added copy/cut/paste
#   2010/07/31  v0.2   - with kind permission,
#                        added Elias Bachaalany's
#                        script to find opcodes/instructions
#   2010/08/25  v0.3  -  added ARM support
#                        primitive stack/pc tracing for ARM
#                        Disassembly view export to file
#                        string reference scanning in disasm view
#                        add support for comments both in rop view and disasm view in sync
#                        sync offset number diplay between ropview and disasm
#                        by Karthik (neox.fx at gmail dot com)
#   2012/09/12 v0.31  -  fixed bug which could prevent files from being loaded (thanks Ivanlef0u)
#                        project is now on github https://github.com/patois/DrGadget.git
#                        Dr. Gadget is now licensed under the Beerware license
#   2013/04/07 v0.4   -  * code modularization
#                        * clean up
#                        * Dr.Gadget can be customized using "plugins" now
#                        * Dr.Gadget aims to be compatible to all the processor modules
#                          that are supported by IDA (including 64bit processor modules)
#                        * added sample plugins
#                        * payload state is saved to idb and restored from it, respectively
#                        
#   2013/06/19 v0.41  -  * some fixes, new disassembly module
#
#   2013/12/18 v0.42  -  * with the introduction of IDA 6.5, there is GetDisasmEx() which allows
#                          code to be disassembled at arbitrary addresses within the IDB. Therefore,
#                          it is no longer required to "destroy" the disassembly by undefining code
#                          using the SDK's MakeUnknown() function, which leaves the original disassembly
#                          intact =)
#                        * This version of Dr.Gadget requires IDA > 6.5.
#
#   2014/07/25 v0.43a -  * changes to disasm module
#                        * made it work "somehow" ;-)
#                        * Decided to release this version as a fork of the "original" Dr.Gadget plugin
#                          under the project name "Dr.rer.oec.Gadget". Most of the new features haven't
#                          (extensively) been tested and/or its implementation been finished.
#                          Although buggy, better release now than never :-P
#                          Please do feel free to fork/modify/do whatever you want and
#                          please use responsibly :-)
#
#   2014/07/26 v0.44b -  * some fixes here and there
#                        * '13158F73919A45915A479DD21C6170375C4BE4B7' edition
#
#   2014/07/26 v0.45b -  * experimental support for processor modules that
#                          support (branch) delay slots
#                        * minor changes/fixes
#                        * 'C2CC13D4198DC2D0D55BFC5F03FC2A8BF92F1395' edition
#
#   2014/07/26 v0.46b -  * various fixes
#                        * added hotkeys "1" and "2" which decrement and
#                          increment an item's value, respectively
#                          -> Comfortably adjust pointers using the keyboard,
#                             view results using hint popup thingie
#                        * '564CFB9617B83F3434DB8633D6D501BDEFD5FAAC' edition
#
#   contributors       : Elias Bachaalany, Karthik, Ivanlef0u
#
#   bugs:
#   - yes :(
#
#   code:
#   - mess :(
#
##################################################


"""
known bugs:
- payload.init()
- plugin hotkeys
- support stack directions?

todo:
- finish disasm "engine"
- add xrefs to "items" class?
- fix plugin hotkey handling
"""

forkname         =  "Dr.rer.oec.Gadget"
__author__       =  "Dennis Elser"
__version__      =  "0.46b"


import struct, os, sys
from idaapi import *
from idc import *

sys.path.append(idadir(os.path.join("plugins", "drgadget")))

import ropviewer
import payload

pluginname = forkname + " " + __version__


# -----------------------------------------------------------------------


class idp_hook(idaapi.IDP_Hooks):
    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)

    def savebase(self, *args):
        if pl:
            print "\n%s: saving...\n" % pluginname
            pl.save_to_idb()
        return _idaapi.IDP_Hooks_savebase(self, *args)


pl = None
rv = None

class drgadget(idaapi.plugin_t):
    flags = 0
    comment = ""
    help = ""
    wanted_name = pluginname
    wanted_hotkey = "Alt-F5"

    def init(self):
        global rv

        self.hook = idp_hook()
        self.hook.hook()
        print "%s: plugin initialized." % pluginname
        rv = None
        return idaapi.PLUGIN_KEEP


    def run(self, arg):
        global pl
        global rv

        if not pl:
            pl = payload.Payload()
            if pl.load_from_idb():
                print "%s: loaded data from IDB." % pluginname
        if not rv:
            rv = ropviewer.ropviewer_t(pl)
            if not rv.Create ():
                print "could not create window."
                return

        rv.Show()
            
    def term(self):
        if self.hook:
            self.hook.unhook()
        pass

# -----------------------------------------------------------------------

def PLUGIN_ENTRY():
    return drgadget()
