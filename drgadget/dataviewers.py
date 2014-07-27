import idaapi
from idc import *
from payload import Item

# simple data container for now
# subject to change

class simpledataviewer_t(idaapi.simplecustviewer_t):
    
    def Create(self, title):
        self.closed = False
        if not idaapi.simplecustviewer_t.Create(self, title):
            return False

        self.content   = []
        return True

    def OnClose(self):
        self.closed = True

    def clear(self):
        self.content = []

    def add_line(self, l):
        self.content.append(l)
        self.update()

    def update(self):
        if self.closed:
            self.Show()
            self.closed = False
        self.ClearLines()
        for l in self.content:
            self.AddLine(l)
        self.Refresh()
