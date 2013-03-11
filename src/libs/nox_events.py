# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno

""" Events declaration for NOX application """

from nox.lib.core import pyevent


class Pck_setFlowEntryEvent(pyevent):
    NAME = 'pck_set_flow_entry_event'

    def __init__(self, ip_src, ip_dst):
        self.ip_src = ip_src
        self.ip_dst = ip_dst

    def describe(self):
        return pyevent(Pck_setFlowEntryEvent.NAME, self)
