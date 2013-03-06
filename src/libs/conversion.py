# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno

""" Conversion (Bitwise Operations) module """


def nodeIDtoUpperLower(node_id):
    return (((node_id & 0xff00) >> 8),(node_id & 0x00ff))
