# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno

""" Conversion (Bitwise Operations) module """


def indextoUpperLower(index):
    return (((index & 0xff00) >> 8),(index & 0x00ff))

def indexfromUpperLower(up, low):
    return (((int(up) & 0x00ff) << 8) | (int(low) & 0x00ff))

def createNodeIPv4(datapath_index, port_index):
    (d_up, d_low) = indextoUpperLower(datapath_index)
    (p_up, p_low) = indextoUpperLower(port_index)
    return str(d_up) + "." + str(d_low) + "." + str(p_up) + "." + str(p_low)
