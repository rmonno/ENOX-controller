# Copyright 2008 (C) Nicira, Inc.
# 
# This file is part of NOX.
# 
# NOX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# NOX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with NOX.  If not, see <http://www.gnu.org/licenses/>.
import array
from nox.lib.packet.ethernet import *
from nox.coreapps.testharness.testdefs import *

large_udp = \
"""\
\xff\xff\xff\xff\xff\xff\x00\x1d\x09\x21\x7f\x14\x08\x00\x45\x00\
\x02\x40\x00\x00\x00\x00\x40\x11\x78\xae\x00\x00\x00\x00\xff\xff\
\xff\xff\x00\x44\x00\x43\x02\x2c\x5e\xe2\x01\x01\x06\x00\x95\x14\
\xf7\x2d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x1d\x09\x21\x7f\x14\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63\x35\x01\x01\x3d\x07\x01\
\x00\x1d\x09\x21\x7f\x14\x3c\x06\x75\x64\x68\x63\x70\x20\x37\x07\
\x01\x03\x06\x0c\x0f\x1c\x2c\xff\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
"""


def fullUDPPacket():    
    eth = ethernet(array('B',large_udp))   
    udph = eth.find('udp')
    iph  = eth.find('ipv4')
    nox_test_assert(udph, 'udp parse')
    nox_test_assert(iph)
    nox_test_assert(udph.srcport == 68)
    nox_test_assert(udph.dstport == 67)
    nox_test_assert(udph.len     == 556)
    nox_test_assert(udph.csum    == 0x5ee2)
    nox_test_assert(udph.checksum() == udph.csum)
    nox_test_assert(len(udph.payload) == udph.len - 8)
    nox_test_assert(udph.tostring() == large_udp[34:] )
    dhcph = eth.find('dhcp')

    nox_test_assert(dhcph)
    nox_test_assert(dhcph.op    == 1)
    nox_test_assert(dhcph.htype == 1)
    nox_test_assert(dhcph.hlen  == 6)
    nox_test_assert(dhcph.hops  == 0)
    nox_test_assert(dhcph.xid   == 0x9514f72d)
    nox_test_assert(dhcph.secs  == 0)
    nox_test_assert(dhcph.flags == 0)
    nox_test_assert(dhcph.ciaddr == 0)
    nox_test_assert(dhcph.yiaddr == 0)
    nox_test_assert(dhcph.siaddr == 0)
    nox_test_assert(dhcph.giaddr == 0)
    nox_test_assert(array_to_octstr(dhcph.chaddr[:6]) == '00:1d:09:21:7f:14')
    nox_test_assert(len(dhcph.parsedOptions.keys()) == 4)
