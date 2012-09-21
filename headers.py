#!/usr/bin/python
# -*- coding: UTF-8 -*-
## This file is part of ccsocket
## Copyright (C) Tomas Dragoun <drakoviens@gmail.com>
## This program is published under a GPLv3 license
########################################################



from scapy.layers.inet6 import ICMPv6Unknown, _IPv6ExtHdr
from scapy.all import * 
import socket

#----------------------------------------------------------------------------------
############################
##                        ##
##        IPv6 AH         ##
##                        ##
############################
#
#    IPv6ExtHdrAH format defined by RFC 4302
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | Next Header   |  Payload Len  |          RESERVED             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                 Security Parameters Index (SPI)               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Sequence Number Field                      |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   +                Authentication Data (variable)                 |
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

try:
  class IPv6ExtHdrAH(_IPv6ExtHdr):
    ''' 
        This class represents IPv6ExtHdrAH structure. ICV is NOT
        computed! Length is computed automatically according to 
        RFC 4302. Metaclass is _IPv6ExtHdr.
    '''
    name = "IPv6 Extension Header - Authentication"
    ''' header fields '''
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    # IPv6 Next Header 1B field
                    FieldLenField("len", None, length_of="icv", fmt="B",
                                  adjust = lambda pkt,x: ((x / 4) + 1)), 
                    # Payload Len 1B field
                    ShortField("res", 0), 
                    # Reserved 2B field
                    IntField("spi", 0),
                    # SPI 2B field
                    IntField("seq", 0),
                    # Sequence Number 2B field
                    StrLenField('icv', '', length_from=lambda pkt:
                               ((pkt.len - 1) * 4))
                    #ICV variable len field 
                    ]

    ''' Next Header field of prior header is overloaded when building packet '''
    overload_fields = {IPv6: { "nh": 51 }}
except:
  pass

try:
    ''' AH Next Header number defined by IANA '''
    ipv6nhcls[51] = "IPv6ExtHdrAH"
except:
  pass

#############################
###   AH layer bindings   ###
#############################

'''  
    New layer added to Scapy must be bound in order to be decoded correctly
    by Next Header field.
'''
try:
    layer_bonds = [( IPv6ExtHdrAH, TCP, {"nh" : socket.IPPROTO_TCP} ),
                   ( IPv6ExtHdrAH, UDP, {"nh" : socket.IPPROTO_UDP} ),
                   ( IPv6ExtHdrAH, ICMP, {"nh" : socket.IPPROTO_ICMP} ),
                   ( IPv6ExtHdrAH, ICMPv6Unknown, {"nh" : socket.IPPROTO_ICMPV6} ),
                   ( IPv6ExtHdrAH, IP, {"nh" : socket.IPPROTO_IPIP} ),
                   ( IPv6ExtHdrAH, IPv6, {"nh" : socket.IPPROTO_IPV6} ),
                   ( IP, IPv6ExtHdrAH, {"proto" : socket.IPPROTO_AH} ),
                   ( IPv6, IPv6ExtHdrAH, { "nh" : socket.IPPROTO_AH} ),]

    for l in layer_bonds:
        bind_layers(*l)
except:
    pass
#----------------------------------------------------------------------------------

############################
##                        ##
##       StrHeader        ##
##                        ##
############################
try:
  class StrHeader(Packet): 
    ''' This class represents pseudo packet used by RawEncoder '''
    name = "StrHeader"
    fields_desc=[ByteEnumField("nh", 59, ipv6nh),
                 FieldLenField('dlen', None, length_of='data'),
                 StrLenField('data', '', length_from=lambda pkt:pkt.dlen), 
                 StrField('msg', ''), ]
except:
    pass
#----------------------------------------------------------------------------------
