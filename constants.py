#!/usr/bin/python
# -*- coding: UTF-8 -*-
## This file is part of ccsocket
## Copyright (C) Tomas Dragoun <drakoviens@gmail.com>
## This program is published under a GPLv3 license
########################################################


############################
##                        ##
##       Constants        ##
##                        ##
############################

class Constants(object):
#----------------------------------------------------------------------------------  
    '''
        This class contains used constants.
    '''
#----------------------------------------------------------------------------------
    def __init__(self):
        ''' Transfer mode '''
        self.SOCK_TYPE_PASSIVE = 0
        self.SOCK_TYPE_ACTIVE = 1
        ''' Socket mode '''
        self.MODE_NONBLOCKING = 0
        self.MODE_BLOCKING = 1        
        self.MODE_TIMEOUT = 2
        ''' Protocol filter '''
        self.PROTO_ALL = 0
        self.PROTO_ICMP = 1
        self.PROTO_TCP = 2
        self.PROTO_UDP = 3
        ''' 
            Ip6tables traffic type:  INPUT (for packets destined to local sockets), 
            FORWARD (for packets being routed through the box), and OUTPUT (for 
            locally-generated packets.
            
        '''
        self.RULE_TYPE_INPUT = 0
        self.RULE_TYPE_OUTPUT = 1
        self.RULE_TYPE_FORWARD_IN = 2
        self.RULE_TYPE_FORWARD_OUT = 3
        ''' Covert channel types '''
        self.TYPE_AHICV = 0
        self.TYPE_AHRES = 1
        self.TYPE_DESTOPTPADN = 2 
        self.TYPE_DESTOPTUNKNOWN = 3                    
        self.TYPE_FLOWLAB = 4
        self.TYPE_FRAGFAKE = 5
        self.TYPE_FRAGRES1 = 6
        self.TYPE_FRAGRES2 = 7
        self.TYPE_FRAGNH = 8
        self.TYPE_HBHPADN = 9
        self.TYPE_HBHUNKNOWN = 10
        self.TYPE_HOPLIMIT = 11
        self.TYPE_RALERT = 12
        self.TYPE_RAW = 13
        self.TYPE_ROUTE0 = 14
        self.TYPE_ROUTERES = 15
        self.TYPE_SRCADDR = 16
        self.TYPE_TRAFFICCLS = 17
#----------------------------------------------------------------------------------
