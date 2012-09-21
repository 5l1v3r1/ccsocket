#!/usr/bin/python
# -*- coding: UTF-8 -*-
## This file is part of ccsocket
## Copyright (C) Tomas Dragoun <drakoviens@gmail.com>
## This program is published under a GPLv3 license
########################################################


import os
from constants import Constants
from cStringIO import StringIO

############################
##                        ##
##    Ip6tablesManager    ##
##                        ##
############################

class Ip6tablesManager(object):
#----------------------------------------------------------------------------------
    '''
        This classs manages Ip6tables rules. When socket is bound, specified  pack-
        ets are redirected to appropriate queue. 	
    '''
#----------------------------------------------------------------------------------    
    @staticmethod
    def addrule(host, proto, port, type, delete = False):
        ''' Edits particular rule in Ip6tables '''
        const = Constants()
        ''' Keywords defined in Ip6tables '''
        protocols = ['all', 'icmpv6', 'tcp', 'udp'] 
        buffer = StringIO()
        ''' Redirect packets to queue with port as number '''
        buffer.write('ip6tables -j NFQUEUE --queue-num ')
        buffer.write(str(port))
        if delete: # removes the rule
            buffer.write(' -D ')
        else:
            buffer.write(' -I')
                
        if type == const.RULE_TYPE_INPUT:                     
            buffer.write(' INPUT') # incoming packets redirected to queue
            if len(host) > 0:
                buffer.write(' -s ')
                buffer.write(str(host))  # source host filter
                
        elif type == const.RULE_TYPE_OUTPUT:            
            buffer.write(' OUTPUT') # outgoing packets redirected to queue
            if len(host) > 0:
                buffer.write(' -d ') 
                buffer.write(str(host)) # target host filter
        
        elif type == const.RULE_TYPE_FORWARD_IN:            
            buffer.write(' FORWARD') # outgoing packets redirected to queue
            if len(host) > 0:
                buffer.write(' -s ') 
                buffer.write(str(host)) # target host filter
                
        elif type == const.RULE_TYPE_FORWARD_OUT:            
            buffer.write(' FORWARD') # outgoing packets redirected to queue
            if len(host) > 0:
                buffer.write(' -d ') 
                buffer.write(str(host)) # target host filter
                
        buffer.write(' -p ' + protocols[proto]) # protocol filter - default all
        command = buffer.getvalue()
        buffer.close()
        os.system(command) # execute command - root privileges needed
        
        ''' Mangle table is used to differ between incoming and outgoing packets'''
        buffer = StringIO()
        buffer.write('ip6tables -t mangle')
        if delete: # remove rule
            buffer.write(' -D')
        else: # insert rule
            buffer.write(' -I')

        if type == const.RULE_TYPE_INPUT:
            buffer.write(' INPUT -j MARK --set-mark 0x01') # mark incoming packets
            if len(host) > 0:
                buffer.write(' -s ')
                buffer.write(str(host)) # source host filter
        
        elif type == const.RULE_TYPE_OUTPUT:
            buffer.write(' OUTPUT -j MARK --set-mark 0x02')# mark outgoing packets
            if len(host) > 0:
                buffer.write(' -d ')
                buffer.write(str(host)) # target host filter            
        
        elif type == const.RULE_TYPE_FORWARD_IN: # mark incoming forwarded
            buffer.write(' FORWARD -j MARK --set-mark 0x01') 
            if len(host) > 0:
                buffer.write(' -s ') 
                buffer.write(str(host))                              
        
        elif type == const.RULE_TYPE_FORWARD_OUT: # mark outgoing forwarded
            buffer.write(' FORWARD -j MARK --set-mark 0x02') 
            if len(host) > 0:
                buffer.write(' -d ') 
                buffer.write(str(host)) # target host filter        
                
        buffer.write(' -p ' + protocols[proto]) # protocol filter - default all 
        command = buffer.getvalue()
        buffer.close()
        os.system(command) # execute command - root privileges needed
#----------------------------------------------------------------------------------    
    @staticmethod
    def removerule(host, proto, port, type):
        ''' Removes rule from Ip6tables '''
        Ip6tablesManager.addrule(host, proto, port, type, True)
#----------------------------------------------------------------------------------
