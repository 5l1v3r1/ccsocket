#!/usr/bin/python
# -*- coding: UTF-8 -*-
## This file is part of ccsocket
## Copyright (C) Tomas Dragoun <drakoviens@gmail.com>
## This program is published under a GPLv3 license
########################################################


from dgram_socket import DgramSocket
from message_encoder_factory import MessageEncoderFactory
from socket import *
import os
import sys

#----------------------------------------------------------------------------------  
def channelsinfo():
        ''' 
            Returns dictionary in format: {channel number:(encoder type, capacity)}
        '''
        encoders = MessageEncoderFactory.getencoders()
        types = {}
        for n in xrange(len(encoders)):
            encoder = encoders[n]()
            types[n] = (type(encoder), encoder.getmax())
        return types
#----------------------------------------------------------------------------------  


############################
##                        ##
##       ccsocket         ##
##                        ##
############################

class socket(socket):
#----------------------------------------------------------------------------------  
    '''
        This class defines entry point of framework. When initialized as dgram 
        socket for IPv6 with ROOT privileges, data are sent via covert channel
        using class DgramSocket. Calls are redirected to regular socket other-
        wise. 
    '''
#----------------------------------------------------------------------------------
    def __init__(self, family = AF_INET6, type = SOCK_DGRAM,
                 proto = 0, _sock = None, chtype = 3, band = 0):
        self._socket = None
        ''' check root '''
        if family == AF_INET6 and type == SOCK_DGRAM and os.getuid() == 0:            
            self._socket = DgramSocket(chtype, band)
        else:
            super(socket, self).__init__(family, type, proto, _sock)
#----------------------------------------------------------------------------------
    def bind(self, addr):
        if self._socket:
            return self._socket.bind(addr)
        else:
            return super(socket, self).bind(addr)
#----------------------------------------------------------------------------------
    def recv(self, bufsize, flags = 0):
        if self._socket:
            return self._socket.recv(bufsize)
        else:
            return super(socket, self).recv(bufsize, flags)
#----------------------------------------------------------------------------------
    def recvfrom(self, bufsize, flags = 0):
        if self._socket:
            return self._socket.recvfrom(bufsize)
        else:
            return super(socket, self).recvfrom(bufsize, flags)
#----------------------------------------------------------------------------------
    def recvfrom_into(self, buffer, nbytes = 0, flags = 0):
        if self._socket:
            self._socket.recvfrom_into(buffer, nbytes)
        else:
            super(socket, self).recvfrom_into(buffer, nbytes, flags)
#----------------------------------------------------------------------------------
    def recv_into(self, buffer, nbytes = 0, flags = 0):
        if self._socket:
            self._socket.recv_into(bufsize, nbytes)
        else:
            super(socket, self).recv_into(bufsize, nbytes, flags)
#----------------------------------------------------------------------------------
    def sendto(self, string, addr = '', flags = 0):
        if self._socket:
            return self._socket.sendto(string, addr)
        else:
            return super(socket, self).sendto(string, addr, flags)
#----------------------------------------------------------------------------------
    def setblocking(self, value):
        if self._socket:
            self._socket.setblocking(value)
        else:
            super(socket, self).setblocking(value)
#----------------------------------------------------------------------------------
    def settimeout(self, value):
        if self._socket:
            self._socket.settimeout(value)
        else:
            super(socket, self).settimeout(value)
#----------------------------------------------------------------------------------
    def gettimeout(self):
        if self._socket:
            return self._socket.gettimeout()
        else:
            return super(socket, self).gettimeout()
#----------------------------------------------------------------------------------
    def close(self):
        if self._socket:
            return self._socket.close()
        else:
            return super(socket, self).close()    
#----------------------------------------------------------------------------------
    def setactive(self, value):
        if self._socket:
            self._socket.setactive(value)
#----------------------------------------------------------------------------------
    def setfilter(self, proto):
        if self._socket:
            self._socket.setfilter(proto)
#----------------------------------------------------------------------------------
    def setdelay(self, seconds):
        if self._socket:
            self._socket.setdelay(seconds)
#----------------------------------------------------------------------------------
    def getbandwith(self):
        if self._socket:
            return self._socket.getbandwith()
#----------------------------------------------------------------------------------
    def userawsock(self, value):
        if self._socket:
            self._socket.userawsock(value)
#----------------------------------------------------------------------------------
    def setsockopt(self, level, optname, value):
        if self._socket:
            return 0
        else:
            return super(socket, self).setsockopt(level, optname, value)  
#----------------------------------------------------------------------------------
    def fileno(self):
        if self._socket:
            return 1
        else:
            return super(socket, self).fileno()  
#----------------------------------------------------------------------------------
