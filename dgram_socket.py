#!/usr/bin/python
# -*- coding: UTF-8 -*-
## This file is part of ccsocket
## Copyright (C) Tomas Dragoun <drakoviens@gmail.com>
## This program is published under a GPLv3 license
########################################################


from network_manager import NetworkManager
from message_encoder_factory import MessageEncoderFactory
from error import *
from socket import gaierror

############################
##                        ##
##      DgramSocket       ##
##                        ##
############################

class DgramSocket(object):
#----------------------------------------------------------------------------------
    '''
        This class represents datagram socket. Handles sending and buffered recept-
        ion. Other calls are forwarded to NetworkManager.
    '''
#----------------------------------------------------------------------------------
    def __init__(self, channeltype, band):
        ''' Get encoder and pass it to NetworkManager '''
        self._channeltype = channeltype
        self._band = band
        encoder = MessageEncoderFactory.create(channeltype, band)
        self._encoder = encoder
        if not encoder:
            raise Error('Such encoder does not exist')
        self._netmanager = NetworkManager(encoder)        
        self._buffer = ('',  None)        
#----------------------------------------------------------------------------------
    def __del__(self):
        del self._netmanager
        del self._buffer
#----------------------------------------------------------------------------------
    def setblocking(self, value):
        ''' 
            Sets socket to blocking/non-blocking/timeout mode. Default is blocking 
            mode.
        '''
        if value not in [0, 1, 2]:
            raise Error('Illegal blocking argument: ' + str(value))	  
        self._netmanager.setblocking(value)
#----------------------------------------------------------------------------------
    def setactive(self, value):
        ''' Sets socket passive or active '''
        if value:
            value = 1
        self._netmanager.setactive(value)
#----------------------------------------------------------------------------------
    def bind(self, addr):
        ''' 
            Binds socket to given host and port. Fails if same port is already bou-
            nd or if privileges are insufficient. NFQueue loop is run in child pro-
            cces. addr is a tuple (host, port).    Localhost is denoted by empty 
            string (' ').
        '''
        if len(addr) < 2:
            raise Error('Invalid argument')
        try:
            if self._encoder.initpackets():
                self._encoder = MessageEncoderFactory.create(self._channeltype, 
                                                             self._band )
            self._netmanager.bind(addr)
        except gaierror,  e:
            raise Error('Given hostname or addres is not valid: ' + str(e))
#----------------------------------------------------------------------------------
    def close(self):
        self._netmanager.unbind()
#----------------------------------------------------------------------------------
    def settimeout(self, value):
        ''' 
            Switches to timeout mode and sets limit in seconds. Settimeout(0.0) is
            eqivalent to setblocking(0), settimeout(None) is eqivalent to 
            setblocking(1)
        '''
        if value < 0:
            value = 0.0
        self._netmanager.settimeout(value)
#----------------------------------------------------------------------------------
    def gettimeout(self):
        ''' Returns current timeout (float) '''
        return self._netmanager.gettimeout()
#----------------------------------------------------------------------------------
    def setfilter(self, proto):
        ''' Sets protocol filter in passive mode '''
        if proto not in [0, 1, 2, 3]:
            raise Error('Illegal filter argument: ' + str(proto))
        self._netmanager.setfilter(proto)
#----------------------------------------------------------------------------------
    def setdelay(self, seconds):
        ''' Sets delay between packets in active mode '''
        if seconds < 0:
            raise Error('Delay must not be negative number.')
        self._netmanager.setdelay(seconds)        
#----------------------------------------------------------------------------------
    def getbandwith(self):
        ''' Returns bandwith of current channel '''
        return self._netmanager.getbandwith()
#----------------------------------------------------------------------------------
    def userawsock(self, value):
        ''' Use raw socket or send packets with Scapy'''
        self._netmanager.userawsock(value)
#----------------------------------------------------------------------------------
    def isactive(self):
        ''' Returns True if socket is in active mode'''
        return self._netmanager.isactive()
#----------------------------------------------------------------------------------
    def sendto(self, msg, addr = ''):
        ''' 
            Checks conditions and sends data to remote socket. addr can be left
            out if socket is bound. Socket must be bound to send in passive mode. 
            One can send data to any arbitrary addr while active, or to bound
            addr while passive. 
        '''
        if len(addr) < 2 and not self._netmanager.isbound():
            raise Error('Invalid argument')
        
        if self._netmanager.isactive(): # active mode 
            ''' Addr given '''
            if len(addr) >= 2:
                return self._netmanager.sendto(msg, addr)
                ''' None addr given, but socket is bound - OK '''
            elif self._netmanager.isbound() and not len(addr):
                return self._netmanager.sendto(msg, self._netmanager.getaddr())
                ''' None addr given, socket is not bound - raises Error '''
            elif not self._netmanager.isbound() and not len(addr):
                raise Error('Socket must be bound or addr given to send')
                ''' addr given '''
        else: # passive mode
            ''' Socket is bound - OK '''
            if self._netmanager.isbound():
                return self._netmanager.sendto(msg, None)
                ''' None addr given, socket is not bound - raises Error '''
            elif not self._netmanager.isbound() and not len(addr):
                raise Error('Socket must be bound or addr given to send')            
                ''' addr given, attempt to bind socket and send '''
            else:
                self._netmanager.bind(addr)
                return self._netmanager.sendto(msg, None)
#----------------------------------------------------------------------------------
    def recv(self, bufsize = 0):
        ''' Returns received data with size of given bufsize (can be left out) '''
        recv = self.recvfrom(bufsize)
        if recv:
            (msg, addr) = recv
            return msg
#----------------------------------------------------------------------------------
    def recv_into(self, buffer, bufsize = 0):
        ''' Puts received data into a buffer with given size (can be left out) '''
        (msg, addr) = self.recvfrom(bufsize)
        buffer = msg
        try:
            l = len(msg)
        except TypeError:
            l = self.getbandwith()
        return l
#----------------------------------------------------------------------------------
    def recvfrom_into(self, buffer, bufsize = 0):
        ''' 
            Puts received data into a buffer with given size (can be left out). Re-
            turns tuple (received bytes, addres).
        '''
        (msg, addr) = self.recvfrom(bufsize)
        buffer = msg
        try:
            l = len(msg)
        except TypeError:
            l = self.getbandwith()
        return (l, addr)
#----------------------------------------------------------------------------------
    def recvfrom(self, bufsize = 0):        
        ''' 
            Returns received data with size of given bufsize (can be left out). 
            Return value is a tuple of (msg, addr).
        '''
        if not self._netmanager.isbound():
            raise NotBoundError('Socket must be bound to receive')
        ''' Bufsize not given '''
        if not bufsize:
            ''' Return data from buffer if any '''
            if len(self._buffer[0]):
                  (msg, addr) = self._buffer
                  self._buffer = ('',  None)
                  return (msg,  addr)
            ''' Try to receive data in case buffer is empty '''
            return self._netmanager.recv()
            ''' Bufsize given '''
        else:
            ''' Return data from buffer if any '''
            if len(self._buffer[0]):
                  msg = self._buffer[0][:bufsize]                  
                  rest = self._buffer[0][bufsize:]                  
                  addr = self._buffer[1]
                  self._buffer = (rest, addr)                  
                  return (msg,  addr)
            ''' Get data into buffer and call again '''
            self._buffer = self._netmanager.recv()
            return self.recvfrom(bufsize)
#----------------------------------------------------------------------------------
