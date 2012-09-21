#!/usr/bin/python
# -*- coding: UTF-8 -*-
## This file is part of ccsocket
## Copyright (C) Tomas Dragoun <drakoviens@gmail.com>
## This program is published under a GPLv3 license
########################################################


import nfqueue
import sys
import signal
from multiprocessing import Process, Pipe, Lock
from socket import AF_INET6
from scapy.all import * 
from scapy.layers.inet6 import ICMPv6Unknown
from headers import IPv6ExtHdrAH
from constants import Constants

############################
##                        ##
##       NFQHandler       ##
##                        ##
############################

class NFQHandler(Process):
#----------------------------------------------------------------------------------  
    '''
        This class handles netfilter queue. Is connected with a parent process 
        via pipe. Messages are decoded and removed from incoming packets, data 
        are send to pipe. In passive mode intercept queue both incoming outgo-
        ing traffic. Inherits multiprocessing.Process
    '''
#----------------------------------------------------------------------------------    
    def __init__(self, encoder, pipe, sendevt, stopevt, proto, active, address):       
        ''' Call parent's constructor at first '''
        Process.__init__(self)         # init parent (multiprocessing.Process)
        self.name = 'NFQHandler-port ' + str(address[1])
        self.daemon = True             # set process daemonic         
        ''' Initialize class attributes '''
        self._const = Constants()
        self._encoder = encoder        # encodes message in packet
        self._pipe = pipe              # exchange data with parent process via pipe
        self._can_send = sendevt         # event shared with parent process
        self._stop_send = stopevt        # event shared with parent process
        self._proto = proto            # upper-layer protocol 
        self._active = active          # mode
        self._host = address[0]
        self._port = address[1]        
        ''' 
            Folowing steps prepare netfilter queue with _port as queue 
            number. There is always only one active queue associated 
            with given number.
        '''
        self._queue = nfqueue.queue()  # create queue 
        self._queue.open()             # open queue
        try:
            self._queue.bind(AF_INET6) #  set family type AF_INET6
        except: # fails when any other queue already runs
            pass
        self._queue.set_callback(self.handlepacket) # set queue callback   
        '''
            Final step raises RuntimeError in case there is some other 
            queue with the same number active, queue wasn't closed 
            properly or user's priviledges are insufficient.
        '''
        try:
            self._queue.create_queue(self._port)
        except Exception,  e:
            raise e 
#----------------------------------------------------------------------------------    
    def __del__(self):
        if self._pipe: # close connection with parent process
            self._pipe.close()
#----------------------------------------------------------------------------------    
    def destroyqueue(self):
        ''' Attempts to close queue '''
        if self._queue:           
            #print 'stopping queue ' + str(self._port)
            self._queue.close() # close queue
            self._queue = None
#----------------------------------------------------------------------------------
    def _clear(self):
        ''' Removes all data to send from pipe and sets state to idle '''
        while self._pipe.poll(): # clear pipe
                self._pipe.recv() 
        self._can_send.set()
        self._stop_send.clear()
#----------------------------------------------------------------------------------    
    def run(self):
        ''' 
            Runs endless loop. Every time a packet is occurs in queue
            _handlepacket method is called.
        
        '''
        #print 'starting queue ' + str(self._port)
        self._queue.try_run()        
#----------------------------------------------------------------------------------    
    def handlepacket(self, number,  payload):   
        ''' Queue callback function '''
        packet = IPv6(payload.get_data()) # decode packet from queue as IPv6        
        ''' 
            Check if packet belongs to this queue - upperlayer ID field must match 
            in active mode. 
        '''        
        modify, reroute = self._checkport(packet)
        if not modify:
            ''' 
                Reroute packet to correct queue. Verdict NF_QUEUE is 32-bit 
                number.   Lower 16 bits code this verdict and upper 16 bits 
                are used to identify target queue.
            '''
            if reroute != -1:
                error = payload.set_verdict(nfqueue.NF_QUEUE | (reroute << 16))
                if not error:
                    return
            ''' 
                Packet doesn't have icmp echo layer or target port isn't active, 
                accept packet 
            '''
            payload.set_verdict(nfqueue.NF_ACCEPT) 
            return
        ''' 
            Port is ok, we need to check if address matches. Ip6tables rules filter
            addresses, but packet might have been rerouted from other queue.
        '''
        if len(self._host): # check source/destination address
            if packet.src != self._host and packet.dst != self._host:
                payload.set_verdict(nfqueue.NF_ACCEPT) 
                return
        ''' 
            Nfqueue mark is used to distinguish between incoming and outgoing 
            packets. Each packet is marked. 
        '''
        mark = payload.get_nfmark() # get mark of this packet             
        if mark == 1: # incoming packet
            self._incoming(packet, payload)
        elif mark == 2: # outgoing packet
            self._outgoing(packet, payload)
#----------------------------------------------------------------------------------    
    def _incoming(self, packet, payload):                     
            message = self._encoder.getmessage(packet) # decode message
            if message is None: # no message 
                ''' Accept packet '''
                payload.set_verdict(nfqueue.NF_ACCEPT)
            else:
                ''' Remove message and pass modified packet to queue '''
                modified_packet = self._encoder.removemessage(packet)
                payload.set_verdict_modified(nfqueue.NF_ACCEPT,
                                             str(modified_packet),
                                             len(modified_packet))
                try:
                    if not len(message):
                        return
                except:
                    pass
                self._pipe.send((message, (packet.src, self._port, 0, 0))) 
#----------------------------------------------------------------------------------    
    def _outgoing(self, packet, payload):
            if self._stop_send.is_set():
                self._clear()
            if self._pipe.poll(): # any data to send?
                message = self._pipe.recv() # get message
                ''' Encode message and return modified packet to queue '''
                modified_packet = self._encoder.addmessage(message, (packet, None))
                payload.set_verdict_modified(nfqueue.NF_ACCEPT, 
                                             str(modified_packet), 
                                             len(modified_packet))
                if not self._pipe.poll(): # sending finished
                    self._can_send.set()
            else: # nothing to send, return packet to queue
                payload.set_verdict(nfqueue.NF_ACCEPT)    
#----------------------------------------------------------------------------------
    def _checkport(self, packet):
        ''' 
        Returns tuple (bool, value). True, if  packet belongs to this queue. In pa-
        ssive mode always returns True. In active mode upperlayer id field must ma-
        tch current _port number. Value is number of queue where will be packet re-
        routed.
        '''
        ''' Passive mode - override icmp id check '''
        if not self._active:
            return (True, 0)
        
        ''' Active mode - check icmp (or fragment) id field (~ represents port) '''
        if packet.haslayer(ICMPv6EchoRequest): # upperlayer ICMPv6EchoRequest
            id = packet[ICMPv6EchoRequest].id 
        elif packet.haslayer(ICMPv6EchoReply): # upperlayer ICMPv6EchoReply
            id = packet[ICMPv6EchoReply].id 
        elif packet.haslayer(IPv6ExtHdrFragment): # fragmented packet
            id = packet[IPv6ExtHdrFragment].id     
        elif packet.haslayer(ICMPv6Unknown) and packet.haslayer(IPv6ExtHdrAH):
            type = packet[ICMPv6Unknown].type # ICMPv6 packet with AH
            if type != 128 and type != 129:
                return (False, -1) # accept packet
            packet[IPv6ExtHdrAH].decode_payload_as(ICMPv6EchoRequest)
            id = packet[ICMPv6EchoRequest].id 
        elif self._proto == self._const.PROTO_ALL: # any protocol
            return (True, 0) # id matches port number
        else:
            return (False, -1) # accept packet
        
        if id == self._port:
            return (True, 0) # id matches port number
        else:
            return (False, id) # reroute to correct queue
#----------------------------------------------------------------------------------
