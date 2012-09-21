#!/usr/bin/python
# -*- coding: UTF-8 -*-
## This file is part of ccsocket
## Copyright (C) Tomas Dragoun <drakoviens@gmail.com>
## This program is published under a GPLv3 license
########################################################


import time
import atexit
import multiprocessing
import logging
''' Hide scapy warnings '''
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from cStringIO import StringIO
from scapy.all import *
from multiprocessing import Pipe
from multiprocessing import Event
from ip6tables_manager import Ip6tablesManager
from error import *
from constants import Constants
from packet_generator import PacketGenerator
from message_encoders import MessageEncoder
from nfq_handler import NFQHandler
import socket

############################
##                        ##
##     NetworkManager     ##
##                        ##
############################

class NetworkManager(object):
#----------------------------------------------------------------------------------  
    '''
        This class handles incoming and outgoing data.   Data are received with aid 
        of nfqueue which is run as child process.  Outgoing data are either sent wi-
        th Scapy in active mode or passed to nfqueue in passive mode.   Binding the 
        socket triggers data reception.        
    '''
#----------------------------------------------------------------------------------    
    def __init__(self, encoder):
        ''' Initialize class attributes '''
        self._const = Constants()
        ''' Delay between packets in active mode '''
        self._delay = 0.0
        ''' Timeout (float) '''
        self._timeout = socket.getdefaulttimeout()
        ''' Sockets are blocking by default '''
        self._blocking = self._const.MODE_BLOCKING
        ''' And also active... '''
        self._active = self._const.SOCK_TYPE_ACTIVE
        ''' PacketGenerator is used in active mode '''
        self._generator = PacketGenerator()
        ''' Addr which is socket bound to '''
        self._address = None
        ''' Netfilter queue handler, child process '''
        self._nfqhandler = None
        ''' Interprocess duplex pipe'''
        self._pipe = None
        ''' Event which signals end of sending in passive mode '''
        self._can_send = None
        self._stop_send = None
        ''' Protocol is used to route correct packets to queue '''
        if not encoder.filterproto():
            self._proto = self._const.PROTO_ALL
        else:
            self._proto = self._const.PROTO_ICMP # ICMPv6 ping by default
        ''' Encodes message in packet '''
        self._encoder = encoder 
        ''' Remember initialized hosts if channell needs do so '''
        self._initialized = []        
        ''' raw socket '''
        self._userawsock = False
        self._raw_socket = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 
                                         socket.IPPROTO_RAW)
        ''' Register cleanup at exit '''
        atexit.register(self.unbind)
#----------------------------------------------------------------------------------    
    def __del__(self):
        self.unbind()
#----------------------------------------------------------------------------------    
    def setblocking(self,  value):
        ''' 
            Sets socket to blocking/non-blocking/timeout mode. Default is blocking 
            mode.
        '''
        self._blocking = value
#----------------------------------------------------------------------------------    
    def setactive(self, value):     
        ''' Sets socket passive or active '''
        address = None
        ''' 
            Socket must not be bound, transfer mode affects behavior of NFQHandler
        '''
        if self.isbound(): # unbind and remember address
            address = self._address
            self.unbind()
        self._active = value
        ''' In active mode are only used Icmp echo / fragmented packets  '''
        if value == self._const.SOCK_TYPE_ACTIVE:
            if not self._encoder.filterproto():
                self._proto = self._const.PROTO_ALL
            else:
                self._proto = self._const.PROTO_ICMP
        if address: # eventually re-bind
            self.bind(address)
#----------------------------------------------------------------------------------    
    def setdelay(self, seconds):
        ''' Sets delay between packets in active mode '''
        self._delay = seconds
#----------------------------------------------------------------------------------
    def userawsock(self, value):
        ''' Switches between sending data using raw socket/Scapy while active'''
        self._userawsock = value
#----------------------------------------------------------------------------------    
    def setfilter(self, proto):
        ''' Sets protocol filter in passive mode '''
        if self._active: # does not affect active mode
            return
        if self.isbound: # socket must not be bound 
            address = self._address
            self.unbind()
        self._proto = proto            
        if address: # eventually re-bind
            self.bind(address)
#----------------------------------------------------------------------------------
    def settimeout(self, seconds):
        ''' 
            Switches to timeout mode and sets limit in seconds. Settimeout(0.0) is
            eqivalent to setblocking(0), settimeout(None) is eqivalent to 
            setblocking(1)
        '''
        if seconds is None:
            self._blocking = self._const.MODE_BLOCKING
        elif not seconds:
            self._blocking = self._const.MODE_NONBLOCKING
        else:
            self._blocking = self._const.MODE_TIMEOUT
            self._timeout = seconds
#----------------------------------------------------------------------------------
    def gettimeout(self):
        ''' Returns current timeout (float) '''
        return self._timeout
#----------------------------------------------------------------------------------
    def getaddr(self):
        ''' Returns tuple (host, port) if socket is bound '''
        return self._address
#----------------------------------------------------------------------------------
    def isbound(self):
        ''' Returns True if socket is bound, False otherwise '''
        return self._address is not None
#----------------------------------------------------------------------------------
    def isactive(self):
        ''' Returns True if socket is active, False otherwise '''
        return self._active == self._const.SOCK_TYPE_ACTIVE
#----------------------------------------------------------------------------------
    def getbandwith(self):
        ''' Returns bandwith of current channel '''
        return self._encoder.getbandwith()
#----------------------------------------------------------------------------------
    def bind(self, address):        
        ''' 
            Binds socket to given host and port. Fails if same port is already bou-
            nd or if privileges are insufficient. NFQueue loop is run in child pro-
            cces. Data are sent via pipe and state of process is signalized by sha-
            red variable.  Address is a tuple (host, port). Localhost is denoted by
            empty string (' '). Appropriate rules are added to Ip6tables.
        '''
        if self.isbound(): # unbind socket if bound
            self.unbind()
        host = address[0]
        port = address[1]
        host = host.strip()
        
        ''' Create duplex pipe between processes '''
        parent_conn, child_conn = Pipe() # create connection with child process
        self._pipe = parent_conn        
        
        ''' Create event which signals that all data have been sent when passive '''        
        self._can_send = Event()
        self._can_send.set()
        self._stop_send = Event()
        ''' 
            Pass encoder, pipe, shared value, protocol transfer mode and address
            to child process. Throws RuntimeError when problem occurs.
        '''
        
        try: 
            self._nfqhandler = NFQHandler(self._encoder, child_conn, self._can_send,
                                          self._stop_send, self._proto, self._active, 
                                          address)
        except RuntimeError, e:
            raise Error('Can not bind socket to' + str(address) + ' : ' + str(e) 
                        + '. Port might be already used. ')        
        self._nfqhandler.start() # start child process
        
        '''
            Add rules to ip6tables. Ip6tables redirects packets from given host (or
            all incoming) of given protocol to queue which number matches port.
        '''
        ''' Redirect incoming traffic to queue '''
        Ip6tablesManager.addrule(host, self._proto, port, 
                                 self._const.RULE_TYPE_INPUT)        
        if not self._active: # intercept traffic in passive mode
            ''' Redirect outgoing packets to queue '''
            Ip6tablesManager.addrule(host, self._proto, port, 
                                     self._const.RULE_TYPE_OUTPUT)     
            ''' Redirect forwarded packets to queue '''
            Ip6tablesManager.addrule(host, self._proto, port, 
                                     self._const.RULE_TYPE_FORWARD_IN)
            Ip6tablesManager.addrule(host, self._proto, port, 
                                     self._const.RULE_TYPE_FORWARD_OUT)
        
        self._address = address # indicates that socket is bound
#----------------------------------------------------------------------------------
    def unbind(self):
        ''' 
            Unbinds socket. Stops child process, frees resources. Appropriate rules
            are removed from Ip6tables. Incoming undelivered data are lost.
        '''
        if not self.isbound():
            return # socket is not bound, return        
        
        if self._nfqhandler:            
            ''' 
                Child process must be terminated before destroying queue, otherwise
                queue.unbind(AF_INET6) halts.
            '''
            self._nfqhandler.terminate() # terminate child process
            self._nfqhandler.destroyqueue() # unbind socket and close queue handle
            self._nfqhandler = None        
        
        if self._pipe:
            self._pipe.close()
            del self._pipe
            self._pipe = None
        
        ''' Remove appropriate rules from Ip6tables '''
        host = self._address[0]
        port = self._address[1]
        Ip6tablesManager.removerule(host, self._proto, port,
                                    self._const.RULE_TYPE_INPUT)         
        if not self._active:
            Ip6tablesManager.removerule(host, self._proto, port, 
                                        self._const.RULE_TYPE_OUTPUT)         
            Ip6tablesManager.removerule(host, self._proto, port,
                                        self._const.RULE_TYPE_FORWARD_IN)
            Ip6tablesManager.removerule(host, self._proto, port, 
                                        self._const.RULE_TYPE_FORWARD_OUT)
        
        self._address = None # signals that socket is unbound
#----------------------------------------------------------------------------------
    def recv(self):
        ''' 
            Receives data from child process. Behaviour depends on socket mode. In
            blocking mode blocks until any data arrive. If there are no data avai-
            lable in non-blocking mode, Error is raised.    In timeout mode blocks
            until time limit is reached, then is a TimeoutError raised.
        '''
        data = ''
        # Non-blocking mode
        if self._blocking == self._const.MODE_NONBLOCKING:
            if not self._pipe.poll():
                raise Error('Nothing to receive')                                 
            
        # Timeout mode 
        elif self._blocking == self._const.MODE_TIMEOUT:
            if not self._pipe.poll(self._timeout):
                raise TimeoutError('Receive operation timed out')
        
        try:
            return self._pipe.recv() # blocks
        
        except IOError:
            ''' Pipe breaks down sometimes, re-bind socket '''
            addr = self._address
            self.unbind()
            self.bind(addr)
            raise Error('Nothing to receive')
#----------------------------------------------------------------------------------
    def sendto(self, msg, address):
        ''' 
            Data are sent either with Scapy (active mode) or to NFQueue 
            (passive mode)
        ''' 
        band = self._encoder.getbandwith()
        if band < 1:
            bytessent = int(band * 10) # BITS sent
        else:
            msg = msg[:band]
            bytessent = len(msg)
        
        ''' Some channels need to send some init packets first '''
        init_packets = self._encoder.initpackets()
        if init_packets:
            if address not in self._initialized:
                self._initialized.append(address)
                for n in xrange(init_packets):
                    if self._active: # active mode
                        self._send_with_scapy(msg, address)            
                    else: # passive mode
                        self._send_to_nfq(msg) 
        
        ''' Send message (depends on current mode) '''
        if self._active: # active mode
            self._send_with_scapy(msg, address)            
        else: # passive mode
            self._send_to_nfq(msg)     
            
        return bytessent   
#----------------------------------------------------------------------------------
    def _send_to_nfq(self, msg):     
        '''
            Sends data in passive mode. Behaviour also depends on current socket 
            mode. Depends on outgoing traffic to given host,     may last forever in 
            worst case (Timeout mode is reccomended).
        '''
        
        # Blocking mode
        if self._blocking == self._const.MODE_BLOCKING:         
            if not self._can_send.is_set():           # already sending..
                self._can_send.wait()                 # wait until notified
            self._can_send.clear()                    # re-set event
            self._pipe.send(msg)                      # send data to child process
            self._can_send.wait()                     # wait until data are sent
        
        # Non-blocking mode 
        elif self._blocking == self._const.MODE_NONBLOCKING:
            if not self._can_send.is_set():           # already sending..
                raise Error('Another send operation in progress')
            self._can_send.clear()                    # re-set event
            self._pipe.send(msg)                      # send data to child process   
            self._can_send.wait()                     # wait until data are sent
            
        # Timeout mode 
        elif self._blocking == self._const.MODE_TIMEOUT:
            time_spent = 0                              
            if not self._can_send.is_set():         # already sending..
                startTime = -time.time()            # get current time
                in_time = self._can_send.wait(self._timeout) # wait
                time_spent += time.time()           # get time we waited
                if not in_time:                     # timeout exceeded
                    raise TimeoutError('Send operation timed out')            
            self._can_send.clear()                  # re-set event
            self._pipe.send(msg)                    # send data to pipe
            in_time = self._can_send.wait(self._timeout - time_spent)
            if not in_time:
                ''' Timeout occured, clear data to send '''
                self._stop_send.set()
                raise TimeoutError('Send operation timed out')
#----------------------------------------------------------------------------------
    def _send_with_scapy(self, msg, address):
        ''' Sends data with Scapy, used in active mode. '''
        ''' Mode does not differ here, lets assume packets are sent immediately '''        
        ip6, upper = self._generator.generate(address, self._proto)
        packet = self._encoder.addmessage(msg, (ip6, upper))
        ''' 
            Scapy is used to send packets on L3. Interval between packets 
            is denoted by _delay (in seconds, float).    Verbosity set to 
            zero hides Scapy messages.
        '''
        if self._userawsock and not self._delay: 
            # send with raw socket for performance
            self._raw_socket.sendto(str(packet), (address[0], 0))
        else: # send with scapy
            send(packet, inter = self._delay, verbose = 0)        
        del packet
        
#        cpu_count = multiprocessing.cpu_count()
#        if cpu_count > 1 and len(packets) > 1 and not self._delay:
#            procs = []
#            pkts_count = (len(packets) + 1) / cpu_count
#            for n in xrange(cpu_count):
#                pkts_part = packets[:pkts_count]
#                packets = packets[pkts_count:]
#                p = multiprocessing.Process(target = self.sendWorker, 
#                                            args = (pkts_part, ))
#                procs.append(p)
#                p.start()
#            for n in xrange(len(procs)):
#                procs[n].join()
#        else:
#            send(packets, inter = self._delay, verbose = 0)
##----------------------------------------------------------------------------------
#    def sendWorker(self, packets):        
#        send(packets, inter = 0, verbose = 1)
