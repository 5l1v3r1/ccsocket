#!/usr/bin/python
# -*- coding: UTF-8 -*-
## This file is part of ccsocket
## Copyright (C) Tomas Dragoun <drakoviens@gmail.com>
## This program is published under a GPLv3 license
########################################################


import random
import string
from cStringIO import StringIO
from scapy.all import *
from headers import *
from error import *

############################
##                        ##
##     MessageEncoder     ##
##                        ##
############################

class MessageEncoder(object):
#----------------------------------------------------------------------------------
    '''
        This abstract class defines interface of MessageEncoders. All encoders are
        descendats of this class.
    '''
#---------------------------------------------------------------------------------- 
    def __init__(self, max, bandwith, layer, prior_headers):
        if bandwith > max:
            err = 'Max bandwith of ' + str(type(self)) + ' is '
            if max >= 1:
                err += (str(max) + ' bytes')
            else:
                err += (str(max * 10) + ' bits')
            raise Error(err)
        self._max = max
        self._bandwith = bandwith # channel bandwith 
        self._layer = layer # type of layer which carries covert data
        self._prior_headers = prior_headers # preceeding headers of this layer
#----------------------------------------------------------------------------------
    def _getheader(self, msg):
        ''' Returns message encoded in extension header '''
        raise NotImplementedError()
#----------------------------------------------------------------------------------
    def getmessage(self, IPv6):
        ''' Returns message contained in packet or None '''
        raise NotImplementedError()
#----------------------------------------------------------------------------------
    def initpackets(self):
        ''' Returns number of packets needed to init channel  '''
        return 0
#---------------------------------------------------------------------------------- 
    def addmessage(self, msg, pkt_orig):
        ''' Adds message to packet, this method might be overloaded '''
        header = self._getheader(msg) # get header with covert data
        ''' 
            In active mode are IP and upper layer delivered separetly.
        '''
        (ip, upper) = pkt_orig
        ''' Div ('/') is overloaded by Scapy - puts layers together '''
        if upper:
            return ip / header / upper
        
        ''' Passive mode '''
        pkt_orig = pkt_orig[0]        
        pkt_copy = pkt_orig.copy() # copy packet
        pkt_copy.remove_payload() # remove payload
        ''' Now we need to place header according to rfc2406. '''
        
        ''' If there is no extension header present: '''
        if pkt_orig.nh not in [0, 43, 44, 51, 50, 60]:
            ''' update IPv6 Next Header '''
            pkt_copy.nh = self._layer.overload_fields[IPv6]['nh']
            ''' attach crafted header to IPv6 '''
            pkt_copy.lastlayer().payload = header
            ''' update Next Header field of inserted header '''
            header.nh = pkt_orig.payload.overload_fields[IPv6]['nh']
            ''' append original payload '''
            pkt_copy.lastlayer().payload = pkt_orig.payload       
        
        else: # there are some extension headers
            ''' order of headers: 0 , 60 , 43 , 44 , 51, 50 , 60 '''
            pkt_iter = pkt_orig.payload
            current_header_number = pkt_orig.nh
            ''' 
                Iterate packet layers and find correct place for 
                crafted header.
            '''
            while current_header_number in self._prior_headers:
                layer_iter = pkt_iter.copy()              # copy layer + payload
                layer_iter.remove_payload()               # cut payload off
                pkt_copy.lastlayer().payload = layer_iter # append layer
                current_header_number = pkt_iter.nh       # update current header
                pkt_iter = pkt_iter.payload            # get next layer + payload
            '''
                We've found place where should be inserted crafted header.
                Underlayers are in pkt_copy, upperlayers in pkt_iter.
            '''
            if current_header_number == self._layer.overload_fields[IPv6]['nh']:
                ''' 
                    When crafted header is already present, we want to replace
                    it.    Exception is replacing Authentication Header, which 
                    would cause integrity check fail and channel could be dis-
                    closed.
                '''
                if current_header_number == 51: 
                    return pkt_orig # don't replace Authentication Header!!
                pkt_iter = pkt_iter.payload # skip present header
                
            ''' Put all three parts of packet together '''
            pkt_copy.lastlayer().nh = self._layer.overload_fields[IPv6]['nh']
            pkt_copy = pkt_copy / header / pkt_iter
        
        ''' Update length of new packet '''
        pkt_copy.plen = len(str(pkt_copy.payload))        
        return pkt_copy
#----------------------------------------------------------------------------------	
    def removemessage(self, pkt_orig):
        ''' Removes message and returns modified IPv6 packet '''
        pkt_copy = pkt_orig.copy()  # copy packet
        pkt_copy.remove_payload()   # get only base header
        pkt_iter = pkt_orig.payload # points to payload of base header
        ''' 
            Iterate packet and find right layer to be removed. It's
            type is stored in self._layer
        '''
        while not isinstance(pkt_iter, NoPayload):
            if isinstance(pkt_iter, self._layer):
                ''' layer should be removed '''
                ''' 
                    Replace Next Header field of last appended layer with NH
                    field of layer which is being removed.
                '''
                pkt_copy.lastlayer().nh = pkt_iter.nh
                '''
                    Append payload of layer which should be removed as 
                    payload of modified packet.
                '''
                pkt_copy.lastlayer().payload = pkt_iter.payload
                break
            else:
                ''' layer should not be removed '''
                layer_tmp = pkt_iter.copy() # copy layer + payload
                layer_tmp.remove_payload()  # cut payload off
                pkt_copy.lastlayer().payload = layer_tmp # append layer to new pkt
            
            pkt_iter = pkt_iter.payload     # continue with next layer
        
        ''' update length of new packet '''
        pkt_copy.plen = len(str(pkt_copy.payload))
        return pkt_copy
#----------------------------------------------------------------------------------	
    def getbandwith(self):
        ''' Returns current number of bytes which can be encoded '''
        return self._bandwith
#----------------------------------------------------------------------------------	
    def getmax(self):
        ''' Returns maximal number of bytes which can be encoded '''
        return self._max
#----------------------------------------------------------------------------------
    def filterproto(self):
        ''' This method is overloaded by encoders which use eg. fragment header '''
        return True
#----------------------------------------------------------------------------------
    def slice(self, string, length):
        ''' Divides string to chunks of given length. '''
        data = []
        if length < 0:
            raise Error('Invalid argument')
        if length == 0:            
            return ['']
        if length >= 1: # bytes
            if len(string) <= length:
                data.append(string)
            else:
                n = 1
                while n * length < len(string):
                    data.append(string[(n - 1) * length : n * length])
                    n += 1           
                data.append(string[(n - 1) * length:])
        else: # bits
            bits = int(length * 10)
            while len(string):
                c = ord(string[-1:])
                string = string[:-1]
                for n in xrange(int(8 / bits)):
                    val = c - ((c >> bits) << bits)
                    data.insert(0, val)
                    c = c >> bits
        return data
#----------------------------------------------------------------------------------
    def _stringtoaddr(self, data):
        '''
            Takes 16 byte long string and transforms it to IPv6 address.
        '''
        buffer = StringIO()
        for n in xrange(16):
            if n % 2 == 0:
                buffer.write(':')
            if n >= len(data):
                if n % 2 == 0:
                   buffer.write('00')
                continue
            if ord(data[n]) <= 15:
                buffer.write('0')
            buffer.write('%x' % ord(data[n]))
        address = buffer.getvalue()
        buffer.close()
        return address[1:]
#----------------------------------------------------------------------------------
    def _addrtostring(self, address):
        ''' 
            Takes IPv6 address and transforms it to string.
        '''
        list = address.split(':')
        buffer = StringIO()
        for token in list:
            if len(token) in [1, 2]:
                buffer.write(chr(int(token, 16)))                
            if len(token) == 3:
                buffer.write(chr(int(token[0], 16)))
                buffer.write(chr(int(token[1:], 16)))
            if len(token) == 4:
                buffer.write(chr(int(token[:2], 16)))
                buffer.write(chr(int(token[2:], 16)))
        message = buffer.getvalue()
        buffer.close()
        return message
#----------------------------------------------------------------------------------
############################
##                        ##
## FragmentMessageEncoder ##
##                        ##
############################

class FragmentMessageEncoder(MessageEncoder):    
#----------------------------------------------------------------------------------
    '''
        This class inherits MessageEncoder and is used by encoders which use 
        fragmented packets
    '''
#----------------------------------------------------------------------------------        
    def __init__(self, max, bandwith, layer, prior_headers):        
        self._offset = 0 # set fragment offset to zero
        MessageEncoder.__init__(self, max, bandwith, layer, prior_headers)        
#----------------------------------------------------------------------------------    
    def filterproto(self):
        ''' This method indicates that traffic shouldnt be filtered '''
        return False
#---------------------------------------------------------------------------------- 
    def addmessage(self, msg, pkt_orig):
        ''' Get crafted header with covert data '''
        header = self._getheader(msg)
        ''' Set correct fragment offset '''
        header.offset = self._offset
        
        (ip,  upper) = pkt_orig

        if upper: # active mode
            ''' Force Scapy to comute automatic fields '''
            upper = IPv6(str(ip/upper)).lastlayer()
            ''' Update next header field '''
            header.nh = upper.overload_fields[IPv6]['nh']
            ''' 
                Set correct fragment ID (same as ICMP ID)
                for the pkt_orig to be accepted by active 
                socket.
            '''
            header.id = upper.id             
            pkt_copy = ip / header # add header
            ''' 
                Fragments must be padded to 8 byte words (with
                except of last fragment (rfc 2460).
            '''
            padlen = (8 - (len(str(upper)) % 8))
            pad = padlen * chr(padlen)
            ''' add upperlayer + padding as raw data '''
            new_payload = str(upper) + pad
            pkt_copy.add_payload(new_payload)
            ''' update offset attribute (13-bit number)'''
            self._offset = (self._offset + len(new_payload) / 8) % 8192
            return pkt_copy
        
        pkt_orig = pkt_orig[0] # passive mode
        pkt_copy = pkt_orig.copy()
        pkt_copy.remove_payload()
   
        #no extension headers present
        if pkt_orig.nh not in [0, 43, 44, 51, 50, 60]:
            ''' update Next Header field of IPv6 base header '''
            pkt_copy.nh = self._layer.overload_fields[IPv6]['nh']            
            ''' add padding '''
            padlen = (8 - (len(str(pkt_orig.payload)) % 8))
            pad = padlen * chr(padlen)
            ''' update next header field of crafted fragment header '''
            header.nh = pkt_orig.nh
            pkt_copy = pkt_copy / header # add fragment header
            ''' add upperlayer + padding as raw data'''
            new_payload = str(pkt_orig.payload) + pad
            pkt_copy.add_payload(new_payload)
            ''' update offset attribute (13-bit number)'''
            self._offset = (self._offset + len(new_payload) / 8) % 8192        
   
        else: # extension headers present
            pkt_iter = pkt_orig.payload
            current_header_number = pkt_orig.nh
            ''' 
                Iterate pkt_orig layers and find correct place for 
                crafted header.
            '''
            while current_header_number in self._prior_headers:
                layer_iter = pkt_iter.copy()         # copy layer + payload
                layer_iter.remove_payload()          # cut payload off
                pkt_copy.lastlayer().payload = layer_iter# append layer
                current_header_number = pkt_iter.nh  # update current header
                pkt_iter = pkt_iter.payload          # get next layer + payload
            '''
                We've found place where should be inserted crafted header.
                Underlayers are in pkt_copy, upperlayers in pkt_iter.
            '''                                
            ''' update Next Header fields '''
            pkt_copy.lastlayer().nh = self._layer.overload_fields[IPv6]['nh']
            header.nh = pkt_iter.overload_fields[IPv6]['nh']
            pkt_copy = pkt_copy / header # add header
            ''' add payload + padding as raw data'''
            padlen = (8 - (len(str(pkt_iter)) % 8))
            pad = padlen * chr(padlen)            
            new_payload = str(pkt_iter) + pad
            pkt_copy.add_payload(new_payload)
            ''' update offset attribute '''
            self._offset = (self._offset + len(new_payload) / 8) % 8192     

        ''' update length of new packet '''
        pkt_copy.plen = len(str(pkt_copy.payload))
        return pkt_copy 
#----------------------------------------------------------------------------------
    def removemessage(self, pkt_orig):
        ''' Removes message and returns modified IPv6 packet '''
        pkt_copy = pkt_orig.copy()  # copy packet
        pkt_copy.remove_payload()   # get only base header
        pkt_iter = pkt_orig.payload = pkt_orig.payload # points to payload of base header
        ''' 
            Iterate packet and find right layer to be removed. It's
            type is stored in self._layer
        '''
        ''' Removes message and returns modified IPv6 packet '''
        pkt_copy = IPv6(str(pkt_orig))
        pkt_copy.remove_payload()
   
        while not isinstance(pkt_iter, NoPayload):
            if isinstance(pkt_iter, self._layer):
                ''' layer should be removed '''
                ''' 
                    Replace Next Header field of last appended layer with NH
                    field of layer which is being removed.
                '''
                pkt_copy.lastlayer().nh = pkt_iter.nh
                ''' Get raw data fragment '''
                pay = str(Raw(pkt_iter.payload).load)
                ''' Remove padding '''
                padlen = ord(pay[-1])
                for n in xrange(padlen):
                    if pay[-(n + 1)] != pay[-1]:
                        return
                ''' append original payload '''
                pkt_copy.lastlayer().payload = pay[:-padlen]
                break
            else:
                ''' layer should not be removed '''
                layer_tmp = pkt_iter.copy() # copy layer + payload
                layer_tmp.remove_payload()  # cut payload off
                pkt_copy.lastlayer().payload = layer_tmp # append layer to new pkt
            
            pkt_iter = pkt_iter.payload     # continue with next layer
     
        ''' update length of modified packet '''
        pkt_copy.plen = len(str(pkt_copy.payload))
        return pkt_copy
#----------------------------------------------------------------------------------

############################
##                        ##
##   DestoptPadNEncoder   ##
##                        ##
############################

class DestoptPadNEncoder(MessageEncoder):    
#----------------------------------------------------------------------------------    
    def __init__(self, bandwith = 254):        
        max = 254        
        prior_headers = [0 , 43 , 44 , 51, 50]
        MessageEncoder.__init__(self, max, bandwith, IPv6ExtHdrDestOpt, 
                                prior_headers)
#----------------------------------------------------------------------------------    
    def _getheader(self, msg):
        header = IPv6ExtHdrDestOpt() # create destination options ext header
        padding = PadN()             # create PadN type padding
        padding.optdata = msg        # set padding value
        header.options = padding     # add PadN to destopt header
        return header
#----------------------------------------------------------------------------------
    def getmessage(self, packet):
        try:
            ''' get correct layer '''
            padding = packet[IPv6ExtHdrDestOpt][PadN].optdata
            padlen = packet[IPv6ExtHdrDestOpt][PadN].optlen
            ''' check if padding contains any message '''
            if padlen <= 5:                        
                if padding == (padlen * '\x00'):
                    return
            return padding
        except:
            return
#----------------------------------------------------------------------------------

############################
##                        ##
##  DestoptUnknownEncoder ##
##                        ##
############################

class DestoptUnknownEncoder(MessageEncoder):    
#----------------------------------------------------------------------------------    
    def __init__(self, bandwith = 1354):        
        max = 1378
        prior_headers = [0 , 43 , 44 , 51, 50]
        MessageEncoder.__init__(self, max, bandwith, IPv6ExtHdrDestOpt, 
                                prior_headers)
#----------------------------------------------------------------------------------    
    def _getheader(self, msg):  
        header = IPv6ExtHdrDestOpt()        # create destination options header
        chunks = self.slice(msg, 255)       # slice message
        ''' create Option Unknown from each part of message '''
        options = [HBHOptUnknown(optdata = elem) for elem in chunks]
        header.options = options            # add options to header
        return header  
#----------------------------------------------------------------------------------
    def getmessage(self, packet):
        try:
            options = packet[IPv6ExtHdrDestOpt].options # get header options
            buffer = StringIO()
            for option in options: # check that option is not a PadN padding
                try:
                    if option.optlen <= 5:
                        if option.optdata == (option.optlen * '\x00'):
                            continue # option is PadN padding, continue
                    buffer.write(option.optdata) # write message to buffer
                except:
                    pass
            message = buffer.getvalue()
            buffer.close()
            return message            
        except:
            pass
#----------------------------------------------------------------------------------

############################
##                        ##
##     FlowlabEncoder     ##
##                        ##
############################

class FlowlabEncoder(MessageEncoder):    
#----------------------------------------------------------------------------------    
    def __init__(self, bandwith = 2):        
        max = 2        
        MessageEncoder.__init__(self, max, bandwith, None, None)
#----------------------------------------------------------------------------------    
    def addmessage(self, msg, packet):
        ''' This encoder uses base IPv6 header, addmessage is overloaded '''
        if len(msg) == 1:
            value = ord(msg)                         # 1 char -> 1B number
        else: #len == 2
            value = (ord(msg[0]) << 8) | ord(msg[1]) # 2 chars -> 2B number
        ''' Active mode '''
        (ip, upper) = packet
        if upper: 
            ip.fl = value       # set false Flow label
            return ip / upper
        
        ''' Passive mode '''
        packet = packet[0]
        packet[IPv6].fl = value # set false Flow label       
        return packet
#----------------------------------------------------------------------------------
    def getmessage(self, packet):
        value = packet[IPv6].fl     # get Flow label field
        if value < 256:             # 1B number -> 1 char
            return chr(value)       
        fst = value >> 8            # 2B number -> 2 chars
        snd = value & ~ (fst << 8)
        return chr(fst) + chr(snd)
#----------------------------------------------------------------------------------
    def removemessage(self, packet):        
        '''removes extension headers from packet
        returns IPv6 packet
        '''
        packet[IPv6].fl = 0 # set Flow label to default value
        return packet
#----------------------------------------------------------------------------------

############################
##                        ##
##       Fragfake         ##
##                        ##
############################

class FragfakeEncoder(FragmentMessageEncoder):    # TODO: comment
#----------------------------------------------------------------------------------    
    def __init__(self, bandwith = 1000):        
        max = 1380
        prior_headers = [0 , 43 , ]                
        super(FragfakeEncoder, self).__init__(max, bandwith, IPv6ExtHdrFragment, 
                                              prior_headers)
        self._id = random.randint(0, pow(2, 32))
        self._offset = 0
#----------------------------------------------------------------------------------    
    def _getheader(self, msg):  
        header = IPv6ExtHdrFragment()
        header.id = self._id
        header.m = 0x01
        header.offset = self._offset
        self._offset = (self._offset + 1) % 8192
        return header  
#----------------------------------------------------------------------------------
    def getmessage(self, packet):
        try:
            pay = packet[Raw].load
            padlen = ord(pay[-1])
            my_header = StrHeader(pay[:-padlen])
            return my_header.msg
        except:
            pass
#---------------------------------------------------------------------------------- 
    def addmessage(self, msg, packet):  
        header = self._getheader(msg)
        header.offset = self._offset
        
        (ip,  upper) = packet

        if upper:
            upper = IPv6(str(ip/upper)).lastlayer()#force Scapy to compute checksum
            header.nh = upper.overload_fields[IPv6]['nh']
            header.id = upper.id                       
            new_packet = ip / header            
            new_payload = str(StrHeader(msg = msg, data = str(upper)))
            padlen = (8 - (len(new_payload) % 8))
            pad = padlen * chr(padlen)
            new_payload += pad
            new_packet.add_payload(new_payload)
            self._offset = (self._offset + len(new_payload) / 8) % 8192
            return new_packet
        
        packet = packet[0]        
        new_packet = packet.copy()
        new_packet.remove_payload()
   
        #no extension headers present
        if packet.nh not in [0, 43, 44, 51, 50, 60]:
            new_packet.nh = self._layer.overload_fields[IPv6]['nh']
            header.nh = packet.nh
            new_packet = new_packet / header            
            new_payload = str(StrHeader(msg=msg, data=str(packet.payload)))
            padlen = (8 - (len(new_payload) % 8))
            pad = padlen * chr(padlen)
            new_payload += pad            
            new_packet.add_payload(new_payload)
            self._offset = (self._offset + len(new_payload) / 8) % 8192        
   
        else:
            # order : 0 , 60 , 43 , 44 , 51, 50 , 60
            pkt_iter = packet.payload
            current_header_number = packet.nh
                
            while current_header_number in self._prior_headers:
                layer_iter = pkt_iter.copy()
                layer_iter.remove_payload()
                new_packet.lastlayer().payload = layer_iter
                current_header_number = pkt_iter.nh
                pkt_iter = pkt_iter.payload
                
            if current_header_number == self._layer.overload_fields[IPv6]['nh']:
                pkt_iter = pkt_iter.payload
                
            header.nh = layer_iter.nh
            new_packet.lastlayer().nh = 44
            new_packet = new_packet / header            
            new_payload = str(StrHeader(msg = msg, data = str(pkt_iter), 
                                        nh = pkt_iter.overload_fields[IPv6]['nh']))
            padlen = (8 - (len(new_payload) % 8))
            pad = padlen * chr(padlen)
            new_payload += pad
            new_packet.add_payload(new_payload)
            self._offset = (self._offset + len(new_payload) / 8) % 8192     

        new_packet.plen = len(str(new_packet.payload))
        return new_packet 
#----------------------------------------------------------------------------------
    def removemessage(self, packet):
        ''' Removes message and returns modified IPv6 packet '''
        new_packet = IPv6(str(packet))
        new_packet.remove_payload()
        pkt_iter = packet.payload
   
        while not isinstance(pkt_iter, NoPayload):
            if isinstance(pkt_iter, self._layer):                
                pay = str(Raw(pkt_iter.payload).load)
                padlen = ord(pay[-1])
                my_header = StrHeader(pay[:-padlen])
                new_packet.lastlayer().nh = pkt_iter.nh
                new_packet.lastlayer().payload = my_header.data
                break
            else:
                layer_tmp = pkt_iter.copy()
                layer_tmp.remove_payload()
                new_packet.lastlayer().payload = layer_tmp
            pkt_iter = pkt_iter.payload
     
        new_packet.plen = len(str(new_packet.payload))
        return new_packet
#----------------------------------------------------------------------------------

############################
##                        ##
##       Fragres1         ##
##                        ##
############################

class Fragres1Encoder(FragmentMessageEncoder):    
#----------------------------------------------------------------------------------    
    def __init__(self, bandwith = 1):        
        max = 1
        prior_headers = [0 , 43 , ]                
        super(Fragres1Encoder, self).__init__(max, bandwith, IPv6ExtHdrFragment, 
                                              prior_headers)
        ''' fragment id and offset might be overwritten in addmessage'''
        self._id = random.randint(0, pow(2, 32))
        self._offset = 0
#----------------------------------------------------------------------------------    
    def _getheader(self, msg):  
        header = IPv6ExtHdrFragment()            # get fragment header
        header.id = self._id                     # set fragment id
        header.m = 0x01                          # set M (More) frag flag
        header.offset = self._offset             # set offset
        self._offset = (self._offset + 1) % 8192 # increment offset mod 13-b   
        header.res1 = ord(msg)                   # put char in reserved field
        return header  
#----------------------------------------------------------------------------------
    def getmessage(self, packet):
        try:
            value = packet[IPv6ExtHdrFragment].res1 # get reserved field
            return chr(value)                       # 1B number -> 1 char
        except:
            pass
#----------------------------------------------------------------------------------

############################
##                        ##
##       Fragres2         ##
##                        ##
############################

class Fragres2Encoder(FragmentMessageEncoder):    
#----------------------------------------------------------------------------------    
    def __init__(self, bandwith = 0.2):        
        max = 0.2
        prior_headers = [0 , 43 , ]                
        super(Fragres2Encoder, self).__init__(max, bandwith, IPv6ExtHdrFragment, 
                                              prior_headers)
        ''' fragment id and offset might be overwritten in addmessage'''
        self._id = random.randint(0, pow(2, 32))
        self._offset = 0
#----------------------------------------------------------------------------------    
    def _getheader(self, msg):  
        header = IPv6ExtHdrFragment()            # get fragment header
        header.id = self._id                     # set fragment id
        header.m = 0x01                          # set M (More) frag flag
        header.offset = self._offset             # set offset
        self._offset = (self._offset + 1) % 8192 # increment offset mod 13-b   
        header.res2 = msg                        # put 2b number in reserved field
        return header  
#----------------------------------------------------------------------------------
    def getmessage(self, packet):
        try:
            value = packet[IPv6ExtHdrFragment].res2 # get reserved field          
            return value
        except:
            pass
#----------------------------------------------------------------------------------

############################
##                        ##
##         Fragnh         ##
##                        ##
############################

class FragnhEncoder(FragmentMessageEncoder):    
#----------------------------------------------------------------------------------    
    def __init__(self, bandwith = 1):        
        max = 1
        self._nh = 59
        prior_headers = [0 , 43 , ]                
        super(FragnhEncoder, self).__init__(max, bandwith, IPv6ExtHdrFragment, 
                                            prior_headers)
        ''' fragment id and offset might be overwritten in addmessage'''
        self._id = random.randint(0, pow(2, 32))
        self._init = 5
        self._offset = 0
#----------------------------------------------------------------------------------
    def initpackets(self):
        ''' Returns number of packets needed to init channel  '''
        return self._init
#----------------------------------------------------------------------------------
    def addmessage(self, msg, packet):  
        ''' Let parent transform packet '''
        packet = super(FragnhEncoder, self).addmessage(msg, packet)
        ''' Store message in Next Header field in case init packets were sent '''
        if packet[IPv6ExtHdrFragment].offset > self._init - 1:
            packet[IPv6ExtHdrFragment].nh = ord(msg)
        return packet
#----------------------------------------------------------------------------------    
    def _getheader(self, msg):  
        header = IPv6ExtHdrFragment()           # get fragment header
        header.id = self._id                    # set fragment id
        header.m = 0x01                         # set M (more) flag
        header.offset = self._offset            # set offset
        self._offset += 1
        if self._offset == 8191: # 2^13 (13-bit offset)
            self._offset = self._init
        return header  
#----------------------------------------------------------------------------------
    def getmessage(self, packet):
        try:
            if packet[IPv6ExtHdrFragment].offset > self._init - 1:
                value = packet[IPv6ExtHdrFragment].nh # get Next Header field
                return chr(value)
            else:
                ''' 
                    Init packet received, store Next Header value. With this
                    value will be replaced the same field of all succeeding 
                    received packets.
                '''
                packet[IPv6ExtHdrFragment].nh = self._nh
                return # header remains, packet is dropped
        except:
            pass
#----------------------------------------------------------------------------------
    def removemessage(self, packet): 
        ''' Restore correct next header field '''
        self._nh = packet[IPv6ExtHdrFragment].nh
        ''' Let parent remove the message '''
        return super(FragnhEncoder, self).removemessage(packet)
#----------------------------------------------------------------------------------
############################
##                        ##
##    HBHPadNEncoder      ##
##                        ##
############################

class HBHPadNEncoder(MessageEncoder):    
#----------------------------------------------------------------------------------    
    def __init__(self, bandwith = 255):        
        max = 255 
        prior_headers = [] # first extension header
        MessageEncoder.__init__(self, max, bandwith, IPv6ExtHdrHopByHop, 
                                prior_headers)
#----------------------------------------------------------------------------------    
    def _getheader(self, msg):  
        header = IPv6ExtHdrHopByHop()   # get Hop-by-hop header
        padding = PadN()                # get PadN
        padding.optdata = msg           # set padding as message
        header.options = padding        # insert padding as option
        return header
#----------------------------------------------------------------------------------
    def getmessage(self, packet):
        try:
            ''' get correct layer '''
            padding = packet[IPv6ExtHdrHopByHop][PadN].optdata
            padlen = packet[IPv6ExtHdrHopByHop][PadN].optlen
            ''' check if padding contains any message '''
            if padlen <= 5:                        
                if padding == (padlen * '\x00'):
                    return
            return padding
        except:
            pass
#----------------------------------------------------------------------------------

############################
##                        ##
##    HBHUnknownEncoder   ##
##                        ##
############################

class HBHUnknownEncoder(MessageEncoder):    
#----------------------------------------------------------------------------------    
    def __init__(self, bandwith = 1354):        
        max = 1378
        prior_headers = []
        MessageEncoder.__init__(self, max, bandwith, IPv6ExtHdrHopByHop, 
                                prior_headers)
#----------------------------------------------------------------------------------    
    def _getheader(self, msg):  
        header = IPv6ExtHdrHopByHop()    # get Hop-by-hop header     
        chunks = self.slice(msg, 255)    # max option length is 255 bytes
        ''' Transform each message to Unknown option '''
        options = [HBHOptUnknown(optdata = elem) for elem in chunks]
        header.options = options # add options to header
        return header  
#----------------------------------------------------------------------------------
    def getmessage(self, packet):
        try:
            ''' get correct layer '''
            options = packet[IPv6ExtHdrHopByHop].options
            buffer = StringIO()
            for option in options:
                try:
                    ''' check if option contains any message '''
                    if option.optlen <= 5:                        
                        if option.optdata == (option.optlen * '\x00'):
                            continue
                    buffer.write(option.optdata)
                except:
                    pass
            message = buffer.getvalue()
            buffer.close()
            return message            
        except:
            pass
#----------------------------------------------------------------------------------

############################
##                        ##
##    HoplimitEncoder     ##
##                        ##
############################

class HoplimitEncoder(MessageEncoder):    
#----------------------------------------------------------------------------------    
    def __init__(self, delta = 10, bandwith = 0.1):        
        max = 0.1 # 1 bit bandwith      
        self._delta = delta # hop limit delta value
        self._init = 5
        self._initialized = {}
        self._initialized_recv = {}
        MessageEncoder.__init__(self, max, bandwith, None, None)
#----------------------------------------------------------------------------------
    def initpackets(self):
        ''' Returns number of packets needed to init channel  '''
        return self._init
#----------------------------------------------------------------------------------    
    def addmessage(self, msg, packet):   
        ''' Overrides parent method '''
        try:
            ''' Check if init packet were sent to given addr '''
            if self._initialized[packet[0].dst] < self._init:
                self._initialized[packet[0].dst] += 1
                if packet[1]: # active mode
                    return packet[0] / packet[1]
                return packet[0] # passive mode
        except:                        
            ''' Need to send init packets to this addr '''
            self._initialized[packet[0].dst] = 1
            if packet[1]:
                    return packet[0] / packet[1]
            return packet
            
        (ip, upper) = packet
        
        if upper: # active mode
            packet = IPv6(str(ip / upper))
            if msg == 0:
                ''' Binary zero - subtract delta from hop limit'''
                packet.hlim -= self._delta
            else:
                ''' Binary one - add delta from hop limit'''
                packet.hlim += self._delta
            return packet
        
        packet = packet[0] # passive mode
        if msg == 0:
            ''' Binary zero - subtract delta from hop limit'''
            ip.hlim -= self._delta
        else:
            ''' Binary one - add delta from hop limit'''
            ip.hlim += self._delta
        return packet
#----------------------------------------------------------------------------------
    def getmessage(self, packet):
        try:
            ''' Compare hop limit with original '''
            if packet.hlim < self._initialized_recv[packet.src]:
                return 0
            elif packet.hlim > self._initialized_recv[packet.src]:
                return 1
            else:
                return
        except:
            ''' Addr not initialzed, store original hop limit '''
            self._initialized_recv[packet.src] = packet.hlim
#----------------------------------------------------------------------------------
    def removemessage(self, packet): 
        ''' Restore original hop limit '''
        packet.hlim = self._initialized_recv[packet.src]
        return packet
#----------------------------------------------------------------------------------

############################
##                        ##
##      RalertEncoder     ##
##                        ##
############################

class RalertEncoder(MessageEncoder):    
#----------------------------------------------------------------------------------    
    def __init__(self, bandwith = 2):        
        max = 2
        prior_headers = [] # Router Alert is Hop-by-hop header option 
        MessageEncoder.__init__(self, max, bandwith, IPv6ExtHdrHopByHop, 
                                prior_headers)
#----------------------------------------------------------------------------------    
    def _getheader(self, msg):
        ''' get message as number '''
        if len(msg) == 1:
            value = ord(msg)
        else: #len == 2
            value = (ord(msg[0]) << 8) | ord(msg[1])   
            
        header = IPv6ExtHdrHopByHop()       # get Hop-by-hop header
        routerAlert = RouterAlert()         # get Router Alert option
        routerAlert.value = value           # add message
        header.options = routerAlert        # add option to header
        return header
#----------------------------------------------------------------------------------
    def getmessage(self, packet):
        try:
            value = packet[RouterAlert].value
            ''' Get RouterAlert value as string '''
            if value < 256:
                return chr(value)
            fst = value >> 8
            snd = value & ~ (fst << 8)
            return chr(fst) + chr(snd)
        except:
            pass
#----------------------------------------------------------------------------------

############################
##                        ##
##       RawEncoder       ##
##                        ##
############################

class RawEncoder(MessageEncoder):     # TODO: comment
#----------------------------------------------------------------------------------    
    def __init__(self, bandwith = 1000):        
        max = 1380           
        MessageEncoder.__init__(self, max, bandwith, None, None)
#----------------------------------------------------------------------------------    
    def filterproto(self):
        return False # dont filter by protocol
#----------------------------------------------------------------------------------    
    def addmessage(self, msg, packet):
        (ip,  upper) = packet
        
        if upper: # active mode
            ''' Force Scapy to compute automatic fields '''
            upper = IPv6(str(ip/upper)).lastlayer()
            ''' 
                Pseudopacket StrHeader is used to separate covert data from upper-
                layer which is added as raw data. Type of upperlayer protocol is
                stored in StrHeader as well.
            '''
            pay = StrHeader(data=str(upper), msg=msg, nh=58)
            ip.nh = 59 # no payload
            packet = ip / pay                     
            return packet
            
        else:
            packet = packet[0] # passive mode
            
        pkt_copy = IPv6(str(packet))
        pkt_copy.remove_payload()
        pkt_iter = packet.payload
   
        while not isinstance(pkt_iter, NoPayload):
            ''' Get last layer '''
            if isinstance(pkt_iter, type(packet.lastlayer())):
                my_header = StrHeader(msg = msg)
                ''' Store upperlayer in StrHeader.data'''
                my_header.data = str(pkt_iter)
                ''' Store upperlayer proto '''
                my_header.nh = pkt_iter.overload_fields[IPv6]['nh']
                pkt_copy.lastlayer().nh = 59 # no next header
                ''' Add StrHeader as payload'''
                pkt_copy.lastlayer().payload = my_header
                break
            else:
                layer_tmp = pkt_iter.copy() # copy layer + payload
                layer_tmp.remove_payload()  # remove payload
                pkt_copy.lastlayer().payload = layer_tmp # add layer
            pkt_iter = pkt_iter.payload     # get next layer
            
        ''' update length of new packet '''
        pkt_copy .plen = len(str(pkt_copy .payload))        
        return pkt_copy 
#----------------------------------------------------------------------------------        
    def removemessage(self, pkt_orig):
        ''' Removes message and returns modified IPv6 packet '''
        pkt_copy = pkt_orig.copy()  # copy packet
        pkt_copy.remove_payload()   # remove payload
        pkt_iter = pkt_orig.payload
   
        while not isinstance(pkt_iter, NoPayload):
            ''' Get raw layer '''
            if isinstance(pkt_iter, Raw):
                pkt_iter = StrHeader(pkt_iter.load)   # get data
                pkt_copy.lastlayer().nh = pkt_iter.nh # restore next header
                pkt_copy.lastlayer().payload = pkt_iter.data # restore upperlayer
                break
            else:
                layer_tmp = pkt_iter.copy() # copy layer + payload
                layer_tmp.remove_payload()  # remove payload
                pkt_copy.lastlayer().payload = layer_tmp # add layer
            pkt_iter = pkt_iter.payload     # get next layer
        
        ''' update length of modified packet '''
        pkt_copy.plen = len(str(pkt_copy.payload))
        return pkt_copy
#----------------------------------------------------------------------------------
    def getmessage(self, packet):
        try:
            return StrHeader(packet[Raw].load).msg # get correct part of StrHeader
        except:
            pass
#----------------------------------------------------------------------------------

############################
##                        ##
##     RouteresEncoder    ##
##                        ##
############################

class RouteresEncoder(MessageEncoder):    
#----------------------------------------------------------------------------------
    def __init__(self, bandwith = 4):
        max = 4 
        prior_headers = [0]
        MessageEncoder.__init__(self, max, bandwith, IPv6ExtHdrRouting, 
                                prior_headers)
#----------------------------------------------------------------------------------    
    def _getheader(self, msg):
        ''' Get message (max 4 bytes) as number '''
        if len(msg) == 1:
            value = ord(msg)
        elif len(msg) == 2:
            value = (ord(msg[0]) << 8) | ord(msg[1])
        elif len(msg) == 3:
            value = (ord(msg[0]) << 16) | (ord(msg[1]) << 8) | ord(msg[2])
        elif len(msg) == 4:
            value = (ord(msg[0]) << 24) | (ord(msg[1]) << 16) | (ord(msg[2]) << 8) \
                     | ord(msg[3])
                     
        header = IPv6ExtHdrRouting() # get routing header
        header.reserved = value      # store number in reserved field
        return header        
#----------------------------------------------------------------------------------    
    def getmessage(self, packet):
        try:
            ''' Get reserved value of Routing header(type 0) as string '''
            value = packet[IPv6ExtHdrRouting].reserved
            if value < 256: # one byte used
                fst = value
                chars = [fst]
            elif value < 65536: # two bytes used
                fst = value >> 8
                snd = value & ~ (fst << 8)
                chars = [fst, snd]
            elif value < 16777216: # three bytes used
                fst = value >> 16
                snd = (value & ~ (fst << 16)) >> 8
                trd = value & ~ (fst << 16 | snd << 8)
                chars = [fst, snd, trd]
            else: # four bytes used
                fst = value >> 24
                snd = (value & ~ (fst << 24)) >> 16
                trd = (value & ~ (fst << 24 | snd << 16)) >> 8
                frth = value & ~ (fst << 24 | snd << 16 | trd << 8)
                chars = [fst, snd, trd, frth]
            msg = ''.join([chr(elem) for elem in chars]) # join chars
            return msg
        except:
            pass
#----------------------------------------------------------------------------------

############################
##                        ##
##     Route0Encoder      ##
##                        ##
############################

class Route0Encoder(MessageEncoder):    
#----------------------------------------------------------------------------------
    def __init__(self, bandwith = 1360):
        max = 1376
        prior_headers = [0]
        MessageEncoder.__init__(self, max, bandwith, IPv6ExtHdrRouting, 
                                prior_headers)
#----------------------------------------------------------------------------------    
    def _getheader(self, msg):          
        data = self.slice(msg, 16) # divide msg in 16-byte strings
        ''' Transform strings directly to IPv6 addr format '''
        addresses = [self._stringtoaddr(elem) for elem in data]        
        header = IPv6ExtHdrRouting()    # get Routing (type 0) header
        header.addresses = addresses    # add addresses
        ''' 
            Set Segments left field to zero in order to prevent nodes from
            fake addresses processing. 
        '''
        header.segleft = 0  
        return header
#----------------------------------------------------------------------------------    
    def getmessage(self, packet):
        try:
            message = ''
            ''' Get fake addresses '''
            addresses = packet[IPv6ExtHdrRouting].addresses
            ''' Transform them to string '''
            message = ''.join([self._addrtostring(addresses[n]) \
                              for n in xrange(len(addresses))])
            return message
        except:
            pass
#----------------------------------------------------------------------------------

############################
##                        ##
##     SrcaddrEncoder     ##
##                        ##
############################

class SrcaddrEncoder(MessageEncoder):
#----------------------------------------------------------------------------------
    def __init__(self, bandwith = 16):
        max = 16 
        self._init = 5
        self._init_sent = 0
        self._initialized = False
        self._real_addr = None
        MessageEncoder.__init__(self, max, bandwith, None, None)
#----------------------------------------------------------------------------------
    def initpackets(self):
        ''' Returns number of packets needed to init channel  '''
        return self._init
#----------------------------------------------------------------------------------    
    def addmessage(self, msg, packet):          
        if self._init_sent < self._init:
            ''' Send some init packets first '''
            self._init_sent += 1
            if packet[1]: # active
                (ip,  upper) = packet
                return ip / upper
            return packet[0] # passive
                
        ''' Transform 16-byte string to IPv6 addr '''
        addr = self._stringtoaddr(msg)
        
        (ip,  upper) = packet
        if upper: # active 
            ip.src = addr # set false source address
            return ip / upper

        packet = packet[0] # passive mode
        packet[IPv6].src = addr # set false source address
        return packet
#----------------------------------------------------------------------------------    
    def getmessage(self, packet):
        ''' Check if real address is initialized '''
        if not self._initialized:
            self._real_addr = packet[IPv6].src
            self._initialized = True
            return
        elif self._initialized and packet[IPv6].src != self._real_addr:
            return self._addrtostring(packet[IPv6].src)
        else:
            return
#----------------------------------------------------------------------------------    
    def removemessage(self, packet):
        ''' Set real address '''
        packet[IPv6].src = self._real_addr
        return packet
#----------------------------------------------------------------------------------

############################
##                        ##
##   TrafficclsEncoder    ##
##                        ##
############################

class TrafficclsEncoder(MessageEncoder):    
#----------------------------------------------------------------------------------    
    def __init__(self, bandwith = 1):        
        max = 1        
        MessageEncoder.__init__(self, max, bandwith, None, None)
#----------------------------------------------------------------------------------    
    def addmessage(self, msg, packet):  
        ''' Overrides parents method '''
        value = ord(msg)        # get character as number
        
        (ip,  upper) = packet
        if upper:               # active mode
            ip.tc = value       # set false traffic class
            return ip / upper
        
        packet = packet[0]      # passive mode
        packet[IPv6].tc = value # set false traffic class
        return packet
#----------------------------------------------------------------------------------
    def getmessage(self, packet):
        return chr(packet[IPv6].tc) # get traffic class value as character 
#----------------------------------------------------------------------------------
    def removemessage(self, packet):        
        ''' Overrides parents method '''
        packet[IPv6].tc = 0
        return packet
#----------------------------------------------------------------------------------

############################
##                        ##
##       AHResEncoder     ##
##                        ##
############################

class AHResEncoder(MessageEncoder):    
#----------------------------------------------------------------------------------    
    def __init__(self, bandwith = 2):        
        max = 2
        self._spi = random.randint(255, pow(2, 32)) # 0-255 IANA reserved
        self._seq = 1                               # rfc 2402 section 3.3.2
        self._ascii = ''.join([chr(n) for n in xrange(255)]) # ASCII chars
        prior_headers = [0 , 43 , 44 ]
        MessageEncoder.__init__(self, max, bandwith, IPv6ExtHdrAH, prior_headers)
#----------------------------------------------------------------------------------    
    def _getheader(self, msg):  
        header = IPv6ExtHdrAH()         # get Authentication header
        header.spi = self._spi          # set SPI field
        header.seq = self._seq          # set sequence field
        ''' Add random string as ICV '''
        header.icv = ''.join(random.sample(self._ascii,random.randint(16, 16)))
        self._seq += 1
        if not self._seq: # int overflow
            ''' 
                Sequence field overflow - we need to generate new SPI, repeating
                AH sequence numbers with identical SPI may raise suspicion.
            '''
            self._spi = random.randint(255, pow(2, 32))
            self._seq = 1
        ''' get message as number '''
        if len(msg) == 1:
            value = ord(msg)
        else: #len == 2
            value = (ord(msg[0]) << 8) | ord(msg[1])   
        ''' store it into AH reserved field'''
        header.res = value
        return header
#----------------------------------------------------------------------------------
    def getmessage(self, packet):
        try:            
            ''' Get value of AH res field as string'''
            value = packet[IPv6ExtHdrAH].res
            if value < 256:
                return chr(value)
            fst = value >> 8
            snd = value & ~ (fst << 8)
            return chr(fst) + chr(snd)
        except:
            pass
#----------------------------------------------------------------------------------

############################
##                        ##
##       AHIcvEncoder     ##
##                        ##
############################

class AHIcvEncoder(MessageEncoder):    
#----------------------------------------------------------------------------------    
    def __init__(self, bandwith = 1014):        
        max = 1014
        self._spi = random.randint(255, pow(2, 32))           # 0-255 IANA reserved
        self._seq = 1                      # first seq = 1 (rfc 2402 section 3.3.2)
        self._ascii = ''.join([chr(n) for n in xrange(255)])
        prior_headers = [0 , 43 , 44 ]
        MessageEncoder.__init__(self, max, bandwith, IPv6ExtHdrAH, prior_headers)
#----------------------------------------------------------------------------------    
    def _getheader(self, msg):
        header = IPv6ExtHdrAH()             # get Authentication header
        header.spi = self._spi              # set SPI field
        header.seq = self._seq              # set sequence number
        self._seq += 1
        if not self._seq: # int overflow
            ''' 
                Sequence field overflow - we need to generate new SPI, repeating
                AH sequence numbers with identical SPI may raise suspicion.
            '''
            self._spi = random.randint(255, pow(2, 32))
            self._seq = 1        
        ''' AH ICV within IPv6 must be padded to 8-byte words (rfc 4302)'''
        padlen = 8 - (len(msg) % 8)
        msg += padlen * chr(padlen)        
        ''' Add message as fake ICV '''
        header.icv = msg
        ''' Set reserved field in order to recognize fabricated header '''
        header.res = 1
        return header
#----------------------------------------------------------------------------------
    def getmessage(self, packet):        
        try:
            ''' Original AH, do NOT remove'''
            if not packet[IPv6ExtHdrAH].res:
                return
            ''' get ICV field'''
            msg = packet[IPv6ExtHdrAH].icv
            ''' remove padding '''
            padlen = ord(msg[-1])
            for n in xrange(padlen):
                if msg[-(n + 1)] != msg[-1]:
                    return
            ''' return message without padding '''
            return msg[:-padlen]
        except:
            pass
#----------------------------------------------------------------------------------
