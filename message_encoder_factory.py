#!/usr/bin/python
# -*- coding: UTF-8 -*-
## This file is part of ccsocket
## Copyright (C) Tomas Dragoun <drakoviens@gmail.com>
## This program is published under a GPLv3 license
########################################################


from constants import Constants
from message_encoders import *

#############################
##                         ##
##  MessageEncoderFactory  ##
##                         ##
#############################

class MessageEncoderFactory(object):
#----------------------------------------------------------------------------------
    ''' 
        This class creates MessageEncoder of given type.
    '''
#----------------------------------------------------------------------------------    
    @staticmethod
    def create(channeltype, bandwith):
        ''' 
            Creates and returns specific encoder, or None if type of channel isn't 
            defined. Types are listed in class Constants.
        '''
        encoders = MessageEncoderFactory.getencoders()    
        if channeltype < len(encoders):
            if bandwith <= 0:
                return encoders[channeltype]()
            else:
                return encoders[channeltype](bandwith)
#----------------------------------------------------------------------------------
    @staticmethod
    def getencoders():
        ''' 
            Returns list of available encoders.
        '''
        encoders = [AHIcvEncoder,
                    AHResEncoder,
                    DestoptPadNEncoder, 
                    DestoptUnknownEncoder,                    
                    FlowlabEncoder, 
                    FragfakeEncoder, 
                    Fragres1Encoder, 
                    Fragres2Encoder,
                    FragnhEncoder,  
                    HBHPadNEncoder, 
                    HBHUnknownEncoder, 
                    HoplimitEncoder, 
                    RalertEncoder,    
                    RawEncoder, 
                    Route0Encoder,
                    RouteresEncoder, 
                    SrcaddrEncoder, 
                    TrafficclsEncoder, ]    
        return encoders
#----------------------------------------------------------------------------------
