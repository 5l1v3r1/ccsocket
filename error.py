#!/usr/bin/python
# -*- coding: UTF-8 -*-
## This file is part of ccsocket
## Copyright (C) Tomas Dragoun <drakoviens@gmail.com>
## This program is published under a GPLv3 license
########################################################


import socket

############################
##                        ##
##         Error          ##
##                        ##
############################

class Error(socket.error):
#----------------------------------------------------------------------------------  
    '''
        Base class for exceptions in this module. Inherits socket.error.
        Attributes: msg  -- explanation of the error
    '''
#----------------------------------------------------------------------------------    
    def __init__(self, msg):
        self._msg = msg
#----------------------------------------------------------------------------------    
    def __str__(self):
        return repr(self._msg)
#----------------------------------------------------------------------------------

############################
##                        ##
##     NotBoundError      ##
##                        ##
############################   
   
class NotBoundError(Error, socket.herror):
#----------------------------------------------------------------------------------
    '''
        Exception raised for unbound socket.
        Attributes: msg  -- explanation of the error
    '''
#----------------------------------------------------------------------------------
    def __init__(self, msg = "Socket is not bound"):        
        self._msg = msg
        Error.__init__(self, msg)
#----------------------------------------------------------------------------------

############################
##                        ##
##      TimeoutError      ##
##                        ##
############################

class TimeoutError(Error, socket.timeout):
#----------------------------------------------------------------------------------
    '''
        Exception raised for timeout.
        Attributes: msg  -- explanation of the error
    '''
#----------------------------------------------------------------------------------
    def __init__(self, msg = "Timeout error"):        
        self._msg = msg
        Error.__init__(self, msg)
#----------------------------------------------------------------------------------
