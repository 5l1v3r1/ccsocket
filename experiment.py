import ccsocket as socket
from multiprocessing import Process
from sys import stdout
import time
import sys
import random
#---------------------------------------------------------------------------------
def getmsg(length):
    if length >= 1:
        msg = length * 'X'
    else:
        msg = pow(2, int(length * 10)) - 1
    return msg
#---------------------------------------------------------------------------------  
def probe_cl(host):
    channels = socket.channelsinfo()    
    count = len(channels)    

    for n in xrange(count):        
        s = socket.socket(chtype = n, band = channels[n][1])
        if n != 16:
            s.bind((host, n))        
        else:
            s.bind(('', n))        
        max = s.getbandwith()    
        print '\n\nChannel number [ ' + str(n) + ' ]'
        print channels[n][0]     
                
        retry = 0
        if max > 1:
            msglen = max - (max / 10)
        elif max < 1:
            msglen = 0.1
        else:
            msglen = 1
        s.settimeout(0.5)
        reply = None
        gotreply = 0                
        while(1):
            s.sendto(getmsg(msglen),(host, n))
            try:
                reply = s.recv(0)
            except:
                retry += 1
                if retry == 5:
                    break
            if reply:   
                reply = None
                gotreply = msglen
                retry = 0
                if msglen >= 1:
                    msglen += 1
                else:
                    msglen += 0.1
                if msglen > max:
                    break
        
        if(gotreply):
            print '[OK]'
            print 'Max capacity: ' + str(gotreply)
            channels[n] = ((channels[n][0]), gotreply)
            
        else:
            print '[FAIL]'
        s.close()        
        del s
    
    stdout.flush()
    return channels
#---------------------------------------------------------------------------------
def probe_srv():
    channels = socket.channelsinfo()
    count = len(channels)
    sockets = []

    for n in xrange(count):
        s = socket.socket(chtype = n)
        sockets.append(s)
        s.bind(('', n))
        p = Process(target = srv_worker, args = (s, ))
        p.start()
        
    print 'Listening for probes..'
    
    while(1):
        pass
    
    for s in sockets:
        s.close()
#---------------------------------------------------------------------------------
def srv_worker(s):
    count = 0
    while(1):
        msg, addr = s.recvfrom(0)
        if addr[0] == '::1':
            continue
        s.sendto(msg, addr)
        count += 1
        stdout.write("\r%d" % count)
        stdout.flush()
#---------------------------------------------------------------------------------
def latency_cl(host, channels = socket.channelsinfo()):    
    count = len(channels)    
    latency = {}
    lost = {}
    print '\nRunning latency test..'

    for n in xrange(count):        
        s = socket.socket(chtype = n, band = channels[n][1])
        port = n
        addr = (host, port, 0, 0)
        if n != 16: # Source addres channel, bind to localhost
            s.bind(addr) 
        else:
            s.bind(('', port))        
            
        print '\n\nChannel number [ ' + str(n) + ' ], address: ' + str(addr)
        print channels[n][0]     
        print 'Capacity: ' + str(channels[n][1])
        
        latency[n] = []
        lost[n] = 0
        s.settimeout(1)
        msg = getmsg(channels[n][1])
        s.sendto(msg,(host, n))
        bytes_sent = 0
        stdout.write("[")
        for m in xrange(10):            
            try:                
                stdout.write(".")
                stdout.flush()
                
                s.sendto(msg,(host, n))
                elapsed = -time.time()
                reply = s.recv(0)                
                elapsed += time.time()
                if len(str(reply)):
                    latency[n].append(elapsed / 2)     
                else:
                    m -= 1
                time.sleep(random.random())
            except:
                lost[n] += 1
        
        stdout.write("]\n")
        
        maxLatency = 0
        minLatency = 0
        avgLatency = 0
        
        if len(latency[n]):
            maxLatency = max(latency[n])
            minLatency = min(latency[n])
            avgLatency = sum(latency[n]) / len(latency[n])
        
        jitter = 0
        for m in xrange(len(latency[n]) - 1):
            jitter += abs(latency[n][m] - latency[n][m+1])
        jitter /= (len(latency[n]) - 1)
        
        print '\nMax latency: ',
        print ("%.4f" % round(maxLatency * 1000,4)),
        print 'ms \nMin latency: ',
        print ("%.4f" % round(minLatency * 1000,4)),
        print 'ms \nAvg latency: ' ,
        print ("%.4f" % round(avgLatency * 1000,4)),
        print 'ms \nAvg RTT:     ' ,
        print ("%.4f" % round(avgLatency * 2000,4)),
        print 'ms \nJitter:       ' ,
        print ("%.4f" % round(jitter * 1000,4)),
        print 'ms \nPacket loss:   ' + str(lost[n]) + ' %'
        
        s.close()        
    return channels
#---------------------------------------------------------------------------------
def latency_srv():
    channels = socket.channelsinfo()
    count = len(channels)
    sockets = []

    for n in xrange(count):
        s = socket.socket(chtype = n)
        sockets.append(s)
        s.bind(('', n))
        p = Process(target = srv_worker, args = (s, ))
        p.start()
        
    print 'Serving..'
    
    while(1):
        pass
    
    for s in sockets:
        s.close()
        del s
#---------------------------------------------------------------------------------
def latency_srv_worker(s):
    while(1):
        msg, addr = s.recvfrom(0)
        if addr[0] == '::1':
            continue
        s.sendto(msg, addr)        
#---------------------------------------------------------------------------------
def bandwith_cl(host, channels = socket.channelsinfo()):
    inter = 120
    print '\n\nRunning troughput test..'
    print 'Interval (seconds): ' + str(inter)
    print 'Press enter to begin packet emission..'
    stdout.flush()
    raw_input()
    
    for n in xrange(len(channels)):
        if n == 11:
           continue
        s = socket.socket(chtype = n, band = channels[n][1])
        msg = getmsg(channels[n][1])
        s.sendto(msg,(host, n + 199))
        print 'Channel [ ' + str(n) + ' ]' + ' capacity: ' + str(channels[n][1])
        stdout.flush()
        elapsed = - time.time()
        while (elapsed + time.time()) <= inter:
            s.sendto(msg,(host, n))
        s.close()
#---------------------------------------------------------------------------------
def bandwith_srv(channels = socket.channelsinfo()):
    count = len(channels)
    inter = 100
    print 'Interval (seconds): ' + str(inter)
    print '\n\nTesting troughput..'

    for n in xrange(count):
        s = socket.socket(chtype = n, band = channels[n][1])
        s.bind(('', n))        
        bytes = 0        
        print '\nChannel number ' + str(n) + ': '
        stdout.flush()
        msg, addr = s.recvfrom(0)
        s.settimeout(10)
        print 'collecting data..'
        stdout.flush()
        elapsed = - time.time()
        while (elapsed + time.time()) <= inter:
            try:
                msg, addr = s.recvfrom(0)
            except:
                continue
            if addr[0] == '::1':
                continue                
            bytes += len(str(msg))
        
        if channels[n][1] < 1:
            bytes *= channels[n][1]
        bytes = bytes / float(inter)
        kbps = bytes / 1024.0        
        stdout.write("\n%d" % bytes)
        if channels[n][1] >= 1:
            print ' bytes/sec'
        else:
            print ' bits/sec'
        stdout.write("\n%.2f" % kbps)
        if channels[n][1] >= 1:
            print ' kBps'
        else:
            print ' kbps'
        stdout.flush()
        s.close()
#---------------------------------------------------------------------------------
if len(sys.argv) < 3:
   print 'Host or mode missing..'
   sys.exit(1)

if sys.argv[1][:1] == 'c':
    if sys.argv[1] == 'cl':
       latency_cl(sys.argv[2])      
    elif sys.argv[1] == 'cb':  
       bandwith_cl(sys.argv[2])
    elif sys.argv[1] == 'cp':  
       probe_cl(sys.argv[2])
    else:
        print '\nRunning client tests..\n\n'
        latency_cl(sys.argv[2])
        channels = probe_cl(sys.argv[2])                
        bandwith_cl(sys.argv[2], channels)        
        

elif sys.argv[1][:1] == 's':
    if sys.argv[1] == 'sl':
       latency_srv()      
    elif sys.argv[1] == 'sb':  
       bandwith_srv()
    else:
       probe_srv()
