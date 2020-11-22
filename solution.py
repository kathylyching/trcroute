from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1
ID = os.getpid() & 0xffff


def checksum(string):

    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    

    myChecksum = 0
   
    
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)

    data = struct.pack("d", time.time())

   
    myChecksum = checksum(header + data)

   
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff 
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)

    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    tracelist1 = [] 
    tracelist2 = []

    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)


            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)


            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t= time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []: # Timeout
                    tracelist1.append("* * * Request timed out.")
          
                    tracelist2.append(tracelist1)
                   
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    tracelist1.append("* * * Request timed out.")
                   
                    tracelist2.append(tracelist1)
                    
            except timeout:
                continue

            else:
               
                icmph = recvPacket[20:28]
                types, code, checksum, packetID, sq = struct.unpack("bbHHh", icmph)
                
                try: 
                    
                    dest = gethostbyname(hostname)
                    
                except herror:  
                    
                    tracelist1.append("hostname not returnable") 
                    tracelist2.append(tracelist1)
                    
                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    rtt = (timeReceived - startedSelect) * 100
                    tracelist1.append([ttl, str(rtt),dest,hostname])
                    tracelist2.append(tracelist1)
                    
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    rtt = (timeReceived - startedSelect) * 100
                    tracelist1.append([ttl, str(rtt),dest,hostname])
                    tracelist2.append(tracelist1) 
                    
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    rtt = (timeReceived - startedSelect) * 100
                    tracelist1.append([ttl, str(rtt),dest,hostname])
                    tracelist2.append(tracelist1)
                    if packetID == ID:
                        return tracelist2
                       
                else:
                    rtt = (timeReceived - startedSelect) * 100
                    tracelist1.append([ttl,str(rtt),dest,"hostname not returnable"])
                    tracelist2.append(tracelist1)
                   
                break
            finally:
                mySocket.close()
                return tracelist2

