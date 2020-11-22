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
# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
# In this function we make the checksum of our packet
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
    #Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.

    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.

    # Don’t send the packet yet , just return the final packet in this function.
    #Fill in end

    # So the function ending should look like this

        # Header is type (8), code (8), checksum (16), id (16), sequence (16)

    myChecksum = 0
    # Make a dummy header with a 0 checksum.
    # struct -- Interpret strings as packed binary data
    
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
                    
                    return "hostname not returnable"
                    

                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                  
                    tracelist1.append(bytes)
                    tracelist2.append(tracelist1)
                    #
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    
                    tracelist1.append(bytes)
                    tracelist2.append(tracelist1) 
                    
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                   
                    tracelist1.append(bytes)
                    tracelist2.append(tracelist1)
                    if packetID == ID:
                        return tracelist2
                   
                else:
                    
                    tracelist1.append("hostname not returnable")
                    tracelist2.append(tracelist1)
                   
                break
            finally:
                mySocket.close()


