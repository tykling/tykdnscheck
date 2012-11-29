#!/usr/local/bin/python
import socket
import struct
import argparse
import time

### Add argument parsing
parser = argparse.ArgumentParser()
parser.add_argument('-p', '--protocol', choices='46', required=True, help='Choose Ipv4 or IPv6 (required)')
parser.add_argument('-d', '--domain', required=True, help='The domain name to serve (remember trailing .) (required)')
parser.add_argument('-i', '--ip', help='One or more "good" IP addresses to trigger the message in --goodreply, leave out to disable check', nargs='*')
parser.add_argument('-g', '--goodreply', help='The message to return if the client IP matches --ip', default="Yay! You are using the right DNS server!")
parser.add_argument('-b', '--badreply', help='The message to return if the client IP doesn\'t match --ip', default="You are NOT using the right DNS server!")
args=parser.parse_args()

### Function to output to the console with a timestamp
def output(message):
    print " [%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),message)

class DNSQuery:
    def __init__(self, data):
        self.data=data
        self.domain=''
        self.opcode = (ord(data[2]) >> 3) & 15                                      ### Opcode bits
        if self.opcode == 0:                                                        ### opcode 0 is a standard query
            position=12                                                             ### query begins at byte 12
            labellength=ord(data[position])                                         ### Length of the first label
            while labellength != 0:                                                 ### search through data until a 0 byte is found
                self.domain+=data[position+1:position+labellength+1]+'.'            ### add this label part to self.domain
                position+=labellength+1                                             ### Move position to the beginning of the next label
                labellength=ord(data[position])                                     ### Find length of the next label
            self.qtype=data[position+1:position+3]                                  ### query type is the next two bytes
            self.qtype=struct.unpack(">h",self.qtype)                               ### Convert to tuple of integers
            self.qtype=self.qtype[0]                                                ### Get first element of the tuple

    def dnsheader(self,rcode):                                                      ### This function builds and returns a DNS header with the given rcode
        packet=''                                                                   ### Initialize packet variable
        packet+=self.data[:2]                                                       ### Query ID (16 bits) (copied from original query)
        packet+='\x81'                                                              ### QR, Opcode (4 bits), AA, TC, RA
        if(rcode==5):
            packet+='\x85'                                                          ### RA, Z, AD, CD, Rcode refused (4 bits)
            packet+=self.data[4:6]                                                  ### QDCOUNT (16 bits) (copied from original query)
            packet+='\x00\x00'                                                      ### ANCOUNT (16 bits)
        elif(rcode==2):
            packet+='\x82'                                                          ### RA, Z, AD, CD, Rcode servfail (4 bits)
            packet+=self.data[4:6]                                                  ### QDCOUNT (16 bits) (copied from original query)
            packet+='\x00\x00'                                                      ### ANCOUNT (16 bits)
        else:
            packet+='\x80'                                                          ### Z, AD, CD, Rcode no error (4 bits)
            packet+=self.data[4:6]                                                  ### QDCOUNT (16 bits) (copied from original query)
            packet+='\x00\x02'                                                      ### ANCOUNT (16 bits)
        packet+='\x00\x00'                                                          ### NSCOUNT (16 bits)
        packet+='\x00\x00'                                                          ### ARCOUNT (16 bits)
        return packet

    def txtreply(self,empty=False):                                                 ### This function builds and returns a v4 RR response packet section
        packet=''                                                                   ### Initialize packet variable
        temp=self.data.find('\x00',12)                                              ### Find the first 0 byte, marks the end of the question
        packet+=self.data[12:temp+5]                                                ### Original RR question (variable length) (copied from original query)
        if not empty:
            ### add first RR in answer section
            packet+='\xc0\x0c'                                                      ### Pointer to domain name (16 bits)
            packet+='\x00\x10'                                                      ### RR type (TXT record) (16 bits)
            packet+='\x00\x01'                                                      ### RR class (IN) (16 bits)
            packet+='\x00\x00\x00\x3c'                                              ### RR TTL (60 seconds) (16 bits)
            txt="Your DNS server IP is %s" % client[0]                              ### Put the answer string together
            packet+='\x00'+chr(len(txt)+1)                                          ### RR RDLENGTH
            packet+=chr(len(txt))+txt                                               ### Answer
            if not args.ip == None:                                                 ### add second RR in answer section
                packet+='\xc0\x0c'                                                  ### Pointer to domain name (16 bits)
                packet+='\x00\x10'                                                  ### RR type (TXT record) (16 bits)
                packet+='\x00\x01'                                                  ### RR class (IN) (16 bits)
                packet+='\x00\x00\x00\x3c'                                          ### RR TTL (60 seconds) (16 bits)
                txt=args.badreply                                                   ### Default to args.badmessage
                for ip in args.ip:                                                  ### Check each IP in args.ip
                    if client[0] == ip:                                             ### Compare with client IP
                        txt=args.goodreply                                          ### Match! Return args.goodmessage
                        break                                                       ### Break out of the loop
            packet+='\x00'+chr(len(txt)+1)                                          ### RR RDLENGTH
            packet+=chr(len(txt))+txt                                               ### Answer
        return packet

if __name__ == '__main__':
    try:
        if args.protocol=="4":
            udpsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)            ### Create IPv4 udp socket
        else:
            udpsocket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)           ### Create IPv6 udp socket
        udpsocket.bind(('',53))                                                     ### and bind to port 53
    except:
        output("Unable to create and bind UDP socket on port 53, exiting.")
        sys.exit()
    
    output("Waiting for queries...")
    try:
        while 1:                                                                    ### loop while waiting for packets
            data, client = udpsocket.recvfrom(1024)                                 ### Receive data from socket
            servfail=False
            queryobject=DNSQuery(data)                                              ### Create queryobject
            if queryobject.qtype != 16 or queryobject.opcode != 0:                  ### Check for invalid queries
                if queryobject.qtype != 16:                                         ### Unknown qtype
                    output("Unknown qtype %s, sending SERVFAIL to client %s" % (queryobject.qtype,client[0]))
                else:                                                               ### Unknown opcode
                    output("Unknown opcode %s, sending SERVFAIL to client %s" % (queryobject.opcode,client[0]))
                packet=queryobject.dnsheader(rcode=2)                               ### Build a DNS header with rcode 2 (servfail)
                packet+=queryobject.txtreply(empty=True)                            ### Build an empty DNS response
            else:
                if (queryobject.domain == args.domain):                             ### Check that the query is for the correct domain
                    packet=queryobject.dnsheader(rcode=0)                           ### Build a DNS header with rcode 0 (no error)
                    packet+=queryobject.txtreply()                                  ### Build a DNS response
                    output('Sending reply to client %s' % client[0])
                else:
                    output('not serving domain %s, refusing query from client %s' % (queryobject.domain,client[0]))
                    packet=queryobject.dnsheader(rcode=5)                           ### Build a DNS header with rcode 5 (refused)
                    packet+=queryobject.txtreply(empty=True)                        ### Build an empty DNS response
            udpsocket.sendto(packet,client)                                         ### Send the response
    except KeyboardInterrupt:
        output('Control-c received, exiting')
        udpsocket.close()