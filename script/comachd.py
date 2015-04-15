from comac import CoMac,CoIPv4
from coshake import BigEdHex,HexStreamToBytes,Latin1ToHexStream
import random

class DeframeError(TypeError):
    pass

class FrameLengthError(ValueError):
    pass

class CoMacHd():
    def __init__(self,dstmac,srcmac,proto_hd):
        if not isinstance(dstmac,CoMac):
            dstmac = CoMac(str(dstmac))
        if not isinstance(srcmac,CoMac):
            srcmac = CoMac(str(srcmac))
        if type(proto_hd) is not int:
            raise TypeError("Expecting proto to be int(like IP=0x800 or ARP=0x806")
        
        self.__dstmac = dstmac
        self.__srcmac = srcmac
        self.__proto_hd = proto_hd

    def __str__(self):
        infos = []
        infos.append("[Mac Head(6+6+2=14 bytes)]")
        infos.append("\tDestination Mac: %s"%self.__dstmac)
        infos.append("\tSource Mac: %s"%self.__srcmac)
        infos.append("\tProto: %.4x"%self.__proto_hd)
        return "\n".join(infos)

    def __len__(self):
        return len(self.toHexStream())
    
    def __eq__(self,rhs):
        return self is rhs or type(rhs) is CoMacIpHd and self.toHexStream().lower() == rhs.toHexStream().lower()

    def DestMac(self):
        return str(self.__dstmac)

    def SrcMac(self):
        return str(self.__srcmac)

    def Proto(self):
        return self.__proto_hd
        
    def toHexStream(self):
        return self.__dstmac.toHexStream() + self.__srcmac.toHexStream() + BigEdHex(self.__proto_hd,2)
    
    @staticmethod
    def New(hs):
        # New for CoMacHd
        if not isinstance(hs,str):
            raise TypeError("Expect hex stream to be string")
        
        if len(hs) != 14*2 or len(hs)%2!=0 :
            raise FrameLengthError("Expect hex stream length of character 14*2")
        
        self = CoMacIpHd("00-00-00-00-00-00","00-00-00-00-00-00")
        self.__dstmac = CoMac(hs[0:6*2])
        self.__srcmac = CoMac(hs[6*2:12*2])
        self.__proto_hd = int(hs[12*2:14*2],16)
        return self

class CoMacIpHd(CoMacHd):
    def __init__(self,dstmac,srcmac):
        CoMacHd.__init__(self,dstmac,srcmac,0x800)

class CoIpv4Hd():
    def __init__(self,src_ip ,dst_ip, tl_proto, verhead = 0x45 , tos = 0, pack_id = 0, flag_offset = 0, ttl=64, chkSum = 0, totLen = 0, options=""):
        self.SetSrcIp(src_ip)
        self.SetDstIp(dst_ip)
        
        self.__verhead = verhead                         # version. head length. (IPv4)
        self.__tos = tos                                       # type of service. 1 bytes
        self.__pack_identification = pack_id        # identification for ip. unsigned short. 2 bytes
        self.__flag_offset = flag_offset                # flag & offset. 2 bytes
        self.__ttl = ttl                                         # time to live. 1 bytes
        self.__proto = tl_proto                            # udp value 17. 1 bytes
        
        self.__hdr_checksum = chkSum  #check sum. unsigned short. 2 bytes
        self.__total_length = totLen  #total length for this ip packet. unsigned short. 2bytes. (calculated by lower implementation)
        self.__options = options   # already in hex-stream
        #self.ChangeId() # by default
        
    def __str__(self):
        infs = []
        infs.append( "[IP Header Info]")
        vh = divmod(self.__verhead,16)
        infs.append( "\tHead-Version: %x\tVersion:%d,\tHead-Length:%d"%(self.__verhead,vh[0],vh[1]*4))
        infs.append( "\tType of Service: %.2x"%self.__tos)
        infs.append( "\tTotal length: %.4x (%d) " %(self.__total_length,self.__total_length))
        infs.append( "\tIdentification: %.4x" %self.__pack_identification)
        infs.append("\tFlag-offset: %.4x"%self.__flag_offset)
        infs.append("\tTime to live: %d"%self.__ttl)
        infs.append("\tProtocal: %d"%self.__proto)
        infs.append("\tHead checksum: %.4x"%self.__hdr_checksum)
        infs.append("\tSource IP: %s"% self.__source_ip)
        infs.append("\tDestination IP: %s" %self.__destination_ip)
        return "\n".join(infs)        

    def toHexStream(self):
        hs = ''
        hs += BigEdHex(self.__verhead,1)
        hs += BigEdHex(self.__tos,1)
        hs += BigEdHex(self.__total_length,2)
        hs += BigEdHex(self.__pack_identification,2)
        hs += BigEdHex(self.__flag_offset,2)
        hs += BigEdHex(self.__ttl,1)
        hs += BigEdHex(self.__proto,1)
        hs += BigEdHex(self.__hdr_checksum,2)
        hs += self.__source_ip.toHexStream()
        hs += self.__destination_ip.toHexStream()
        return hs
    
    def __len__(self):
        return len(self.toHexStream())

    def __eq__(self,rhs):
        raise NotImplemented("Not implemented for CoIpUdp")
    
    def ChangeId(self):
        self.__pack_identification = random.randint(0,65535)

    def SetSrcIp(self,newSrc):
        if isinstance(newSrc,CoIPv4):
            self.__source_ip = newSrc
        else:
            self.__source_ip = CoIPv4(newSrc)

    def SetDstIp(self,newDst):
        if isinstance(newDst,CoIPv4):
            self.__destination_ip = newDst
        else:
            self.__destination_ip = CoIPv4(newDst)

    def SourceIP(self):
        return str(self.__source_ip)

    def DestinationIP(self):
        return str(self.__destination_ip)

    def Proto(self):
        return self.__proto

    def SetProto(self, proto):
        self.__proto = proto
        return proto

    @staticmethod
    def New(hs):
        """ Reconstruct an ip head"""
        if not isinstance(hs,str):
            raise TypeError("Expected hex-stream to be of type str")
        if len(hs) < 20 * 2:
            raise RuntimeError("Hex-stream too short to be for IPv4 head")

        if len(hs) % 2 != 0:
            raise FrameLengthError("Hex-stream length is not even.(IPv4 head hex-stream)")
        
        src_ip = CoIPv4(hs[12*2:16*2])
        dst_ip = CoIPv4(hs[16*2:20*2])
        vhead = int(hs[0*2:1*2],16)    #一般来说是0x45
        tos = int(hs[1*2:2*2],16)  #一般来说是 0
        totLength = int(hs[2*2:4*2],16)
        pack_id = int(hs[4*2:6*2],16)
        flag_offset = int(hs[6*2:8*2],16)
        ttl = int(hs[8*2:9*2],16)
        proto = int(hs[9*2:10*2],16)
        checkSum = int(hs[10*2:12*2],16)
        self = CoIpv4Hd(src_ip ,dst_ip, proto, vhead, tos, pack_id, flag_offset, ttl, checkSum, totLength, hs[20*2:] )
        return self

    @staticmethod
    def CheckIpHeadLength(hs):
        """Retrieve the length of the ip head"""
        vhead = int(hs[0*2:1*2],16)
        return (vhead &0xF) * 4

class CoIpUdp(CoIpv4Hd):
    def __init__(self,src_ip,dst_ip):
        CoIpv4Hd.__init__(self,src_ip,dst_ip, 17)

class CoIpTcp(CoIpv4Hd):
    def __init__(self,src_ip,dst_ip):
        CoIpv4Hd.__init__(self,src_ip,dst_ip,6)

###############################Splitting ####################
###############################Splitting   ####################
###############################Splitting   ####################
############## Common class for TCP/UDP #############
        
class CoUdpTcpHd():
    def __init__(self,src_port,dst_port):
        self.SetSourcePort(src_port)
        self.SetDestinationPort(dst_port)
        
    def DestinationPort(self):
        return self.__dst_port

    def SourcePort(self):
        return self.__src_port

    def SetSourcePort(self,port):
        if type(port) != int:
            raise TypeError("Source port type expected to be int.")
        if port not in range(0,65536):
            raise ValueError("out of range")
        self.__src_port = port
        return port

    def SetDestinationPort(self,port):
        if type(port) != int:
            raise TypeError("Desitination port type expected to be int.")
        if port not in range(0,65536):
            raise ValueError("out of range")
        self.__dst_port = port
        return port

####### Splitting for CoUdpHd #################
        
class CoUdpHd(CoUdpTcpHd):
    def __init__(self,src_port,dst_port, udp_length = 0, check_sum = 0):
        CoUdpTcpHd.__init__(self,src_port,dst_port)
        self.__udp_length = udp_length
        self.__udp_checksum = check_sum

    def __str__(self):
        infos = []
        infos.append("[UDP head(8bytes)]")
        infos.append("\tSource Port: %d" % self.SourcePort () )
        infos.append("\tDestination Port: %d"% self.DestinationPort() )
        infos.append("\tUDP length: %d" %self.__udp_length)
        infos.append("\tUDP checksum: %.4x" %self.__udp_checksum)
        return "\n".join(infos)

    def toHexStream(self):
        hs = ''
        hs += BigEdHex ( self.SourcePort () ,  2 )
        hs += BigEdHex ( self.DestinationPort() ,  2  )
        hs += BigEdHex(self.__udp_length,2)         #udp length
        hs += BigEdHex(self.__udp_checksum,2)    #udp cheksum
        return hs

    def __eq__(self,rhs):
        return type(rhs) == CoUdpHd and self.toHexStream().lower() == rhs.toHexStream().lower()
    
    def Length(self):
        return self.__udp_length

    @staticmethod
    def New(hs):
        # new for CoUdpHd
        if not isinstance(hs,str):
            raise TypeError("Expect string for hex stream.")
        if len(hs) != 16:   #8 bytes for Udp head.
            raise FrameLengthError("Expecting hex stream length of 8 bytes (16 hex stream characters)")
        self = CoUdpHd(int(hs[0:2*2],16), int(hs[2*2:4*2],16 )
                       ,int(hs[4*2:6*2],16)
                       ,int(hs[6*2:8*2],16))
        return self
    
##########################Splitting for CoTcpHd ####################
##########################Splitting for CoTcpHd ####################
##########################Splitting for CoTcpHd ####################
    
class CoTcpHd(CoUdpTcpHd):
    " TCP head of 20 bytes-length version"
    def __init__(self,src_port,dst_port,seq, ackno,flags, window_size, head_size = 0x50, check_sum = 0, urgent_pointer = 0, options=""):
        CoUdpTcpHd.__init__(self, src_port, dst_port )
        
        self.SetSeq ( seq )
        self.SetAckNo ( ackno )
        
        self.__head_size = head_size
        self.__flags = flags
        self.SetWindowSize ( window_size)
        self.SetCheckSum( check_sum)                    # do not set this. when being sent, it will be set. this is reserved for reverse building from Hex-Stream
        self.SetUrgentPointer( urgent_pointer )          # no more urgent data attached
        self.__options = options

    def Seq(self):
        return self.__seq

    def SetSeq(self,seq):
        self.__seq = seq

    def AckNo(self):
        return self.__ackno

    def SetAckNo(self,ackno):
        self.__ackno = ackno

    def HeadSizeValue(self):
        " Need further processing to get the real head length"
        return self.__head_size

    def FlagsValue(self):
        " The famous Urg/Ack/Psh/Rst/Syn/Fin Flags"
        return self.__flags

    def SetFlags(self, urg, ack, psh, rst, syn, fin ):
        self.__flags =(
            (urg<<5) | (ack <<4) | (psh<<3) | (rst<<2) | (syn<<1) | (fin<<0) )

    #Attributes of Flags
    def IsUrg(self):
        return ((self.__flags>>5)&1) != 0
    def IsAck(self):
        return ((self.__flags>>4)&1) != 0
    def IsPsh(self):
        return ((self.__flags>>3)&1) != 0
    def IsRst(self):
        return ((self.__flags>>2)&1) != 0
    def IsSyn(self):
        return ((self.__flags>>1)&1) != 0
    def IsFin(self):
        return ((self.__flags>>0)&1) != 0
    
    def WindowSize(self):
        return self.__window_size
    def SetWindowSize(self,ws):
        self.__window_size = ws

    def CheckSum(self):
        "The check sum for this TCP packet ( checksum refers to the whole TCP head and TCP body ) "
        return self.__check_sum
    def SetCheckSum(self, newCheckSum ):
        self.__check_sum = newCheckSum

    def UrgentPointer(self):
        return self.__urgent_pointer
    def SetUrgentPointer(self,up):
        self.__urgent_pointer = up

    def Options(self):
        " The options in TCP head is in hex-stream "
        return self.__options

    def __str__(self):
        infos = []
        infos.append("[Tcp Head ]")
        infos.append( "Source Port = %d" % self.SourcePort() )
        infos.append( "Destination Port = %d" % self.DestinationPort() )
        infos.append( "Sequence = %d (0x%.8x)" % (self.__seq, self.__seq) )
        infos.append( "Ack no = %d (0x%.8x)" % ( self.__ackno, self.__ackno) )
        infos.append(" Tcp Head Length = %d (0x%.4x) " % ((self.__head_size>>2),(self.__head_size>>2) ))
        infos.append( " Tcp flags = 0x%.2x  " % self.__flags + 
            "[ Congestion Window Reduced = %d" %(1&(self.__flags>>7)) +
            " ECN-Echo = %d" %(1&(self.__flags>>6)) +
            " Urg = %d" % (1&(self.__flags>>5)) +
            "  Ack = %d" % (1&(self.__flags>>4)) +
            "  Psh = %d" % (1&(self.__flags>>3)) +
            "  Rst = %d" % (1&(self.__flags>>2)) +
            "  Syn = %d" % (1&(self.__flags>>1)) +
            "  Fin = %d ]" % (1&(self.__flags>>0))
        )
        
        infos.append("Window Size = %d" % self.__window_size )
        infos.append(" Check sum = %d (0x%.4x)" % (self.__check_sum, self.__check_sum) )
        infos.append(" Urgent pointer = %d (0x%.4x)" % (self.__urgent_pointer, self.__urgent_pointer) )
        infos.append(" Options (In hex-stream)= [%s]  (length = %d)" % (self.__options, len(self.__options)/2) )
        return "\n".join(infos)

    def Length(self):
        return (self.__head_size>>2)
    
    def toHexStream(self):
        hs = ""
        hs += BigEdHex ( self.SourcePort(), 2 )
        hs += BigEdHex ( self.DestinationPort(), 2 )
        
        hs += BigEdHex(self.__seq, 4)
        hs += BigEdHex(self.__ackno, 4 )
        
        hs += BigEdHex(self.__head_size ,1 )
        hs += BigEdHex(self.__flags, 1 )
        hs += BigEdHex(self.__window_size, 2 )
        
        hs += BigEdHex(self.__check_sum, 2 )               # This is for check sum
        hs += BigEdHex(self.__urgent_pointer, 2 )           # This is for urgent pointer
        hs += self.__options
        # And no more options for this version
        return hs

    @staticmethod
    def New(hs:str):
        if len(hs)%2 != 0:
            raise ValueError("Hex-Stream must be of even length.")
        if len(hs)< 20*2:
            raise ValueError("Hex-Stream is corrupted (too short to be an tcp head)")

        s_port =  int(hs[0*2:2*2],16)
        d_port =  int(hs[2*2:4*2],16)
        seq_no = int(hs[4*2:8*2],16)
        ack_no = int(hs[8*2:12*2],16)
        head_len = int(hs[12*2:13*2],16)
        flags = int(hs[13*2:14*2],16)
        win_size = int(hs[14*2:16*2],16)
        check_sum = int(hs[16*2:18*2],16)
        urgent_pointer = int(hs[18*2:20*2],16) #
        options = hs[20*2:]                                     # the rest will be options
        return CoTcpHd(s_port,d_port,seq_no,ack_no, flags, win_size, head_len, check_sum, urgent_pointer, options)

    @staticmethod
    def CheckTcpHdLength(hs:str):
        if len(hs)%2!=0:
            raise ValueError("Hex-stream must be of even length.")
        if len(hs)< 20*2:
            raise ValueError("Hex-Stream is corrupted(too short to be a TCP head.")
        head_len = int(hs[12*2:13*2],16)
        return (head_len>>2)

##########################Splitting for CoTcpUdpPacketRoot###################
##########################Splitting for CoTcpUdpPacketRoot###################
##########################Splitting for CoTcpUdpPacketRoot###################

class CoTcpUdpPacketRoot:
    """Coded on July.18th.2o1o
        Enhanced on August.29th.2o1o
        """
    def __init__(self, mac_h:CoMacHd, ip_h:CoIpv4Hd, tcp_udp_h:CoUdpTcpHd, msg:str):
        self.__macHead = mac_h
        self.__ipHead = ip_h
        self.__tcpudpHd = tcp_udp_h
        self.__msg = msg  #in hex-stream

    def __str__(self):
        rv = ""
        rv += str(self.__macHead)
        rv +="\n"
        rv += str(self.__ipHead)
        rv += "\n"
        rv += str(self.__tcpudpHd)
        rv += "\n"
        
        #rv += "[Udp data:]\n"
        #rv += str(self.__msg)
        #rv += "\n"
        rv += "[Data(hex-stream):]\n"
        rv += self.__msg
        return rv

    def IpProto(self):
        return self.__ipHead.Proto()

    def DestPort(self):
        return self.__tcpudpHd.DestinationPort()

    def SrcPort(self):
        return self.__tcpudpHd.SourcePort()

    def SrcIP(self):
        return self.__ipHead.SourceIP()

    def DestIP(self):
        return self.__ipHead.DestinationIP()

    def TcpUdpLength(self):
        return self.__tcpudpHd.Length()


    #Expose the segments>>
    def MacHead(self):
        return self.__macHead

    def IpHead(self):
        return self.__ipHead
    
    def TcpUdpHd(self):
        return self.__tcpudpHd

    def Data(self):
        " data in hex-stream"
        return self.__msg

    def toHexStream(self):
        return self.__macHead.toHexStream() + self.__ipHead.toHexStream() + self.__tcpudpHd.toHexStream() +  self.__msg

    @staticmethod
    def New(hs):
        """build udp packet(full frame) from hex-stream"""
        if len(hs)%2 != 0:
            raise FrameLengthError("What the fuck length of hex-stream")
        mc = CoMacHd.New(hs[0*2:14*2])
        if mc.Proto() != 0x800:
            raise DeframeError("Not an IPv4 ether frame.")
        hs = hs[14*2:]
        
        hlen = CoIpv4Hd.CheckIpHeadLength(hs)
        ip = CoIpv4Hd.New(hs[:hlen*2])
        hs = hs[hlen*2:]

        if ip.Proto() == 17:
            tcp_udp_h = CoUdpHd.New(hs[:8*2])
            return CoTcpUdpPacketRoot(mc,  ip,  tcp_udp_h,  hs [ 8*2 : ] )
        elif ip.Proto() == 6:
            tcp_head_length = CoTcpHd.CheckTcpHdLength(hs)
            tcp_udp_h = CoTcpHd.New(hs[:tcp_head_length*2])
            return CoTcpUdpPacketRoot(mc,ip,tcp_udp_h,  hs[ tcp_head_length*2 : ]  )
        raise DeframeError("Unsupported protocol of %d" % ip.Proto())

#####################################ICMP definitions#############################
#####################################ICMP definitions#############################
#####################################ICMP definitions#############################

class CoIcmpHd():
    def __init__(self,theType:int,theCode:int):
        if type(theType) is not int or type(theCode) is not int:
            raise TypeError("Expecting int parameter for icmp(type,code)")
        self.__type = theType
        self.__code = theCode
        self.__checksum = 0 

    def toHexStream(self):
        rs = ''
        rs += BigEdHex(self.__type,1)
        rs += BigEdHex(self.__code,1)
        rs += BigEdHex(self.__checksum,2)
        return rs

    def Code(self):
        return self.__code

    def Type(self):
        return self.__type

    def __str__(self):
        res = []
        res.append("Icmp Head [Length = 4 bytes]")
        res.append("Type = %d"% self.__type)
        res.append("Code = %d"%self.__code)
        res.append("Checksum = %.4x" %self.__checksum)
        return "\n".join(res)

    @staticmethod
    def New(hs:str):
        """From 8 characters's hex-stream, which rebuilds the 4 bytes ICMP head"""
        if type(hs) != str:
            raise TypeError("Hex-stream expected.")
        if len(hs) != 8:
            raise ValueError("Hex-stream length restricted to 8")
        me = CoIcmpHd(0,0)
        me.__type = int(hs[0:2],16)
        me.__code = int(hs[2:4],16)
        me.__checksum = int(hs[4:8],16) #just in big-endian
        return me

class CoIcmpPing(CoIcmpHd):
    def __init__(self,theId = 1, theSeq = 1, data="eminem"):
        CoIcmpHd.__init__(self,8,0)   #Ping: Type = 8 (request ping) , Code = 0
        self.__identifier = theId
        self.__seq = theSeq
        self.__data = data

    def Identifier(self):
        return self.__identifier

    def Sequence(self):
        return self.__seq

    def Data(self):
        return str(self.__data)

    def toHexStream(self):
        rv = CoIcmpHd.toHexStream(self)
        rv += BigEdHex(self.__identifier,2)
        rv += BigEdHex(self.__seq,2)
        rv += Latin1ToHexStream(self.__data)
        return rv

    def __str__(self):
        hds = CoIcmpHd.__str__(self)
        res = []
        res.append("\t[Icmp Ping]")
        res.append("Identifier = %d"%self.__identifier)
        res.append("Sequence = %d"%self.__seq)
        res.append("data = %s \n\t( DataLength = %d )"%(str(self.__data),len(self.__data)))
        return hds+"\n" + "\n".join(res)

    @staticmethod
    def New(hs:str):
        if type(hs) != str:
            raise TypeError("Hex-stream expected.")
        if len(hs) < 16:
            raise ValueError("Hex-stream must be of length not less than 16 characters.")
        me = CoIcmpPing()
        me.__type = int(hs[0:2],16)
        me.__code = int(hs[2:4],16)
        me.__checksum = int(hs[4:8],16)
        me.__identifier = int(hs[8:12],16)
        me.__seq = int(hs[12:16],16)
        me.__data = str(HexStreamToBytes(hs[16:]),"latin1")
        return me

##################################Splitting Line########################################
##################################Splitting Line########################################
##################################Splitting Line########################################
##################################Splitting Line########################################
    
if '__main__' == __name__:
    import unittest
    
    class TestCoMacHd(unittest.TestCase):
        #@unittest.skip("demonstrating skipping")
        def runTest(self):
            self.failUnlessRaises( Exception, CoMacIpHd, (CoMac('00-11-22-33-44-55'),CoMac('AA-BB-CC-DD-EE-FF')))
            self.assertRaises(Exception, CoMacIpHd,(CoMac.RandomMac(),123))
            self.assertRaises(Exception, CoMacIpHd,(CoMac.RandomMac(),'123'))
            self.assertEqual(CoMacIpHd(CoMac('00-11-22-33-44-55'),CoMac('AA-BB-CC-DD-EE-FF')),CoMacIpHd("001122334455","AAbbCCddEEff"))
            h = CoMacIpHd(CoMac('00-11-22-33-44-55'),CoMac("aabbccddeeff"))
            self.assertEqual(len(h),14*2,"Test for length of hex-stream for CoMacIpHd)")
            self.assertEqual(CoMac(h.SrcMac()),CoMac("AA-BB-CC-DD-EE-FF"))
            self.assertEqual(CoMac(h.DestMac()),CoMac("00-11-22-33-44-55"))
            self.assertEqual(h.Proto(),0x800)
            print()
            print(h)

            a = CoMacIpHd.New("ffffffffffff0016d3f8464f0806")
            b = CoMacIpHd.New(a.toHexStream())
            self.assertEqual(a,b,"Test for persistency of CoMacIpHd")
            
    class TestCoIpUdp(unittest.TestCase):
        #@unittest.skip("demonstrating skipping")
        def runTest(self):
            src = "192.168.1.100"
            dst = "192.168.1.1"
            s = CoIpUdp(src,dst)
            print()
            print(s)
            self.assertEqual(src,s.SourceIP())
            self.assertEqual(len(s),20*2,"Test length of IpUdp")

            for i in range(0,1000):
                kiss = []
                for j in range(0,4):
                    kiss.append( random.randint(0,255) )
                addr = '.'.join(map(str,kiss))
                s.SetSrcIp(addr)
                self.assertEqual(s.SourceIP(),addr)
                
            for i in range(0,1000):
                kiss = []
                for j in range(0,4):
                    kiss.append( random.randint(0,255) )
                addr = '.'.join(map(str,kiss))
                s.SetDstIp(addr)
                self.assertEqual(s.DestinationIP(),addr)
    
        for i in range(0,2000):
            s = CoIpUdp('1.0.0.1','2.0.0.2')
            s.ChangeId()
            s.SetDstIp(CoIPv4.RandomIPv4())
            s.SetSrcIp(CoIPv4.RandomIPv4())

    class TestCoUdpHd(unittest.TestCase):
        #@unittest.skip("demonstrating skipping")
        def runTest(self):
            import re
            # if excetpion are thrown.
            # the exception will be caught
            # and the test will be marked as 'failed'. So, good for us!
            c = CoUdpHd(2425,2425)
            print()
            print(c)
            self.assertEqual(c.toHexStream(),'0979097900000000')
            print()
            print(CoUdpHd.New('0979097900000000'))

            r = re.compile(r'^[\da-fA-F]{8}0{8}$')
            for i in range(0,666):
                self.assertTrue(r.match(CoUdpHd(random.randint(0,65535),random.randint(0,65535)).toHexStream()))

            for i in range(0,666):
                c = CoUdpHd( random.randint(0,65535), random.randint(0,65535) )
                d = CoUdpHd.New(c.toHexStream())
                self.assertEqual(c,d,"Test for persistency")

    class TestIcmpPing(unittest.TestCase):
        def runTest(self):
            print()
            s = CoIcmpPing(data ="haha")
            
            print(s)
            s = CoIcmpPing.New("00005559000100026162636465666768696a6b6c6d6e6f7071727374757677616263646566676869")
            print()            
            print(s)
            print("Type = ",s.Type())
            print("Code =",s.Code())
            print("Identifier =",s.Identifier())
            print("Sequence =",s.Sequence())
            print("Data =",s.Data())
            
            s = CoIcmpHd.New("00005559")
            print()            
            print(s)
            print("\nSingles>>")
            print("Type = ",s.Type())
            print("Code =",s.Code())

    class TestTcpHd(unittest.TestCase):
        def runTest(self):
            print()
            s = CoTcpHd(80,81, 1000, 2000, 0x02, 8192)
            print(repr(s))
            print(str(s))
            print(s.toHexStream())
            
    #Here we go        
    unittest.main()
