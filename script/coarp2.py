
from comac import CoMac,CoIPv4
from coshake import BigEdHex

class CoArp2:
    def __init__(self,src_ip,src_mac,dst_ip):
        self.__destMacHd = CoMac('00-11-22-33-44-55')
        if isinstance(src_mac,CoMac):
            self.__srcMacHd = src_mac #July.14th.2o1o
        else:
            self.__srcMacHd = CoMac(src_mac)
            
        self.__frameType = 0x0806    # arp, 2 bytes
        self.__hardware_tp = 0x0001  # ethernet  2 bytes
        self.__proto_tp = 0x0800  #IP proto, 2 bytes
        self.__hardware_length = 6  # 1 bytes
        self.__proto_length = 4  #1 bytes
        self.__op = 0  # 2 bytes
        self.__senderMac = self.__srcMacHd  # 6 bytes.
        if isinstance(src_ip,CoIPv4):       # 4 bytes
            self.__senderIP = src_ip
        else:
            self.__senderIP = CoIPv4(src_ip)

        self.__destinationMac = CoMac("55-44-33-22-11-00") #which differs in different OP(only dummy here)
        if isinstance(dst_ip,CoIPv4):
            self.__destinationIP = dst_ip
        else:
            self.__destinationIP = CoIPv4(dst_ip)

    def toHexStream(self):
        rv  = self.__destMacHd.toHexStream()
        rv += self.__srcMacHd.toHexStream()
        rv += BigEdHex(self.__frameType, 2 )
        rv += BigEdHex(self.__hardware_tp,2)
        rv += BigEdHex(self.__proto_tp, 2)
        rv += BigEdHex(self.__hardware_length,1)
        rv += BigEdHex(self.__proto_length,1)
        rv += BigEdHex(self.__op,2)
        rv += self.__senderMac.toHexStream()
        rv += self.__senderIP.toHexStream()
        rv += self.__destinationMac.toHexStream()
        rv += self.__destinationIP.toHexStream()
        return rv

    def __len__(self):
        return len(self.toHexStream())

    def __eq__(self,rhs):
        return isinstance(rhs,CoArp2) and self.toHexStream().lower() == rhs.toHexStream().lower()

    def __str__(self):
        rv = []
        rv.append('[Mac Head(6 + 6 + 2) bytes]')
        rv.append("\tDestination Mac:\t %s" % str(self.__destMacHd))
        rv.append("\tSource Mac:\t %s" % str(self.__srcMacHd))
        rv.append("\tType: %s" % BigEdHex(self.__frameType,2))
        rv.append("[Arp(2+2+2+1+1+2+6+4+6+4=30) bytes]")
        rv.append("\tHardware Type:\t %s" % BigEdHex(self.__hardware_tp,2))
        rv.append("\tProtocal Type:\t %s"% BigEdHex(self.__proto_tp,2))
        rv.append("\tHardware Addr Length: %s" % BigEdHex(self.__hardware_length,1))
        rv.append("\tProtocal Addr Length: %s" %BigEdHex(self.__proto_length,1))
        rv.append("\tOp Code: %s"%BigEdHex(self.__op,2))
        rv[-1] += "\t(%s)" % ( 1 == self.__op and "Request" or 2 == self.__op and "Reply" or "Unknown ARP")
        rv.append("\tSender Mac: %s"% str(self.__senderMac))
        rv.append("\tSender IPv4: %s"% str(self.__senderIP))
        rv.append("\tDestination Mac: %s"% str(self.__destinationMac))
        rv.append("\tDestination IP: %s"% str(self.__destinationIP))
        return "\n".join(rv)

    def DestinationMacHdHexStream(self):
        return self.__destMacHd.toHexStream()
    
    def DestinationMacHexStream(self):
        return self.__destinationMac.toHexStream()

    def SourceMacHdHexStream(self):
        return self.__srcMacHd.toHexStream()
    
    def SourceMacHexStream(self):
        return self.__senderMac.toHexStream()
    
    @staticmethod
    def New(hs):
        if not isinstance(hs,str):
            raise TypeError("Expcet hex stream for this")
        if len(hs) != 42 * 2:
            raise ValueError("Expect hex stream length of 42*2 for this")
        
        #slot
        self = CoArp2('1.2.3.4','00-00-00-11-11-11','2.0.0.2')
        self.__destMacHd = CoMac(hs[0*2:6*2])
        self.__srcMacHd = CoMac(hs[6*2:12*2])
        self.__frameType = int(hs[12*2:14*2],16)

        self.__hardware_tp = int(hs[14*2:16*2],16)
        self.__proto_tp = int(hs[16*2:18*2],16)
        self.__hardware_length = int(hs[18*2:19*2],16)
        self.__proto_length = int(hs[19*2:20*2],16)
        self.__op = int(hs[20*2:22*2],16)
        self.__senderMac = CoMac(hs[22*2:28*2])
        self.__senderIP = CoIPv4(hs[28*2:32*2])
        self.__destinationMac = CoMac(hs[32*2:38*2])
        self.__destinationIP = CoIPv4(hs[38*2:42*2])
        return self

class CoArpReq2(CoArp2):
    def __init__(self,src_ip,src_mac,dst_ip):
        CoArp2.__init__(self,src_ip,src_mac,dst_ip)
        self._CoArp2__op = 1 #request op
        self._CoArp2__destMacHd = CoMac("ff-ff-ff-ff-ff-ff")
        self._CoArp2__destinationMac = CoMac("00-00-00-00-00-00")

class CoArpReply2(CoArp2):
    def __init__(self,src_ip,src_mac,dst_ip,dst_mac):
        CoArp2.__init__(self,src_ip,src_mac,dst_ip)
        self._CoArp2__op = 2 #reply op
        if isinstance(dst_mac,CoMac):
            self._CoArp2__destMacHd = dst_mac
        else:
            self._CoArp2__destMacHd = CoMac(dst_mac)
        self._CoArp2__destinationMac = self._CoArp2__destMacHd

if '__main__' == __name__:

    import random
    from coshake import HexStreamToBytes
    import RapLanV1
    
    devs = RapLanV1.AdList()
    d1 = RapLanV1.PcapIf(devs[0])
    print(d1.AdDesc)
    myMac = "AA-BB-CC-DD-EE-FF"
    
    import unittest
    class TestCoArp2(unittest.TestCase):
        def runTest(self):
            a = CoArp2('192.168.1.100',myMac,"192.168.1.1")
            print(a)
            self.assertEqual(len(a),42*2,"Test Arp length in bytes")
            self.assertEqual(a.SourceMacHexStream(),a.SourceMacHdHexStream())

    class TestCoArpReq2(unittest.TestCase):
        def runTest(self):
            a = CoArpReq2('192.168.1.100',myMac,"192.168.1.1")
            self.assertEqual(len(a),42*2,"Test Arp Request length in bytes")
            self.assertEqual(a.SourceMacHexStream(),a.SourceMacHdHexStream())
            self.assertEqual(a.DestinationMacHexStream(),"000000000000")
            self.assertEqual(a.DestinationMacHdHexStream().lower(),"ffffffffffff")
            
            self.assertGreater(d1.Send(HexStreamToBytes(a.toHexStream())),0,"Send it!Request")            

    class TestCoArpReply2(unittest.TestCase):
        def runTest(self):
            a = CoArpReply2('10.1.1.20',myMac,"10.1.1.1","00-22-44-66-88-01")
            self.assertEqual(a.SourceMacHexStream(),a.SourceMacHdHexStream())
            self.assertEqual(a.DestinationMacHdHexStream(),"002244668801")
            self.assertEqual(a.DestinationMacHdHexStream(),a.DestinationMacHexStream())
            
            self.assertGreater(d1.Send(HexStreamToBytes(a.toHexStream())),0,"Send it!Reply")

    class TestCoArp2New(unittest.TestCase):
        def runTest(self):
            a = CoArp2.New("0023cd4ef3700016d3f8464f080600010800060400010016d3f8464fc0a801640023cd4ef370c0a80101")
            b = CoArp2.New(a.toHexStream())
            self.assertEqual(a,b,"Test for persistency")
            a = CoArp2.New("0023cd4ef3700016d3f8464f080600010800060400010016d3f8464fc0a801640023cd4ef370c0a80101")
            b = CoArp2.New(a.toHexStream())
            self.assertEqual(a,b,"Test for persistency 2")
            a = CoArp2.New("001122334455aabbccddeeff08060001080006040002aabbccddeeff0a0101140022446688000a010101")
            b = CoArp2.New(a.toHexStream())
            self.assertEqual(a,b,"Test for persistency 3")
            for i in range(0,20000):
                s = ''
                for j in range(0,84):
                    s += "%x"%random.randint(0,15)
                a = CoArp2.New(s)
                b = CoArp2.New(a.toHexStream())
                self.assertEqual(a,b,"Test for persistency in random fashion.")
                    
    unittest.main()
