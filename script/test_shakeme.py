

#Description: send some packet throught WinPcap and retrieve it by normal socket
#:yeah, shake it baby

from coshake import Latin1ToHexStream,HexStreamToBytes

words = "Earth is so dangerous for us."

def TestRandomSend(dev1):
    """ Dont care where this went """
    from comac import CoMac,CoIPv4
    from comachd import CoMacIpHd,CoIpUdp,CoUdpHd
    from random import randint

    mac_head = CoMacIpHd(CoMac.RandomMac(),CoMac.RandomMac())
    ip_head = CoIpUdp(CoIPv4.RandomIPv4(),CoIPv4.RandomIPv4())
    udp_head = CoUdpHd(randint(1,65535),3000)
    packet = mac_head.toHexStream() + ip_head.toHexStream() + udp_head.toHexStream()  + Latin1ToHexStream("Random test on random ip random port")
    return dev1.Send(HexStreamToBytes(packet))

def TestSend2Me(dev1,sndCnt):
    """Last Modified on July.18th.2o1o: use tcp-udp packet to manage"""
    from comac import CoMac,CoIPv4
    from comachd import CoMacIpHd,CoIpUdp,CoUdpHd,CoTcpUdpPacketRoot
    from time import sleep
    from coshake import ObtainIPv4
    from random import randint

    myIP = ObtainIPv4(dev1)
    print("Send from some random to",myIP)
    
    sleep(1.0)
    for i in range(sndCnt):
        herIP  = "192.168.1.%d"%randint(1,255)
        packet = CoTcpUdpPacketRoot(CoMacIpHd( dev1.PhysicalAddr, dev1.PhysicalAddr ),CoIpUdp(herIP,myIP),CoUdpHd(randint(1,65535),3003),
                                    Latin1ToHexStream(words))
        dev1.Send(HexStreamToBytes(packet.toHexStream()))
    #Done

if '__main__' == __name__:
    import unittest,threading
    import time
    import RapLanV1
    dev1 = RapLanV1.PcapIf(RapLanV1.AdList()[0])
    print(dev1.AdDesc)
    
    class TestSendFromRandomToRandom(unittest.TestCase):
        def runTest(self):
            for i in range(10):
                self.assertGreater(TestRandomSend(dev1),0,"Test RapLanV1.Send")

    class TestSendToMe(unittest.TestCase):
        def runTest(self):
            expectedCnt = 100            
            s = threading.Thread(target = TestSend2Me,args=(dev1,expectedCnt,))
            s.start()
            
            ###catch the data here####
            import socket
            svr = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            svr.bind( ('',3003))
            svr.settimeout(3.0)
            print("Expecting something...")

            recvCnt = 0
            for i in range(0,expectedCnt):
                try:
                    (din,addr) = svr.recvfrom(2048)
                    print("From (",addr[0],":",addr[1],"):",din)
                    recvCnt += 1
                    self.assertEqual(bytes(words,"latin1"),din,"Test for din/dout")
                except socket.timeout:
                    pass
            svr.close()
            ##clean
            s.join()
            print("Receive Count:",recvCnt)
            self.assertGreater(recvCnt,expectedCnt*8/10)    #80%+

    #Start            
    unittest.main()


    
