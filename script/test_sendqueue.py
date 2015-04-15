

if '__main__' == __name__:
        import unittest
        class TestPcapQueue(unittest.TestCase):
                def runTest(self):
                        import RapLanV1
                        mySize = 2000*1024
                        s = RapLanV1.PcapQueue(mySize)
                        self.assertEqual(s.MaxLength,mySize)
                        din = bytes("".ljust(20,'#'),'latin1')
                        self.assertTrue( s.Enque(din) )
                        self.assertEqual(s.MaxLength,mySize)
                        self.assertEqual(s.Length,len(din)+16)

                        ## corrupted size should be raised
                        self.assertRaises(RapLanV1.RapError,RapLanV1.PcapQueue,-1,)

                        ## small queue cannot queue anything
                        s = RapLanV1.PcapQueue(Size = 10)
                        self.assertFalse(s.Enque(din))
                        self.assertEqual(s.MaxLength,10)
                        self.assertEqual(s.Length,0)

                        ## default parameters works
                        s = RapLanV1.PcapQueue()

        class TestSendArpThruQueue(unittest.TestCase):
                def runTest(self):
                        from coarp2 import CoArpReq2
                        from coshake import HexStreamToBytes
                        import RapLanV1
                        dev1 = RapLanV1.PcapIf(RapLanV1.AdList()[0])
                        que = RapLanV1.PcapQueue(2000)
                        req = CoArpReq2("10.0.0.97","00-11-22-11-99-88","10.0.0.98")
                        for i in range(10):
                                self.assertTrue(que.Enque( HexStreamToBytes(req.toHexStream())))
                        lz = que.Length
                        self.assertEqual(lz,que.Transmit(dev1,1))

        class TestSendUdpThruQueue(unittest.TestCase):
                def runTest(self):
                        import RapLanV1
                        from comachd import CoMacIpHd, CoIpUdp, CoUdpHd, CoTcpUdpPacketRoot
                        from random import randint
                        from coshake import HexStreamToBytes, Latin1ToHexStream
                        dev1 = RapLanV1.PcapIf(RapLanV1.AdList()[0])
                        herIP = "10.0.0.99"
                        myIP = "10.0.0.88"
                        msg = "Just grant me the strengh I need to get through another day"
                        packet = CoTcpUdpPacketRoot(CoMacIpHd( "00-11-22-aa-bb-cc", "cc-bb-aa-22-11-00" ),
                                           CoIpUdp(herIP,myIP),
                                           CoUdpHd(randint(1,65535),3003),Latin1ToHexStream(msg))
                        print(packet.toHexStream())# August.29th.2o1o
                        dout = HexStreamToBytes(packet.toHexStream())
                        que = RapLanV1.PcapQueue(2000)
                        cntsz = 0
                        for i in range(10):
                                self.assertTrue(que.Enque(dout))
                                cntsz += len(dout)+16
                        self.assertEqual(que.Length,cntsz)
                        lz = que.Length
                        print(lz,"byte(s) in queue.")
                        self.assertEqual(lz,que.Transmit(dev1,1))
                        
        #Start
        unittest.main()



