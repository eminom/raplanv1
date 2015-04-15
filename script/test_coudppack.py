
from comachd import DeframeError, FrameLengthError
from comachd import CoMacHd,CoMacIpHd,CoIpv4Hd,CoIpUdp,CoUdpHd,CoTcpUdpPacketRoot
from coshake import HexStreamToBytes,Latin1ToHexStream

if '__main__' == __name__:
    import unittest
    class TestCoUdpPack(unittest.TestCase):
        def runTest(self):
            a = CoTcpUdpPacketRoot.New("0016d3f8464f0023cd4ef3700800450000a30000400034117"
                              "4c7db8533f1c0a801641f400fa0008fc852021a3500176db10369e04c0708"
                              "6f93439740996642c803dc73ffe4919edc17e96991aaf40554e6d42f2bc7bf5c04ecb8470f"
                              "0b3c425a65422b2615e814c1df3daaaf457265f451fda6e1b225b957b31afe0aeb3"
                              "d62facddebcc68d302cffe508c6cc1462299526285e4052a0063dc2dfe9cec722c"
                              "e9033e172e4a606a661e2f9ad5e54450c1f03")
            print()
            print(a)
            self.assertEqual(a.Data(),"021a3500176db10369e04c07086f93439740996"
                                                           "642c803dc73ffe4919edc17e96991aaf40554e6d42f2bc7bf5c04ecb"
                                                           "8470f0b3c425a65422b2615e814c1df3daaaf457265f451fda6e1b225b957"
                                                           "b31afe0aeb3d62facddebcc68d302cffe508c6cc1462299526285e4052a0"
                                                           "063dc2dfe9cec722ce9033e172e4a606a661e2f9ad5e54450c1f03" )

            #This is tcp packet for tcp-udp packet construction
            print(CoTcpUdpPacketRoot.New("0023cd4ef3700016d3"
                              "f8464f080045000028107f4000800"
                              "6466ec0a80164ca621774d41f0050f"
                              "537116e17c1e75b501140b0a3fd0000"))
            
            #This is arp packet for tcp-udp construct
            self.assertRaises(DeframeError,CoTcpUdpPacketRoot.New,"0016d3f8464f0023c"
                              "d4ef3700806000108000604"
                              "00020023cd4ef370c0a801010016d3f8464fc"
                              "0a801640000ffffffffffff00e0a018008408060001")

            #Hex-strem length corrupted for tcp-udp packet construct
            self.assertRaises(FrameLengthError,CoTcpUdpPacketRoot.New,"001122001122001122001122"
                                                               "001122001122001122001122001122"
                                                               "001122001122001122001122001122"
                                                               "001122001122001122001122001122"
                                                               "001122001122001122001122001122"
                                                               "001122001122001122001122001122"
                                                               "001122001122001122001122001122"
                                                               "001122001122001122001122001122"
                                                               "001122001122001122001122001122001122A")
            #odd length for CoMacHd
            self.assertRaises(FrameLengthError,CoTcpUdpPacketRoot.New,"01234567890123A")
            #odd length for CoIpv4Hd
            self.assertRaises(FrameLengthError,CoTcpUdpPacketRoot.New,"001122001122001122001122001122001122001122001122a")
            #18 charaters hex-stream to CoUdp.New.(16 chars expected)
            self.assertRaises(FrameLengthError,CoUdpHd.New,"012345678901234512")

    #Start
    unittest.main()
            
