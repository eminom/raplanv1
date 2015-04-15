
from comachd import CoMacIpHd, CoIpv4Hd, CoIpTcp,CoTcpHd
from comac import CoMac, CoIPv4
from coshake import HexStreamToBytes,BigEdHex
import RapLanV1
import unittest

if '__main__' == __name__:
    class TestTcpHd(unittest.TestCase):
        def runTest(self):
            #From 5544...11 to 0011...55
            mac_head = CoMacIpHd("001122334455","554433221100")
            ip_head = CoIpTcp("10.0.0.199", "20.10.5.3")
            tcp_head = CoTcpHd(80,81,0x11223344,0x22AA,2,8192)
            #print(tcp_head)
            #print("#########")
            packet = mac_head.toHexStream() +  ip_head.toHexStream() +  tcp_head.toHexStream()
            dev1 = RapLanV1.PcapIf( RapLanV1.AdList()[0])
            #print(dev1.AdDesc)
            dev1.Send( HexStreamToBytes( packet ) )

    unittest.main()            
