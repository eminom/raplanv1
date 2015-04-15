
from coshake import HexStreamToBytes,Latin1ToHexStream
from comachd import CoIcmpPing,CoMacHd,CoIpv4Hd,CoMacIpHd
import RapLanV1
from coshake import ObtainIPv4
from comac import CoMac,CoIPv4
import threading
import unittest



class TestPingNow(unittest.TestCase):
    def runTest(self):

        def ProcessIcmp(din,prompt):
            print(prompt)

        def TheWatcher(dev1,judge):
            c = dev1.ProcessPcap(20,ProcessIcmp)
            print(c,"icmp packet(s) captured.")
            judge.assertGreater(c,10)
            return c
        
        dev1 = RapLanV1.PcapIf(RapLanV1.AdList()[0],Timeout = 1333)
        print(dev1.AdDesc)
        dev1.SetFilter("icmp",0xFFFFFF)
        dev1.SetBuff(16*1024*1024)
        dev1.SetMinToCopy(14+20+8)
        guard = threading.Thread(target = TheWatcher, args = (dev1,self))
        guard.start()

        dst = RapLanV1.SendArp("192.168.1.1")
        if dst[0]:
            dst = dst[2]
        
        mc = CoMacIpHd(dst,dev1.PhysicalAddr)
        iph = CoIpv4Hd(ObtainIPv4(dev1),"192.168.1.1",1) #1 for icmp
        
        icmp = CoIcmpPing(data="Hello,world")
        dout = mc.toHexStream() + iph.toHexStream() + icmp.toHexStream()
        for i in range(10):
            dev1.Send(HexStreamToBytes(dout))

        guard.join()

if '__main__' == __name__:
    unittest.main()
