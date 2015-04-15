
#July.15th.2o1o@ Retrieev all ARP information in a flahs
# Slimshady Tech

def DetectHosts(lower,higher,fmt):
    import re
    if not re.match(r"(?:\d{1,3}\.){3}%d",fmt):
        raise ValueError("Paramter fmt need to be a.b.c.%d")
    
    from coarp2 import CoArp2,CoArpReq2,CoArpReply2
    from coshake import BytesToHexStream,HexStreamToBytes
    from coshake import ObtainIPv4
    import time,threading
    import RapLanV1
    
    dev1 = RapLanV1.PcapIf(RapLanV1.AdList()[0])
    dev1.SetFilter("arp",0xffFFff)

    global counter
    counter = 0
    opVal = time.time()
    def ArpWatcher(din,msg):
        global counter
        if len(din) >= 42:
            c = CoArp2.New(BytesToHexStream(din[0:42]))
            if 0x806 != c._CoArp2__frameType:
                raise RuntimeError("Filtered out a non-arp packet???")
            if c._CoArp2__op == 2:
                counter += 1
                print(c._CoArp2__senderIP)
        if counter >= higher-lower:
            return False
        return time.time() - opVal < 30.0


    def ArpGo(dv):
        dv.ProcessPcap(0,ArpWatcher)

    gs = threading.Thread(target = ArpGo,args=(dev1,))
    gs.start()

    myIp = ObtainIPv4(dev1)
    for i in range(lower,higher):
        destIP = fmt % i
        #print("Requesting for ",destIP,"...")
        a = CoArpReq2(myIp,dev1.PhysicalAddr,destIP )
        dev1.Send( HexStreamToBytes(a.toHexStream()) )
    #print("All %d request(s) sent."%(higher - lower))
    gs.join()

if '__main__' == __name__:
    import unittest
    class TestHostDetector(unittest.TestCase):
        def runTest(self):
            fmt = "192.168.1.%d"
            op = 1
            ed = 255
            print("Detecting for >>")
            print(",".join([fmt % i for i in range(op,ed)]))
            print("####")
            DetectHosts(1,255,"192.168.1.%d")

    #Start
    unittest.main()


    
    
