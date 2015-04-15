#July.13th.2o1o

def DbProcessor(din,prompt):
    print(prompt)
    return True

tc = 0
def DbProc2(din,prompt):
    print(prompt)
    global tc
    tc += 1
    return tc<10

if '__main__' == __name__:
    import RapLanV1
    import unittest
    class TestPcap(unittest.TestCase):
        def runTest(self):
            ds = RapLanV1.AdList()
            dev1 = RapLanV1.PcapIf(ds[0])
            print(dev1.FriendlyName)
            print(RapLanV1.BaseLib())
            print(dev1.DataLink)

            self.assertRaises(TypeError,dev1.SetFilter,"mmx")
            self.assertRaises(TypeError,dev1.SetFilter,0)
            self.assertRaises(RapLanV1.RapError,dev1.SetFilter,"mmx",0,)
            
            print(dev1.ProcessPcap(20,DbProcessor),"processed")
            
            print("\n".ljust(20,'#'))
            print(dev1.ProcessPcap(0,DbProc2),"processed(2)")

            dev1.SetFilter("arp",0xffffff)
            print("\nARP>>".ljust(20,'#'))
            print(dev1.ProcessPcap(30,DbProcessor),"processed")

            dev1.SetFilter("udp",0xffffff)
            print("\nUDP>>".ljust(20,'#'))
            print(dev1.ProcessPcap(30,DbProcessor),"processed")


            
    #Start
    unittest.main()
