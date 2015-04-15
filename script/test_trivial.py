def TrivialTest():
    """ 简单测试 """
    import RapLanV1
    import sys
    from comac import CoMac
    print("Lib:",RapLanV1.Compiled())
    print()
    print("RapLanV1.ListAd()".rjust(40,'#').ljust(40,'#'))
    RapLanV1.ListAd()
    print()
    print("".rjust(20,'*'),'\n')
    print("Obtaining interface:>>".rjust(40,'#').ljust(40,'#'))
    print("{")
    print(",\n".join(RapLanV1.AdList()))
    print("}")
    print()
    
    print(''.rjust(20,'*'),'\n')
    print("Object Testing>>".rjust(40,'#').ljust(40,'#'))
    ad_ls = RapLanV1.AdList()
    for i in range(0,len(ad_ls)):
        s = RapLanV1.PcapIf(RapLanV1.AdList()[i])
        print("repr:",repr(s))
        print("str:",str(s))
        print(s)
        #s.Description = "Hello,world"  #errornous cuz not writable:)
        print("Description = ",s.Description)
        print("AdDesc = ",s.AdDesc) #July.5th.2o1o
        print("Friendly name = ",s.FriendlyName)
        try:
            print("Mac = ",CoMac(s.PhysicalAddr))
        except TypeError as e:
            print("No Mac for this adpter.",file=sys.stderr)
            print("Exception Information:",type(e),":",e,file=sys.stderr)
        print("Index = ",s.Index)
        print("Loopback = ",s.Loopback)
        
        for addr in s.Addresses:
            print('    '.ljust(10,'#'))
            print("\tAddress Family:\t",addr["AddressFamily"])
            print("\tAddress Family Name:\t",addr["AddressFamilyName"])
            print("\tAddress:\t",addr["Address"])
            print('    ',addr)
        print()
        print(''.rjust(20,'$'))
        
    print(''.rjust(20,'*'),'\n')
    print("Arp Table".rjust(40,'#').ljust(40,'#'))
    macs = RapLanV1.MacList()
    for m in macs:
        print(''.join([ki.rjust(20,' ') for ki in m.split(':')]))
    return "Trivial Test Completed."

if '__main__' == __name__:
    import unittest
    class TestMe(unittest.TestCase):
        def runTest(self):
            print(TrivialTest())
            
    #This test is added on. July.14th.2o1o
    class TestObtain2(unittest.TestCase):
        def runTest(self):
            import RapLanV1
            from coshake import ObtainIPv4,ObtainIPv4Netmask
            print("\nTwo obstains>>>")
            s = RapLanV1.PcapIf(RapLanV1.AdList()[0])
            print(ObtainIPv4(s))
            print(ObtainIPv4Netmask(s))

    class TestMore(unittest.TestCase):
        def runTest(self):
            import RapLanV1
            
            print()
            dev2 = RapLanV1.PcapIf(RapLanV1.AdList()[0])
            print(dev2.Snapshot)
            print(dev2.Statistics)
            
            print()
            dev3 = RapLanV1.PcapIf(RapLanV1.AdList()[0],100,3133)
            print(dev3.Snapshot)
            print(dev3.Statistics)

            print()
            dev4 = RapLanV1.PcapIf(Name = RapLanV1.AdList()[0],Timeout=5133)
            print(dev4.Snapshot)
            print(dev4.Statistics)

            print()
            dev5 = RapLanV1.PcapIf(Timeout=2000,Name=RapLanV1.AdList()[0],Caplen=2048)
            print(dev5.Snapshot)
            print(dev5.Statistics)

    class TestMore2(unittest.TestCase):
        def runTest(self):
            import RapLanV1
            print(RapLanV1.BaseLib())

            print('\n'.ljust(20,'*'))
            for s in ['192.168.1.78','192.168.1.100','192.168.1.1','192.168.1.200','localhost','eminem']:
                b = RapLanV1.SendArp(s)
                if b[0]:
                    print("Mac for ",s,"is",b[2])
                else:
                    print("Error: ",b)

            print('\n'.ljust(20,'*'))
            for i in range(245,250):
                print(RapLanV1.SendArp("192.168.1.%d" % i))
          
    #start            
    unittest.main()
    
