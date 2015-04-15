
import RapLanV1

def IfNoToName():
    a = RapLanV1.IfMan()
    dc = {}
    for (ifno,name) in a.IfInfos:
        if ifno in dc:
            raise RuntimeError("Already in my list. God.")
        dc[ifno] = name
    del a
    return dc

def PrintIfMan():
    a = RapLanV1.IfMan()
    #print(a.first)
    #print(a.last)
    #print(a.number)
    print("There are",a.IfCounts,"interface(s), including loopback.")
    print(">>")
    print("\n".join(map(str,a.IfInfos)))
    names = IfNoToName()

    tts = a.IfTable
    print()
    for e in tts:
        print()
        print( e['Index'] in names and names[e['Index']] or '<<>>')
        for w in e.keys():
           print(w," => ",e[w])
    return a

if '__main__' == __name__:
    import unittest
    #@unittest.skip("Skip this one")
    class TestIfMan(unittest.TestCase):
        def runTest(self):
            t = PrintIfMan()
            #July.24th.2o1o

    class TestJuly24th2o1oPre(unittest.TestCase):
        def runTest(self):
            import RapLanV1
            t = RapLanV1.IfMan()
            print()
            print(''.rjust(20,'*'),'\n')
            hostBasic = t.HostBasicInfo
            print("Host Name:",hostBasic["HostName"])
            print("Domain Name:",hostBasic["DomainName"])
            print("DNS List:\n","\n".join(["\t" + f for f in hostBasic["DnsList"]]))
            print(''.rjust(20,'*'),'\n')
            

    class TestJuly24th2o1o(unittest.TestCase):
        def runTest(self):
            import RapLanV1
            t = RapLanV1.IfMan()
            print('\n'.ljust(20,'*'))
            for a in t.IpTable:
                for e in ['Address','Mask','BCast','Index','Reasm','wType']:
                    if type(a[e]) is int:
                        print(e,' => 0x%x'%a[e])
                    else:
                        print(e,' => ',a[e])
                print()

    class TestJuly24th2o1oB(unittest.TestCase):
        def runTest(self):
            import RapLanV1
            t = RapLanV1.IfMan()
            print('\n'.ljust(20,'*'))
            d = t.IpStatistics
            for s in d.keys():
                print(s,'=',d[s])
            
    #Start
    unittest.main()


