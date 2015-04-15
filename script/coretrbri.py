import os,re

def RetrieveArp():
    arp = {}
    be = re.compile(r'\[(.+)\].*\[(.+)\]')
    f = None
    entry = None
    for s in os.popen('perl elicit_arp.pl','r').read().split():
        f = be.match(s)
        if f:
            if f.group(1) in arp:
                raise RuntimeError("Fatal error for me!")
            entries = {}
            arp[f.group(1)] = {"Ino":f.group(2), "Entries":entries}
            continue
        s = s.rstrip('"').lstrip('"')
        s = s.split(':')
        entries[s[0]] = (s[1],s[2])
    return arp

def ResolveIPtoMacByArpTable(arp,ip):
    #print(__name__)    #in main this is still main
    for s in arp.keys():
        ens = arp[s]["Entries"]
        for r in ens:
            if r == ip:
                return ens[r]
    
    return (None,None)

if '__main__' == __name__:

    import unittest
    class TestCoRetrbri(unittest.TestCase):
        def runTest(self):
            a = RetrieveArp()
            for s in a.keys():
                print("Interface:",s)
                print("Ino: ",a[s]["Ino"])
                b = a[s]["Entries"]
                print("Entries:")
                print('\n'.join(['\t' + k + ':' + b[k][0] + ':' + b[k][1] for k in b.keys()]))
                
            self.assertTupleEqual((None,None),ResolveIPtoMacByArpTable(a,"10.0.0.1"),"Test for negativity")
            self.assertTrue(ResolveIPtoMacByArpTable(a,"192.168.1.1"))

    ##Start
    unittest.main()
        
