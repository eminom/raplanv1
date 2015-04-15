

#Latest: repr is held for the oringal
#Modification Date: July.10th.2o1o
#the new "representation" is toHexStream
# CoMac.toHexStream & CoIPv4Addr.toHexStream

#June-July. 2o1o
#RapLanV1 Project
import re,random

class CoMac():
    def __init__(self,macAddrStr):
        if not isinstance(macAddrStr,str):
            raise TypeError("Expect string for mac address")
        if re.match(r'^([\da-fA-F]{2}-){5}[\da-fA-F]{2}$',str(macAddrStr)):
            self.__hs = ''.join( [macAddrStr[f:f+2] for f in range(0,len(macAddrStr),3)])
        elif re.match(r'^([\da-fA-F]{2}){6}$',macAddrStr):
            self.__hs = macAddrStr
        else:
            raise ValueError("Wrong Format for CoMac")
        
    def __str__(self):
        "Debug representation of MAC(802.11) address"
        return '-'.join( [self.__hs[f:f+2] for f in range(0,len(self.__hs),2)])
    
    def toHexStream(self):
        "Raw representation of mac address in network order(as the same in x86 order)"
        return self.__hs

    def __eq__(self,rhs):
        return type(rhs)==CoMac and self.toHexStream().lower() == rhs.toHexStream().lower()

    @staticmethod
    def RandomMac():
        return CoMac(''.join([hex(random.randint(0,255))[2:].rjust(2,'0') for i in range(0,6)]))

class CoIPv4():
    def __init__(self,ipstr):
        if type(ipstr) != str:
            raise TypeError("Wrong value type for IP string: string needed")
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$',ipstr):
            self.__ip = ipstr
            for s in ipstr.split('.'):
                s = int(s)
                if s<0 or s >=256:
                    raise ValueError("Wrong IP sub value for CoIPv4Addr")
            self.__hexstream =  ''.join([hex(int(s))[2:].rjust(2,'0') for s in ipstr.split('.')])
        elif re.match(r'[\da-fA-F]{8}',ipstr):
            v = ''
            for i in range(0,4):
                v += str( int(ipstr[i*2:i*2+2],16) )
                v += '.'
            self.__ip = v.rstrip('.')
            self.__hexstream = ''.join([hex(int(s))[2:].rjust(2,'0') for s in self.__ip.split('.')])
        else:
            raise ValueError("Wrong Format for CoIPv4Addr")
        
    def __str__(self):
        "Debug representation of IPv4"
        return self.__ip
    
    def toHexStream(self):
        "Raw representation of IPv4 address in network order(as the same in x86 order)"
        return self.__hexstream
    
    def __eq__(self,rhs):
        return type(rhs)==CoIPv4 and self.toHexStream().lower() == rhs.toHexStream().lower()

    @staticmethod
    def RandomIPv4():
        return CoIPv4('.'.join([str(random.randint(0,255)) for i in range(0,4)]))

if '__main__' == __name__:
    import unittest
    class TestCoMac(unittest.TestCase):
        def runTest(self):
            self.assertEqual(CoMac("0a-02-03-04-05-fA"),CoMac("0a02030405fa"),"Test for equality")            

            for i in range(0,1000):
                macStr = ""
                for j in range(0,6):
                    macStr += hex(random.randint(0,255))[2:].rjust(2,'0')
                self.assertEqual(CoMac(macStr).toHexStream().lower(),macStr.lower(),"Test for CoMac.toHexStream()")
                self.assertEqual('-'.join( [macStr[i:i+2] for i in range(0,len(macStr),2)]).lower(),str(CoMac(macStr)),"Test for CoMac.__str__")
                
            for i in range(0,1000):
                s = []
                for j in range(0,6):s.append(hex(random.randint(0,255))[2:].rjust(2,'0'))
                self.assertEqual(CoMac(''.join(s)),CoMac('-'.join(s)),"Test for equality (between the different construction)")

    class TestCoIPv4Addr(unittest.TestCase):
        def runTest(self):
            for i in range(10,20):
                for j in range(30,40):
                    for p in range(95,100):
                        for q in range(127,132):
                            c = "%d.%d.%d.%d"%(i,j,p,q)
                            ad = CoIPv4(c)
                            self.assertEqual(str(ad),c)
                            self.assertEqual(CoIPv4(ad.toHexStream()),ad,"Test for equality for CoIPv4Addr")



    class TestMiscellence(unittest.TestCase):
        def runTest(self):
            for i in range(0,100):
                c = CoMac.RandomMac()
            for i in range(0,10):
                c = CoIPv4.RandomIPv4()
            print(''.ljust(20,'#'))
            from coretrbri import RetrieveArp
            rapdb = RetrieveArp()
            for s in rapdb:
                print("Interface for ",CoIPv4(s))
                for k in rapdb[s]["Entries"]:
                    print('\t',CoIPv4(k), "=>", CoMac(rapdb[s]["Entries"][k][0]))

            print("".rjust(20,'*'))
            for s in rapdb:
                r = rapdb[s]["Entries"]
                break
            print(r)


    unittest.main()


    



    
    
    
    
