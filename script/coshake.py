
#History:
# June-July. the RapLanV1 Project

#Latest Modification: July.10th.2o1o.
#BigEdHex() added

def HexStreamToBytes(strm):
    if len(strm) % 2 != 0:
        raise Exception("Cannot got it")
    bs= b''
    for si in [strm[i:i+2] for i in range(0,len(strm),2)]:
        ei = bytes(chr(int(si,16)),'latin1')
        bs += ei
        #print(ei)
    return bs

def Latin1ToHexStream(latin1):
    rvs = ""
    for c in latin1:
        rvs += hex(ord(c))[2:].rjust(2,'0')
    return rvs

def BigEdHex(v,sz):
    v = hex(v)[2:]
    return v.rjust(sz*2,'0')


def BytesToHexStream(bs):
    if not isinstance(bs,bytes):
        raise TypeError("bytes excepted.")
    return ''.join(map(lambda b:hex(b)[2:].rjust(2,'0'), bs))


#For RapLanV1.PcapIf
def ObtainIPv4(s):
    d = [f['Address'] for f in s.Addresses if f['AddressFamilyName'] == 'AF_INET']
    return d[0]

#For RapLanV1.PcapIf
def ObtainIPv4Netmask(s):
    d = [f['Netmask'] for f in s.Addresses if f['AddressFamilyName'] == 'AF_INET']
    return d[0]

if '__main__' == __name__:
    print("Shake-Utility 1.0")
    import unittest
    class ShakeUtilityTestBigEdHex(unittest.TestCase):
        def runTest(self):
            self.assertEqual(BigEdHex(0x806,2),'0806')
            self.assertEqual(BigEdHex(1,1),'01')
            self.assertEqual(BigEdHex(0x806,4),'00000806')

    class TestBytesToHexStream(unittest.TestCase):
        def runTest(self):
            from random import randint
            self.assertEqual(BytesToHexStream(b'123'),"313233")
            f = BytesToHexStream
            h = HexStreamToBytes
            # f(x) = y
            # h(y) = x
            # h(f(x)) = x
            # f(h(y)) = y
            for i in range(0,667):
                ln = randint(1,1000)
                s = ''
                for j in range(ln):
                    s += chr(randint(0,255))
                y = Latin1ToHexStream(s)
                self.assertEqual( f(h(y)),y)

    #Ok,here we go
    unittest.main()
