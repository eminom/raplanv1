

import RapLanV1

import unittest
class TestTrivial2(unittest.TestCase):
    def runTest(self):
        print()
        dev1 = RapLanV1.PcapIf(RapLanV1.AdList()[0])
        print("Hi, my name is",str(dev1))
        print(dev1.AdDesc)

        print("Version for this interface:",dev1.Ver)
        print("Is swapped:",dev1.IsSwapped)


def ProcessPackets(din,prompt):
    print(prompt)
    return True

class TestTrivial2Plus(unittest.TestCase):
    def runTest(self):
        print()
        dev1 = RapLanV1.PcapIf(RapLanV1.AdList()[0],Timeout = 133)
        print("SetBuf=>",dev1.SetBuff(32))
        print("Returned from SetMinToCopy():",dev1.SetMinToCopy(-1))
        self.assertRaises(RapLanV1.RapError,dev1.ProcessPcap,0,ProcessPackets)
        dev1.SetBuff(16*1024*1024)
        readCnt = dev1.ProcessPcap(20,ProcessPackets)
        print("Read in all:",readCnt)

if '__main__' == __name__:
    unittest.main()
    
