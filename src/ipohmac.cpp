

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#define _DEBUG_IPOHMAC	0


#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <strsafe.h>
#include "ipohmac.h"

#pragma comment(lib,"iphlpapi")

// Compose an mac address to one single long long integer. which can be indexing later
u_int64 makeUni(const u_char* bAddr,int sz)
{
    u_int64 rv = 0;
    for(int i=0;i<sz;++i)
        rv |= (1LL*((bAddr[i])&0xFF)) << (8*i) ;
    return rv;
}

const char* printf802p3Addr(u_int64 mac)
{
	const int ___pmac_ad30fgw = 20;
    static char buf[___pmac_ad30fgw][0x200];
	static int index = 0;
	index = (1+index) % ___pmac_ad30fgw;
    sprintf_s(buf[index],sizeof(buf[0])-1,"%02X-%02X-%02X-%02X-%02X-%02X",
        (unsigned int)(mac&0xff),
        (unsigned int)((mac>>8)&0xff),
        (unsigned int)((mac>>16)&0xff),
        (unsigned int)((mac>>24)&0xff),
        (unsigned int)((mac>>32)&0xff),
        (unsigned int)((mac>>40)&0xff));
    return buf[index];
}

const char* printfIpv4Addr(u_int ip)
{
	const int ___ip_ad3ofwi3 = 20;
    static char buf[___ip_ad3ofwi3][0x100];
	static int index = 0;
	index = (1+index)%___ip_ad3ofwi3;
    sprintf_s(buf[index],sizeof(buf[0]),"%d.%d.%d.%d",ip&0xff,(ip>>8)&0xff,(ip>>16)&0xff,ip>>24);
    return buf[index];
}           


#if _EXPORT_IPOHMAC_CLASS

void printfEntry(const MIB_IPNETROW &entry)
{
    static const char*typeOf[]={    "other","invalid","dynamic","static"};
    if( 6 == entry.dwPhysAddrLen )
    {
        printf("%s\t%s\t%s\n",
            printfIpv4Addr(entry.dwAddr),
            printf802p3Addr(makeUni(entry.bPhysAddr,entry.dwPhysAddrLen)),
            typeOf[entry.dwType-1]);
    }
    else
    {
        printf("Unrecognized address length.\n");
    }
}

// The mapping from Mac Address to IPv4 address
u64vmib retrieveMap802p3ToIpv4()
{
    u64vmib m;
    DWORD sz = 0;
    GetIpNetTable(0,&sz,FALSE);
    MIB_IPNETTABLE *pTable = (MIB_IPNETTABLE*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sz);
    RtlZeroMemory(pTable,sz);
    GetIpNetTable(pTable,&sz,TRUE);
    for(int i=0;i<pTable->dwNumEntries;++i)
	{
        //m[makeUni(pTable->table[i].bPhysAddr,pTable->table[i].dwPhysAddrLen)] = pTable->table[i].dwAddr;
		// Full Copy(July3rd.2o1o)
		u_int64 item = makeUni(pTable->table[i].bPhysAddr,pTable->table[i].dwPhysAddrLen);
		if( m.find(item)!=m.end() )
		{
			fprintf(stderr,"Fatal error: for misunderstanding the uniue of MAC\n");
		}
		m[item] = pTable->table[i];
	}
    HeapFree(GetProcessHeap(),HEAP_NO_SERIALIZE,pTable);

#if _DEBUG_IPOHMAC

    printf("********************\n");
	for(u64vmib::const_iterator pos=m.begin();pos!=m.end();++pos)
        printf("%s\t%s\n",printf802p3Addr(pos->first),printfIpv4Addr(pos->second.dwAddr));
        
    system("pause");

#endif

    return m;
}

struct Map802p3ToIpv4Private
{
	u64vmib m;
};

Map802p3ToIpv4::~Map802p3ToIpv4()
{
}

Map802p3ToIpv4::Map802p3ToIpv4()
	:d(new Map802p3ToIpv4Private)
{
	d->m = retrieveMap802p3ToIpv4();
}

bool Map802p3ToIpv4::toIpv4(u_int64 mac,u_int &addr)
{
	addr = 0;
	if( allOnes64 == mac || 	allZero64 == mac )
		return true;

	u64vmib::const_iterator pos = d->m.find(mac);
	if( d->m.end() == pos )
	{
		// Reload the ARP table
		d->m = retrieveMap802p3ToIpv4();
		pos = d->m.find(mac);
		if( d->m.end() == pos )
			return false;
	}
	addr = pos->second.dwAddr;
	return true;
}
   
void Map802p3ToIpv4::refresh()
{
	d->m = retrieveMap802p3ToIpv4();
}

#endif