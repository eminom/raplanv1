

#ifndef _IPOHMAC_DEF
#define _IPOHMAC_DEF

#include <windows.h>

#define _EXPORT_IPOHMAC_CLASS 0
const char* printfIpv4Addr(u_int ip);
const char* printf802p3Addr(u_int64 mac);

u_int64 makeUni(const u_char* bAddr,int sz);
const u_int64 allZero64=0;
const u_int64 allOnes64= 0xFFFFFFFF | (((u_int64)(0xFFFF)) << 32);

#if _EXPORT_IPOHMAC_CLASS

#include <iphlpapi.h>
#include <map>
#include <boost/scoped_ptr.hpp>

typedef std::map<u_int64,MIB_IPNETROW> u64vmib;
u64vmib retrieveMap802p3ToIpv4();
struct Map802p3ToIpv4Private;
class Map802p3ToIpv4
{
public:
    Map802p3ToIpv4();
	~Map802p3ToIpv4();
	void refresh();
    bool toIpv4(u_int64 mac,u_int &addr);

private:
	boost::scoped_ptr<Map802p3ToIpv4Private> d;
};
#endif

#endif
