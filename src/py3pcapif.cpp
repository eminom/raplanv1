
#pragma warning(disable:4995)

#include "rapv1.h"
#include <structmember.h>

#include "py3pcapif.h"

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <comdef.h>
#include <string.h>
#include <strsafe.h>
#include <stddef.h>
#include <assert.h>

#include "netstru.h"
#include "dproc.h"

#include <string>
#include <sstream>

#define ADDRESS_FAMILY_NAME_STRITEM	"AddressFamilyName"
#define ADDRESS_STRITEM	"Address"


bool RapV1Ex2Func(RetrieveXpAddrs)(const char*dev_name,
	Py3_PcapIf *const self,
	Ex2RefMem mac,  
	Ex2RefMem index,  
	Ex2RefMem desc,
	Ex2RefMem friendly)
{
	const char *rbr = strrchr(dev_name,'{');
	if ( ! rbr || !mac || !index || !desc || ! friendly )
		return false;
	const std::string dname(rbr);

	/*
	PySys_WriteStderr("FFdfef;wemfwlemfwmem23#*@$&$#*$&(#@$&(#@$&(#@$&#@\r\n");
	PySys_WriteStderr(dname.c_str());
	PySys_WriteStderr("\r\nFFdfef;wemfwlemfwmem23#*@$&$#*$&(#@$&(#@$&(#@$&#@\r\n");
	*/
	
	
	PIP_ADAPTER_ADDRESSES AdapterAddresses = NULL;
	ULONG OutBufferLength = 0;
	ULONG RetVal = 0;
	for (int i = 0; i < 5; i++) 
	{	//Explanation in MSDN.2oo8
		//ms-help://MS.VSCC.v90/MS.MSDNQTR.v90.en/iphlp/iphlp/getadaptersaddresses.htm
		RetVal = GetAdaptersAddresses(AF_INET, 0,NULL,AdapterAddresses, &OutBufferLength);
		if (RetVal != ERROR_BUFFER_OVERFLOW) 
			break;

		if (AdapterAddresses != NULL)
			HeapFree(GetProcessHeap(),0,AdapterAddresses);

		AdapterAddresses = (PIP_ADAPTER_ADDRESSES) HeapAlloc(GetProcessHeap(),0,OutBufferLength);
		if (NULL == AdapterAddresses) 
		{
			RetVal = GetLastError();
			break;
		}
	}

	bool found = false;
	if (NO_ERROR == RetVal)
	{
		// If successful, output some information from the data we received
		PIP_ADAPTER_ADDRESSES AdapterList = AdapterAddresses;
		while (AdapterList) 
		{
			if( !_stricmp(dname.c_str(),AdapterList->AdapterName) )
			{
				Py_XDECREF(self->*mac);
				Py_XDECREF(self->*index);
				Py_XDECREF(self->*desc);
				Py_XDECREF(self->*friendly);
				
				// for mac
				std::ostringstream out;
				for(unsigned int i = 0;i<AdapterList->PhysicalAddressLength;++i)
				{
					char parts[64];
					if( i == AdapterList->PhysicalAddressLength-1 )
						sprintf_s(parts,sizeof(parts),"%.2X",AdapterList->PhysicalAddress[i]);
					else
						sprintf_s(parts,sizeof(parts),"%.2X-",AdapterList->PhysicalAddress[i]);
					out<<parts;
				}
				self->*mac = PyUnicode_FromString( out.str().c_str() );
				
				// for index
				self->*index = PyLong_FromLong( AdapterList->IfIndex);
				
				// for description
				_bstr_t wsd(AdapterList->Description);
				self->*desc = PyUnicode_FromWideChar(wsd.operator wchar_t*(),wsd.length());
				if (NULL == self->*desc)
				{
					PySys_WriteStderr("desc null: error\r\n");
					Py_INCREF(Py_None);
					self->*desc = Py_None;
				}
				
				// for friendly
				_bstr_t one(AdapterList->FriendlyName);
				self->*friendly = PyUnicode_FromWideChar(one.operator wchar_t*(),one.length());
				if(NULL == self->*friendly )
				{
					PySys_WriteStderr("friendly null: error.\r\n");
					Py_INCREF(Py_None);
					self->*friendly = Py_None;
				}
				
				found = true;
				break;
			}
			AdapterList = AdapterList->Next;
		}
	}
	else 
	{ 
		LPVOID MsgBuf = NULL;
		if (FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | 	FORMAT_MESSAGE_FROM_SYSTEM | 
			FORMAT_MESSAGE_IGNORE_INSERTS,NULL,
			RetVal,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
			(LPTSTR) &MsgBuf,	0,	NULL )) 
		{
			char buf[2048];
			sprintf_s(buf,sizeof(buf),"Error: %s", MsgBuf);
			PyErr_SetString(RapperExc,buf);
		}
		LocalFree(MsgBuf);
	}  
	if (AdapterAddresses != NULL) 
		HeapFree(GetProcessHeap(),0,AdapterAddresses);
	return found;
}


static
void RapV1Func(Dealloc)(Py3_PcapIf* self)
{
	Py_XDECREF(self->name);
	
	Py_XDECREF(self->description);
	Py_XDECREF(self->loopback);
	Py_XDECREF(self->addresses);
	Py_XDECREF(self->physical_addr);
	Py_XDECREF(self->adIndex);
	Py_XDECREF(self->adapterDesc);
	Py_XDECREF(self->friendly_name);
	
	if( self->f_pcap_if)
	{
		pcap_close(self->f_pcap_if);
		self->f_pcap_if = 0;
	}
	
	Py_TYPE(self)->tp_free((PyObject*)self);
		/*Notice that Py_TYPE is different from Py_Type*/
}

static
PyObject*RapV1Func(New)(PyTypeObject *_type, PyObject *args, PyObject *kwds)
{
	//PySys_WriteStdout("Hello, in New\n");
	if( Py3_PcapIf *self = (Py3_PcapIf*)_type->tp_alloc(_type,0) )
	{
		self->name = PyUnicode_FromString("[unknown interface for pcap]");
		if(NULL == self->name)
		{
			Py_DECREF(self);
			PyErr_SetString(PyExc_RuntimeError,"Cannot allocate name for Py3_PcapIf");
			return NULL;
		}
		self->f_pcap_if = NULL;
		
		self->description = NULL;
		self->loopback = NULL;
		self->addresses = NULL;
		self->physical_addr = NULL;
		self->adIndex = NULL;
		self->adapterDesc = NULL;
		self->friendly_name = NULL;
		return (PyObject*)self;
	}
	PyErr_SetString(PyExc_RuntimeError,"Cannot allocate object for Py3_PcapIf");
	return NULL;	/*raise*/
}

//Interal 
/*
static
bool RapV1Func(Retrieve802p3OnDevice)(Py3_PcapIf*self,const char *device_name)
{
	const std::string dev(device_name);
	char buf[1024];    
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	PIP_ADAPTER_INFO pAdapterInfo = NULL;
	boost::scoped_ptr<char> _freeIt((char*)(pAdapterInfo = (PIP_ADAPTER_INFO)new char[ulOutBufLen]));

	if (GetAdaptersInfo( pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) 
	{
		_freeIt.reset((char*)(pAdapterInfo = (PIP_ADAPTER_INFO)new char[ulOutBufLen]));
		DWORD dwRetVal = 0;
		if ((dwRetVal = GetAdaptersInfo( pAdapterInfo, &ulOutBufLen)) == NO_ERROR) 
		{
			bool found = false;
			PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
			while (pAdapter) 
			{
				//PySys_WriteStdout(pAdapter->AdapterName);
				std::string name(pAdapter->AdapterName);
				
				//if(name.size()>=2 && '{' == *name.begin()  && '}' == *name.rbegin() )
				//	name = std::string(name.c_str(),1,name.size()-2);
				//{} are included in string name

				if( dev.find(name) != std::string::npos )
				{
					std::string mac;
					for (UINT i = 0; i < pAdapter->AddressLength; i++) 
					{
						char parts[64];
						if (i == (pAdapter->AddressLength - 1))
							sprintf_s(parts,sizeof(parts),"%.2X",(int)pAdapter->Address[i]);
						else
							sprintf_s(parts,sizeof(parts),"%.2X-",(int)pAdapter->Address[i]);
						mac+=parts;
					}
					//Update MAC
					Py_XDECREF(self->physical_addr);
					self->physical_addr = PyUnicode_FromString(mac.c_str());
					Py_XDECREF(self->adIndex);
					self->adIndex = PyLong_FromLong(pAdapter->Index);
					Py_XDECREF(self->adapterDesc);
					self->adapterDesc = PyUnicode_FromString(pAdapter-> Description);
					found = true;
					break;
				}
								
				//printf("\tIP Address: \t%s\n", pAdapter->IpAddressList.IpAddress.String);
				//printf("\tIP Mask: \t%s\n", pAdapter->IpAddressList.IpMask.String);
				//printf("\tGateway: \t%s\n", pAdapter->GatewayList.IpAddress.String);
				//printf("\t***\n");
				
				pAdapter = pAdapter->Next;
			}
			return found;
		}
		else 
		{
			sprintf_s(buf,sizeof(buf),"GetAdaptersInfo failed with error: %d", dwRetVal);
			PyErr_SetString(RapperExc,buf);
			return false;
		}
	}
	return false;
}
*/

//Internal
static
bool RapV1Func(RefreshOne)(Py3_PcapIf*self,const char*device_name)
{
	//Retrieve the information of this adapter. By walking throught is again;
	pcap_if_t *alldevs = NULL,*d = NULL;
	char errbuf[PCAP_ERRBUF_SIZE+1];
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		char buf[sizeof(errbuf)+1024];
		sprintf_s(buf,sizeof(buf),"Error in pcap_findalldevs: %s\n", errbuf);
		PyErr_SetString(RapperExc,buf);
		return false;
	}
	
	/* Scan the list:July.4th.2o1o*/
	// Update for self
	bool found = false;
	for(d=alldevs;d;d=d->next)
	{
		if( !_stricmp(d->name,device_name) )
		{
			found = true;
			char ip6str[1024];
			if( d->description )
			{
				//"%s"
				Py_XDECREF(self->description);
				self->description = PyUnicode_FromString(d->description);
			}
			
			Py_XDECREF(self->loopback);
			self->loopback = PyBool_FromLong((d->flags & PCAP_IF_LOOPBACK));

			int count = 0;
			for(pcap_addr_t *a=d->addresses;a;a=a->next)
				++count;
			PyObject *newAddrs = PyTuple_New(count);
			Py_XDECREF(self->addresses);
			self->addresses = newAddrs;
			
			/* IP addresses */
			int i=0;
			for(pcap_addr_t *a=d->addresses;a;a=a->next,++i) 
			{
				PyObject *entry  = PyDict_New();
				PyDict_SetItemString(entry,"AddressFamily",PyLong_FromLong(a->addr->sa_family));
				
				switch(a->addr->sa_family)
				{
				case AF_INET:
					PyDict_SetItemString(entry,ADDRESS_FAMILY_NAME_STRITEM
						,PyUnicode_FromString("AF_INET"));
					if(a->addr)
					{
						PyDict_SetItemString(entry,ADDRESS_STRITEM,
							PyUnicode_FromString(inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr)));
					}
					if (a->netmask)
					{
						PyDict_SetItemString(entry,"Netmask",
							PyUnicode_FromString(inet_ntoa(((struct sockaddr_in *)a->netmask)->sin_addr)));
					}
					if (a->broadaddr)
					{
						PyDict_SetItemString(entry,"BroadcastAddress",
							PyUnicode_FromString(inet_ntoa(((struct sockaddr_in *)a->broadaddr)->sin_addr)));
					}
					
					if (a->dstaddr)
					{
						PyDict_SetItemString(entry,"DestinationAddress",
							PyUnicode_FromString(inet_ntoa(((struct sockaddr_in *)a->dstaddr)->sin_addr)));
					}
					break;

				case AF_INET6:
					PyDict_SetItemString(entry,ADDRESS_FAMILY_NAME_STRITEM,
						PyUnicode_FromString("AF_INET6"));
					
					#ifndef __MINGW32__ 
						/* Cygnus doesn't have IPv6 */
					if (a->addr)
					{
						PyDict_SetItemString(entry,ADDRESS_STRITEM,
							PyUnicode_FromString(ip6tos(a->addr, ip6str, sizeof(ip6str))));
					}
					#endif
					break;
				default:
					PyDict_SetItemString(entry,"AddressFamily",	PyUnicode_FromString("Unknown"));
					break;
				}
				PyTuple_SetItem(newAddrs,i,entry);
			}
			break;
		}//end of name check
	}
	/* Free the device list */
	pcap_freealldevs(alldevs);
	return found;
}

static
int RapV1Func(Init)(Py3_PcapIf *self, PyObject *args, PyObject *kwds)
{
	//PySys_WriteStdout("Hello, in Init\n");
	PyObject *name = NULL;
	
	//July.15th.2o1o. :>>
	//:User can customize the capture length now.
	//: and the timeout
	int capLength = 65536;	
	int timeout = 1000;

	static char *kwlist[] = {"Name", "Caplen","Timeout",NULL};
	if ( !PyArg_ParseTupleAndKeywords(args, kwds, "U|ii", kwlist, &name,&capLength,&timeout))
	{
		//PyErr_SetString(PyExc_TypeError,"Error for PcapIf constructor.");
		//PySys_WriteStderr("God, here we go again.\n");
		// If the parsing goes wrong, 
		// Python Layer will set the TypeError which contains the exact information.
		// No need to set exception ourselves.
		return  -1; 
	}

	/*	
	if(1)
	{
		char buf[1024];
		sprintf_s(buf,sizeof buf,"CapLength = %d, Timeout = %d\r\n",capLength,timeout);
		PySys_WriteStderr(buf);
	}*/

	if( name )
	{
		PyObject *tmp = self->name;
		Py_INCREF(name);
		self->name = name;
		Py_XDECREF(tmp);
	}

	PyObject *latin1 = PyUnicode_AsLatin1String(name);
	const char *const dev_name = PyBytes_AsString(latin1);
	char errbuf[PCAP_ERRBUF_SIZE+1] = {0};
	
	if( !RapV1Func(RefreshOne)(self,dev_name))
		PySys_WriteStderr("Cannot find information about this adapter.\r\n");
	/*
	if(!RapV1Func(Retrieve802p3OnDevice)(self,dev_name))
		PySys_WriteStderr("Cannot find physical address for this adapter.\r\n");
		*/
	if( ! RapV1Ex2Func(RetrieveXpAddrs)(dev_name,self,
		&Py3_PcapIf::physical_addr,&Py3_PcapIf::adIndex,&Py3_PcapIf::adapterDesc,&Py3_PcapIf::friendly_name))
		PySys_WriteStderr("Cannot locate mac info and so on for this adapter.\r\n");
		
	pcap_t *fp = fp= pcap_open(dev_name,capLength,
		PCAP_OPENFLAG_PROMISCUOUS,timeout,NULL,errbuf);	
	Py_DECREF(latin1);	//destroy tmp;
	if(fp)
	{
		self->f_pcap_if = fp;
	}
	else
	{
		char buf[1024];
		sprintf_s(buf,sizeof(buf),"Cannot open interface of %s",name);
		PyErr_SetString(RapperExc,buf);
		return -1;
	}
	return 0;	/*Success of ctor!*/
}


static PyMemberDef Py3_PcapIfMembers[] = {
	/*	
    {"first", T_OBJECT_EX, offsetof(Noddy, first), 0,
     "first name"},
    {"last", T_OBJECT_EX, offsetof(Noddy, last), 0,
     "last name"},
    {"number", T_INT, offsetof(Noddy, number), 0,
     "noddy number"},
	{"name",T_OBJECT_EX,offsetof(Py3_PcapIf,name),0,"name for interface"},
	*/
    {NULL,NULL,NULL,NULL}  /* Sentinel */
};


static
PyObject* RapV1Func(Send)(Py3_PcapIf *self,PyObject*args)
{
	if( ! self->f_pcap_if )
	{
		PyErr_SetString(RapperExc,"no interface available.");
		return NULL;
	}

	const char *pOrg = NULL;
	int length = 0;
	if( !PyArg_ParseTuple(args,"y#",&pOrg,&length) )
		return NULL;

	char *buffer = (char*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,length);
	__try
	{
		memcpy(buffer,pOrg,length);
		
		/*
		#if _ME_DEBUG
		PrintSizeOfMyStruct();
		#endif
		*/

		//~ 8 for IP proto
		if( length >= sizeof(MacHead) && 0x0008 == ((MacHead*)buffer)->_type 
			&& length - sizeof(MacHead) >= sizeof(IpHead) )
		{
			if( !ProcessIpPacket(buffer,length))
				return NULL;	/*raise some exception which is set in ProcessIpPacket()*/
		}
		else
		{	/*Process some proto else here:TODO*/
		
		}

		if (pcap_sendpacket(self->f_pcap_if, (const u_char*)buffer, length) != 0)
		{
			PyErr_SetString(RapperExc,"sendpacket failed.");
			return NULL;
		}
	}
	__finally
	{
		if(buffer)
			HeapFree(GetProcessHeap(),0,buffer);
	}
	return PyLong_FromLong(length);
}

static 
PyObject* 
RapV1Func(Str)(Py3_PcapIf *self)
{
	return PyUnicode_FromFormat("%U",self->name);
}


//July.13th.2o1o: Process some captures.^_^
static
PyObject*
RapV1Func(ProcessPcap)(Py3_PcapIf *self,PyObject*args)
{
	//~ Experimental:
	pcap_t *adhandle = self->f_pcap_if;
	if(!adhandle)
	{
		PyErr_SetString(RapperExc,"No adatper handle opened.");
		return NULL;
	}
	
	int timeCount = 0;
	PyObject* pCallback = NULL;
	if( !PyArg_ParseTuple(args,"iO",&timeCount,&pCallback)) 
		return NULL;
	if( !PyCallable_Check(pCallback) )
	{
		PyErr_SetString(PyExc_TypeError,"The second parameter must be callable.");
		return NULL;
	}

	//Waiting to be filled
	struct pcap_pkthdr *pk_header = NULL;
	const u_char *pkt_data= NULL;
	long readCount = 0;
	bool breakNow = false;
	for(int i=0;(timeCount<=0 || i<timeCount) && !breakNow;++i)
	{
		int res = pcap_next_ex(adhandle,&pk_header,&pkt_data);
		if (res < 0 )
		{
			char pcapErr[1024]={0};
			sprintf_s(pcapErr,sizeof(pcapErr),"Error reading captures:%s",pcap_geterr(adhandle));
			PyErr_SetString(RapperExc,pcapErr);
			return NULL;
		}

		int theLength = 0;
		const char *din = "";
		char packInfoStr[1024]={0};/*This may be empty*/
		
		if(res>0)
		{
			++readCount;		
			theLength = pk_header->caplen;
			din = (char*)pkt_data;
			
			//:See interpreting a packet in WinPcap's help.
			char timeStr[32];
			struct tm ltime;
			time_t local_tv_sec = pk_header->ts.tv_sec;
			localtime_s(&ltime,&local_tv_sec);
			strftime(timeStr,sizeof timeStr,"%H:%M:%S",&ltime);
			sprintf_s(packInfoStr,sizeof(packInfoStr),"%s,%.6d len:%6d,caplen:%6d",timeStr,
					pk_header->ts.tv_usec,
					pk_header->len,
					pk_header->caplen);
		}
		else
		{
			//~ no data coming. timeout
			sprintf_s(packInfoStr,sizeof(packInfoStr),"timeouted");
		}
		
		PyObject *bytesObj = PyBytes_FromStringAndSize(din,theLength);
		if (!bytesObj)
		{
			PyErr_SetString(RapperExc,"Not enough memory for PyBytes_FromStringAndSize().");
			return NULL;
		}
	
		PyObject *infoStr = PyUnicode_FromString(packInfoStr);
		if(!infoStr)
		{
			PyErr_SetString(RapperExc,"Not enough memory for information string.");
			return NULL;
		}
	
		PyObject *argList = Py_BuildValue("(OO)",bytesObj,infoStr);
		if(!argList)
		{
			PyErr_SetString(RapperExc,"Not enough memory for Py_BuildValue.");
			return NULL;
		}
		
		PyObject *ans = PyObject_CallObject(pCallback,argList);
		if( !ans )
		{
			//PyErr_SetString(RapperExc,"The callback give me null???");
			return NULL;
		}

		if( PyBool_Check(ans) && ans == Py_False )
			breakNow = true;
		
		Py_DECREF(argList);
		Py_DECREF(bytesObj);
		Py_DECREF(infoStr);
		Py_DECREF(ans);
	}
	return PyLong_FromLong(readCount);
}


//~July.22nd.2o1o@2205
static 
PyObject*
RapV1Func(IsSwapped)(Py3_PcapIf*self,void*closure)
{
	if(!self->f_pcap_if)
	{
		PyErr_SetString(RapperExc,"No pcap interface opened.");
		return NULL;
	}
	return PyBool_FromLong(pcap_is_swapped(self->f_pcap_if));
}

//~July.22nd.2o1o@2210
static 
PyObject*
RapV1Func(PcapVer)(Py3_PcapIf*self,void*closure)
{
	if(!self->f_pcap_if)
	{
		PyErr_SetString(RapperExc,"No pcap interface opened.");
		return NULL;
	}
	PyObject* ver = PyTuple_New(2);
	PyTuple_SetItem(ver,0,PyLong_FromLong(pcap_major_version(self->f_pcap_if))); 
	PyTuple_SetItem(ver,1,PyLong_FromLong(pcap_minor_version(self->f_pcap_if)));
	return ver;
}

//~July.22nd.2o1o@2213
//~ the Default for Winpcap is 1MB
static 
PyObject*
RapV1Func(SetBuffer)(Py3_PcapIf*self,PyObject*args)
{
	if(!self->f_pcap_if)
	{
		PyErr_SetString(RapperExc,"No pcap interface opened.");
		return NULL;
	}
	int bufsiz = 0;
	if(!PyArg_ParseTuple(args,"i",&bufsiz))
		return NULL;
	int res = pcap_setbuff(self->f_pcap_if,bufsiz);
	//~ 0 indicates success
	return PyBool_FromLong( 0 == res );
}


//July22nd.2o1o@2216
//~the default for Winpcap min-to-copy is 16000 bytes
static
PyObject*
RapV1Func(SetMinToCopy)(Py3_PcapIf*self,PyObject*args)
{
	if(!self->f_pcap_if)
	{
		PyErr_SetString(RapperExc,"No pcap interface opened.");
		return NULL;
	}
	int siz = 0;
	if(!PyArg_ParseTuple(args,"i",&siz))
		return NULL;
	int res = pcap_setmintocopy(self->f_pcap_if,siz);
	return PyLong_FromLong(res);		//~ if it works??
}


static
PyObject*
RapV1Func(SetFilter)(Py3_PcapIf*self,PyObject*args)
{
	const char *filter;
	u_int netmask = 0;
	if( !PyArg_ParseTuple(args,"sI",&filter,&netmask) )
		return NULL;

	if( !self->f_pcap_if )
	{
		PyErr_SetString(RapperExc,"No pcap interface opened.");
		return NULL;
	}

	/*
	if(1) {
		char buf[1024];
		sprintf_s(buf,sizeof buf,"netmask for filter is:%u\r\n",netmask);
		PySys_WriteStdout(buf);
	}
	*/
	
	struct bpf_program fcode={0};
	if (pcap_compile(self->f_pcap_if,&fcode,filter,1,netmask) < 0)
	{
		PyErr_SetString(RapperExc,"Unable to compile the packet filter. Check the syntax.");
		return NULL;
	}

	if ( pcap_setfilter(self->f_pcap_if,&fcode) < 0 )
	{
		PyErr_SetString(RapperExc,"Error setting the filter.");
		return NULL;
	}

	pcap_freecode(&fcode);	//Void for return value
	return PyBool_FromLong(1L);
}


//~
static 
PyObject* RapV1Func(Description)(Py3_PcapIf*self,void*closure)
{
	if( self->description)
	{
		Py_INCREF(self->description);
		return self->description;
	}
	
	Py_INCREF(Py_None);
	return Py_None;
}

//~
static
PyObject* RapV1Func(Loopback)(Py3_PcapIf*self,void*closure)
{
	if( self->loopback )
	{
		Py_INCREF(self->loopback);
		return self->loopback;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static
PyObject* RapV1Func(Addresses)(Py3_PcapIf*self,void*closure)
{
	if(self->addresses)
	{
		Py_INCREF(self->addresses);
		return self->addresses;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static
PyObject* RapV1Func(PhysicalAddress)(Py3_PcapIf*self,void*closure)
{
	if(self->physical_addr)
	{
		Py_INCREF(self->physical_addr);
		return self->physical_addr;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static
PyObject* RapV1Func(Index)(Py3_PcapIf*self,void*closure)
{
	if(self->adIndex)
	{
		Py_INCREF(self->adIndex);
		return self->adIndex;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static 
PyObject* RapV1Func(AdDesc)(Py3_PcapIf*self,void*closure)
{
	if(self->adapterDesc)
	{
		Py_INCREF(self->adapterDesc);
		return self->adapterDesc;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static
PyObject* RapV1Func(Friendly)(Py3_PcapIf*self,void*closure)
{
	if( self->friendly_name )
	{
		Py_INCREF(self->friendly_name);
		return self->friendly_name;
	}
	Py_INCREF(Py_None);
	return Py_None;
}


//July.15th.2o1o
static 
PyObject* RapV1Func(PcapSnapshot)(Py3_PcapIf*self,void*)
{
	if( !self->f_pcap_if )
	{
		PyErr_SetString(RapperExc,"No rpcap interface opened.");
		return NULL;
	}
	return PyLong_FromLong(pcap_snapshot(self->f_pcap_if));
}

//July.15th.2o1o.2nd
static
PyObject* RapV1Func(PcapStatEx)(Py3_PcapIf*self,void*)
{
	if( !self->f_pcap_if )
	{
		PyErr_SetString(RapperExc,"No rpcap interface opened.");
		return NULL;
	}
	int size = 0;
	struct pcap_stat* stat = pcap_stats_ex(self->f_pcap_if,&size);
	if(!stat)
	{
		PyErr_SetString(RapperExc,pcap_geterr(self->f_pcap_if));
		return NULL;
	}
	PyObject *res = PyDict_New();
	#define _SET_STATRES(fd)\
		PyDict_SetItemString(res,#fd,PyLong_FromLong(stat->fd));
	
	_SET_STATRES(ps_recv)
	_SET_STATRES(ps_drop)
	//_SET_STATRES(bs_capt)
	
	#undef _SET_STATRES
	return res;
}


//July.13th.2o1o
static
PyObject*
RapV1Func(DataLinkName)(Py3_PcapIf*self,void*closure)
{
	if(self->f_pcap_if)
	{
		const char *datalink_name = 
			pcap_datalink_val_to_description(
				pcap_datalink(self->f_pcap_if));
		//~ we should never pass NULL to PyUnicode_FromString.
		if(datalink_name)
		{
			return PyUnicode_FromString(datalink_name);
		}
	}
	
	Py_INCREF(Py_None);
	return Py_None;
}

static PyGetSetDef Rapv1ClassGetSetter[] = {
	{"Description",     (getter)RapV1Func(Description), (setter)0,     "Description for this interface",     NULL},
	{"Loopback",(getter)RapV1Func(Loopback),(setter)0,"Loopback or not",NULL},
	{"Addresses",(getter)RapV1Func(Addresses),(setter)0,"Addresses on this interface",NULL},
	{"PhysicalAddr",(getter)RapV1Func(PhysicalAddress),(setter)0,"Physical address for this interface",NULL},
	{"Index",(getter)RapV1Func(Index),(setter)0,"Index of this adapter",NULL},
	{"AdDesc",(getter)RapV1Func(AdDesc),(setter)0,"Adapter description for this interface",NULL},
	{"FriendlyName",(getter)RapV1Func(Friendly),(setter)0,"Friendly name for this interface.",NULL},
	{"DataLink",(getter)RapV1Func(DataLinkName),(setter)0,"Data link layer name.",NULL},//July.13th.2o1o
	{"Snapshot",(getter)RapV1Func(PcapSnapshot),(setter)0,"int pcap_snapshot(pcap_t  *p)",NULL},//July.15th.2o1o 
	{"Statistics",(getter)RapV1Func(PcapStatEx),(setter)0,"struct pcap_stat* pcap_stats_ex(pcap_t  *,int *)",NULL},//July.15th.2o1o
	{"IsSwapped",(getter)RapV1Func(IsSwapped),(setter)0,
		"returns true if the current savefile "
		"uses a different byte order than the current system. "},//~July.22nd.2o1o
	{"Ver",(getter)RapV1Func(PcapVer),(setter)0,"return (major,minor) for this WinPcap version."},
	{NULL}  /* Sentinel */
};

PyMethodDef Py3_PcapIfMethods[] = {
    {"Send",(PyCFunction)RapV1Func(Send), 
			METH_VARARGS,  "Return the name, combining the first and last name"    },
    	{"ProcessPcap",(PyCFunction)RapV1Func(ProcessPcap),
    			METH_VARARGS,"Process some captures for me."},
    	{"SetFilter",(PyCFunction)RapV1Func(SetFilter),
    			METH_VARARGS,"Set filter for winpcap core."},
    	{"SetBuff",(PyCFunction)RapV1Func(SetBuffer),
    			METH_VARARGS,"Set the size of the kernel buffer associated with an adapter. "},
    	{"SetMinToCopy",(PyCFunction)RapV1Func(SetMinToCopy),
    		METH_VARARGS,"Set the minumum amount of data received by the kernel in a single call."},
    {NULL}  /* Sentinel */
};

PyTypeObject Py3_PcapIfType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "Py3.PcapIf",             /* tp_name */
    sizeof(Py3_PcapIf),             /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)RapV1Func(Dealloc), /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,				   /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    (reprfunc)RapV1Func(Str), /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "Py3_PcapIf objects",           /* tp_doc */
    0,		               /* tp_traverse */
    0,		               /* tp_clear */
    0,		               /* tp_richcompare */
    0,		               /* tp_weaklistoffset */
    0,		               /* tp_iter */
    0,		               /* tp_iternext */
    Py3_PcapIfMethods,             /* tp_methods */
    Py3_PcapIfMembers,             /* tp_members */
    Rapv1ClassGetSetter,                /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)RapV1Func(Init), /* tp_init */
    0,                         /* tp_alloc */
    RapV1Func(New),                 /* tp_new */
};

