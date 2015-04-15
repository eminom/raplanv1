
/////////////////////////////
///////July.20.2o1o////////
////////////////////////////


///:run test: test_ifman.py


#pragma warning(disable:4995)

#include "rapv1.h"
#include <Python.h>
#include <StructMember.h>		//~ From python includes

#include <windows.h>
#include <comdef.h>
#include <iphlpapi.h>
#include <strsafe.h>
#include "py3ifman.h"

static void
IfMan_dealloc(Py3_IfMan* self)
{
	//
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
IfMan_new(PyTypeObject *_type, PyObject *args, PyObject *kwds)
{
	Py3_IfMan *self = (Py3_IfMan *)_type->tp_alloc(_type, 0);
	return (PyObject*)self;
}

static int
IfMan_init(Py3_IfMan *self, PyObject *args, PyObject *kwds)
{
	//~ No parameter for this contructor
	return 0;
}

static PyMemberDef IfMan_members[] = {
    {NULL}  /* Sentinel */
};


/////////////////////////////////////////////////////////////////////////////
///////////////// getters' function for Py3_IfMan definitions/////////
////////////////////////////////////////////////////////////////////////////

//~ the number of interfaces of current host. including the loopback interface.
static PyObject*
IfCounts(PyObject*, void *)
{
	DWORD ifCounts = 0;
	if( NO_ERROR != GetNumberOfInterfaces(&ifCounts) )
	{
		PyErr_SetString(RapperExc,"IP helper error.");
		return NULL;
	}
	return PyLong_FromLong(ifCounts);
}

//~ the interfaces for current host excluding the loopback interface
static PyObject*
ObtainInterfaces(PyObject*,void*)
{
	PIP_INTERFACE_INFO pInfo = NULL;
	__try
	{
		ULONG ulOutBufLen = 0;
		DWORD dwRetVal = GetInterfaceInfo(NULL, &ulOutBufLen);
		if  (ERROR_INSUFFICIENT_BUFFER == dwRetVal) 
		{
			pInfo = (IP_INTERFACE_INFO *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,ulOutBufLen);
			if (!pInfo)
			{
				PyErr_SetString(RapperExc,"Cannot allocate memory for interface information storage.");
				return NULL;
			}
		}

		dwRetVal = GetInterfaceInfo(pInfo, &ulOutBufLen);
		if (NO_ERROR == dwRetVal )
		{
			PyObject *ifs = PyTuple_New(pInfo->NumAdapters);
			for(int i=0;i<pInfo->NumAdapters;++i)
			{
				PyObject *item = PyTuple_New(2);
				PyTuple_SetItem(item,0,PyLong_FromLong(pInfo->Adapter[i].Index));
				PyTuple_SetItem(item,1,PyUnicode_FromWideChar(pInfo->Adapter[i].Name,wcslen(pInfo->Adapter[i].Name)));
				PyTuple_SetItem(ifs,i,item);
			}
			return ifs;
		} 
		else if (ERROR_NO_DATA==dwRetVal) 
		{
			PyErr_SetString(RapperExc,"No interfaecs associated with IPv4.");
			return NULL;
		} 
	}
	__finally
	{
		if( pInfo )
			HeapFree(GetProcessHeap(),0,pInfo);	//~Flags equal Zero
		//PySys_WriteStdout("Jesus. Free the interface infor\n");
	}
	PyErr_SetString(RapperExc,"IP helper error.");
	return NULL;
}


static PyObject*
ObtainIfTable(PyObject*,void*)
{
	MIB_IFTABLE *pIfTable = NULL;
	pIfTable = (MIB_IFTABLE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof (MIB_IFTABLE));
	if (!pIfTable) 
	{
		PyErr_SetString(RapperExc,"Error allocating memory needed to call GetIfTable().");
		return NULL;
	}
		
	DWORD dwSize = sizeof (MIB_IFTABLE);
	if (ERROR_INSUFFICIENT_BUFFER == GetIfTable(pIfTable, &dwSize, FALSE) ) 
	{
		HeapFree(GetProcessHeap(),0,pIfTable);
		pIfTable = (MIB_IFTABLE *) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSize);
		if(!pIfTable)
		{
			PyErr_SetString(RapperExc,"Error allocating memory needed to call GetIfTable().");
			return NULL;
		}
	}

	DWORD dwRetVal = 0;
	if ((dwRetVal = GetIfTable(pIfTable, &dwSize, FALSE)) == NO_ERROR) 
	{
		PyObject *coll = PyTuple_New( pIfTable->dwNumEntries);
		for (unsigned int i = 0; i < pIfTable->dwNumEntries; ++i)
		{
			MIB_IFROW *pIfRow = (MIB_IFROW *) & pIfTable->table[i];
			PyObject *dc = PyDict_New();
			PyTuple_SetItem(coll,i,dc);	//~ 
			
			PyDict_SetItemString(dc,"Index",
				PyLong_FromLong(pIfRow->dwIndex));
			PyDict_SetItemString(dc,"InterfaceName",
				PyUnicode_FromWideChar(pIfRow->wszName,wcslen(pIfRow->wszName)));


			_bstr_t mbcsStr((char*)pIfRow->bDescr);
			PyDict_SetItemString(dc,"Description",
				PyUnicode_FromWideChar(mbcsStr.operator wchar_t*(),mbcsStr.length()));

			char typeBuffer[1024]={0};
			const char *theType = "UnknownType";
			switch (pIfRow->dwType) 
			{
			case IF_TYPE_OTHER:
				theType = "Other";
				break;
			case IF_TYPE_ETHERNET_CSMACD:
				theType = ("Ethernet");
				break;
			case IF_TYPE_ISO88025_TOKENRING:
				theType = ("Token Ring");
				break;
			case IF_TYPE_PPP:
				theType = ("PPP");
				break;
			case IF_TYPE_SOFTWARE_LOOPBACK:
				theType = ("Software Lookback");
				break;
			case IF_TYPE_ATM:
				theType = ("ATM");
				break;
			case IF_TYPE_IEEE80211:
				theType = ("IEEE 802.11 Wireless");
				break;
			case IF_TYPE_TUNNEL:
				theType = ("Tunnel type encapsulation");
				break;
			case IF_TYPE_IEEE1394:
				theType = ("IEEE 1394 Firewire");
				break;
			default:
				sprintf_s(typeBuffer,sizeof(typeBuffer),"%d",pIfRow->dwType);
				theType = typeBuffer;
				break;
			}
			PyDict_SetItemString(dc,"Type",  PyUnicode_FromString(theType));
			PyDict_SetItemString(dc,"Mtu",   PyLong_FromLong(pIfRow->dwMtu));
			PyDict_SetItemString(dc,"Speed",	PyLong_FromLong(pIfRow->dwSpeed));

			char mac[128] = {0};
			for (unsigned int j = 0; j < pIfRow->dwPhysAddrLen; ++j)
			{
				char part[32];
				if (j == (pIfRow->dwPhysAddrLen - 1))
					sprintf_s(part,sizeof part,"%.2X", (int) pIfRow->bPhysAddr[j]);
				else
					sprintf_s(part,sizeof part,"%.2X-", (int) pIfRow->bPhysAddr[j]);
				strcat_s(mac,sizeof mac,part);
			}
			PyDict_SetItemString(dc,"Physical Addr",PyUnicode_FromString(mac));
			PyDict_SetItemString(dc,"Admin Status",PyLong_FromLong(pIfRow->dwAdminStatus));
			
			char operStatusBuffer[1024]={0};
			const char *theOperStatus = "Oper Status unspecified";
			switch (pIfRow->dwOperStatus) 
			{
			case IF_OPER_STATUS_NON_OPERATIONAL:
				theOperStatus = ("Non Operational");
				break;
			case IF_OPER_STATUS_UNREACHABLE:
				theOperStatus = ("Unreasonable");
				break;
			case IF_OPER_STATUS_DISCONNECTED:
				theOperStatus = ("Disconnected");
				break;
			case IF_OPER_STATUS_CONNECTING:
				theOperStatus = ("Connecting");
				break;
			case IF_OPER_STATUS_CONNECTED:
				theOperStatus = ("Connected");
				break;
			case IF_OPER_STATUS_OPERATIONAL:
				theOperStatus = ("Operational");
				break;
			default:
				sprintf_s(operStatusBuffer,sizeof operStatusBuffer,
					"Unknown status %ld", pIfRow->dwAdminStatus);
				theOperStatus = operStatusBuffer;
				break;
			}
			PyDict_SetItemString(dc,"Oper Status",PyUnicode_FromString(theOperStatus));
		}
		return coll;
	} 
	
	if (pIfTable != NULL) 
	{
		HeapFree(GetProcessHeap(),0,pIfTable);
		pIfTable = NULL;
	}
	PyErr_SetString(RapperExc,"Failed");
	return NULL;
}


static PyObject* 
HostBasicInfo(PyObject*,void *)
{
	//:reference: July.4th.2o1o
	//:ms-help://MS.VSCC.v90/MS.MSDNQTR.v90.en/iphlp/iphlp/retrieving_information_using_getnetworkparams.htm
	
	ULONG ulOutBufLen = sizeof( FIXED_INFO );
	FIXED_INFO *pFixedInfo = (FIXED_INFO *)HeapAlloc(GetProcessHeap(),
		HEAP_ZERO_MEMORY,ulOutBufLen);
	
	// to elicit the length
	if ( GetNetworkParams( pFixedInfo, &ulOutBufLen ) == ERROR_BUFFER_OVERFLOW )
	{
		HeapFree(GetProcessHeap(),0,pFixedInfo);
		pFixedInfo = (FIXED_INFO*)HeapAlloc(GetProcessHeap(),
			HEAP_ZERO_MEMORY,ulOutBufLen);
	}

	//
	DWORD dwRetVal = NO_ERROR;
	if ( (dwRetVal = GetNetworkParams( pFixedInfo, &ulOutBufLen )) != NO_ERROR)
	{
		char buf[1024];
		sprintf_s(buf,sizeof(buf),"GetNetworkParams call failed with %d", dwRetVal);
		PyErr_SetString(RapperExc,buf);
		HeapFree(GetProcessHeap(),0,pFixedInfo);
		return NULL;
	}

	PyObject *pBasic  = PyDict_New();
	PyDict_SetItemString(pBasic,"HostName",
		PyUnicode_FromString(pFixedInfo->HostName));
	
	PyDict_SetItemString(pBasic,"DomainName",
		PyUnicode_FromString(pFixedInfo->DomainName));
	
	int count = 1;	/*at least one for me.*/
	IP_ADDR_STRING *pIpAddr = pFixedInfo->DnsServerList.Next;
	while(pIpAddr)
	{
		++count;
		pIpAddr = pIpAddr->Next;
	}

	PyObject *dnsIpList = PyTuple_New(count);
	int i=0;
	PyTuple_SetItem(dnsIpList,i++,PyUnicode_FromString(pFixedInfo-> DnsServerList.IpAddress.String));
	pIpAddr = pFixedInfo->DnsServerList.Next;
	while(pIpAddr)
	{
		PyTuple_SetItem(dnsIpList,i++,PyUnicode_FromString(pIpAddr -> IpAddress.String));
		pIpAddr = pIpAddr->Next;
	}
	
	PyDict_SetItemString(pBasic,"DnsList",dnsIpList);
	HeapFree(GetProcessHeap(),0,pFixedInfo);
	return pBasic;
}

static PyObject*
GetIpStatistics(PyObject*,void*)
{
	MIB_IPSTATS ipstat;
	RtlZeroMemory(&ipstat,sizeof(ipstat));
#if !defined(_TR_SET)
#define _TR_SET(AA)\
	PyDict_SetItemString(_dc,#AA,PyLong_FromLong(ipstat.AA));

	if( NO_ERROR ==GetIpStatistics(&ipstat) )
	{
		PyObject *_dc = PyDict_New();
		_TR_SET(dwForwarding)
		_TR_SET(dwDefaultTTL)
		_TR_SET(dwInReceives)
		_TR_SET(dwInHdrErrors)
		_TR_SET(dwInAddrErrors)
		_TR_SET(dwForwDatagrams)
		_TR_SET(dwInUnknownProtos)
		_TR_SET(dwInDiscards)
		_TR_SET(dwInDelivers)
		_TR_SET(dwOutRequests)
		_TR_SET(dwRoutingDiscards)
		_TR_SET(dwOutDiscards)
		_TR_SET(dwOutNoRoutes)
		_TR_SET(dwReasmTimeout)
		_TR_SET(dwReasmReqds)
		_TR_SET(dwReasmOks)
		_TR_SET(dwReasmFails)
		_TR_SET(dwFragOks)
		_TR_SET(dwFragFails)
		_TR_SET(dwFragCreates)
		_TR_SET(dwNumIf)
		_TR_SET(dwNumAddr)
		_TR_SET(dwNumRoutes)
		return _dc;
	}
	else
	{
		PyErr_SetString(RapperExc,"GetIpStatistics() fails");
		return NULL;
	}
#undef _TR_SET
#endif
	
	Py_INCREF(Py_None);
	return Py_None;
}	

static PyObject* 
GetIPsForCurrentHost(PyObject*,void*)
{
	DWORD dwSize = sizeof(MIB_IPADDRTABLE);
	PMIB_IPADDRTABLE pIPAddrTable = (MIB_IPADDRTABLE*)GlobalAlloc( GPTR,dwSize);
	if ( pIPAddrTable ) 
	{
		if (GetIpAddrTable(pIPAddrTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) 
		{
			GlobalFree( pIPAddrTable );
			pIPAddrTable = (MIB_IPADDRTABLE *) GlobalAlloc ( GPTR,dwSize );
		}
	}
	
	if ( pIPAddrTable ) 
	{
		if ( GetIpAddrTable( pIPAddrTable, &dwSize, 0) == NO_ERROR ) 
		{ 
			PyObject *items = PyTuple_New(pIPAddrTable->dwNumEntries);
			char buf[1024];
			for(unsigned int i=0;i<pIPAddrTable->dwNumEntries;++i)
			{
				PyObject *one = PyDict_New();
				sprintf_s(buf,sizeof(buf),"%s",inet_ntoa(*(in_addr*)&pIPAddrTable->table[i].dwAddr));
				PyDict_SetItemString(one,"Address",PyUnicode_FromString(buf));
				sprintf_s(buf,sizeof(buf),"%s",inet_ntoa(*(in_addr*)&pIPAddrTable->table[i].dwMask));
				PyDict_SetItemString(one,"Mask",PyUnicode_FromString(buf));
				PyDict_SetItemString(one,"Index",
						PyLong_FromLong(pIPAddrTable->table[i].dwIndex));
				sprintf_s(buf,sizeof(buf),"%s",inet_ntoa(*(in_addr*)&pIPAddrTable->table[i].dwBCastAddr));
				PyDict_SetItemString(one,"BCast",PyUnicode_FromString(buf));
				sprintf_s(buf,sizeof(buf),"%ld", pIPAddrTable->table[i].dwReasmSize);
				PyDict_SetItemString(one,"Reasm",PyUnicode_FromString(buf));


				char typeString[1024]={0};
				const unsigned short wType = pIPAddrTable->table[i].wType;
				if( (wType&MIB_IPADDR_PRIMARY) )
					strcat_s(typeString,sizeof(typeString),":Primary");
				if( (wType&MIB_IPADDR_DYNAMIC) )
					strcat_s(typeString,sizeof(typeString),":Dynamic");
				if( (wType&MIB_IPADDR_DISCONNECTED) )
					strcat_s(typeString,sizeof(typeString), ":Disconnected");
				if( (wType&MIB_IPADDR_DELETED) )
					strcat_s(typeString,sizeof(typeString),":Deleted");
				if( (wType&MIB_IPADDR_TRANSIENT) )
					strcat_s(typeString,sizeof(typeString),":Transient");
				
				PyDict_SetItemString(one,"wType",
					PyUnicode_FromString(typeString));
				PyTuple_SetItem(items,i,one);
			}
			return items;
		}
		GlobalFree( pIPAddrTable );
	}
	Py_INCREF(Py_None);
	return Py_None;
}

/*
static PyObject*
CreateDummy(PyObject*,void*)
{
	PyObject* ob = PyDict_New();
	if( PyDict_SetItemString(ob,"1",PyUnicode_FromString("haha")) < 0 )
		return NULL;
	if( PyDict_SetItemString(ob,"1",PyLong_FromLong(123123)) < 0 )
		return NULL;
	return ob;
}*/

	
static 
PyGetSetDef IfMan_GetterSetter[] = {
	{"IfCounts",IfCounts, (setter)0,
		"GetNumberOfInterfaces():IPv4 interface counts, including loopback interface.",  NULL},
		
	{"IfInfos",ObtainInterfaces,(setter)0,
    		"GetInterfaceInfo():IPv4 Interfaces, excluding loopback interface.",NULL},
    		
    	{"IfTable",ObtainIfTable,(setter)0,
    		"GetIfTable():The GetIfTable function retrieves the MIB-II interface table.",NULL},
    		
	{"HostBasicInfo",HostBasicInfo,(setter)0,
		"Get basic information about this host.",NULL},
		
	{"IpStatistics",GetIpStatistics,(setter)0,	"Get IP statistics.",NULL},
	
	{"IpTable",GetIPsForCurrentHost,(setter)0,"IPs for this host.",NULL},
	
    	//{"Dummy",(getter)CreateDummy,(setter)0,"Dummy",NULL},
    {NULL}  /* Sentinel */
};

static 
PyMethodDef IfMan_methods[] = {
    {NULL}  /* Sentinel */
};

PyTypeObject Py3_IfManType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "RapLanV1.InterfaceManager",/* tp_name */
    sizeof(Py3_IfMan),  /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)IfMan_dealloc, /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "InterfaceManager objects",           /* tp_doc */
    0,		               /* tp_traverse */
    0,		               /* tp_clear */
    0,		               /* tp_richcompare */
    0,		               /* tp_weaklistoffset */
    0,		               /* tp_iter */
    0,		               /* tp_iternext */
    IfMan_methods,             /* tp_methods */
    IfMan_members,             /* tp_members */
    IfMan_GetterSetter,           /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)IfMan_init, /* tp_init */
    0,                         /* tp_alloc */
    IfMan_new,                 /* tp_new */
};




