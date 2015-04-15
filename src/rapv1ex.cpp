

//////////////////////////
//July.5th.2o1o
//////////////////////////


/////////////////////////////////////////
//Run test: test_ext1.py
/////////////////////////////////////////


#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <string>
#include <python.h>
#include <pcap.h>
#include "rapv1.h"
#include "rapv1ex.h"


PyObject* RapV1FuncEx(SendArp)(PyObject*self,PyObject*args)
{
	const char *destIpString = NULL;
	if( !PyArg_ParseTuple(args,"s",&destIpString))
		return NULL;

	IPAddr DestIp = inet_addr(destIpString);
	if( INADDR_NONE == DestIp )
	{
		PyObject *rv =  PyTuple_New(3);
		PyTuple_SetItem(rv,0,PyBool_FromLong(0));
		Py_INCREF(Py_None);
		PyTuple_SetItem(rv,1,Py_None);
		PyTuple_SetItem(rv,2,PyUnicode_FromString("Invalid IP address"));
		return rv;
	}
	
	char MacAddr[12];
	RtlZeroMemory(MacAddr,sizeof(MacAddr));
	ULONG PhysAddrLen = 6;	/*the default*/
	DWORD dwRetVal = SendARP(DestIp, 0, &MacAddr, &PhysAddrLen);

	if (dwRetVal == NO_ERROR) 
	{
		BYTE *bPhysAddr = (BYTE *)&MacAddr;
		std::string phyaddr;
		for (int i = 0; i < (int) PhysAddrLen; i++) 
		{
			char parts[16];
			if (i == (PhysAddrLen - 1))
				sprintf_s(parts,sizeof(parts),"%.2X", (int)bPhysAddr[i]);
			else
				sprintf_s(parts,sizeof(parts),"%.2X-",(int) bPhysAddr[i]);
			phyaddr += parts;
		} 
		if( !PhysAddrLen)
			phyaddr = "Zero-Length-Physical-Address";
		PyObject *rv = PyTuple_New(3);
		PyTuple_SetItem(rv,0,PyBool_FromLong(1));
		PyTuple_SetItem(rv,1,PyUnicode_FromString(destIpString));
		PyTuple_SetItem(rv,2,PyUnicode_FromString(phyaddr.c_str()));
		return rv;
	} 
	else 
	{
		char errPrompt[1024];
		switch (dwRetVal) 
		{
		case ERROR_GEN_FAILURE:
			strcpy_s(errPrompt,sizeof(errPrompt),"ERROR_GEN_FAILURE");
			break;
		case ERROR_INVALID_PARAMETER:
			strcpy_s(errPrompt,sizeof(errPrompt),"ERROR_INVALID_PARAMETER");
			break;
		case ERROR_INVALID_USER_BUFFER:
			strcpy_s(errPrompt,sizeof(errPrompt),"ERROR_INVALID_USER_BUFFER");
			break;
		case ERROR_BAD_NET_NAME:
			strcpy_s(errPrompt,sizeof(errPrompt),"ERROR_BAD_NET_NAME");
			break;
		case ERROR_BUFFER_OVERFLOW:
			strcpy_s(errPrompt,sizeof(errPrompt),"ERROR_BUFFER_OVERFLOW");
			break;
		case ERROR_NOT_FOUND:
			strcpy_s(errPrompt,sizeof(errPrompt),"ERROR_NOT_FOUND");
			break;
		default:
			strcpy_s(errPrompt,sizeof(errPrompt),"Unknown Error");
			break;
		}
		PyObject *rv = PyTuple_New(3);
		PyTuple_SetItem(rv,0,PyBool_FromLong(0));
		PyTuple_SetItem(rv,1,PyLong_FromLong(dwRetVal));
		PyTuple_SetItem(rv,2,PyUnicode_FromString(errPrompt));
		return rv;
	}
	Py_INCREF(Py_None);
	return Py_None;
}


