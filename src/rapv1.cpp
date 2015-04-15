


#pragma warning(disable:4995)

#include "rapv1.h"
#include "rapv1ex.h"
#include "ipohmac.h"


//~classes
#include "py3ifman.h"
#include "py3pcapif.h"
#include "py3pque.h"

#include <windows.h>
#include <iphlpapi.h>
#include <comdef.h>
#include <string.h>
#include <strsafe.h>

PyObject *RapV1Func(CompilingDate)(PyObject*self)
{
	char buf[1024] = {0};
	if( sprintf_s(buf,sizeof(buf),"Compiled on %s:%s",__TIME__,__DATE__) < 0 )
	{
		Py_INCREF(Py_None);
		return Py_None;
	}
	return PyUnicode_FromString(buf);
}

//METH_NOARGS
static
PyObject* RapV1Func(ListAd)(PyObject*)
{
	pcap_if_t *alldevs = NULL;
	char errbuf[PCAP_ERRBUF_SIZE]={0};
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		char buf[1024];
		sprintf_s(buf,sizeof(buf),"Error in pcap_findalldevs: %s", errbuf);
		PyErr_SetString(RapperExc,buf);
		return NULL;
	}

	int i = 0;	
	/* Print the list */
	for(pcap_if_t *d=alldevs; d; d=d->next)
	{
		char buf[1024];
		sprintf_s(buf,"%d. %s\n", ++i, d->name);
		PySys_WriteStdout(buf);
		if (d->description)
		{
			sprintf_s(buf," (%s)\n",d->description);
			PySys_WriteStdout(buf);
		}
		else
		{
			PySys_WriteStdout(" (No description available)\n");
		}
	}
	
	if (!i)
	{
		PyErr_SetString(RapperExc,"No interfaces found! Make sure WinPcap is installed.\n");
		return NULL;	/*raise*/
	}

	pcap_freealldevs(alldevs);
	
	Py_INCREF(Py_None);
	return Py_None;
}

static
PyObject* RapV1Func(Mac802p3List)(PyObject*self)
{
	DWORD sz = 0;
	GetIpNetTable(0,&sz,FALSE);
	MIB_IPNETTABLE *pTable = (MIB_IPNETTABLE*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sz);
	RtlZeroMemory(pTable,sz);
	GetIpNetTable(pTable,&sz,TRUE);
	PyObject *els = PyTuple_New(pTable->dwNumEntries);
	for(int i=0;i<(int)pTable->dwNumEntries;++i)
	{
		u_int64 mac6 = makeUni(pTable->table[i].bPhysAddr,pTable->table[i].dwPhysAddrLen);
		const MIB_IPNETROW &tabItem = pTable->table[i];
		PyObject *newIpRow = PyUnicode_FromFormat(
			"%s:%s:%s:%x",
			printf802p3Addr(mac6),
			printfIpv4Addr(tabItem.dwAddr),
			(4 == tabItem.dwType ? "static" :
			 3 ==tabItem.dwType ? "dynamic":
			 2 == tabItem.dwType ? "invalid":
			 1 == tabItem.dwType ? "other" : "unrecognized"),
			 tabItem.dwIndex);
		PyTuple_SetItem(els,i,newIpRow);
	}
	HeapFree(GetProcessHeap(),HEAP_NO_SERIALIZE,pTable);
	return els;
}

//METH_NOARGS
static
PyObject* RapV1Func(AdList)(PyObject*self)
{
	pcap_if_t *alldevs = NULL;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	if( pcap_findalldevs(&alldevs,errbuf) == -1 )
	{
		char buf[1024];
		sprintf_s(buf,sizeof(buf),"Error in pcap_findalldevs: %s",errbuf);
		PyErr_SetString(RapperExc,buf);
		return NULL;
	}
	int i=0;	/*counter*/
	for(pcap_if_t*d=alldevs;d;d=d->next,++i);
	if( !i )
	{
		Py_INCREF(Py_None);
		return Py_None;
	}
	const int tot = i;
	PyObject *ad_list = PyTuple_New(tot);
	
	i = 0;
	for(pcap_if_t*d=alldevs;d;d=d->next,++i)
	{		
		char buf[1024];
		sprintf_s(buf,"%s",d->name);
		PyTuple_SetItem(ad_list,i,PyUnicode_FromString(buf));
	}
	
	pcap_freealldevs(alldevs);
	return ad_list;
}

static
PyObject* RapV1Func(BaseLib)(PyObject*self)
{
	const char *str = pcap_lib_version();
	if(str)
		return PyUnicode_FromString(str);
	Py_INCREF(Py_None);
	return Py_None;
}


PyObject *RapperExc = NULL;

static PyMethodDef Rapv1Methods[] = 
{
	{"Compiled",(PyCFunction)RapV1Func(CompilingDate),METH_NOARGS,"Version of compiling datetime."},
	{"BaseLib",(PyCFunction)RapV1Func(BaseLib),METH_NOARGS,"WinPcap information."},
	
    	{"ListAd",(PyCFunction)RapV1Func(ListAd),METH_NOARGS,"Demo show for network adapters installed"},
	{"AdList",(PyCFunction)RapV1Func(AdList),METH_NOARGS,"Get adapter list."},
	
	{"MacList",(PyCFunction)RapV1Func(Mac802p3List),METH_NOARGS,"Get 802.3 mac table"},
	{"SendArp",RapV1FuncEx(SendArp),METH_VARARGS,"Retrieve mac for some ip."},

	{NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef rapv1module = {
	PyModuleDef_HEAD_INIT,
	"Rapv1",
	NULL,
	-1,
	Rapv1Methods
};

PyMODINIT_FUNC PyInit_RapLanV1(void)
{
	if( PyType_Ready(&Py3_PcapIfType) < 0 )
	{
		PyErr_SetString(PyExc_RuntimeError,"PcapIfType not ready !");
		return NULL;
	}

	if( PyType_Ready(&Py3_IfManType) < 0 )
	{
		PyErr_SetString(PyExc_RuntimeError,"IfManType not ready!");
		return NULL;
	}

	if( PyType_Ready(&Py3_PcapQueueType) < 0 )
	{
		PyErr_SetString(PyExc_RuntimeError,"PcapQueueType not ready!");
		return NULL;
	}

	if( PyObject *m = PyModule_Create(&rapv1module) )
	{
		RapperExc = PyErr_NewException("Rapv1.Excetpion",NULL,NULL);
		Py_INCREF(RapperExc);
		PyModule_AddObject(m,"RapError",RapperExc);  
			/*Appear as the module global name, checked by dir(r1lan)*/

		Py_INCREF(&Py3_PcapIfType);
		PyModule_AddObject(m,"PcapIf",(PyObject*)&Py3_PcapIfType);

		Py_INCREF(&Py3_IfManType);
		PyModule_AddObject(m,"IfMan",(PyObject*)&Py3_IfManType);

		Py_INCREF(&Py3_PcapQueueType);
		PyModule_AddObject(m,"PcapQueue",(PyObject*)&Py3_PcapQueueType);
			
		return m;
	}
	PyErr_SetString(PyExc_RuntimeError,"Init for Rapv1Mod failed. God");
	return NULL;
}



