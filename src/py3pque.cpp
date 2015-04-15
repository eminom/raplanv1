
#pragma warning(disable:4995)

#include "rapv1.h"
#include <Python.h>
#include <StructMember.h>		//~ From python includes
#include "py3pque.h"
#include "py3pcapif.h"
#include "dproc.h"
#include "netstru.h"

static void
PcapQueue_dealloc(Py3_PcapQueue* self)
{
	if(self->pQue )
	{
		pcap_sendqueue_destroy(self->pQue);
		self->pQue = 0;
	}
	Py_TYPE(self)->tp_free((PyObject*)self);
}


//~new: no parameters at all. Jesus
static PyObject*
PcapQueue_new(PyTypeObject *_type, PyObject*, PyObject*)
{
	Py3_PcapQueue *self = (Py3_PcapQueue *)_type->tp_alloc(_type, 0);
	if (self != NULL)
	{
		self->pQue = 0;
	}
	return (PyObject*)self;
}

static int
PcapQueue_init(Py3_PcapQueue *self, PyObject *args, PyObject *kwds)
{
	int qsz = 16*1024;	//~ 16k buffer
	static char *kwlist[] = {"Size", NULL};
	
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist, &qsz))
		return -1;/*indicator of failure*/

	self->pQue = pcap_sendqueue_alloc(qsz);
	if( !self->pQue )
	{
		PyErr_SetString(RapperExc,"Cannot allocate pcap queue.");
		return -1;
	}
	return 0;	/*indicator of success*/
}

static PyMemberDef PcapQueue_members[] = {
    {NULL}  /* Sentinel */
};

static PyObject*
PcapQueue_MaxLength(Py3_PcapQueue*self,void*)
{
	if(!self->pQue)
	{
		PyErr_SetString(RapperExc,"No pcap queue.");
		return NULL;
	}
	return PyLong_FromLong(self->pQue->maxlen);
}

static PyObject*
PcapQueue_Length(Py3_PcapQueue*self,void*)
{
	if(!self->pQue)
	{
		PyErr_SetString(RapperExc,"No pcap queue.");
		return NULL;
	}
	return PyLong_FromLong(self->pQue->len);
}
	
static 
PyGetSetDef PcapQueue_GetterSetter[] = {
    {"MaxLength",   (getter)PcapQueue_MaxLength, (setter)0,
		"Totoal length of this queue buffer.",  NULL},
	{"Length",(getter)PcapQueue_Length,(setter)0,
		"Lengtg of buffer taken.",NULL},
    {NULL}  /* Sentinel */
};

static PyObject*
PcapQueue_QueuePacket(Py3_PcapQueue*self,PyObject*args)
{
	PyObject *ob = NULL;
	if( !PyArg_ParseTuple(args,"O",&ob))
		return NULL;
	
	if( !PyBytes_CheckExact(ob))
		return NULL;

	if(!self->pQue)
	{
		PyErr_SetString(RapperExc,"No queue opened.");
		return NULL;
	}

	const char *const pBuf = PyBytes_AsString(ob);
	if(!pBuf)
		return NULL;
	size_t length = PyBytes_Size(ob);

	if( !length )
	{
		PyErr_SetString(RapperExc,"Empty buffer to queue? Mallicious.");
		return NULL;
	}

	char *const theBuffer = (char*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,length);
	__try
	{
		RtlCopyMemory(theBuffer,pBuf,length);
		//Just like the one in RapLanV1.PcapIf.Send
		if( length >= sizeof(MacHead) && 0x0008 == ((MacHead*)theBuffer)->_type 
			&& length - sizeof(MacHead) >= sizeof(IpHead) )
		{
			//PySys_WriteStdout("about to process ip packet before queuing.\r\n");
			if( !ProcessIpPacket(theBuffer,length))
				return NULL;	/*raise some exception which is set in ProcessIpPacket()*/
		}

		struct pcap_pkthdr pkt_header = {0};
		pkt_header.caplen = pkt_header.len = length;
		int res = pcap_sendqueue_queue(self->pQue,&pkt_header,(u_char*)theBuffer);
		return PyBool_FromLong( 0==res);
	}
	__finally
	{
		if(theBuffer)
			HeapFree(GetProcessHeap(),0,theBuffer);
	}
	return NULL;
}

static PyObject*
PcapQueue_Transmit(Py3_PcapQueue*self,PyObject*args)
{
	PyObject* ob = NULL;
	int sync = 0;
	if(! PyArg_ParseTuple(args,"O|i",&ob,&sync) )
		return NULL;
	if( !PyIs_PcapIfType(ob) )
	{
		PyErr_SetString(PyExc_TypeError,"Expect to be a PcapIf object.");
		return NULL;
	}

	Py3_PcapIf *fp = reinterpret_cast<Py3_PcapIf*>(ob);

	if(! fp->f_pcap_if )
	{
		PyErr_SetString(RapperExc,"No pcap interface opened.");
		return NULL;
	}

	int res = pcap_sendqueue_transmit(fp->f_pcap_if,self->pQue,sync);
	if( res <0 || (u_int)res < self->pQue->len )
	{
		PyErr_SetString(RapperExc,"Queue transmite error.");
		return NULL;
	}

	return PyLong_FromLong(res);
}

static 
PyMethodDef PcapQueue_methods[] = 
{
	{"Enque", (PyCFunction)PcapQueue_QueuePacket, METH_VARARGS,"Shove the data in." },
	{"Transmit",(PyCFunction)PcapQueue_Transmit,METH_VARARGS,"Shove it to wires."},
	{NULL}  /* Sentinel */
};

PyTypeObject Py3_PcapQueueType = 
{
    PyVarObject_HEAD_INIT(NULL, 0)
    "RapLanV1.PcapQueue",/* tp_name */
    sizeof(Py3_PcapQueue),  /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)PcapQueue_dealloc, /* tp_dealloc */
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
    "PcapQueue objects",           /* tp_doc */
    0,		               /* tp_traverse */
    0,		               /* tp_clear */
    0,		               /* tp_richcompare */
    0,		               /* tp_weaklistoffset */
    0,		               /* tp_iter */
    0,		               /* tp_iternext */
   PcapQueue_methods,             /* tp_methods */
    PcapQueue_members,             /* tp_members */
    PcapQueue_GetterSetter,           /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)PcapQueue_init, /* tp_init */
    0,                         /* tp_alloc */
    PcapQueue_new,                 /* tp_new */
};



