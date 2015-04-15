

#ifndef _PQUE_HDR
#define _PQUE_HDR

#include <Python.h>
#include <pcap.h>

typedef struct _Py3_PcapQueue
{
	PyObject_HEAD
	struct pcap_send_queue *pQue;
} Py3_PcapQueue;

extern PyTypeObject Py3_PcapQueueType;
#define PyIs_PcapQueueType(a)	(&Py3_PcapQueueType == (Py_TYPE(a))

#endif
