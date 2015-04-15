
#ifndef _RAPV1CLASS_DEF
#define _RAPV1CLASS_DEF

#include "python.h"
#include "pcap.h"

typedef struct {
	PyObject_HEAD
	/* Type-specific fields go here. */
	pcap_t *f_pcap_if;
	PyObject *name;
		
	PyObject *description;
	PyObject *loopback;	
	PyObject *addresses;
	
	PyObject *physical_addr;
	PyObject *adIndex;
	PyObject *adapterDesc;
	PyObject *friendly_name;
}Py3_PcapIf;

#define RapV1Ex2Func(a)	__RapV1Ex2Func_##a
typedef PyObject* Py3_PcapIf::* Ex2RefMem;

extern PyTypeObject Py3_PcapIfType;
#define PyIs_PcapIfType(a)		(&Py3_PcapIfType == Py_TYPE(a))

#endif
