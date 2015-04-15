

#ifndef _RAPV1_HDR
#define _RAPV1_HDR

#include "python.h"
#include "pcap.h"

#define RapV1Func(func)		_Rapv1p##func

extern PyObject *RapperExc;;

#define _ME_DEBUG 1

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif


#endif
