#ifndef __INST_HANDLE_H__
#define __INST_HANDLE_H__

#endif


#define BUFFER_SIZE 8192
struct memref {
	VOID *ip;
	ADDRINT addr;
	INT size;
	INT write;
};

extern BUFFER_ID bufid;

VOID* BufferFull(BUFFER_ID id, THREADID tid, const CONTEXT *ctxt, VOID *buf, UINT64 numElts, VOID *v);
VOID inst_check(INS ins, VOID* v);
VOID load_store_inst(INS ins, VOID *v);
