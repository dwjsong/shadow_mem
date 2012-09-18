#include <stdio.h>
#include "pin.H"
#include "inst_handle.h"
#include "shadow_map.h"
#include "syscall_handle.h"

#define BUFSZ 8192
#define MODUL 8191

BUFFER_ID bufid;

void *addr_buff[BUFSZ];
int pos;

VOID RecordMemRead1(VOID * ip, ADDRINT addr, UINT32 size)
{
	addr_buff[pos] = (void *)addr;
	pos++;
	pos = pos & MODUL;
//	printf(" pos : %d\n", pos);
//	printf("r g %p %p h %p %p s %p %p a %p s %d\n", global_range.lower_addr, global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
}

VOID RecordMemWrite1(VOID * ip, ADDRINT  addr, UINT32 size)
{
	addr_buff[pos] = (void *)addr;
	pos++;
	pos = pos & MODUL;
//	printf(" pos : %d\n",pos);
}

VOID RecordMemRead2(VOID * ip, ADDRINT addr, UINT32 size)
{
	int shadowed;
	int t;
//	int size = 4;
	unsigned long addr_val = (unsigned long) addr;
	unsigned char *shadow_addr;
	char wh;
	int ct = 0;
	int count = 0;

	addr_buff[pos] = (void *)addr;
	pos++;
	pos = pos & MODUL;
	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.read += size;
//		count = checkShadowMap(addr, size);
		heap_success.read += count;
		heap_fail.read += size - count;
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else {
		other_count.read += size;
	}
}

VOID RecordMemWrite2(VOID * ip, ADDRINT  addr, UINT32 size)
{
	int shadowed;
	int t;
//	int size = 4;
	unsigned long addr_val = (unsigned long) addr;
	unsigned char *shadow_addr;
	char wh;
	int count = 0;
	int ct = 0;

//	printf("w g %p %p h %p %p s %p %p a %p s %d\n", global_range.lower_addr, global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
	addr_buff[pos] = (void *)addr;
	pos++;
	pos = pos & MODUL;
	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.write += size;
//		count = checkShadowMap(addr, size);
		heap_success.write += count;
		heap_fail.write += size - count;
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else {
		other_count.write += size;
	}
}

VOID RecordMemRead3(VOID * ip, ADDRINT addr, UINT32 size)
{
	int shadowed;
	int t;
//	int size = 4;
	unsigned long addr_val = (unsigned long) addr;
	unsigned char *shadow_addr;
	char wh;
	int ct = 0;
	int count = 0;

	addr_buff[pos] = (void *)addr;
	pos++;
	pos = pos & MODUL;
	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.read += size;
		count = checkShadowMap(addr, size);
		heap_success.read += count;
		heap_fail.read += size - count;
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else {
		other_count.read += size;
	}
}

VOID RecordMemWrite3(VOID * ip, ADDRINT  addr, UINT32 size)
{
	int shadowed;
	int t;
	unsigned long addr_val = (unsigned long) addr;
	unsigned char *shadow_addr;
	char wh;
	int ct = 0;
	int count = 0;

//	printf("w g %p %p h %p %p s %p %p a %p s %d\n", global_range.lower_addr, global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
	addr_buff[pos] = (void *)addr;
	pos++;
	pos = pos & MODUL;
	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.write += size;
		count = checkShadowMap(addr, size);
		heap_success.write += count;
		heap_fail.write += size - count;
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else {
		other_count.write += size;
	}
}

VOID RecordMemRead4(VOID * ip, ADDRINT addr, UINT32 size)
{
	int shadowed;
	int t;
//	int size = 4;
	unsigned long addr_val = (unsigned long) addr;
	unsigned char *shadow_addr;
	char wh;
	int ct = 0;
	int count = 0;

//	printf("r g %p %p h %p %p s %p %p a %p s %d\n", global_range.lower_addr, global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
	addr_buff[pos] = (void *)addr;
	pos++;
	pos = pos & MODUL;
	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.read += size;
		count = checkShadowMap(addr, size);
		heap_success.read += count;
		heap_fail.read += size - count;
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else {
		other_count.read += size;
	}
}

VOID RecordMemWrite4(VOID * ip, ADDRINT  addr, UINT32 size)
{
	int shadowed;
	int t;
//	int size = 4;
	unsigned long addr_val = (unsigned long) addr;
	unsigned char *shadow_addr;
	char wh;
	int ct = 0;
	int count = 0;

//	printf("w g %p %p h %p %p s %p %p a %p s %d\n", global_range.lower_addr, global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
	addr_buff[pos] = (void *)addr;
	pos++;
	pos = pos & MODUL;
	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.write += size;
		count = checkShadowMap(addr, size);
		heap_success.write += count;
		heap_fail.write += size - count;
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else {
		other_count.write += size;
	}
}

VOID* BufferFull(BUFFER_ID id, THREADID tid, const CONTEXT *ctxt, VOID *buf, UINT64 numElts, VOID *v)
{
	struct memref* ref = (struct memref*)buf;

	for (UINT32 i = 0; i < numElts; i++, ref++) {
//		printf("	full %p\n", ref->addr);
		if (ref->write) 
			RecordMemWrite1(ref->ip, ref->addr, ref->size);
		else
			RecordMemRead1(ref->ip, ref->addr, ref->size);
	}

	VOID * newbuf = PIN_AllocateBuffer(id);
	PIN_DeallocateBuffer(id, buf);

	return newbuf;
}

VOID load_store_inst(INS ins, VOID *v)
{
	UINT32 memOperands = INS_MemoryOperandCount(ins);

	for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
		if (INS_MemoryOperandIsRead(ins, memOp)) {

			INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead3,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
				IARG_UINT32, INS_MemoryReadSize(ins),
                IARG_END);
/*
			INS_InsertFillBufferPredicated(ins, IPOINT_BEFORE, bufid,
				IARG_INST_PTR, offsetof(struct memref, ip),
                IARG_MEMORYOP_EA, memOp, offsetof(struct memref, addr),
				IARG_UINT32, INS_MemoryReadSize(ins), offsetof(struct memref, size),
				IARG_UINT32, 0, offsetof(struct memref, write),
                IARG_END);
				*/

		}
		
		if (INS_MemoryOperandIsWritten(ins, memOp)) {
			INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite3,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
				IARG_UINT32, INS_MemoryWriteSize(ins),
                IARG_END);

/*
			INS_InsertFillBufferPredicated(ins, IPOINT_BEFORE, bufid,
				IARG_INST_PTR, offsetof(struct memref, ip),
                IARG_MEMORYOP_EA, memOp, offsetof(struct memref, addr),
				IARG_UINT32, INS_MemoryWriteSize(ins), offsetof(struct memref, size),
				IARG_UINT32, 1, offsetof(struct memref, write),
                IARG_END);
				*/
		}
	}
}

