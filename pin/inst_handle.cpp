#include <stdio.h>
#include "pin.H"
#include "inst_handle.h"
#include "shadow_map.h"
#include "syscall_handle.h"

#define BUFSZ 8192
#define MODUL 8191

/*
#define PIN_FAST_ANALYSIS_CALL RecordMemRead1
#define PIN_FAST_ANALYSIS_CALL RecordMemWrite1

#define PIN_FAST_ANALYSIS_CALL RecordMemRead2
#define PIN_FAST_ANALYSIS_CALL RecordMemWrite2

#define PIN_FAST_ANALYSIS_CALL RecordMemRead3
#define PIN_FAST_ANALYSIS_CALL RecordMemWrite3

#define PIN_FAST_ANALYSIS_CALL RecordMemRead4
#define PIN_FAST_ANALYSIS_CALL RecordMemWrite4
*/

BUFFER_ID bufid;
struct mem_ref_t {
	bool write;
	void *addr;
	size_t size;
};

void *addr_buff[BUFSZ];
int pos;
struct mem_ref_t buff[BUFSZ];


void check()
{
	for (int i=0; i<BUFSZ; i++) {
		if (buff[pos].write) {
		}
		else {
		}
	}
}


VOID PIN_FAST_ANALYSIS_CALL RecordMemRead1(VOID * ip, ADDRINT addr, UINT32 size)
{
//	addr_buff[pos] = (void *)addr;
	buff[pos].addr = (void *)addr;
	buff[pos].write = false;
	buff[pos].size = size;
	pos++;
	pos = pos & MODUL;
//	printf(" pos : %d\n", pos);
//	printf("r g %p %p h %p %p s %p %p a %p s %d\n", global_range.lower_addr, global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
}

VOID PIN_FAST_ANALYSIS_CALL RecordMemWrite1(VOID * ip, ADDRINT  addr, UINT32 size)
{
	buff[pos].addr = (void *)addr;
	buff[pos].write = true;
	buff[pos].size = size;
	pos++;
	pos = pos & MODUL;
}

VOID PIN_FAST_ANALYSIS_CALL RecordMemRead2(VOID * ip, ADDRINT addr, UINT32 size)
{
//	int size = 4;
	unsigned long addr_val = (unsigned long) addr;

/*
	addr_buff[pos] = (void *)addr;
	pos++;
	pos = pos & MODUL;
	*/
	buff[pos].addr = (void *)addr;
	buff[pos].write = false;
	buff[pos].size = size;
	pos++;
	pos = pos & MODUL;
	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.read += size;
//		count = checkShadowMap(addr, size);
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else {
		other_count.read += size;
	}
}

VOID PIN_FAST_ANALYSIS_CALL RecordMemWrite2(VOID * ip, ADDRINT  addr, UINT32 size)
{
//	int size = 4;
	unsigned long addr_val = (unsigned long) addr;

//	printf("w g %p %p h %p %p s %p %p a %p s %d\n", global_range.lower_addr, global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
/*
	addr_buff[pos] = (void *)addr;
	pos++;
	pos = pos & MODUL;
	*/
	buff[pos].addr = (void *)addr;
	buff[pos].write = true;
	buff[pos].size = size;
	pos++;
	pos = pos & MODUL;
	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.write += size;
//		count = checkShadowMap(addr, size);
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else {
		other_count.write += size;
	}
}

VOID PIN_FAST_ANALYSIS_CALL RecordMemRead3(VOID * ip, ADDRINT addr, UINT32 size)
{
	char wh;
	unsigned long addr_val = (unsigned long) addr;
	unsigned char *shadow_addr;
	int count = 0;

/*`
	addr_buff[pos] = (void *)addr;
	pos++;
	pos = pos & MODUL;
	*/
	buff[pos].addr = (void *)addr;
	buff[pos].write = false;
	buff[pos].size = size;
	pos++;
	pos = pos & MODUL;
	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.read += size;
	//	count = checkShadowMap(addr, size);
		shadow_addr = (unsigned char *) (((addr) >> 3) + offset);
		for (unsigned int i = 0; i < size; i++) {
			//byte-location

			//bit-position
			wh = (addr + i) & 7;

			//checking for bit-value
			wh = (*shadow_addr >> wh) & 1;
			count += wh;
		}
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

VOID PIN_FAST_ANALYSIS_CALL RecordMemWrite3(VOID * ip, ADDRINT  addr, UINT32 size)
{
	unsigned long addr_val = (unsigned long) addr;
	unsigned char *shadow_addr;
	char wh;
	int count = 0;

//	printf("w g %p %p h %p %p s %p %p a %p s %d\n", global_range.lower_addr, global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
/*`
	addr_buff[pos] = (void *)addr;
	pos++;
	pos = pos & MODUL;
	*/
	buff[pos].addr = (void *)addr;
	buff[pos].write = true;
	buff[pos].size = size;
	pos++;
	pos = pos & MODUL;
	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.write += size;
//		count = checkShadowMap(addr, size);
		shadow_addr = (unsigned char *) (((addr) >> 3) + offset);
		for (unsigned int i = 0; i < size; i++) {
			//byte-location

			//bit-position
			wh = (addr + i) & 7;

			//checking for bit-value
			wh = (*shadow_addr >> wh) & 1;
			count += wh;
		}
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

VOID PIN_FAST_ANALYSIS_CALL RecordMemRead4(VOID * ip, ADDRINT addr, UINT32 size)
{
//	int size = 4;
	unsigned long addr_val = (unsigned long) addr;
	unsigned char *shadow_addr;
	int count = 0;

//	printf("r g %p %p h %p %p s %p %p a %p s %d\n", global_range.lower_addr, global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
/*
	addr_buff[pos] = (void *)addr;
	pos++;
	pos = pos & MODUL;
	*/
	buff[pos].addr = (void *)addr;
	buff[pos].write = false;
	buff[pos].size = size;
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

VOID PIN_FAST_ANALYSIS_CALL RecordMemWrite4(VOID * ip, ADDRINT  addr, UINT32 size)
{
//	int size = 4;
	unsigned long addr_val = (unsigned long) addr;
	int count = 0;

//	printf("w g %p %p h %p %p s %p %p a %p s %d\n", global_range.lower_addr, global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
/*
	addr_buff[pos] = (void *)addr;
	pos++;
	pos = pos & MODUL;
	*/
	buff[pos].addr = (void *)addr;
	buff[pos].write = true;
	buff[pos].size = size;
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
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead1, IARG_FAST_ANALYSIS_CALL,
//                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead2, IARG_FAST_ANALYSIS_CALL,
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
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite1, IARG_FAST_ANALYSIS_CALL,
//                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite2, IARG_FAST_ANALYSIS_CALL,
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

