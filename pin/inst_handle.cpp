#include <stdio.h>
#include "pin.H"
#include "inst_handle.h"
#include "shadow_map.h"

VOID RecordMemRead(VOID * ip, VOID * addr, UINT32 size)
{
	int shadowed;
//	int size = 4;
	unsigned char *c;
	unsigned long addr_val = (unsigned long) addr;

	if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {

		heap_count.read += size;
		shadowed = checkShadowMap(addr_val, size);
		heap_success.read += shadowed;
		heap_fail.read += size - shadowed;
//		printf("r g %p h %p %p s %p %p a %p s %d\n", global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
		if (size > shadowed) {
		//	printShadowMap(addr_val, size);
		}
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else {
		other_count.read += size;
	}
}

VOID RecordMemWrite(VOID * ip, VOID * addr, UINT32 size)
{
	int shadowed;
//	int size = 4;
	unsigned long addr_val = (unsigned long) addr;

//	printf("g %p %p h %p %p s %p %p a %p\n", global_range.lower_addr, global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr);
	if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.write += size;
		shadowed = checkShadowMap(addr_val, size);
		heap_success.write += shadowed;
		heap_fail.write += size - shadowed;
//		printf("w g %p h %p %p s %p %p a %p s %d\n", global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
		/*
		heap_suc += shadowed;
		heap_fail += size - shadowed;
		*/
		if (size > shadowed) {
//				printf("	malloc %p\n", (void *)addr_val);
//				printf("	shadowed %d %d\n", shadowed, size - shadowed);
		}
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else {
		other_count.write += size;
	}
//	printf("%p: W %p\n", ip, addr);
}

VOID load_store_inst(INS ins, VOID *v)
{
	UINT32 memOperands = INS_MemoryOperandCount(ins);

	for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
		if (INS_MemoryOperandIsRead(ins, memOp)) {
			INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
				IARG_UINT32, INS_MemoryReadSize(ins),
                IARG_END);
		}

		if (INS_MemoryOperandIsWritten(ins, memOp)) {
			INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
				IARG_UINT32, INS_MemoryWriteSize(ins),
                IARG_END);
		}
	}
}

