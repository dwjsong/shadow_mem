#include <stdio.h>
#include "pin.H"
#include "inst_handle.h"
#include "shadow_map.h"

VOID RecordMemRead(VOID * ip, VOID * addr)
{
	int shadowed;
	int size = 4;
	unsigned long addr_val = (unsigned long) addr;

	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		if (!doingMalloc) {
			heap_count.read += size;
			shadowed = checkShadowMap(addr_val, size);
			heap_success.read += shadowed;
			heap_fail.read += size - shadowed;
			/*
			heap_suc += shadowed;
			heap_fail += size - shadowed;
			*/
			if (size > shadowed) {
//				printf("	malloc %p\n", (void *)addr_val);
//				printf("	shadowed %d %d\n", shadowed, size - shadowed);
			}
		}
	}
	else if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.read += size;
	}
	else {
		other_count.read += size;
	}
//	printf("%p: R %p\n", ip, addr);
}

VOID RecordMemWrite(VOID * ip, VOID * addr)
{
	int shadowed;
	int size = 4;
	unsigned long addr_val = (unsigned long) addr;

	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		if (!doingMalloc) {
			heap_count.write += size;
			shadowed = checkShadowMap(addr_val, size);
			heap_success.write += shadowed;
			heap_fail.write += size - shadowed;
			/*
			heap_suc += shadowed;
			heap_fail += size - shadowed;
			*/
			if (size > shadowed) {
//				printf("	malloc %p\n", (void *)addr_val);
//				printf("	shadowed %d %d\n", shadowed, size - shadowed);
			}
		}
	}
	else if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.write += size;
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
                IARG_END);
		}

		if (INS_MemoryOperandIsWritten(ins, memOp)) {
			INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
		}
	}
}

