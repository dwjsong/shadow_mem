#include <stdio.h>
#include "pin.H"
#include "inst_handle.h"
#include "shadow_map.h"

// load count
VOID DoLoad(REG reg, ADDRINT *addr, ADDRINT size)
{
	int shadowed;
	unsigned long addr_val = (unsigned long) addr;

	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read++;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.read++;
		shadowed = checkShadowMap(addr_val, size);
		heap_suc += shadowed;
		heap_fail += size - shadowed;
	}
	else if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.read++;
	}
	else {
		other_count.read++;
	}
}

// store count
VOID DoStore(REG reg, ADDRINT *addr, ADDRINT size)
{
	int shadowed;
	unsigned long addr_val = (unsigned long) addr;

	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write++;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.write++;
		shadowed = checkShadowMap(addr_val, size);
		heap_suc += shadowed;
		heap_fail += size - shadowed;
	}
	else if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.write++;
	}
	else {
		other_count.write++;
	}
}


// load & store count
VOID DoLoadStore(REG reg, ADDRINT *addr, ADDRINT size)
{
	int shadowed;
	unsigned long addr_val = (unsigned long) addr;

	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read++;
		stack_count.write++;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		printf("addr %p %d %d %d\n", addr, *addr, *(addr + 1), *(addr - 1));
		heap_count.read++;
		heap_count.write++;
		shadowed = checkShadowMap(addr_val, size);
		printf("load store %d %d\n", size, shadowed);
		printf("heap range %x %x\n", heap_range.lower, heap_range.upper);
	}
	else if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.read++;
		global_count.write++;
	}
	else {
		other_count.read++;
		other_count.write++;
	}
}

// if the instruction is load
VOID inst_check(INS ins, VOID* v)
{
	int size;
	REG src, dst, base, idx;
	xed_iclass_enum_t ins_idx = (xed_iclass_enum_t)INS_Opcode(ins);


	switch (ins_idx) {
	// Find the instructions that move a value from a register to memory
		case XED_ICLASS_ADC :
		/* add */
		case XED_ICLASS_ADD :
		/* and */
		case XED_ICLASS_AND :
		/* or */
		case XED_ICLASS_OR :
		/* xor */
		case XED_ICLASS_XOR :
		/* sbb */
		case XED_ICLASS_SBB :
		/* sub */
		case XED_ICLASS_SUB :
		case XED_ICLASS_DIV:
		case XED_ICLASS_IDIV:
		case XED_ICLASS_MUL:
		case XED_ICLASS_IMUL:
			/* 2nd operand is memory */
			if (INS_OperandIsMemory(ins, 1)) {
				dst = INS_OperandReg(ins, 0);
				if (REG_is_gr32(dst))
					size = 4;
				else if (REG_is_gr16(dst))
					size = 2;
				else if (REG_is_Upper8(dst))
					size = 1;
				else 
					size = 1;
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoLoadStore),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 0)),
							   IARG_MEMORYREAD_EA,
							   IARG_UINT32, size,
							   IARG_END);

/*
				INS_InsertCall(ins,
							   IPOINT_AFTER,
							   AFUNPTR(DoStore),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 0)),
							   IARG_MEMORYWRITE_EA,
							   IARG_UINT32, size,
							   IARG_END);
							   */
			}
			/* 1st operand is memory */
			else if (INS_OperandIsMemory(ins, 0)) {
				src = INS_OperandReg(ins, 1);
				if (REG_is_gr32(src))
					size = 4;
				else if (REG_is_gr16(src))
					size = 2;
				else if (REG_is_Upper8(src))
					size = 1;
				else 
					size = 1;

				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoStore),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 1)),
							   IARG_MEMORYREAD_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}
		break;

		/* bsf */
		case XED_ICLASS_BSF:
		/* bsr */
		case XED_ICLASS_BSR:
		/* mov */
		case XED_ICLASS_MOV :
		case XED_ICLASS_MOVSX:
		case XED_ICLASS_MOVZX:
			if (INS_IsMemoryWrite(ins) && 
				INS_OperandIsMemory(ins, 0) &&
				INS_OperandIsReg(ins, 1))
			{
				size = 4;
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoStore),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 1)),
							   IARG_MEMORYWRITE_EA,
							   IARG_UINT32, size,
							   IARG_END);

			}
			// Find the instructions that move a value from memory to a register
			if (INS_IsMemoryRead(ins) && 
				INS_OperandIsReg(ins, 0) &&
				INS_OperandIsMemory(ins, 1))
			{
				size = 4;
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoLoad),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 0)),
							   IARG_MEMORYREAD_EA,
							   IARG_UINT32, size,
							   IARG_END);

			}
		break;

		case XED_ICLASS_CMOVB:
		case XED_ICLASS_CMOVBE:
		case XED_ICLASS_CMOVL:
		case XED_ICLASS_CMOVLE:
		case XED_ICLASS_CMOVNB:
		case XED_ICLASS_CMOVNBE:
		case XED_ICLASS_CMOVNL:
		case XED_ICLASS_CMOVNLE:
		case XED_ICLASS_CMOVNO:
		case XED_ICLASS_CMOVNP:
		case XED_ICLASS_CMOVNS:
		case XED_ICLASS_CMOVNZ:
		case XED_ICLASS_CMOVO:
		case XED_ICLASS_CMOVP:
		case XED_ICLASS_CMOVS:
		case XED_ICLASS_CMOVZ:

			/* 2nd operand is memory */
			if (INS_MemoryOperandCount(ins) != 0) {
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoLoad),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 0)),
							   IARG_MEMORYREAD_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}

		break;

		case XED_ICLASS_CBW:
		case XED_ICLASS_CWD:
		case XED_ICLASS_CWDE:
		case XED_ICLASS_CDQ:

		break;

		/* conditional sets */
		case XED_ICLASS_SETB:
		case XED_ICLASS_SETBE:
		case XED_ICLASS_SETL:
		case XED_ICLASS_SETLE:
		case XED_ICLASS_SETNB:
		case XED_ICLASS_SETNBE:
		case XED_ICLASS_SETNL:
		case XED_ICLASS_SETNLE:
		case XED_ICLASS_SETNO:
		case XED_ICLASS_SETNP:
		case XED_ICLASS_SETNS:
		case XED_ICLASS_SETNZ:
		case XED_ICLASS_SETO:
		case XED_ICLASS_SETP:
		case XED_ICLASS_SETS:
		case XED_ICLASS_SETZ:

			if (INS_MemoryOperandCount(ins) != 0) {
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoStore),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 0)),
							   IARG_MEMORYWRITE_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}

		break;

		case XED_ICLASS_STMXCSR:
		/* smsw */
		case XED_ICLASS_SMSW:
		/* str */
		case XED_ICLASS_STR:

			if (INS_MemoryOperandCount(ins) != 0) {

				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoLoad),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 0)),
							   IARG_MEMORYREAD_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}

		break;

		case XED_ICLASS_LAR:
			if (INS_OperandIsMemory(ins, 1)) {
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoLoad),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 0)),
							   IARG_MEMORYREAD_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}
		break;
		/* rdpmc */
		case XED_ICLASS_RDPMC:
		/* rdtsc */
		case XED_ICLASS_RDTSC:
		break;
		case XED_ICLASS_CPUID:
		break;
		case XED_ICLASS_LAHF:
		break;
		case XED_ICLASS_CMPXCHG:
			if (INS_OperandIsMemory(ins, 1)) {
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoLoadStore),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 0)),
							   IARG_MEMORYREAD_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}
			break;
		case XED_ICLASS_XCHG:

			if (INS_OperandIsMemory(ins, 0)) {
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoLoadStore),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 1)),
							   IARG_MEMORYREAD_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}
			else if (INS_OperandIsMemory(ins, 1)) {
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoLoadStore),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 0)),
							   IARG_MEMORYREAD_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}
			break;

		/* XADD reg/mem, reg */
		/* exchange and add */
		case XED_ICLASS_XADD:
			if (INS_OperandIsMemory(ins, 0)) {
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoLoadStore),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 1)),
							   IARG_MEMORYWRITE_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}
		break;

		case XED_ICLASS_XLAT:
		case XED_ICLASS_LODSB:
		case XED_ICLASS_LODSW:
		case XED_ICLASS_LODSD:
			if (INS_OperandIsMemory(ins, 0)) {
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoLoad),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 1)),
							   IARG_MEMORYREAD_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}
			break;

		case XED_ICLASS_STOSB:
		case XED_ICLASS_STOSW:
		case XED_ICLASS_STOSD:

			if (INS_OperandIsMemory(ins, 0)) {
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoStore),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 1)),
							   IARG_MEMORYWRITE_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}
			break;

		case XED_ICLASS_MOVSD:
		case XED_ICLASS_MOVSW:
		case XED_ICLASS_MOVSB:

			if (INS_OperandIsMemory(ins, 0)) {
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoStore),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 1)),
							   IARG_MEMORYREAD_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}
			if (INS_OperandIsMemory(ins, 1)) {
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoStore),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 0)),
							   IARG_MEMORYREAD_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}

		break;
		case XED_ICLASS_SALC:
		break;
		/* rcl */
		case XED_ICLASS_RCL:
		/* rcr */        
		case XED_ICLASS_RCR:
		/* rol */        
		case XED_ICLASS_ROL:
		/* ror */        
		case XED_ICLASS_ROR:
		/* sal/shl */
		case XED_ICLASS_SHL:
		/* sar */
		case XED_ICLASS_SAR:
		/* shr */
		case XED_ICLASS_SHR:
		/* shld */
		case XED_ICLASS_SHLD:
		case XED_ICLASS_SHRD:
			if (INS_OperandIsMemory(ins, 0)) {
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoLoadStore),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 1)),
							   IARG_MEMORYWRITE_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}
		/* done */
		break;

		case XED_ICLASS_POP:
			if (INS_OperandIsMemory(ins, 0)) {
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoLoad),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 1)),
							   IARG_MEMORYREAD_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}
		break;

		case XED_ICLASS_PUSH:
			if (INS_OperandIsMemory(ins, 0)) {
				INS_InsertCall(ins,
							   IPOINT_BEFORE,
							   AFUNPTR(DoStore),
							   IARG_UINT32,
							   REG(INS_OperandReg(ins, 1)),
							   IARG_MEMORYWRITE_EA,
							   IARG_UINT32, size,
							   IARG_END);
			}
		break;


		case XED_ICLASS_POPA:
		case XED_ICLASS_POPAD:
		case XED_ICLASS_PUSHA:
		case XED_ICLASS_PUSHAD:
		case XED_ICLASS_PUSHF:
		case XED_ICLASS_PUSHFD:

		break;

		case XED_ICLASS_CALL_NEAR:

		break;
		case XED_ICLASS_LEAVE:
		break;
		case XED_ICLASS_LEA:
		break;

		case XED_ICLASS_CMPXCHG8B:
		case XED_ICLASS_ENTER:
		break;
		default:
		break;
	}
}


