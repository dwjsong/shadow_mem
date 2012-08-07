#include <stdio.h>
#include "syscall_handle.h"
#include "shadow_map.h"

#include "pin.H"

int syscall_nr;
int brk_arg;
int mmap_size;
ADDRINT unadd;

void syscall_enter(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
	ADDRINT arg1;
	ADDRINT arg2;
	syscall_nr = PIN_GetSyscallNumber(ctx, std);

	switch (syscall_nr) {

		case BRK_SYSCALL :
//			printf("brk enter : %d\n", syscall_nr);
			arg1 = PIN_GetSyscallArgument(ctx, std, 0);
			brk_arg = arg1;
//			printf("	brk addr %d %p\n", arg1, (void *)arg1);
			break;

		case MUNMAP_SYSCALL :
//			printf("unmap enter : %d\n", syscall_nr);
			arg1 = PIN_GetSyscallArgument(ctx, std, 0);
			arg2 = PIN_GetSyscallArgument(ctx, std, 1);
			unadd = arg1;
			mmap_size = arg2;
//			printf("	unmap size %p %d\n", (void *)arg1, arg2);
			break;

		case MMAP_SYSCALL :
//			printf("mmap enter : %d\n", syscall_nr);
			arg1 = PIN_GetSyscallArgument(ctx, std, 0);
			arg2 = PIN_GetSyscallArgument(ctx, std, 1);
//			printf("	mmap size %d\n", arg2);
			mmap_size = arg2;
			break;
	}
//	PIN_GetSyscallArgument(ctx, std, 
}

void syscall_exit(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
	ADDRINT ret;

	switch (syscall_nr) {

		case BRK_SYSCALL :
			ret = PIN_GetSyscallReturn(ctx, std);
			if (!brk_arg) {
				read_map();
//				printf("brk at %p\n", (void *)ret);

				global_range.upper = ret;
				global_range.upper_addr = (void *)ret;

				heap_range.lower = ret;
				heap_range.lower_addr = (void *)ret;


				heap.lower = ret;
				heap.lower_addr = (void *)ret;
			}
			else {
//				printf("brk at %p\n", (void *)ret);
				heap_range.upper = ret;
				heap_range.upper_addr = (void *)ret;

				heap.upper = ret;
				heap.upper_addr = (void *)ret;

				/* mark brk heap */
//				printf("shadow %p %p %d\n", heap.lower_addr, heap.upper_addr, heap.upper - heap.lower);
				if (markAlloc(heap.lower, heap.upper - heap.lower) < 0)
					printf("Shadow Map Mark Failed at %p", heap.lower_addr);
//				else
//					printShadowMap(heap.lower, heap.upper - heap.lower);
			}
//			printf("	brk ret %d %p\n", ret, (void *)ret);
			break;

		case MUNMAP_SYSCALL :
//			printf("unmap exit : %d\n", syscall_nr);
			if (unmarkAlloc(unadd, mmap_size) < 0)
				printf("Shadow Map Unmark Failed at %p", (void *)ret);
			break;

		case MMAP_SYSCALL :
//			printf("mmap exit : %d %d\n", syscall_nr, mmap_size);
			ret = PIN_GetSyscallReturn(ctx, std);

			if (markAlloc(ret, mmap_size) < 0)
				printf("Shadow Map Mark Failed at %p", (void *)ret);
//			printf("	mmap ret %p\n", (void *)ret);
			break;
	}
}

