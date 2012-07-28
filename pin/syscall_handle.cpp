#include <stdio.h>
#include "syscall_handle.h"
#include "shadow_map.h"

#include "pin.H"

int syscall_nr;
int brk_arg;
int mmap_size;

void syscall_enter(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
	ADDRINT arg1;
	ADDRINT arg2;
	syscall_nr = PIN_GetSyscallNumber(ctx, std);

	switch (syscall_nr) {

		case BRK_SYSCALL :
			printf("brk enter : %d\n", syscall_nr);
			arg1 = PIN_GetSyscallArgument(ctx, std, 0);
			brk_arg = arg1;
			printf("	brk addr %d %p\n", arg1, (void *)arg1);
			break;

		case MUNMAP_SYSCALL :
			printf("unmap enter : %d\n", syscall_nr);
			arg1 = PIN_GetSyscallArgument(ctx, std, 0);
			arg2 = PIN_GetSyscallArgument(ctx, std, 1);
			printf("	unmap size %p %d\n", (void *)arg1, arg2);
			break;

		case MMAP_SYSCALL :
			printf("mmap enter : %d\n", syscall_nr);
			arg1 = PIN_GetSyscallArgument(ctx, std, 0);
			arg2 = PIN_GetSyscallArgument(ctx, std, 1);
			printf("	mmap size %d\n", arg2);
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
			printf("brk exit : %d\n", syscall_nr);
			ret = PIN_GetSyscallReturn(ctx, std);
			read_map();
			if (!brk_arg) {
				heap_range.lower = ret;
				heap_range.lower_addr = (void *)ret;


				heap.lower = ret;
				heap.lower_addr = (void *)ret;
			}
			else {
				heap_range.upper = ret;
				heap_range.upper_addr = (void *)ret;

				heap.upper = ret;
				heap.upper_addr = (void *)ret;

				/* mark brk heap */
				if (markMalloc(ret, heap.upper - heap.lower))
					printf("Shadow Map Mark Failed at %p", (void *)ret);
			}
			printf("	brk ret %d %p\n", ret, (void *)ret);
			break;

		case MUNMAP_SYSCALL :
			printf("unmap exit : %d\n", syscall_nr);
			break;

		case MMAP_SYSCALL :
			printf("mmap exit : %d\n", syscall_nr);
			ret = PIN_GetSyscallReturn(ctx, std);

			if (markMalloc(ret, mmap_size))
				printf("Shadow Map Mark Failed at %p", (void *)ret);
			printf("	mmap ret %p\n", (void *)ret);
			break;
	}
}

