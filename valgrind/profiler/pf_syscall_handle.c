#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)
#include "valgrind.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_vki.h"
#include "pub_tool_aspacemgr.h"

#include "config.h"

#include "pf_include.h"

void pre_syscall(ThreadId tid, UInt syscallno,
                           UWord* args, UInt nArgs)
{
}

void post_syscall(ThreadId tid, UInt syscallno,
                            UWord* args, UInt nArgs, SysRes res)
{
	ULong addr;
	Int size;

	unmap = 0;
	switch (syscallno) {
		case BRK_SYSCALL :
//			VG_(printf)("brk = %p\n", args[0]);
//			VG_(printf)("brk ret %d %p\n", args[0], res);
			addr = (ULong)sr_Res(res);

			if ((ULong)args[0] == 0) {
				global_range.upper = addr;
				global_range.upper_addr = (void *)addr;

				heap_range.lower = addr;
				heap_range.lower_addr = (void *)addr;
			}
			else {
				start = 1;

				heap_range.upper = addr;
				heap_range.upper_addr = (void *)addr;

				mark_alloc(heap_range.lower, heap_range.upper - heap_range.lower);
			}
			break;

		case MUNMAP_SYSCALL :
//			unmap = 1;
//			VG_(printf)("unmap ret %p\n", args[0]);
//			VG_(printf)("	munmap return = %d\n", res);
			addr = (ULong)sr_Res(res);
			size = args[1];
			unmark_alloc(addr, size);
			break;

		case MMAP_SYSCALL :
			//VG_(printf)("mmap size = %d\n", args[1]);
//			if (args[1] == 4096) stt = 1;
//			VG_(printf)("mmap ret %d %p\n", args[1], res);
			addr = (ULong)sr_Res(res);
			size = args[1];
			mark_alloc(addr, size);
			break;

		default :
//			VG_(printf)("syscall %d\n", syscallno);
			break;

	}
}

