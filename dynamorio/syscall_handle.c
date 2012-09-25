#include "profiler.h"

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    per_thread_t *data = drmgr_get_tls_field(drcontext, tls_index);

	//dr_fprintf(STDERR, "pre sysnum %d\n", sysnum);

	switch (sysnum) {
	
		case BRK_SYSCALL :
			data->param[0] = dr_syscall_get_param(drcontext, 0);
//			dr_fprintf(STDERR, "	brk %u\n", nm);
			break;

		case MMAP_SYSCALL :
			data->param[1] = dr_syscall_get_param(drcontext, 1);
//			dr_fprintf(STDERR, "	mmap %u\n", nm);
			break;

		case MUNMAP_SYSCALL :
			data->param[0] = dr_syscall_get_param(drcontext, 0);
			data->param[1] = dr_syscall_get_param(drcontext, 1);
//			dr_fprintf(STDERR, "	mmap %u\n", nm);
			break;
	}
	return true;
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
	unsigned long ret;
    per_thread_t *data = drmgr_get_tls_field(drcontext, tls_index);

//	dr_fprintf(STDERR, "post sysnum %d\n", sysnum);

	switch (sysnum) {

		case BRK_SYSCALL :
			ret = dr_syscall_get_result(drcontext);

			if (!data->param[0]) {
				global_range.upper = ret;
				global_range.upper_addr = (void *)ret;

				heap_range.lower = ret;
				heap_range.lower_addr = (void *)ret;
			}
			else {
				heap_range.upper = ret;
				heap_range.upper_addr = (void *)ret;
				markAlloc(heap_range.lower, heap_range.upper - heap_range.lower);
			}
//			dr_printf("brk %u ret %x\n", data->param[0], ret);
//			dr_fprintf(STDERR, "	ret %x\n", ret);

			break;

		case MMAP_SYSCALL :
			ret = dr_syscall_get_result(drcontext);

//			dr_printf("mmap %u %x\n", data->param[1], ret);
	//		dr_fprintf(STDERR, "	ret %x\n", ret);

			markAlloc(ret, data->param[1]);

			break;

		case MUNMAP_SYSCALL :
//			dr_printf("unmap %x %u\n", data->param[0], data->param[1]);
			ret = dr_syscall_get_result(drcontext);
	//		dr_fprintf(STDERR, "ret %u\n", ret);

			unmarkAlloc(data->param[0], data->param[1]);

			break;
	}
}

