#include <string.h> /* for memset */
#include <stddef.h> /* for offsetof */
#include "dr_api.h"
#include "drutil.h"
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>

#include "shadow_map.h"
#include "memtrace.h"

/* 
 * Global variables
 */
unsigned long offset = 0x20000000;;
static const unsigned long shadowMemSize = 1024 * 1024 * 128 * 3;
pid_t pid;

/*
 * Function body begins
 */

DR_EXPORT void 
dr_init(client_id_t id)
{
  //shared memory space init
	reserve_shadow_map();
	read_map();
	print_space();

    //thread init/exit
	dr_register_thread_init_event(event_thread_init);
	dr_register_thread_exit_event(event_thread_exit);

    //syscall instrumentation
    dr_register_filter_syscall_event(event_filter_syscall);
    dr_register_pre_syscall_event(event_pre_syscall);
    dr_register_post_syscall_event(event_post_syscall);

    //main instrumation
	dr_register_bb_event(event_basic_block);
    
    //registering signal handling
    dr_register_signal_event(event_signal);

	dr_register_exit_event(event_exit);
    code_cache_init();
}


/*
 * Signal handler
 */
static
dr_signal_action_t event_signal(void *drcontext, dr_siginfo_t *info)
{
    if (info->sig == SIGSEGV) {
		dr_fprintf(STDERR, "Shadow Memory Write Error!\n");
		exit(0);
    }

    return DR_SIGNAL_DELIVER;
}

static void 
event_exit()
{
	char tmp[10];
	int read_total = stack_count.read + heap_count.read + global_count.read + other_count.read;
	int write_total = stack_count.write + heap_count.write + global_count.write + other_count.write;

	dr_fprintf(STDERR, "heap %x %x\n", heap_range.lower_addr, heap_range.upper_addr);
	dr_fprintf(STDERR, "stack %x %x\n", stack_range.lower_addr, stack_range.upper_addr);
	dr_fprintf(STDERR, "global %x %x\n", global_range.lower_addr, global_range.upper_addr);
	dr_fprintf(STDERR, "read %d %d\n", global_range.lower_addr, global_range.upper_addr);

	dr_fprintf(STDERR, "==============================\n");
	dr_fprintf(STDERR, "Read \n");
	dr_fprintf(STDERR, "Stack : %d ", stack_count.read);
	percentify(stack_count.read, read_total, tmp);
	dr_fprintf(STDERR, "(%s)\n", tmp);
	dr_fprintf(STDERR, "Heap  : %d ", heap_count.read);
	percentify(heap_count.read, read_total, tmp);
	dr_fprintf(STDERR, "(%s)\n", tmp);
	dr_fprintf(STDERR, "	Success : %d\n", heap_success.read);
	dr_fprintf(STDERR, "	Fail : %d\n", heap_fail.read);
	percentify(global_count.read, read_total, tmp);
	dr_fprintf(STDERR, "Global : %d ", global_count.read);
	dr_fprintf(STDERR, "(%s)\n", tmp);
	percentify(other_count.read, read_total, tmp);
	dr_fprintf(STDERR, "Other : %d ", other_count.read);
	dr_fprintf(STDERR, "(%s)\n", tmp);
	dr_fprintf(STDERR, "Total : %d\n", read_total);
	dr_fprintf(STDERR, "==============================\n");

	dr_fprintf(STDERR, "Write \n");
	dr_fprintf(STDERR, "Stack : %d ", stack_count.write);
	percentify(stack_count.write, write_total, tmp);
	dr_fprintf(STDERR, "(%s)\n", tmp);
	dr_fprintf(STDERR, "Heap  : %d ", heap_count.write);
	percentify(heap_count.write , write_total, tmp);
	dr_fprintf(STDERR, "(%s)\n", tmp);
	dr_fprintf(STDERR, "	Success : %d\n", heap_success.write);
	dr_fprintf(STDERR, "	Fail : %d\n", heap_fail.write);
	percentify(global_count.write, write_total, tmp);
	dr_fprintf(STDERR, "Global : %d ", global_count.write);
	dr_fprintf(STDERR, "(%s)\n", tmp);
	percentify(other_count.write, write_total, tmp);
	dr_fprintf(STDERR, "Other : %d ", other_count.write);
	dr_fprintf(STDERR, "(%s)\n", tmp);
	dr_fprintf(STDERR, "Total : %d\n", write_total);
	dr_fprintf(STDERR, "==============================\n");
    code_cache_exit();
}

static void
code_cache_exit(void)
{
    dr_nonheap_free(code_cache, PAGE_SIZE);
}

static void
code_cache_init(void)
{
    void         *drcontext;
    instrlist_t  *ilist;
    instr_t      *where;
    byte         *end;

    drcontext  = dr_get_current_drcontext();
    code_cache = dr_nonheap_alloc(PAGE_SIZE, 
                                  DR_MEMPROT_READ  |
                                  DR_MEMPROT_WRITE |
                                  DR_MEMPROT_EXEC);

    ilist = instrlist_create(drcontext);

    /* The lean procecure simply performs a clean call, and then jump back */
    /* jump back to the DR's code cache */
    where = INSTR_CREATE_jmp_ind(drcontext, opnd_create_reg(DR_REG_XCX));
    instrlist_meta_append(ilist, where);

    /* clean call */
    dr_insert_clean_call(drcontext, ilist, where, (void *)clean_call, false, 0);

    /* Encodes the instructions into memory and then cleans up. */
    end = instrlist_encode(drcontext, ilist, code_cache, false);
    DR_ASSERT((end - code_cache) < PAGE_SIZE);
    instrlist_clear_and_destroy(drcontext, ilist);

    /* set the memory as just +rx now */
    dr_memory_protect(code_cache, PAGE_SIZE, DR_MEMPROT_READ | DR_MEMPROT_EXEC);
}

static void
event_thread_init(void *drcontext)
{
	per_thread_t *data = (per_thread_t *) dr_thread_alloc(drcontext, sizeof(per_thread_t));

	dr_set_tls_field(drcontext, data);
    data->buf_base = dr_thread_alloc(drcontext, MEM_BUF_SIZE);
    data->buf_ptr  = data->buf_base;
    data->buf_end  = -(ptr_int_t)(data->buf_base + MEM_BUF_SIZE);
    data->num_refs = 0;
}

static void
event_thread_exit(void *drcontext)
{
	per_thread_t *data = (per_thread_t *)dr_get_tls_field(drcontext);
	dr_thread_free(drcontext, data, sizeof(per_thread_t));  
}

static void memtrace(void *drcontext)
{
    per_thread_t *data;
    int num_refs;
    mem_ref_t *mem_ref;
    int i;

    data      = dr_get_tls_field(drcontext);
    mem_ref   = (mem_ref_t *)data->buf_base;
    num_refs  = (int)((mem_ref_t *)data->buf_ptr - mem_ref);

    for (i = 0; i < num_refs; i++) {
		if (mem_ref->write)
			trace_store((unsigned long) mem_ref->addr, mem_ref->size);
		else
			trace_load((unsigned long)mem_ref->addr, mem_ref->size);
        ++mem_ref;
    }


    memset(data->buf_base, 0, MEM_BUF_SIZE);
    data->num_refs += num_refs;
    data->buf_ptr   = data->buf_base;
}

static void trace_load(unsigned long addr, int size)
{
	int count;
	unsigned long addr_val = (unsigned long) addr;

	
	if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
//		dr_fprintf(STDERR, "r g %p h %p %p s %p %p a %p s %d\n", global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
		heap_count.read += size;
		count = check_alloc(addr, size);
		heap_success.read += count;
		heap_fail.read += size - count;
		/*
		if (size > count)
			dr_fprintf(STDERR, "load %x %d\n", addr, size);
		*/
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else {
		other_count.read += size;
	}
}

static void trace_store(unsigned long addr, int size)
{
	int count; 
	unsigned long addr_val = (unsigned long) addr;

	if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
//		dr_fprintf(STDERR, "w g %p h %p %p s %p %p a %p s %d\n", global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
		heap_count.write += size;
		count = check_alloc(addr, size);
		heap_success.write += count;
		heap_fail.write += size - count;
		/*
		if (size > count)
			dr_fprintf(STDERR, "store %x %d\n", addr, size);
		*/
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else {
		other_count.write += size;
	}
}

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
				  bool for_trace, bool translating)
{
	int i;
	instr_t *instr;

	instr = instrlist_first(bb);

    if (instr_get_app_pc(instr) == NULL)
        return DR_EMIT_DEFAULT;

    if (instr_reads_memory(instr)) {
        for (i = 0; i < instr_num_srcs(instr); i++) {
            if (opnd_is_memory_reference(instr_get_src(instr, i))) {
				instrument_mem(drcontext, bb, instr, i, false);
            }
        }
    }

    if (instr_writes_memory(instr)) {
        for (i = 0; i < instr_num_dsts(instr); i++) {
            if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
				instrument_mem(drcontext, bb, instr, i, true);
            }
        }
    }

	return DR_EMIT_DEFAULT;
}


static void
instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where, 
			   int pos, bool write)
{

    instr_t *instr, *call, *restore;
    opnd_t   ref, opnd1, opnd2;
    reg_id_t reg1 = DR_REG_XBX; /* We can optimize it by picking dead reg */
    reg_id_t reg2 = DR_REG_XCX; /* reg2 must be ECX or RCX for jecxz */
    per_thread_t *data;
    
    data = dr_get_tls_field(drcontext);

    /* Steal the register for memory reference address *
     * We can optimize away the unnecessary register save and restore 
     * by analyzing the code and finding the register is dead. 
     */
    dr_save_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
    dr_save_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);

    if (write)
       ref = instr_get_dst(where, pos);
    else
       ref = instr_get_src(where, pos);

    /* use drutil to get mem address */
    drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg1, reg2);
    
    /* The following assembly performs the following instructions
     * buf_ptr->write = write;
     * buf_ptr->addr  = addr;
     * buf_ptr->size  = size;
     * buf_ptr++;
     * if (buf_ptr >= buf_end_ptr) 
     *    clean_call();
     */
    dr_insert_read_tls_field(drcontext, ilist, where, reg2);
    /* Load data->buf_ptr into reg2 */
    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_MEMPTR(reg2, offsetof(per_thread_t, buf_ptr));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Move write/read to write field */
    opnd1 = OPND_CREATE_MEM32(reg2, offsetof(mem_ref_t, write));
    opnd2 = OPND_CREATE_INT32(write);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Store address in memory ref */
    opnd1 = OPND_CREATE_MEMPTR(reg2, offsetof(mem_ref_t, addr));
    opnd2 = opnd_create_reg(reg1);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Store size in memory ref */
    opnd1 = OPND_CREATE_MEMPTR(reg2, offsetof(mem_ref_t, size));
    /* drutil_opnd_mem_size_in_bytes handles OP_enter */
    opnd2 = OPND_CREATE_INT32(drutil_opnd_mem_size_in_bytes(ref, where));
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Increment reg value by pointer size using lea instr */
    opnd1 = opnd_create_reg(reg2);
    opnd2 = opnd_create_base_disp(reg2, DR_REG_NULL, 0, 
                                  sizeof(mem_ref_t), 
                                  OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Update the data->buf_ptr */
    dr_insert_read_tls_field(drcontext, ilist, where, reg1);
    opnd1 = OPND_CREATE_MEMPTR(reg1, offsetof(per_thread_t, buf_ptr));
    opnd2 = opnd_create_reg(reg2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* we use lea + jecxz trick for better performance
     * lea and jecxz won't disturb the eflags, so we won't insert
     * code to save and restore application's eflags. 
     */
    /* lea [reg2 - buf_end] => reg2 */
    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_MEMPTR(reg1, offsetof(per_thread_t, buf_end));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    opnd1 = opnd_create_reg(reg2);
    opnd2 = opnd_create_base_disp(reg1, reg2, 1, 0, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    
    call  = INSTR_CREATE_label(drcontext);
    opnd1 = opnd_create_instr(call);
    instr = INSTR_CREATE_jecxz(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    restore = INSTR_CREATE_label(drcontext);
    opnd1 = opnd_create_instr(restore);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* clean call */
    /* We jump to lean procedure which performs full context switch and 
     * clean call invocation. This is to reduce the code cache size. 
     */
    instrlist_meta_preinsert(ilist, where, call);
    /* mov restore DR_REG_XCX */
    opnd1 = opnd_create_reg(reg2);
    /* this is the return address for jumping back from lean procedure */
    opnd2 = opnd_create_instr(restore);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* jmp code_cache */
    opnd1 = opnd_create_pc(code_cache);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* restore %reg */
    instrlist_meta_preinsert(ilist, where, restore);
    dr_restore_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
    dr_restore_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);
}

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    return true; /* intercept everything */
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
	per_thread_t *data = (per_thread_t *)dr_get_tls_field(drcontext);

	//dr_fprintf(STDERR, "pre sysnum %d\n", sysnum);

	switch (sysnum) {
	
		case BRK_SYSCALL :
			data->param0 = dr_syscall_get_param(drcontext, 0);
//			dr_fprintf(STDERR, "	brk %u\n", nm);
			break;

		case MMAP_SYSCALL :
			data->param1 = dr_syscall_get_param(drcontext, 1);
//			dr_fprintf(STDERR, "	mmap %u\n", nm);
			break;

		case MUNMAP_SYSCALL :
			data->param0 = dr_syscall_get_param(drcontext, 0);
			data->param1 = dr_syscall_get_param(drcontext, 1);
//			dr_fprintf(STDERR, "	mmap %u\n", nm);
			break;
	}
	return true;
}

static int check_alloc(unsigned long addr, int size)
{
	int i, ct = 0;
	char wh;
	unsigned char *shadow_addr;

	for (i = 0; i < size; i++) {
		//byte-location
		shadow_addr = (unsigned char *) (((addr + i) >> 3) + offset);

//		if (i % 8 == 0)
//			dr_fprintf(STDERR, "check shadow_addr %x %d\n", shadow_addr, *shadow_addr);

		//bit-position
		wh = (addr + i) & 7;

		//checking for bit-value
		wh = (*shadow_addr >> wh) & 1;
		ct += wh;
	}
	return ct;
}

int markAlloc(unsigned long addr, int size)
{
	int i;
	char wh;
	unsigned char *shadow_addr;

	for (i = 0; i < size; i++) {
		//byte-location
		shadow_addr = (unsigned char *) (((addr + i) >> 3) + offset);

		//bit-position
		wh = (addr + i) & 7;

		//marking 
		*shadow_addr = *shadow_addr | (1 << wh);
		/*
		if (i % 8 == 0)
			dr_fprintf(STDERR, "mark shadow_addr %x %d\n", shadow_addr, *shadow_addr);
		*/
	}
	return 0;
}

int unmarkAlloc(unsigned long addr, int size)
{
	int i = 0;
	int clr;
	unsigned char *shadow_addr;

	if (addr % 8 && size > 8) {
		shadow_addr = (unsigned char *) ((addr >> 3) + offset);
		clr = ((8 - (addr % 8)) > size) ? (8 - (addr % 8)) : size;
		*shadow_addr = (*shadow_addr << clr) >> clr;

		i = clr;
	}

	for (; i < size - 8; i += 8) {
		shadow_addr = (unsigned char *) (((addr + i) >> 3) + offset);
		*shadow_addr = 0;
	}

	if (i < size) {
		shadow_addr = (unsigned char *) (((addr + i) >> 3) + offset);
		*shadow_addr = (*shadow_addr >> (size - i)) << (size - i);
	}

	return 0;
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
	unsigned long ret;
	per_thread_t *data = (per_thread_t *)dr_get_tls_field(drcontext);

//	dr_fprintf(STDERR, "post sysnum %d\n", sysnum);

	switch (sysnum) {

		case BRK_SYSCALL :
			ret = dr_syscall_get_result(drcontext);

			if (!data->param0) {
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
			dr_fprintf(STDERR, "brk %u\n", data->param0);
			dr_fprintf(STDERR, "	ret %x\n", ret);

			break;

		case MMAP_SYSCALL :
			ret = dr_syscall_get_result(drcontext);

			dr_fprintf(STDERR, "mmap %u %x\n", data->param1, ret);
	//		dr_fprintf(STDERR, "	ret %x\n", ret);

			markAlloc(ret, data->param1);

			break;

		case MUNMAP_SYSCALL :
	//		dr_fprintf(STDERR, "	munmap %x %u\n", data->param0, data->param1);
			ret = dr_syscall_get_result(drcontext);
	//		dr_fprintf(STDERR, "ret %u\n", ret);

			unmarkAlloc(data->param0, data->param1);

			break;
	}
}


/*
 * Utility functions
 */

static void percentify(unsigned long a, unsigned long b, char *transformed)
{
	unsigned long c, d;

	c = a * 100 / b;
	d = (a * 10000 / b) % 100;

	sprintf(transformed, "%ld.%0ld", c, d);
}

static void
clean_call(void)
{
    void *drcontext = dr_get_current_drcontext();
    memtrace(drcontext);
}
