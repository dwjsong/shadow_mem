#include <string.h> /* for memset */
#include <stddef.h> /* for offsetof */
#include "dr_api.h"
#include "drmgr.h"
#include "drutil.h"

#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <syscall.h>

#include "shadow_map.h"
#include "memtrace2.h"

/*
 * Global variables
 */

/* counters */
static access_count_t stack_count;
static access_count_t other_count;
static access_count_t heap_count;
static access_count_t global_count;
static access_count_t heap_success;
static access_count_t heap_fail;

/* DR variables */
static unsigned long syscall_param;
static app_pc code_cache;
static client_id_t client_id;
static app_pc code_cache;

#ifdef __MUTEX__
static void  *mutex;    /* for multithread support */
#endif

static uint64 num_refs; /* keep a global memory reference count */
static int tls_index;

/* constants */
unsigned long offset = 0x20000000;;
static const unsigned long shadowMemSize = 1024 * 1024 * 128 * 3;
pid_t pid;

/* ??? */
void *addr_buf[BUFSZ];
int buf_pos;

DR_EXPORT void
dr_init(client_id_t id)
{
  /* init. shadow_map */
  reserve_shadow_map();
  read_map();
  print_space();

  /* Specify priority relative to other instrumentation operations: */
  drmgr_priority_t priority = {
    sizeof(priority), /* size of struct */
    "memtrace",       /* name of our operation */
    NULL,             /* optional name of operation we should precede */
    NULL,             /* optional name of operation we should follow */
    0};               /* numeric priority */

  /* init. extensions */
  drmgr_init();
  drutil_init();

  client_id = id;

#ifdef __MUTEX__
  mutex = dr_mutex_create();
#endif

  /* registering events */
  if (!dr_register_exit_event(event_exit) ||
      !drmgr_register_thread_init_event(event_thread_init) ||
      !drmgr_register_thread_exit_event(event_thread_exit) ||
      /* 1st stage */
      !drmgr_register_bb_app2app_event(event_bb_app2app, &priority) ||
      /* 2nd and 3rd stage */
      !drmgr_register_bb_instrumentation_event(event_bb_analysis,
                                               event_bb_insert, &priority)||
      !drmgr_register_pre_syscall_event(event_pre_syscall) ||
      !dr_register_post_syscall_event(event_post_syscall)
    ) {
    /* something is wrong: can't continue */
    DR_ASSERT(false);
    return;
  }

  tls_index = drmgr_register_tls_field();
  DR_ASSERT(tls_index != -1);

  code_cache_init();
#ifdef SHOW_RESULTS
  if (dr_is_notify_on()) {
    dr_fprintf(STDERR, "Client memtrace is running\n");
  }
#endif
}


static void percentify(unsigned long a, unsigned long b, char *transformed)
{
  unsigned long c, d;

  if (!b)
    sprintf(transformed, "0.0");
  else {
    c = a * 100 / b;
    d = (a * 10000 / b) % 100;

    sprintf(transformed, "%lu.%0lu", c, d);
  }
}

static void
event_exit()
{
#ifdef SHOW_RESULTS
  char msg[512];
  char tmp[10];

  unsigned long read_total = stack_count.read + heap_count.read + \
    global_count.read + other_count.read;
  unsigned long write_total = stack_count.write + heap_count.write + \
    global_count.write + other_count.write;

  dr_printf("heap %x %x\n", heap_range.lower_addr, heap_range.upper_addr);
  dr_printf("stack %x %x\n", stack_range.lower_addr, stack_range.upper_addr);
  dr_printf("global %x %x\n", global_range.lower_addr, global_range.upper_addr);
  dr_printf("read %d %d\n", global_range.lower_addr, global_range.upper_addr);

  dr_printf("==============================\n");
  dr_printf("Read \n");
  dr_printf("Stack : %lu ", stack_count.read);
  percentify(stack_count.read, read_total, tmp);
  dr_printf("(%s)\n", tmp);
  dr_printf("Heap  : %lu ", heap_count.read);
  percentify(heap_count.read, read_total, tmp);
  dr_printf("(%s)\n", tmp);
  dr_printf("	Success : %lu\n", heap_success.read);
  dr_printf("	Fail : %lu\n", heap_fail.read);
  percentify(global_count.read, read_total, tmp);
  dr_printf("Global : %lu ", global_count.read);
  dr_printf("(%s)\n", tmp);
  percentify(other_count.read, read_total, tmp);
  dr_printf("Other : %lu ", other_count.read);
  dr_printf("(%s)\n", tmp);
  dr_printf("Total : %lu\n", read_total);
  dr_printf("==============================\n");
  
  dr_printf("Write \n");
  dr_printf("Stack : %lu ", stack_count.write);
  percentify(stack_count.write, write_total, tmp);
  dr_printf("(%s)\n", tmp);
  dr_printf("Heap  : %lu ", heap_count.write);
  percentify(heap_count.write , write_total, tmp);
  dr_printf("(%s)\n", tmp);
  dr_printf("	Success : %lu\n", heap_success.write);
  dr_printf("	Fail : %lu\n", heap_fail.write);
  percentify(global_count.write, write_total, tmp);
  dr_printf("Global : %lu ", global_count.write);
  dr_printf("(%s)\n", tmp);
  percentify(other_count.write, write_total, tmp);
  dr_printf("Other : %lu ", other_count.write);
  dr_printf("(%s)\n", tmp);
  dr_printf("Total : %lu\n", write_total);
  dr_printf("==============================\n");

  NULL_TERMINATE(msg);
  DISPLAY_STRING(msg);
#endif /* SHOW_RESULTS */
  code_cache_exit();
  drmgr_unregister_tls_field(tls_index);

#ifdef __MUTEX__
  dr_mutex_destroy(mutex);
#endif

  drutil_exit();
  drmgr_exit();
}

static void
event_thread_init(void *drcontext)
{
  per_thread_t *data;

  /* allocate thread private data */
  data = dr_thread_alloc(drcontext, sizeof(per_thread_t));
  drmgr_set_tls_field(drcontext, tls_index, data);
  data->buf_base = dr_thread_alloc(drcontext, MEM_BUF_SIZE);
  data->buf_ptr  = data->buf_base;
  /* set buf_end to be negative of address of buffer end for the lea later */
  data->buf_end  = -(ptr_int_t)(data->buf_base + MEM_BUF_SIZE);
  data->num_refs = 0;
}


static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data;

    memtrace(drcontext);
    data = drmgr_get_tls_field(drcontext, tls_index);

#ifdef __MUTEX__
    dr_mutex_lock(mutex);
#endif __MUTEX__

    num_refs += data->num_refs;

#ifdef __MUTEX__
    dr_mutex_unlock(mutex);
#endif

//    dr_close_file(data->log);
    dr_thread_free(drcontext, data->buf_base, MEM_BUF_SIZE);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}


/*
 * we transform string loops into regular loops so we can more easily monitor
 * every memory reference they make
 */
static dr_emit_flags_t
event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb,
                 bool for_trace, bool translating)
{
    if (!drutil_expand_rep_string(drcontext, bb)) {
        DR_ASSERT(false);
        /* in release build, carry on: we'll just miss per-iter refs */
    }
    return DR_EMIT_DEFAULT;
}

/*
 * our operations here only need to see a single-instruction window so we do not
 * need to do any whole-bb analysis
 */
static dr_emit_flags_t
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating,
                  OUT void **user_data)
{
    return DR_EMIT_DEFAULT;
}

/*
 * event_bb_insert calls instrument_mem to instrument every application memory
 * reference.
 */
static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb,
                instr_t *instr, bool for_trace, bool translating,
                void *user_data)
{
    int i;
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

int check_alloc(unsigned long addr, int size)
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

/*
static void trace_load(unsigned long addr, int size)
{
	addr_buf[buf_pos] = (void *)addr;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
}

static void trace_store(unsigned long addr, int size)
{
	addr_buf[buf_pos] = (void *)addr;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
}
static void trace_load(unsigned long addr, int size)
{
	int count = 0;
	unsigned long addr_val = (unsigned long) addr;


	addr_buf[buf_pos] = (void *)addr;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
	if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.read += size;
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

static void trace_store(unsigned long addr, int size)
{
	int count = 0;
	unsigned long addr_val = (unsigned long) addr;

	addr_buf[buf_pos] = (void *)addr;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
	if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.write += size;
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

*/
static void trace_load(unsigned long addr, int size)
{
	int count;
	unsigned long addr_val = (unsigned long) addr;


//	dr_printf("r g %p h %p %p s %p %p a %p s %d\n", global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
	addr_buf[buf_pos] = (void *)addr;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
	if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.read += size;
		count = check_alloc(addr, size);
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

static void trace_store(unsigned long addr, int size)
{
	int count;
	unsigned long addr_val = (unsigned long) addr;

	addr_buf[buf_pos] = (void *)addr;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
	if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
//		dr_fprintf(STDERR, "w g %p h %p %p s %p %p a %p s %d\n", global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
		heap_count.write += size;
		count = check_alloc(addr, size);
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

static void
memtrace(void *drcontext)
{
    per_thread_t *data;
    int num_refs;
    mem_ref_t *mem_ref;
//#ifdef READABLE_TRACE
    int i;
//#endif

    data      = drmgr_get_tls_field(drcontext, tls_index);
    mem_ref   = (mem_ref_t *)data->buf_base;
    num_refs  = (int)((mem_ref_t *)data->buf_ptr - mem_ref);

//#ifdef READABLE_TRACE
    for (i = 0; i < num_refs; i++) {
		if (mem_ref->write) {
			trace_store((unsigned long)mem_ref->addr, mem_ref->size);
		}
		else {
			trace_load((unsigned long)mem_ref->addr, mem_ref->size);
		}
//        dr_fprintf(data->log, "%c%d:"PFX"\n",
//                   mem_ref->write ? 'w' : 'r', mem_ref->size, mem_ref->addr);
        ++mem_ref;
    }
	/*
#else
    dr_write_file(data->log, data->buf_base,
                  (size_t)(data->buf_ptr - data->buf_base));
#endif
*/

    memset(data->buf_base, 0, MEM_BUF_SIZE);
    data->num_refs += num_refs;
    data->buf_ptr   = data->buf_base;
}

/* clean_call dumps the memory reference info to the log file */
static void
clean_call(void)
{
    void *drcontext = dr_get_current_drcontext();
    memtrace(drcontext);
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
code_cache_exit(void)
{
    dr_nonheap_free(code_cache, PAGE_SIZE);
}


/*
 * instrument_mem is called whenever a memory reference is identified.
 * It inserts code before the memory reference to to fill the memory buffer
 * and jump to our own code cache to call the clean_call when the buffer is full.
 */
static void
instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where,
               int pos, bool write)
{
    instr_t *instr, *call, *restore;
    opnd_t   ref, opnd1, opnd2;
    reg_id_t reg1 = DR_REG_XBX; /* We can optimize it by picking dead reg */
    reg_id_t reg2 = DR_REG_XCX; /* reg2 must be ECX or RCX for jecxz */
    per_thread_t *data;

    data = drmgr_get_tls_field(drcontext, tls_index);

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
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg2);
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
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg1);
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

    /* jecxz call */
    call  = INSTR_CREATE_label(drcontext);
    opnd1 = opnd_create_instr(call);
    instr = INSTR_CREATE_jecxz(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jump restore to skip clean call */
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

