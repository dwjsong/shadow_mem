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

#include "profiler.h"

static void read_map();
static void print_space();
static void reserve_shadow_map();

static void event_exit(void);
static void event_thread_init(void *drcontext);
static void event_thread_exit(void *drcontext);
static dr_emit_flags_t event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb,
                                        bool for_trace, bool translating);

static dr_emit_flags_t event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                                         bool for_trace, bool translating,
                                         OUT void **user_data);

static dr_emit_flags_t event_bb_insert(void *drcontext, void *tag, instrlist_t *bb,
                                       instr_t *instr, bool for_trace, bool translating,
                                       void *user_data);

static bool event_pre_syscall(void *drcontext, int sysnum);
static void clean_call(void);
static void memtrace(void *drcontext);
static void code_cache_init(void);
static void code_cache_exit(void);
static void instrument_mem(void        *drcontext, 
                           instrlist_t *ilist, 
                           instr_t     *where, 
                           int          pos, 
                           bool         write);

static void event_post_syscall(void *drcontext, int sysnum); 

DR_EXPORT void 
dr_init(client_id_t id)
{
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
    drmgr_init();
    drutil_init();
    client_id = id;
    mutex = dr_mutex_create();
    dr_register_exit_event(event_exit);
    if (!drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit) ||
        !drmgr_register_bb_app2app_event(event_bb_app2app,
                                         &priority) ||
        !drmgr_register_bb_instrumentation_event(event_bb_analysis,
                                                 event_bb_insert,
                                                 &priority)) {
        /* something is wrong: can't continue */
        DR_ASSERT(false);
        return;
    }
    drmgr_register_pre_syscall_event(event_pre_syscall);
	dr_register_post_syscall_event(event_post_syscall);
    tls_index = drmgr_register_tls_field();
    DR_ASSERT(tls_index != -1);

    code_cache_init();
    /* make it easy to tell, by looking at log file, which client executed */
//    dr_log(NULL, LOG_ALL, 1, "Client 'memtrace' initializing\n");
#ifdef SHOW_RESULTS
    if (dr_is_notify_on()) {
# ifdef WINDOWS
        /* ask for best-effort printing to cmd window.  must be called in dr_init(). */
        dr_enable_console_printing();
# endif
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
//    int len;
	unsigned long read_total = stack_count.read + heap_count.read + global_count.read + other_count.read;
	unsigned long write_total = stack_count.write + heap_count.write + global_count.write + other_count.write;

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

/*
    len = dr_snprintf(msg, sizeof(msg)/sizeof(msg[0]),
                      "load  %llu\n"
                      "store %llu\n",
                      load_count, store_count);
					  */
					  /*
    dr_snprintf(msg, sizeof(msg)/sizeof(msg[0]), "load  %lu\n", load_count);
    dr_snprintf(msg, sizeof(msg)/sizeof(msg[0]), "store %lu\n", store_count);
	*/

/*
	dr_fprintf(STDERR, "load %lu\n", load_count);
	dr_fprintf(STDERR, "store %lu\n", store_count);
	*/

//    DR_ASSERT(len > 0);
    NULL_TERMINATE(msg);
    DISPLAY_STRING(msg);
#endif /* SHOW_RESULTS */
    code_cache_exit();
    drmgr_unregister_tls_field(tls_index);
    dr_mutex_destroy(mutex);
    drutil_exit();
    drmgr_exit();
}

#ifdef WINDOWS
# define IF_WINDOWS(x) x
#else
# define IF_WINDOWS(x) /* nothing */
#endif

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

    /* We're going to dump our data to a per-thread file.
     * On Windows we need an absolute path so we place it in
     * the same directory as our library. We could also pass
     * in a path and retrieve with dr_get_options().
     */
	 /*
    len = dr_snprintf(logname, sizeof(logname)/sizeof(logname[0]),
                      "%s", dr_get_client_path(client_id));
    DR_ASSERT(len > 0);
    for (dirsep = logname + len; *dirsep != '/' IF_WINDOWS(&& *dirsep != '\\'); dirsep--)
        DR_ASSERT(dirsep > logname);
    len = dr_snprintf(dirsep + 1,
                      (sizeof(logname) - (dirsep - logname))/sizeof(logname[0]),
                      "memtrace.%d.log", dr_get_thread_id(drcontext));
    DR_ASSERT(len > 0);
    NULL_TERMINATE(logname);
    data->log = dr_open_file(logname, 
                             DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(data->log != INVALID_FILE);
    dr_log(drcontext, LOG_ALL, 1, 
           "memtrace: log for thread %d is memtrace.%03d\n",
           dr_get_thread_id(drcontext), dr_get_thread_id(drcontext));
#ifdef SHOW_RESULTS
    if (dr_is_notify_on()) {
        dr_fprintf(STDERR, "<memtrace results for thread %d in %s>\n",
                   dr_get_thread_id(drcontext), logname);
    }
#endif
*/
}


static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data;

    memtrace(drcontext);
    data = drmgr_get_tls_field(drcontext, tls_index);
    dr_mutex_lock(mutex);
    num_refs += data->num_refs;
    dr_mutex_unlock(mutex);
//    dr_close_file(data->log);
    dr_thread_free(drcontext, data->buf_base, MEM_BUF_SIZE);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}


/* we transform string loops into regular loops so we can more easily
 * monitor every memory reference they make
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

/* our operations here only need to see a single-instruction window so
 * we do not need to do any whole-bb analysis
 */
static dr_emit_flags_t
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating,
                  OUT void **user_data)
{
    return DR_EMIT_DEFAULT;
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

