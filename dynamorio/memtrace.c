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

#define BRK_SYSCALL 45
#define MUNMAP_SYSCALL 91
#define MMAP_SYSCALL 192

#define STACK "[stack]"
#define HEAP "[heap]"

#ifdef WINDOWS
# define DISPLAY_STRING(msg) dr_messagebox(msg)
#else
# define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
#endif

#define NULL_TERMINATE(buf) buf[(sizeof(buf)/sizeof(buf[0])) - 1] = '\0'


/* Each mem_ref_t includes the type of reference (read or write), 
 * the address referenced, and the size of the reference.
 */
typedef struct _mem_ref_t{
    bool  write;
    void *addr;
    int size;
} mem_ref_t;

/* Control the format of memory trace: readable or hexl */
#define READABLE_TRACE 
/* Max number of mem_ref a buffer can have */
#define MAX_NUM_MEM_REFS 8192 
/* The size of memory buffer for holding mem_refs. When it fills up, 
 * we dump data from the buffer to the file.
 */
#define MEM_BUF_SIZE (sizeof(mem_ref_t) * MAX_NUM_MEM_REFS)
#define MODUL_SIZE (sizeof(mem_ref_t) * (MAX_NUM_MEM_REFS - 1))

struct _mem_ref_t buffer[MAX_NUM_MEM_REFS];
int bpos;
int new_write;

struct range {
	unsigned long lower;
	unsigned long upper;

	void *lower_addr;
	void *upper_addr;
};

#define BUFSZ 8192
#define MODUL 8191

#define TESTALL(mask, var) (((mask) & (var)) == (mask))
#define TESTANY(mask, var) (((mask) & (var)) != 0)

void *addr_buf[BUFSZ];
int adddr;
static int buf_pos;
//static int modul = 8191;

/* thread private log file and counter */
typedef struct {
	int param[2];

    char   *buf_ptr;
    char   *buf_base;
    /* buf_end holds the negative value of real address of buffer end. */
    ptr_int_t buf_end; 
    void   *cache;
//    file_t  log;
    uint64  num_refs;
} per_thread_t;

struct access_count {
	unsigned long long read;
	unsigned long long write;
};

struct access_count stack_count;
struct access_count other_count;
struct access_count heap_count;
struct access_count global_count;
struct access_count heap_success;
struct access_count heap_fail;

struct range heap_range;
struct range stack_range;
struct range global_range;

unsigned long syscall_param;

//static app_pc code_cache;


static client_id_t client_id;
//static app_pc code_cache;
static void  *mutex;    /* for multithread support */
static uint64 num_refs; /* keep a global memory reference count */
static int tls_index;

unsigned long offset = 0x20000000;;
static const unsigned long shadowMemSize = 1024 * 1024 * 128 * 3;
pid_t pid;

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
//static void clean_call(void);
//static void memtrace(void *drcontext);
static void code_cache_init(void);
//static void code_cache_exit(void);
/*
static void instrument_mem(void        *drcontext, 
                           instrlist_t *ilist, 
                           instr_t     *where, 
                           int          pos, 
                           bool         write);
						   */

static void event_post_syscall(void *drcontext, int sysnum); 
static dr_signal_action_t event_signal(void *drcontext, dr_siginfo_t *info);

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
	buf_pos = 0;
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
	dr_register_signal_event(event_signal);
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

static dr_signal_action_t event_signal(void *drcontext, dr_siginfo_t *info)
{
	if (info->sig == SIGFPE) {
//        dr_printf("%d \n", buf_pos);
//        dr_printf("%d \n", bpos);
	/*
		app_pc pc = decode_next_pc(drcontext, info->mcontext->xip);
		if (pc != NULL)
			info->mcontext->xip = pc;
		return DR_SIGNAL_REDIRECT;
		*/
	}
	return DR_SIGNAL_DELIVER;
}


static void
event_exit()
{
	unsigned long long read_total = stack_count.read + heap_count.read + global_count.read + other_count.read;
	unsigned long long write_total = stack_count.write + heap_count.write + global_count.write + other_count.write;

	dr_printf("heap %x %x\n", heap_range.lower_addr, heap_range.upper_addr);
	dr_printf("stack %x %x\n", stack_range.lower_addr, stack_range.upper_addr);
	dr_printf("global %x %x\n", global_range.lower_addr, global_range.upper_addr);
	dr_printf("read %d %d\n", global_range.lower_addr, global_range.upper_addr);

	dr_printf("==============================\n");
	dr_printf("Read \n");
	dr_printf("Stack : %llu ", stack_count.read);
	dr_printf("(%.2f)\n", (float)stack_count.read * 100 / read_total);
	dr_printf("Heap  : %llu ", heap_count.read);
	dr_printf("(%.2f)\n", (float)heap_count.read * 100 / read_total);
	dr_printf("	Success : %llu\n", heap_success.read);
	dr_printf("	Fail : %llu\n", heap_fail.read);
	dr_printf("Global : %llu ", global_count.read);
	dr_printf("(%.2f)\n", (float)global_count.read * 100 / read_total);
	dr_printf("Other : %llu ", other_count.read);
	dr_printf("(%.2f)\n", (float)other_count.read * 100 / read_total);
	dr_printf("Total : %llu\n", read_total);
	dr_printf("==============================\n");

	dr_printf("Write \n");
	dr_printf("Stack : %llu ", stack_count.write);
	dr_printf("(%.2f)\n", (float)stack_count.write * 100 / write_total);
	dr_printf("Heap  : %llu ", heap_count.write);
	dr_printf("(%.2f)\n", (float)heap_count.write * 100 / write_total);
	dr_printf("	Success : %llu\n", heap_success.write);
	dr_printf("	Fail : %llu\n", heap_fail.write);
	dr_printf("Global : %llu ", global_count.write);
	dr_printf("(%.2f)\n", (float)global_count.write * 100 / write_total);
	dr_printf("Other : %llu ", other_count.write);
	dr_printf("(%.2f)\n", (float)other_count.write * 100 / write_total);
	dr_printf("Total : %llu\n", write_total);
	dr_printf("==============================\n");

					  /*
    len = dr_snprintf(msg, sizeof(msg)/sizeof(msg[0]),
                      "load  %llu\n"
                      "store %llu\n",
                      load_count, store_count);
    dr_snprintf(msg, sizeof(msg)/sizeof(msg[0]), "load  %lu\n", load_count);
    dr_snprintf(msg, sizeof(msg)/sizeof(msg[0]), "store %lu\n", store_count);
	*/

/*
	dr_fprintf(STDERR, "load %lu\n", load_count);
	dr_fprintf(STDERR, "store %lu\n", store_count);
	*/

//    DR_ASSERT(len > 0);
//    NULL_TERMINATE(msg);
//    DISPLAY_STRING(msg);
//    code_cache_exit();
//    drmgr_unregister_tls_field(tls_index);
//    dr_mutex_destroy(mutex);
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

//    memtrace(drcontext);
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

int check_alloc_read(unsigned long addr, int size)
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
	heap_success.read += ct;
	heap_fail.read += size - ct;
	return ct;
}

int check_alloc_write(unsigned long addr, int size)
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
	heap_success.write += ct;
	heap_fail.write += size - ct;
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
*/

/*
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
//   dr_printf("wha????\n");
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
#else
    dr_write_file(data->log, data->buf_base,
                  (size_t)(data->buf_ptr - data->buf_base));
#endif

    memset(data->buf_base, 0, MEM_BUF_SIZE);
    data->num_refs += num_refs;
    data->buf_ptr   = data->buf_base;
}
*/

/* clean_call dumps the memory reference info to the log file */
/*
static void
clean_call(void)
{
    void *drcontext = dr_get_current_drcontext();
    memtrace(drcontext);
}
*/

static void
code_cache_init(void)
{
    void         *drcontext;

    drcontext  = dr_get_current_drcontext();
	/*
    code_cache = dr_nonheap_alloc(PAGE_SIZE, 
                                  DR_MEMPROT_READ  |
                                  DR_MEMPROT_WRITE |
                                  DR_MEMPROT_EXEC);
    ilist = instrlist_create(drcontext);
    where = INSTR_CREATE_jmp_ind(drcontext, opnd_create_reg(DR_REG_XCX));
    instrlist_meta_append(ilist, where);
    dr_insert_clean_call(drcontext, ilist, where, (void *)clean_call, false, 0);
    end = instrlist_encode(drcontext, ilist, code_cache, false);
    DR_ASSERT((end - code_cache) < PAGE_SIZE);
    instrlist_clear_and_destroy(drcontext, ilist);
    dr_memory_protect(code_cache, PAGE_SIZE, DR_MEMPROT_READ | DR_MEMPROT_EXEC);
	dr_printf("code_cache %x \n", code_cache);
	*/
}


/*
static void
code_cache_exit(void)
{
    dr_nonheap_free(code_cache, PAGE_SIZE);
}
*/
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

static void print_space()
{
}

static void read_map()
{
	int i;
	int buff_size;
	int read_size = 32;
	int made_line;
	int prev_line_size;
	FILE *proc_map;
	char buff[10];
	char name[20] = "/proc/";
	char line[256];
	char prev_line[256];
	char temp_line[256];
	struct rlimit limit;
	struct rlimit rl;
	struct rlimit rl2;

	pid = getpid();
	sprintf(buff, "%d", pid);
	strncpy(name + 6, buff, strlen(buff));
	strcat(name, "/maps");
	
	proc_map = fopen(name, "r");

	getrlimit(RLIMIT_STACK, &limit);

	global_range.lower = 0x8048000;
	global_range.lower_addr = (void *)global_range.lower;
	buff_size = fread(line, 1, read_size, proc_map);
	prev_line_size = 0;

	made_line = 0;

	for (i = buff_size - 1; i >= 0; i--)
		if (line[i] == '\n') {
			strncpy(prev_line + prev_line_size, line, i);
			prev_line[prev_line_size + i] = '\x0';
			made_line = 1;
			break;
		}
		else if (i == 0) {
			strncpy(prev_line, line, buff_size);
			prev_line_size = buff_size;
			prev_line[buff_size] = '\x0';
			made_line = 0;
		}

	while (buff_size == read_size) {
		buff_size = fread(line, 1, read_size, proc_map);
	//	buff_size = fgets(line, read_size, proc_map);

		for (i = buff_size - 1; i >= 0; i--)
			if (line[i] == '\n') {
				strncpy(prev_line + prev_line_size, line, i);
				prev_line[prev_line_size + i] = '\x0';
				prev_line_size += i;
				
				if (!strncmp(prev_line + prev_line_size - strlen(STACK), STACK, strlen(STACK))) {

					sscanf(prev_line, "%x-%x", (unsigned int *)&stack_range.lower, (unsigned int *)&stack_range.upper);
//					stack_range.upper = VG_(strtoull16)(temp_s2, NULL);

					getrlimit(RLIMIT_STACK, &rl);
					getrlimit(RLIMIT_DATA, &rl2);
					stack_range.lower = stack_range.upper - rl.rlim_cur;

					stack_range.lower_addr = (void *)stack_range.lower;
					stack_range.upper_addr = (void *)stack_range.upper;

//					heap_range.upper = stack_range.lower;
//					heap_range.upper_addr  = (void *)heap_range.upper;

//					dr_fprintf(STDERR, "stack %x %x\n", stack_range.lower, stack_range.upper);
				}
				strcpy(temp_line, prev_line);
				i++;
				strncpy(prev_line, line + i, buff_size - i);
				prev_line_size = buff_size - i;

				break;
			}
			else if (i == 0) {
				strncpy(prev_line + prev_line_size, line, buff_size);
				prev_line_size += buff_size;
				prev_line[prev_line_size] = '\x0';
				made_line = 0;
			}
	}

	fclose(proc_map);
}

static void reserve_shadow_map()
{
	void *protect_addr;
	
	offset = (unsigned long) mmap((void *)offset, shadowMemSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	protect_addr = (void *)((offset >> 3) + offset);
	if (mprotect(protect_addr, shadowMemSize / 8, PROT_NONE) < 0) {
		dr_fprintf(STDERR, "Shadow Memory Protection Error\n");
	}
}

void print_addr()
{
	printf("pos = %p %p\n", (void *)adddr, buffer);
}

void add_check_add_range(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg2, opnd_t ref, int write,  instr_t *label, struct range *range, struct access_count *count)
{
    instr_t *instr;
    opnd_t  opnd1, opnd2;

    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_ABSMEM((byte *)&range->lower, OPSZ_4);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_instr(label);
    instr = INSTR_CREATE_jcc_short(drcontext, OP_jna, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_ABSMEM((byte *)&range->upper, OPSZ_4);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_instr(label);
    instr = INSTR_CREATE_jcc(drcontext, OP_ja, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

	if (write) {
		opnd1 = OPND_CREATE_ABSMEM((byte *)&count->write, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(drutil_opnd_mem_size_in_bytes(ref, where));
		instr = INSTR_CREATE_add(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);

		opnd1 = OPND_CREATE_ABSMEM((byte *)&count->write + 4, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(0);
		instr = INSTR_CREATE_adc(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);

/*
		opnd1 = OPND_CREATE_ABSMEM((byte *)&count->write + 8, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(0);
		instr = INSTR_CREATE_adc(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);
		
		opnd1 = OPND_CREATE_ABSMEM((byte *)&count->write + 12, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(0);
		instr = INSTR_CREATE_adc(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);
		*/
	}
	else {
		opnd1 = OPND_CREATE_ABSMEM((byte *)&count->read, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(drutil_opnd_mem_size_in_bytes(ref, where));
		instr = INSTR_CREATE_add(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);

		opnd1 = OPND_CREATE_ABSMEM((byte *)&count->read + 4, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(0);
		instr = INSTR_CREATE_adc(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);
		/*

		opnd1 = OPND_CREATE_ABSMEM((byte *)&count->read + 8, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(0);
		instr = INSTR_CREATE_adc(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);
		
		opnd1 = OPND_CREATE_ABSMEM((byte *)&count->read + 12, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(0);
		instr = INSTR_CREATE_adc(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);
		*/
	}

}

/*
void print_addr_call(unsigned long addr)
{
	printf("%p %p %p\n ", global_range.lower_addr, (void *)addr, global_range.upper_addr);
}
*/

/*
static void
instrument_mem_check(void *drcontext, instrlist_t *ilist, instr_t *where, 
               int pos, bool write)
{
    instr_t *instr;
//	instr_t *stack_label, *heap_label;
	instr_t *heap_label, *stack_label, *global_label, *other_label;
	instr_t *end_label;
    opnd_t   ref, opnd1, opnd2;
//    reg_id_t reg1 = DR_REG_XBX; 
    reg_id_t reg2 = DR_REG_XCX; 
    reg_id_t reg3 = DR_REG_XAX;
	uint flags;
	uint save = 0;

    if (write)
       ref = instr_get_dst(where, pos);
    else
       ref = instr_get_src(where, pos);

	flags = instr_get_arith_flags(where);
	if (!(TESTALL(EFLAGS_WRITE_6, flags) && !TESTANY(EFLAGS_READ_6, flags))) {
		dr_save_reg(drcontext, ilist, where, reg3, SPILL_SLOT_1);
		dr_save_arith_flags_to_xax(drcontext, ilist, where);	
		save = 1;
	}
	else 
		dr_save_reg(drcontext, ilist, where, reg3, SPILL_SLOT_1);
    dr_save_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);

    drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg2, reg3);

	end_label = INSTR_CREATE_label(drcontext);

	stack_label = INSTR_CREATE_label(drcontext);
	add_check_add_range(drcontext, ilist, where, reg2, ref, write, stack_label, &stack_range, &stack_count);

    opnd1 = opnd_create_instr(end_label);
    instr = INSTR_CREATE_jcc_short(drcontext, OP_jmp, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    instrlist_meta_preinsert(ilist, where, stack_label);

	heap_label = INSTR_CREATE_label(drcontext);
	add_check_add_range(drcontext, ilist, where, reg2, ref, write, heap_label, &heap_range, &heap_count);
	
    opnd1 = opnd_create_instr(end_label);
    instr = INSTR_CREATE_jcc(drcontext, OP_jmp, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);
    instrlist_meta_preinsert(ilist, where, heap_label);

	global_label = INSTR_CREATE_label(drcontext);
	add_check_add_range(drcontext, ilist, where, reg2, ref, write, global_label, &global_range, &global_count);

//	dr_insert_clean_call(drcontext, ilist, where, 
//	(void *)print_addr_call, false , 1,
//	opnd_create_reg(reg2));


    opnd1 = opnd_create_instr(end_label);
    instr = INSTR_CREATE_jcc(drcontext, OP_jmp, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);
    instrlist_meta_preinsert(ilist, where, global_label);

	other_label = INSTR_CREATE_label(drcontext);

	if (write) {
		opnd1 = OPND_CREATE_ABSMEM((byte *)&other_count.write, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(drutil_opnd_mem_size_in_bytes(ref, where));
		instr = INSTR_CREATE_add(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);

		opnd1 = OPND_CREATE_ABSMEM((byte *)&other_count.write + 4, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(0);
		instr = INSTR_CREATE_adc(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);
	}
	else {
		opnd1 = OPND_CREATE_ABSMEM((byte *)&other_count.read, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(drutil_opnd_mem_size_in_bytes(ref, where));
		instr = INSTR_CREATE_add(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);

		opnd1 = OPND_CREATE_ABSMEM((byte *)&other_count.read + 4, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(0);
		instr = INSTR_CREATE_adc(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);
	}

    instrlist_meta_preinsert(ilist, where, end_label);

	if (save) {
		dr_restore_arith_flags_from_xax(drcontext, ilist, where);
	}
	dr_restore_reg(drcontext, ilist, where, reg3, SPILL_SLOT_1);
//    dr_restore_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
    dr_restore_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);
}
*/
static void
instrument_mem_shadow(void *drcontext, instrlist_t *ilist, instr_t *where, 
               int pos, bool write)
{
    instr_t *instr;
//	instr_t *stack_label, *heap_label;
	instr_t *heap_label, *stack_label, *global_label, *other_label;
	instr_t *end_label;
    opnd_t   ref, opnd1, opnd2;
//    reg_id_t reg1 = DR_REG_XBX; 
    reg_id_t reg2 = DR_REG_XCX; 
    reg_id_t reg3 = DR_REG_XAX;
	uint flags;
	uint save = 0;

    if (write)
       ref = instr_get_dst(where, pos);
    else
       ref = instr_get_src(where, pos);

	flags = instr_get_arith_flags(where);
	if (!(TESTALL(EFLAGS_WRITE_6, flags) && !TESTANY(EFLAGS_READ_6, flags))) {
		dr_save_reg(drcontext, ilist, where, reg3, SPILL_SLOT_1);
		dr_save_arith_flags_to_xax(drcontext, ilist, where);	
		save = 1;
	}
	else 
		dr_save_reg(drcontext, ilist, where, reg3, SPILL_SLOT_1);
    dr_save_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);

    drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg2, reg3);

	end_label = INSTR_CREATE_label(drcontext);

	stack_label = INSTR_CREATE_label(drcontext);
	add_check_add_range(drcontext, ilist, where, reg2, ref, write, stack_label, &stack_range, &stack_count);

    opnd1 = opnd_create_instr(end_label);
    instr = INSTR_CREATE_jcc_short(drcontext, OP_jmp, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    instrlist_meta_preinsert(ilist, where, stack_label);

	heap_label = INSTR_CREATE_label(drcontext);
	add_check_add_range(drcontext, ilist, where, reg2, ref, write, heap_label, &heap_range, &heap_count);
	
    if (write)
		dr_insert_clean_call(drcontext, ilist, where, 
			(void *)check_alloc_write, false, 2,
			opnd_create_reg(reg2), OPND_CREATE_INT32(drutil_opnd_mem_size_in_bytes(ref, where)));
	else
		dr_insert_clean_call(drcontext, ilist, where, 
			(void *)check_alloc_read, false, 2,
			opnd_create_reg(reg2), OPND_CREATE_INT32(drutil_opnd_mem_size_in_bytes(ref, where)));

    opnd1 = opnd_create_instr(end_label);
    instr = INSTR_CREATE_jcc(drcontext, OP_jmp, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);
    instrlist_meta_preinsert(ilist, where, heap_label);

	global_label = INSTR_CREATE_label(drcontext);
	add_check_add_range(drcontext, ilist, where, reg2, ref, write, global_label, &global_range, &global_count);

//	dr_insert_clean_call(drcontext, ilist, where, 
//	(void *)print_addr_call, false , 1,
//	opnd_create_reg(reg2));


    opnd1 = opnd_create_instr(end_label);
    instr = INSTR_CREATE_jcc(drcontext, OP_jmp, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);
    instrlist_meta_preinsert(ilist, where, global_label);

	other_label = INSTR_CREATE_label(drcontext);

	if (write) {
		opnd1 = OPND_CREATE_ABSMEM((byte *)&other_count.write, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(drutil_opnd_mem_size_in_bytes(ref, where));
		instr = INSTR_CREATE_add(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);

		opnd1 = OPND_CREATE_ABSMEM((byte *)&other_count.write + 4, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(0);
		instr = INSTR_CREATE_adc(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);
	}
	else {
		opnd1 = OPND_CREATE_ABSMEM((byte *)&other_count.read, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(drutil_opnd_mem_size_in_bytes(ref, where));
		instr = INSTR_CREATE_add(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);

		opnd1 = OPND_CREATE_ABSMEM((byte *)&other_count.read + 4, OPSZ_4);
		opnd2 = OPND_CREATE_INT32(0);
		instr = INSTR_CREATE_adc(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(ilist, where, instr);
	}

    instrlist_meta_preinsert(ilist, where, end_label);

	if (save) {
		dr_restore_arith_flags_from_xax(drcontext, ilist, where);
	}
	dr_restore_reg(drcontext, ilist, where, reg3, SPILL_SLOT_1);
//    dr_restore_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
    dr_restore_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);
}

/*
static void
instrument_mem_buffer(void *drcontext, instrlist_t *ilist, instr_t *where, 
               int pos, bool write)
{
//    instr_t *instr, *call, *restore;
    instr_t *instr;
    opnd_t   ref, opnd1, opnd2;
    reg_id_t reg1 = DR_REG_XAX; 
    reg_id_t reg2 = DR_REG_XCX; 

//	uint flags, dead;

    if (write)
       ref = instr_get_dst(where, pos);
    else
       ref = instr_get_src(where, pos);


    dr_save_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
    dr_save_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);

    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_ABSMEM((byte *)&buf_pos, OPSZ_4);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

	// reg2 = buf_pos
    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_ABSMEM((byte *)&buf_pos, OPSZ_4);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

	// reg1 = &buffer
    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_INTPTR(buffer);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

	// reg1 = reg1 + reg2 * sizeof(mem_ref_t)
	// 		= buffer + buf_pos * sizeof(mem_ref_t)
	// 		= buffer[buf_pos]
    opnd1 = opnd_create_reg(reg1);
    opnd2 = opnd_create_base_disp(reg1, reg2, sizeof(mem_ref_t), 0, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

	// buffer[buf_pos].write = write
    opnd1 = OPND_CREATE_MEMPTR(reg1, offsetof(mem_ref_t, write));
    opnd2 = OPND_CREATE_INT32(write);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

	// buffer[buf_pos].size = mem_size 
    opnd1 = OPND_CREATE_MEMPTR(reg1, offsetof(mem_ref_t, size));
    opnd2 = OPND_CREATE_INT32(drutil_opnd_mem_size_in_bytes(ref, where));
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

	// buffer[buf_pos].addr = addr;
    opnd1 = OPND_CREATE_MEMPTR(reg1, offsetof(mem_ref_t, addr));
    drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg2, reg1);
    opnd2 = opnd_create_reg(reg2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

	dr_save_arith_flags_to_xax(drcontext, ilist, where);	

    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_ABSMEM((byte *)&buf_pos, OPSZ_4);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(reg2);
    instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_INT32(0x00001fff);
    instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = OPND_CREATE_ABSMEM((byte *)&buf_pos, OPSZ_4);
    opnd2 = opnd_create_reg(reg2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

	dr_restore_arith_flags_from_xax(drcontext, ilist, where);

    dr_restore_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
    dr_restore_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);
}
*/

/* event_bb_insert calls instrument_mem to instrument every
 * application memory reference.
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
                instrument_mem_shadow(drcontext, bb, instr, i, false);
            }
        }
    }
    if (instr_writes_memory(instr)) {
        for (i = 0; i < instr_num_dsts(instr); i++) {
            if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
                instrument_mem_shadow(drcontext, bb, instr, i, true);
            }
        }
    }
//   dr_printf("%d\n", buf_pos);
    return DR_EMIT_DEFAULT;
}


