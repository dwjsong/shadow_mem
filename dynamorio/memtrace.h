#ifdef LINUX
  #include <syscall.h>
#endif

#define BRK_SYSCALL 45
#define MUNMAP_SYSCALL 91
#define MMAP_SYSCALL 192

#define STACK "[stack]"
#define HEAP "[heap]"

typedef struct _mem_ref_t{
    bool  write;
    void *addr;
    size_t size;
} mem_ref_t;

#define MAX_NUM_MEM_REFS 1
#define MEM_BUF_SIZE (sizeof(mem_ref_t) * MAX_NUM_MEM_REFS)

struct range {
	unsigned long lower;
	unsigned long upper;

	void *lower_addr;
	void *upper_addr;
};

typedef struct {
	int param0;
	int param1;

    char   *buf_ptr;
    char   *buf_base;
    ptr_int_t buf_end; 
    uint64  num_refs;
} per_thread_t;

struct access_count {
	unsigned long read;
	unsigned long write;
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

static app_pc code_cache;
static void print_space();
static void event_post_syscall(void *drcontext, int sysnum);
static bool event_pre_syscall(void *drcontext, int sysnum);
static bool event_filter_syscall(void *drcontext, int sysnum);
static void reserve_shadow_map();
static void event_thread_init(void *drcontext);
static void event_thread_exit(void *drcontext);
static void event_exit();
static dr_emit_flags_t event_basic_block(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating);
static void instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where, int pos, bool write);
static void clean_call(void);
static void code_cache_init(void);
static void code_cache_exit(void);
static int check_alloc(unsigned long addr, int size);
static void trace_load(unsigned long addr, int size);
static void trace_store(unsigned long addr, int size);
static dr_signal_action_t event_signal(void *drcontext, dr_siginfo_t *info);


static void percentify(unsigned long a, unsigned long b, char *transformed);
