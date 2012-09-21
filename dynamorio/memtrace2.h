/*
 * syscall numbers
 */

#define BRK_SYSCALL 45
#define MUNMAP_SYSCALL 91
#define MMAP_SYSCALL 192

/*
 * symbols for /proc/<pid>/map
 */
#define STACK "[stack]"
#define HEAP "[heap]"

#define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
#define NULL_TERMINATE(buf) buf[(sizeof(buf)/sizeof(buf[0])) - 1] = '\0'


/* Control the format of memory trace: readable or hexl */
#define READABLE_TRACE 
/* Max number of mem_ref a buffer can have */
#define MAX_NUM_MEM_REFS 8192 * 16


/* 
 * The size of memory buffer for holding mem_refs. When it fills up, we dump
 * data from the buffer to the file.
 */
#define MEM_BUF_SIZE (sizeof(mem_ref_t) * MAX_NUM_MEM_REFS)

/* more defines */
#define BUFSZ 8192
#define MODUL 8191


/* 
 * Types 
 */

/*
 * Each mem_ref_t includes the type of reference (read or write), the address
 * referenced, and the size of the reference.
 */
typedef struct _mem_ref_t{
    bool  write;
    void *addr;
    size_t size;
} mem_ref_t;


/* range type */
typedef struct range {
	unsigned long lower;
	unsigned long upper;

	void *lower_addr;
	void *upper_addr;
} range_t;


/* thread private log file and counter */
typedef struct {
	int param[2];
    char   *buf_ptr;
    char   *buf_base;
    /* buf_end holds the negative value of real address of buffer end. */
    ptr_int_t buf_end; 
    void   *cache;
    uint64  num_refs;
} per_thread_t;

/* counter for read/write access */
typedef struct access_count {
	unsigned long read;
	unsigned long write;
} access_count_t;


/* 
 * Function definitions
 */

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
