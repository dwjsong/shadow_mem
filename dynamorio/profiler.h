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
    size_t size;
} mem_ref_t;

/* Control the format of memory trace: readable or hexl */
#define READABLE_TRACE 
/* Max number of mem_ref a buffer can have */
#define MAX_NUM_MEM_REFS 8192 * 16
/* The size of memory buffer for holding mem_refs. When it fills up, 
 * we dump data from the buffer to the file.
 */
#define MEM_BUF_SIZE (sizeof(mem_ref_t) * MAX_NUM_MEM_REFS)
struct range {
	unsigned long lower;
	unsigned long upper;

	void *lower_addr;
	void *upper_addr;
};

#define BUFSZ 8192
#define MODUL 8191

void *addr_buf[BUFSZ];
int buf_pos;

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


static client_id_t client_id;
static app_pc code_cache;
static void  *mutex;    /* for multithread support */
static uint64 num_refs; /* keep a global memory reference count */
static int tls_index;

unsigned long offset = 0x20000000;;
static const unsigned long shadowMemSize = 1024 * 1024 * 128 * 3;
pid_t pid;

