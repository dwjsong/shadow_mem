#ifndef __PF_INCLUDE_H
#define __PF_INCLUDE_H

typedef 
enum { Event_Load, Event_Store }
EventKind;

typedef
struct {
	EventKind  ekind;
	IRExpr*    addr;
	Int        size;
} Event;

typedef struct {
	unsigned char bits;
} Shadow;

extern Addr reserve_map;

extern Int xx;
extern Int stt;
extern Int map_size;
extern Int unmap;

//static const ULong shadowMemSize = 1024 * 1024 * 128 * 3;
extern ULong shadowMemSize;

#define MAX_EVENTS 4

extern Event eventList[MAX_EVENTS];
extern Int   eventCount;

extern ULong loadCount;
extern ULong storeCount;

struct mov_count {
	ULong read;
	ULong write;
};

extern struct mov_count stack_count;
extern struct mov_count other_count;
extern struct mov_count heap_count;
extern struct mov_count global_count;

extern struct mov_count heap_success;
extern struct mov_count heap_fail;

struct range {
	unsigned long lower;
	unsigned long upper;

	void *lower_addr;
	void *upper_addr;
};

extern struct range heap_range;
extern struct range stack_range;
extern struct range global_range;

extern Int start;

#define __NR_mmap2 192

#define PROT_READ	0x1
#define PROT_WRITE	0x2
#define MAP_SHARED	0x01
#define MAP_ANONYMOUS	0x20

#define BRK_SYSCALL 45
#define MUNMAP_SYSCALL 91
#define MMAP_SYSCALL 192

#define STACK "[stack]"
#define HEAP "[heap]"

#define BUFSZ 8192
#define MODUL 8191

extern Addr add_buf[BUFSZ];
extern int buf_pos;

VG_REGPARM(2) void trace_load(Addr addr, SizeT size);
VG_REGPARM(2) void trace_store(Addr addr, SizeT size);
VG_REGPARM(2) void trace_load2(Addr addr, SizeT size);
VG_REGPARM(2) void trace_store2(Addr addr, SizeT size);
VG_REGPARM(2) void trace_load3(Addr addr, SizeT size);
VG_REGPARM(2) void trace_store3(Addr addr, SizeT size);
VG_REGPARM(2) void trace_load4(Addr addr, SizeT size);
VG_REGPARM(2) void trace_store4(Addr addr, SizeT size);
void flushEvents(IRSB* sb);
void addLoadEvent(IRSB *sb, IRExpr* addr, Int size);
void addStoreEvent(IRSB *sb, IRExpr* addr, Int size);
void pre_syscall(ThreadId tid, UInt syscallno, UWord* args, UInt nArgs);
void post_syscall(ThreadId tid, UInt syscallno, UWord* args, UInt nArgs, SysRes res);
void check_mem_map();
void reserve_shadow_memory();
void free_shadow_memory();
Int check_map(ULong addr, Int size);
Int mark_alloc(ULong addr, Int size);
Int unmark_alloc(ULong addr, Int size);

#endif
