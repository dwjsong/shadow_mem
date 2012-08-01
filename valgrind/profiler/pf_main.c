#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)
#include "valgrind.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcfile.h"

#include "config.h"

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

Shadow shadow_map[402653184];
//unsigned Int offset = 0x20000000;

Int xx = 0;

//static const ULong shadowMemSize = 1024 * 1024 * 128 * 3;
static const ULong shadowMemSize = 1024;

#define MAX_EVENTS 4

static Event eventList[MAX_EVENTS];
static Int   eventCount= 0;

static ULong loadCount = 0;
static ULong storeCount = 0;

struct mov_count {
	ULong read;
	ULong write;
};

struct mov_count stack_count;
struct mov_count other_count;
struct mov_count heap_count;
struct mov_count global_count;

struct mov_count heap_success;
struct mov_count heap_fail;

struct range {
	unsigned long lower;
	unsigned long upper;

	void *lower_addr;
	void *upper_addr;
};

struct range heap_range;
struct range stack_range;
struct range global_range;

Int start;

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

static void check_mem_map()
{
	Int i;
	Int buff_size;
	Int pid;
	Int fd;
	Int prev_line_size;
	Int read_size = 32;
	Int made_line;
	SysRes res;
	Char buff[10];
	Char name[20] = "/proc/";
	Char line[256];
	Char prev_line[256];
	Char temp_s[16];
	Char temp_s2[16];
	struct range temp;
	ULong tt;
	
	pid = VG_(getpid)();
	VG_(sprintf)(buff, "%d", pid);
	VG_(strncpy)(name + 6, buff, VG_(strlen)(buff));
	VG_(strcat)(name, "/maps");

	VG_(printf)("pid = %s %d\n", name, pid);

	res = VG_(open)(name, 0, 0);
	fd = (Int) sr_Res(res);

	buff_size = VG_(read)(fd, line, read_size);
	prev_line_size = 0;

	made_line = 0;
	for (i = buff_size - 1; i >= 0; i--)
		if (line[i] == '\n') {
			VG_(strncpy)(prev_line + prev_line_size, line, i);
			prev_line[prev_line_size + i] = '\x0';
			made_line = 1;
			break;
		}
		else if (i == 0) {
			VG_(strncpy)(prev_line, line, buff_size);
			prev_line_size = buff_size;
			prev_line[buff_size] = '\x0';
			made_line = 0;
		}


	while (buff_size == read_size) {

		buff_size = VG_(read)(fd, line, read_size);

		for (i = buff_size - 1; i >= 0; i--)
			if (line[i] == '\n') {
				VG_(strncpy)(prev_line + prev_line_size, line, i);
				prev_line[prev_line_size + i] = '\x0';
				prev_line_size += i;
				VG_(printf)("%s\n", prev_line);
		//		VG_(printf)("===========================================\n");
				
				if (!VG_(strncmp)(prev_line + prev_line_size - VG_(strlen)(STACK), STACK, VG_(strlen)(STACK))) {

					VG_(strncpy)(temp_s, prev_line, 8);
					
					stack_range.lower = VG_(strtoull16)(temp_s, NULL);
					VG_(strncpy)(temp_s2, prev_line + 9, 8);
					stack_range.upper = VG_(strtoull16)(temp_s2, NULL);


					stack_range.lower_addr = (void *)stack_range.lower;
					stack_range.upper_addr = (void *)stack_range.upper;
					

					heap_range.upper = stack_range.lower;
					heap_range.upper_addr  = (void *)heap_range.upper;
				}
				VG_(strncpy)(prev_line, line + ++i, buff_size - i);
				prev_line_size = buff_size - i;

				break;
			}
			else if (i == 0) {
				VG_(strncpy)(prev_line + prev_line_size, line, buff_size);
				prev_line_size += buff_size;
				prev_line[prev_line_size] = '\x0';
				made_line = 0;
			}
//		VG_(printf)("%d\n", buff_size);
	}

	VG_(close)(name);
}

static void reserveShadowMemory()
{
	Addr a = 0x20000000;
//	VG_(do_syscall)(__NR_mmap2, NULL, 4096, 0, 0, -1, 0, 0, 0);
//	vgPlain_do_syscall(1);
	//PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0, 0, 0);
//	offset = VG_(do_syscall)(__NR_mmap2, (void *)offset, (SizeT)shadowMemSize, (UInt)PROT_READ | PROT_WRITE, (UInt)MAP_SHARED | MAP_ANONYMOUS, (UInt)-1, (UInt)0);
//	VG_(printf)("Shadow Memory %p\n", (void *)offset);
//	offset = (Int) syscall(__NR_mmap2, (void *)offset, shadowMemSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	/*
	protect_addr = (void *)((offset >> 3) + offset);


	if (mprotect(protect_addr, shadowMemSize / 8, PROT_NONE) < 0) {
		VG_(printf)("Shadow Memory Protection Error\n");
	}
	*/
}

static void freeShadowMemory()
{
	/*
	Int ret = munmap((void *)offset, shadowMemSize);

	if (ret < 0)
		VG_(printf)("Shadow Memory at %p Free Failed!\n", (void *)offset);
	*/
	
}

static VG_REGPARM(2) void trace_load(Addr addr, SizeT size)
{
	Int count;
	ULong addr_val = (unsigned long) addr;

	if (global_range.upper > addr_val) {
		global_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.read += size;
		count = checkShadowMap(addr, size);
		heap_success.read += count;
		heap_fail.read += size - count;
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
}

static VG_REGPARM(2) void trace_store(Addr addr, SizeT size)
{
	Int count; 
	ULong addr_val = (unsigned long) addr;

	if (global_range.upper > addr_val) {
		global_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.write += size;
		count = checkShadowMap(addr, size);
		heap_success.write += count;
		heap_fail.write += size - count;
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
}

static void flushEvents(IRSB* sb)
{
	Int        i;
	Char*      helperName;
	void*      helperAddr;
	IRExpr**   argv;
	IRDirty*   di;
	Event*     ev;

	for (i = 0; i < eventCount; i++) {

		ev = &eventList[i];

		switch (ev->ekind) {

			case Event_Load : 
				helperName = "trace_load";
				helperAddr =  trace_load;  
				break;

			case Event_Store : 
				helperName = "trace_store";
				helperAddr =  trace_store;  
				break;

		}

		argv = mkIRExprVec_2( ev->addr, mkIRExpr_HWord( ev->size ) );
		di   = unsafeIRDirty_0_N( /*regparms*/2, 
				helperName, VG_(fnptr_to_fnentry)( helperAddr ),
				argv );
		addStmtToIRSB( sb, IRStmt_Dirty(di) );
	}

	eventCount = 0;
}

static void addLoadEvent(IRSB *sb, IRExpr* addr, Int size)
{
	Event* evt;

	if (eventCount == MAX_EVENTS)
		flushEvents(sb);
	evt = &eventList[eventCount];
	evt->ekind = Event_Load;
	evt->addr = addr;
	evt->size = size;
	eventCount++;
}

static void addStoreEvent(IRSB *sb, IRExpr* addr, Int size)
{
	Event* evt;

	if (eventCount == MAX_EVENTS)
		flushEvents(sb);
	evt = &eventList[eventCount];
	evt->ekind = Event_Store;
	evt->addr = addr;
	evt->size = size;
	eventCount++;
}

static void pf_post_clo_init(void)
{
}

	static
IRSB* pf_instrument ( VgCallbackClosure* closure,
		IRSB* sbIn,
		VexGuestLayout* layout, 
		VexGuestExtents* vge,
		IRType gWordTy, IRType hWordTy )
{
	Int i;
	IRSB*      sbOut;
	IRDirty*   di;
	IRTypeEnv* tyenv = sbIn->tyenv;


	// Make a new SB for return
	sbOut = deepCopyIRSBExceptStmts(sbIn);

	eventCount = 0;

	// check every statement in BB
	for (i = 0; i < sbIn->stmts_used; i++) {
		IRStmt* stmt = sbIn->stmts[i];

		if (!stmt || stmt->tag == Ist_NoOp) continue;

//		ppIRStmt(stmt);
//		VG_(printf)("\n");

		// what kind of statement is it?
		switch (stmt->tag) {
			// Nothing to do with these instructions
			case Ist_NoOp:
			case Ist_AbiHint:
			case Ist_Put:
			case Ist_PutI:
			case Ist_MBE:
			case Ist_IMark:
				addStmtToIRSB( sbOut, stmt );
				break;

			case Ist_WrTmp : {
								 IRExpr *data = stmt->Ist.WrTmp.data;

								 if (data->tag == Iex_Load) {
									 addLoadEvent(sbOut, data->Iex.Load.addr, 
											 sizeofIRType(data->Iex.Load.ty));
								 }
								 addStmtToIRSB( sbOut, stmt );
								 break;
							 }

			case Ist_Store : {
								 IRExpr *data = stmt->Ist.Store.data;
								 addStoreEvent(sbOut, stmt->Ist.Store.addr,
										 sizeofIRType(typeOfIRExpr(tyenv, data)) );
								 addStmtToIRSB( sbOut, stmt );
								 break;
							 }
			case Ist_LLSC : {
								IRType dataTy;
								if (stmt->Ist.LLSC.storedata == NULL) {
									/* LL */
									dataTy = typeOfIRTemp(tyenv, stmt->Ist.LLSC.result);
									addLoadEvent( sbOut, stmt->Ist.LLSC.addr,
											sizeofIRType(dataTy) );
								} else {
									/* SC */
									dataTy = typeOfIRExpr(tyenv, stmt->Ist.LLSC.storedata);
									addStoreEvent( sbOut, stmt->Ist.LLSC.addr,
											sizeofIRType(dataTy) );
								}
								addStmtToIRSB( sbOut, stmt );
								break;
							}
			case Ist_Dirty: {
								Int      dsize;
								IRDirty* d = stmt->Ist.Dirty.details;
								if (d->mFx != Ifx_None) {
									// This dirty helper accesses memory.  Collect the details.
									dsize = d->mSize;
									if (d->mFx == Ifx_Read || d->mFx == Ifx_Modify)
										addLoadEvent( sbOut, d->mAddr, dsize );
									if (d->mFx == Ifx_Write || d->mFx == Ifx_Modify)
										addStoreEvent( sbOut, d->mAddr, dsize );
								} else {
								}
								addStmtToIRSB( sbOut, stmt );
								break;
							}

			case Ist_CAS: 
							{
								/* We treat it as a read and a write of the location.  I
								   think that is the same behaviour as it was before IRCAS
								   was introduced, since prior to that point, the Vex
								   front ends would translate a lock-prefixed instruction
								   into a (normal) read followed by a (normal) write. */
								Int    dataSize;
								IRType dataTy;
								IRCAS* cas = stmt->Ist.CAS.details;
								dataTy   = typeOfIRExpr(tyenv, cas->dataLo);
								dataSize = sizeofIRType(dataTy);
								if (cas->dataHi != NULL)
									dataSize *= 2; /* since it's a doubleword-CAS */

								addLoadEvent( sbOut, cas->addr, dataSize );
								addStoreEvent( sbOut, cas->addr, dataSize );

								addStmtToIRSB( sbOut, stmt );
								break;
							}


			case Ist_Exit:
							flushEvents(sbOut);

							addStmtToIRSB( sbOut, stmt );      // Original statement
							break;


			default :
							break;
		}


	}

	return sbOut;
}

Int checkShadowMap(ULong addr, Int size)
{
	Int i;
	Int ct = 0;
	Int idx;
	char wh;
	ULong tmp_addr;
	ULong new_addr;
	unsigned char *temp_addr;
	ULong offset;

	tmp_addr = addr;
	offset = shadow_map;
//	if (start)
//		VG_(printf)("check offset %p shadow_map %p check shadow_map %p offset %p size %d\n", (void *)offset, shadow_map, shadow_map[(tmp_addr >> 3)], (void *)((tmp_addr >> 3) + offset), size);

	for (i = 0; i < size; i++) {
		idx = (tmp_addr + i) >> 3;
//		new_addr = offset[(tmp_addr + i) >> 3];
//		new_addr = ((tmp_addr + i) >> 3) + offset;
//		temp_addr = (unsigned char *)new_addr;
//		temp_addr = (unsigned char *)shadow_map[(tmp_addr + i) >> 3];
		wh = (tmp_addr + i) & 7;
		wh = ((shadow_map[idx].bits >> wh) & 1);
//		VG_(printf)("	heap range %lu %lu %p %p \n", heap_range.lower, heap_range.upper, heap_range.lower_addr, heap_range.upper_addr);
//		VG_(printf)("	check %p %p %d \n", shadow_map, shadow_map[idx], shadow_map[idx].bits);
		ct += wh;
	}
	return ct;
}

Int unmarkMalloc(ULong addr, Int size)
{
	Int i;
	ULong tmp_addr;
	ULong new_addr;
	unsigned char *temp_addr;
	ULong offset;

	tmp_addr = addr;
	offset = shadow_map;
	// unmark shadow memory by byte
//	printf("unmark Memory at %p size %d\n", (void *)offset, size);
	for (i = 0; i < size; i += 8) {
		new_addr = ((tmp_addr + i) >> 3) + offset;
		temp_addr = (unsigned char *)new_addr;
		// if 8 byte is going to be unmarked the shadow memory will be 0
		if (i + 8 < size) {
			*temp_addr = 0;
		}
		// if less than 8 bytes left
		else {
			*temp_addr = (*temp_addr >> (i + 8 - size)) << (i + 8 - size);
		}
	}

	return 0;
}

Int markMalloc(ULong addr, Int size)
{
	Int i;
	char wh;
	Int idx;
	ULong tmp_addr;
	ULong new_addr;
	unsigned char *temp_addr;
	ULong offset;

	tmp_addr = addr;
	offset = shadow_map;
// 	VG_(printf)("tmp_addr %d\n", (tmp_addr >> 3));
// 	VG_(printf)("g %lu h %lu %lu s %lu %lu a %lu\n", global_range.upper, heap_range.lower, heap_range.upper, stack_range.lower, stack_range.upper, addr);
// 	VG_(printf)("g %p h %p %p s %p %p a %p\n", global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr);
// 	VG_(printf)("offset %p shadow_map %p check shadow_map %p offset %p size %d\n", (void *)offset, shadow_map, shadow_map[(tmp_addr >> 3)], (void *)((tmp_addr >> 3) + offset), size);

	for (i = 0; i < size; i++) {
		idx = (tmp_addr + i) >> 3;
//		new_addr = offset[(tmp_addr + i) >> 3];
//		new_addr = ((tmp_addr + i) >> 3) + offset;
//		temp_addr = (unsigned char *)new_addr;
//		temp_addr = (unsigned char *)shadow_map[(tmp_addr + i) >> 3];
		wh = (tmp_addr + i) & 7;
//		VG_(printf)("	check %p %d %d %p %p %d\n", (void *)offset, (tmp_addr+i)shadow_map[(tmp_addr+i)>>3], (tmp_addr + i), temp_addr, *temp_addr);
		shadow_map[idx].bits = shadow_map[idx].bits | (1 << wh);
//		VG_(printf)("	mark %p %p %d \n", shadow_map, shadow_map[idx], shadow_map[idx].bits);
	}
	return 0;
}

static void pre_syscall(ThreadId tid, UInt syscallno,
                           UWord* args, UInt nArgs)
{
/*
	Int h;

	switch (syscallno) {
		case BRK_SYSCALL :
			VG_(printf)("brk = %p\n", args[0]);
			break;

		case MUNMAP_SYSCALL :
			VG_(printf)("munmap = %p\n", args[0]);
			break;

		case MMAP_SYSCALL :
			VG_(printf)("mmap size = %d\n", args[1]);
			break;

	}
	*/
}

static
void post_syscall(ThreadId tid, UInt syscallno,
                            UWord* args, UInt nArgs, SysRes res)
{
	ULong addr;
	Int size;

	switch (syscallno) {
		case BRK_SYSCALL :
			VG_(printf)("brk = %p\n", args[0]);
			VG_(printf)("	brk return = %p\n", res);
			addr = (ULong)sr_Res(res);

			if ((ULong)args[0] == 0) {
				global_range.upper = addr;
				global_range.upper_addr = (void *)addr;

				heap_range.lower = addr;
				heap_range.lower_addr = (void *)addr;
			}
			else {
				start = 1;
			/*
				heap_range.upper = addr;
				heap_range.upper_addr = (void *)addr;
				*/
			}
			break;

		case MUNMAP_SYSCALL :
//			VG_(printf)("munmap = %p\n", args[0]);
//			VG_(printf)("	munmap return = %d\n", res);
			addr = (ULong)sr_Res(res);
			size = args[1];
			unmarkMalloc(addr, size);
			break;

		case MMAP_SYSCALL :
//			VG_(printf)("mmap size = %d\n", args[1]);
//			VG_(printf)("	mmap return = %p\n", res);
			addr = (ULong)sr_Res(res);
			size = args[1];
			markMalloc(addr, size);
			break;

	}
}

static void set_range(void)
{
	global_range.lower = 0x08048000;
	global_range.lower_addr = (void *)global_range.lower;

/*
	stack_range.upper = 0xc0000000;
	stack_range.upper_addr = (void *)stack_range.upper;
	stack_range.lower = 0xbf000000;
	stack_range.lower_addr = (void *)stack_range.lower;
	*/

/*
	heap_range.upper = 0xbf000000;
	heap_range.upper_addr = (void *)heap_range.upper;
	*/
}

static void pf_fini(Int exitcode)
{
	Int total = stack_count.read + heap_count.read + global_count.read + other_count.read;

	VG_(printf)("Read\n", shadow_map);
	
	VG_(printf)("Stack : %d (%f)\n", stack_count.read, (float)(100 * stack_count.read / total));
	VG_(printf)("Heap  : %d (%f)\n", heap_count.read, (float)(100 * heap_count.read / total));

	VG_(printf)("	Success : %d\n", heap_success.read);
	VG_(printf)("	Fail : %d\n", heap_fail.read);
	VG_(printf)("Global : %d (%f)\n", global_count.read, (float)(100 * global_count.read / total));
}

static void pf_pre_clo_init(void)
{
	VG_(details_name)            ("val_shadow");
	VG_(details_version)         ("0.1");
	VG_(details_description)     ("Valgrid Shadow Memory Tool");
	VG_(details_copyright_author)(
			"Copyright (C) 2002-2011, and GNU GPL'd, by Wonjoon Song.");
	VG_(details_bug_reports_to)  (VG_BUGS_TO);

	VG_(details_avg_translation_sizeB) ( 275 );

	VG_(basic_tool_funcs)        (pf_post_clo_init,
			pf_instrument,
			pf_fini);

    VG_(needs_syscall_wrapper)(pre_syscall,
			       post_syscall);

	set_range();
	check_mem_map();
	//reserveShadowMemory();
}

VG_DETERMINE_INTERFACE_VERSION(pf_pre_clo_init)

	/*--------------------------------------------------------------------*/
	/*--- end                                                          ---*/
	/*--------------------------------------------------------------------*/
