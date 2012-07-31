#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)
#include "valgrind.h"

#include "config.h"

#include "pub_tool_threadstate.h"
#include "pub_tool_gdbserver.h"
#include <sys/syscall.h>
#include <sys/mman.h>

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
	UChar bits;
} Shadow;

Shadow shadow_map[402653184];
//unsigned int offset = 0x20000000;

int xx = 0;

//static const unsigned long shadowMemSize = 1024 * 1024 * 128 * 3;
static const unsigned long shadowMemSize = 1024;

#define MAX_EVENTS 4

static Event eventList[MAX_EVENTS];
static Int   eventCount= 0;

static ULong loadCount = 0;
static ULong storeCount = 0;

struct mov_count {
	unsigned long read;
	unsigned long write;
};

struct mov_count heap_count;

int heap_suc;
int heap_fail;

#define __NR_mmap2 192

#define PROT_READ	0x1
#define PROT_WRITE	0x2
#define MAP_SHARED	0x01
#define MAP_ANONYMOUS	0x20

#define BRK_SYSCALL 45
#define MUNMAP_SYSCALL 91
#define MMAP_SYSCALL 192

static void reserveShadowMemory()
{
	Addr a = 0x20000000;
//	VG_(do_syscall)(__NR_mmap2, NULL, 4096, 0, 0, -1, 0, 0, 0);
//	vgPlain_do_syscall(1);
	//PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0, 0, 0);
//	offset = VG_(do_syscall)(__NR_mmap2, (void *)offset, (SizeT)shadowMemSize, (UInt)PROT_READ | PROT_WRITE, (UInt)MAP_SHARED | MAP_ANONYMOUS, (UInt)-1, (UInt)0);
//	VG_(printf)("Shadow Memory %p\n", (void *)offset);
//	offset = (int) syscall(__NR_mmap2, (void *)offset, shadowMemSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
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
	int ret = munmap((void *)offset, shadowMemSize);

	if (ret < 0)
		VG_(printf)("Shadow Memory at %p Free Failed!\n", (void *)offset);
	*/
	
}

static VG_REGPARM(2) void trace_load(Addr addr, SizeT size)
{
	int count;

	heap_count.read++;
	count = checkShadowMap(addr, size);

	heap_suc += count;
	heap_fail += size - count;
//	VG_(printf)(" L %08lx,%lu\n", addr, size);
}

static VG_REGPARM(2) void trace_store(Addr addr, SizeT size)
{
	int count; 

	heap_count.write++;
	count = checkShadowMap(addr, size);

	heap_suc += count;
	heap_fail += size - count;
//	VG_(printf)(" S %08lx,%lu\n", addr, size);
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
	int i;
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

int checkShadowMap(int addr, int size)
{
	int i;
	int ct = 0;
	char wh;
	unsigned long tmp_addr;
	unsigned long new_addr;
	unsigned char *temp_addr;
	unsigned long offset;

	tmp_addr = addr;
	offset = shadow_map;
//	printf("Shadow Memory at %p checking %p\n", (void *)offset, (void *)((tmp_addr >> 3) + offset));
	for (i = 0; i < size; i++) {
		new_addr = ((tmp_addr + i) >> 3) + offset;
		temp_addr = (unsigned char *)new_addr;
		wh = (tmp_addr + i) & 7;
//		printf("	check %p %p %d\n", (tmp_addr + i), temp_addr, *temp_addr);
		wh = (*temp_addr >> wh) & 1;
		ct += wh;
	}
	return ct;
}
static void pf_fini(Int exitcode)
{
	VG_(printf)("shadow map : %p \n", shadow_map);
	
	VG_(printf)("Load  : %d \n", heap_count.read);
	VG_(printf)("Store : %d \n", heap_count.write);

	VG_(printf)("Heap Success : %d\n", heap_suc);
	VG_(printf)("Heap Fail : %d\n", heap_fail);
}

int unmarkMalloc(unsigned long addr, int size)
{
	int i;
	unsigned long tmp_addr;
	unsigned long new_addr;
	unsigned char *temp_addr;
	unsigned long offset;

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

int markMalloc(unsigned long addr, int size)
{
	int i;
	char wh;
	unsigned long tmp_addr;
	unsigned long new_addr;
	unsigned char *temp_addr;
	unsigned long offset;

	tmp_addr = addr;
	offset = shadow_map;
	// mark shadow memory bit by bit
//	VG_(printf)("Shadow Memory at %p and checking %p\n", (void *)offset, (void *)((tmp_addr >> 3) + offset));
	for (i = 0; i < size; i++) {
		new_addr = ((tmp_addr + i) >> 3) + offset;
		temp_addr = (unsigned char *)new_addr;
		wh = (tmp_addr + i) & 7;
//		VG_(printf)("	mark %p %p %d\n", (tmp_addr + i), temp_addr, *temp_addr);
		*temp_addr = *temp_addr | (1 << wh);
	}

	return 0;
}

static void pre_syscall(ThreadId tid, UInt syscallno,
                           UWord* args, UInt nArgs)
{
/*
	int h;

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
	unsigned long addr;
	int size;

	switch (syscallno) {
		case BRK_SYSCALL :
			VG_(printf)("brk = %p\n", args[0]);
			VG_(printf)("	brk return = %p\n", res);
			break;

		case MUNMAP_SYSCALL :
			VG_(printf)("munmap = %p\n", args[0]);
			VG_(printf)("	munmap return = %d\n", res);
			break;

		case MMAP_SYSCALL :
			VG_(printf)("mmap size = %d\n", args[1]);
			VG_(printf)("	mmap return = %p\n", res);
			addr = (unsigned long)sr_Res(res);
			size = args[1];
			markMalloc(addr, size);
			break;

	}
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

	//reserveShadowMemory();
}

VG_DETERMINE_INTERFACE_VERSION(pf_pre_clo_init)

	/*--------------------------------------------------------------------*/
	/*--- end                                                          ---*/
	/*--------------------------------------------------------------------*/
