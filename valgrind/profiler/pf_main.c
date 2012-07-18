#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)

typedef 
enum { Event_Load, Event_Store}
EventKind;

typedef
struct {
	EventKind  ekind;
	IRExpr*    addr;
	Int        size;
} Event;



#define MAX_EVENTS 4

static Event eventList[MAX_EVENTS];
static Int   eventCount= 0;

static ULong loadCount = 0;
static ULong storeCount = 0;


static VG_REGPARM(2) void trace_load(Addr addr, SizeT size)
{
	loadCount++;
}

static VG_REGPARM(2) void trace_store(Addr addr, SizeT size)
{
	storeCount++;
	//   VG_(printf)(" S %08lx,%lu\n", addr, size);
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

static void pf_fini(Int exitcode)
{
	VG_(printf)("Load  : %d \n", loadCount);
	VG_(printf)("Store : %d \n", storeCount);
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

}

VG_DETERMINE_INTERFACE_VERSION(pf_pre_clo_init)

	/*--------------------------------------------------------------------*/
	/*--- end                                                          ---*/
	/*--------------------------------------------------------------------*/
