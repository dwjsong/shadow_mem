#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)
#include "valgrind.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_vki.h"
#include "pub_tool_aspacemgr.h"

#include "config.h"

#include "pf_include.h"

Int xx;
Int stt;
Int map_size = 402653184;
Int unmap;

ULong shadowMemSize = 1024;

struct range heap_range;
struct range stack_range;
struct range global_range;

Event eventList[MAX_EVENTS];
Int   eventCount;

ULong loadCount;
ULong storeCount;

Addr reserve_map;

Addr add_buf[BUFSZ];
int buf_pos;
Int start;

void pf_post_clo_init(void)
{
}

void print_tag(IRExpr* data)
{
	switch (data->tag) {
		case Iex_Get :
			VG_(printf)("Get\n");
			break;
		case Iex_GetI :
			VG_(printf)("GetI\n");
			break;
		case Iex_RdTmp :
			VG_(printf)("RdTmp\n");
			break;
		case Iex_Qop :
			VG_(printf)("Iex_Qop\n");
			break;
		case Iex_Triop :
			VG_(printf)("Iex_Triop\n");
			break;
		case Iex_Binop :
			VG_(printf)("Iex_Binop\n");
			break;
		case Iex_Unop :
			VG_(printf)("Iex_Unop\n");
			break;
		case Iex_Load :
			VG_(printf)("Iex_Load\n");
			break;
		case Iex_Const :
			VG_(printf)("Iex_Const\n");
			break;
		case Iex_Mux0X :
			VG_(printf)("Iex_Mux0X\n");
			break;
		case Iex_CCall :
			VG_(printf)("Iex_CCall\n");
			break;
	}
}

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
/*
		ppIRStmt(stmt);
		VG_(printf)("\n");
*/
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
									if (d->mFx == Ifx_Read || d->mFx == Ifx_Modify) {
										VG_(printf)("dirty read\n");
										addLoadEvent( sbOut, d->mAddr, dsize );
									}
									if (d->mFx == Ifx_Write || d->mFx == Ifx_Modify)
										addStoreEvent( sbOut, d->mAddr, dsize );
								} else {
								}
								addStmtToIRSB( sbOut, stmt );
								break;
							}

			case Ist_CAS: 
							{
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
	flushEvents(sbOut);

	return sbOut;
}

static void set_range(void)
{
	global_range.lower = 0x08048000;
	global_range.lower_addr = (void *)global_range.lower;

}

static void percentify(ULong a, ULong b, char *transformed)
{
	ULong c, d;

	if (b > 0) {
		c = a * 100 / b;
		d = (a * 10000 / b) % 100;

		VG_(sprintf)(transformed, "%ld.%0ld%", c, d);
	}
	else {
		VG_(sprintf)(transformed, "0.0");
	}
}

static void pf_fini(Int exitcode)
{
	ULong read_total = stack_count.read + heap_count.read + global_count.read + other_count.read;
	ULong write_total = stack_count.write + heap_count.write + global_count.write + other_count.write;
	Char tmp[10];


	VG_(printf)("==============================\n");
	VG_(printf)("Read \n");
	percentify(stack_count.read, read_total, tmp);
	VG_(printf)("Stack : %llu ", stack_count.read);
	VG_(printf)("(%s)\n", tmp);
	percentify(heap_count.read, read_total, tmp);
	VG_(printf)("Heap  : %llu ", heap_count.read);
	VG_(printf)("(%s)\n", tmp);
	VG_(printf)("	Success : %llu\n", heap_success.read);
	VG_(printf)("	Fail : %llu\n", heap_fail.read);
	percentify(global_count.read, read_total, tmp);
	VG_(printf)("Global : %llu ", global_count.read);
	VG_(printf)("(%s)\n", tmp);
	percentify(other_count.read, read_total, tmp);
	VG_(printf)("Other : %llu ", other_count.read);
	VG_(printf)("(%s)\n", tmp);
	VG_(printf)("Total : %llu\n", read_total);
	VG_(printf)("==============================\n");

	VG_(printf)("Write\n");
	
	percentify(stack_count.write, write_total, tmp);
	VG_(printf)("Stack : %llu ", stack_count.write);
	VG_(printf)("(%s)\n", tmp);
	percentify(heap_count.write, write_total, tmp);
	VG_(printf)("Heap  : %llu ", heap_count.write);
	VG_(printf)("(%s)\n", tmp);

	VG_(printf)("	Success : %llu\n", heap_success.write);
	VG_(printf)("	Fail : %llu\n", heap_fail.write);
	percentify(global_count.write, write_total, tmp);
	VG_(printf)("Global : %llu ", global_count.write);
	VG_(printf)("(%s)\n", tmp);
	percentify(other_count.write, write_total, tmp);
	VG_(printf)("Other : %llu ", other_count.write);
	VG_(printf)("(%s)\n", tmp);
	VG_(printf)("Total : %llu\n", write_total);
	VG_(printf)("==============================\n");
}

void new_mem_startup( Addr a, SizeT len, Bool rr, Bool ww, Bool xx, ULong di_handle )
{
//	VG_(printf)("new mem addr = %p size = %d\n", a, len);
	mark_alloc(a, len);
}

void make_mem_undefined_w_tid ( Addr a, SizeT len, ThreadId tid ) 
{
//	VG_(printf)("undefined addr = %p size = %d\n", a, len);
//	markMalloc(a, len);
}

void check_write(CorePart part, ThreadId tid, Addr a, SizeT len)
{
//	VG_(printf)("write %p \n",a);
}

void remap(Addr from, Addr to, SizeT len)
{
//	VG_(printf)("remap %p \n", from);
}

void new_mmap(Addr a, SizeT len, Bool rr, Bool ww, Bool xx, ULong di_handle)
{
//	VG_(printf)("new mmap %p \n", a);
}

void new_mem_stack(Addr a, SizeT len)
{
//	VG_(printf)("new stack %p \n", a);
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
	
	VG_(track_new_mem_startup)     ( new_mem_startup );
	VG_(track_new_mem_brk)         ( make_mem_undefined_w_tid );
	VG_(track_new_mem_mmap)         ( new_mmap );

	VG_(track_post_mem_write)	   ( check_write );
	VG_(track_copy_mem_remap) (remap);
	VG_(track_new_mem_stack)        ( new_mem_stack );

	set_range();
	check_mem_map();
	reserve_shadow_memory();
}

VG_DETERMINE_INTERFACE_VERSION(pf_pre_clo_init)

	/*--------------------------------------------------------------------*/
	/*--- end                                                          ---*/
	/*--------------------------------------------------------------------*/
