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

struct mov_count stack_count;
struct mov_count other_count;
struct mov_count heap_count;
struct mov_count global_count;

struct mov_count heap_success;
struct mov_count heap_fail;

struct mem_ref buf[BUFSZ];

VG_REGPARM(2) void trace_load(Addr addr, SizeT size)
{
	buf[buf_pos].addr = addr;
	buf[buf_pos].size = size;
	buf[buf_pos].write = False;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
}

VG_REGPARM(2) void trace_store(Addr addr, SizeT size)
{
	buf[buf_pos].addr = addr;
	buf[buf_pos].size = size;
	buf[buf_pos].write = True;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
}

VG_REGPARM(2) void trace_load2(Addr addr, SizeT size)
{
	ULong addr_val = (unsigned long) addr;

	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.read += size;
	}
	else if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.read += size;
	}
	else {
		other_count.read += size;
	}
}

VG_REGPARM(2) void trace_store2(Addr addr, SizeT size)
{
	ULong addr_val = (unsigned long) addr;

	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.write += size;
	}
	else if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.write += size;
	}
	else {
		other_count.write += size;
	}
}

VG_REGPARM(2) void trace_load3(Addr addr, SizeT size)
{
	Int count = 0;
	ULong addr_val = (unsigned long) addr;
	Int i;
	Int ct = 0;
	Char wh;
	Addr idAddr;
	UChar *t;
	UChar data;
	Int tt = 0;

/*
	buf[buf_pos].addr = addr;
	buf[buf_pos].size = size;
	buf[buf_pos].write = False;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
	*/
	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.read += size;
//		count = check_map(addr, size);

		idAddr = ((addr) >> 3) + reserve_map;
		t = idAddr;
		data = *t;
		for (i = 0; i < size; i++) {

			wh = (addr + i) & 7;

			tt  = ((data >> wh) & 1);

			count += tt;
		}
		heap_success.read += count;
		heap_fail.read += size - count;
	}
	else if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.read += size;
	}
	else {
		other_count.read += size;
	}
}

VG_REGPARM(2) void trace_store3(Addr addr, SizeT size)
{
	Int count = 0; 
	ULong addr_val = (unsigned long) addr;
	Int i;
	Int ct = 0;
	Char wh;
	Addr idAddr;
	UChar *t;
	UChar data;
	Int tt = 0;

/*
	buf[buf_pos].addr = addr;
	buf[buf_pos].size = size;
	buf[buf_pos].write = True;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
	*/
	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.write += size;
//		count = check_map(addr, size);
		idAddr = ((addr) >> 3) + reserve_map;
		t = idAddr;
		data = *t;
		for (i = 0; i < size; i++) {

			wh = (addr + i) & 7;

			tt  = ((data >> wh) & 1);

			count += tt;
		}
		heap_success.write += count;
		heap_fail.write += size - count;
	}
	else if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.write += size;
	}
	else {
		other_count.write += size;
	}
}

VG_REGPARM(2) void trace_load4(Addr addr, SizeT size)
{
	Int t;
	Int count;
	ULong addr_val = (unsigned long) addr;

/*
	buf[buf_pos].addr = addr;
	buf[buf_pos].size = size;
	buf[buf_pos].write = False;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
	*/
	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.read += size;
//		count = check_map(addr, size);
		heap_success.read += count;
		heap_fail.read += size - count;
	}
	else if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.read += size;
	}
	else {
		other_count.read += size;
	}
}

VG_REGPARM(2) void trace_store4(Addr addr, SizeT size)
{
	Int count; 
	ULong addr_val = (unsigned long) addr;

/*
	buf[buf_pos].addr = addr;
	buf[buf_pos].size = size;
	buf[buf_pos].write = True;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
	*/
	if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.write += size;
//		count = check_map(addr, size);
		heap_success.write += count;
		heap_fail.write += size - count;
	}
	else if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.write += size;
	}
	else {
		other_count.write += size;
	}
}

void flushEvents(IRSB* sb)
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
				helperAddr =  trace_load2;
				break;

			case Event_Store : 
				helperName = "trace_store";
				helperAddr =  trace_store2;  
				break;

		}
		argv = mkIRExprVec_2( ev->addr, mkIRExpr_HWord( ev->size ) );
		di   = unsafeIRDirty_0_N( 2, 
				helperName, VG_(fnptr_to_fnentry)( helperAddr ),
				argv );
		addStmtToIRSB( sb, IRStmt_Dirty(di) );
	}

	eventCount = 0;
}

void addLoadEvent(IRSB *sb, IRExpr* addr, Int size)
{
	Char*      helperName = "trace_load2";
	void*      helperAddr = trace_load2;
	IRExpr**   argv;
	IRDirty*   di;

	argv = mkIRExprVec_2( addr, mkIRExpr_HWord( size ) );
	di   = unsafeIRDirty_0_N( 2, 
			helperName, VG_(fnptr_to_fnentry)( helperAddr ),
			argv );
	addStmtToIRSB( sb, IRStmt_Dirty(di) );
	/*
	Event* evt;

	if (eventCount == MAX_EVENTS)
		flushEvents(sb);
	evt = &eventList[eventCount];
	evt->ekind = Event_Load;
	evt->addr = addr;
	evt->size = size;
	eventCount++;
	*/
}

void addStoreEvent(IRSB *sb, IRExpr* addr, Int size)
{
	Char*      helperName = "trace_store2";
	void*      helperAddr = trace_store2;
	IRExpr**   argv;
	IRDirty*   di;

	argv = mkIRExprVec_2( addr, mkIRExpr_HWord( size ) );
	di   = unsafeIRDirty_0_N( 2, 
			helperName, VG_(fnptr_to_fnentry)( helperAddr ),
			argv );
	addStmtToIRSB( sb, IRStmt_Dirty(di) );
	/*
	Event* evt;

	if (eventCount == MAX_EVENTS)
		flushEvents(sb);
	evt = &eventList[eventCount];
	evt->ekind = Event_Store;
	evt->addr = addr;
	evt->size = size;
	eventCount++;
	*/
}

