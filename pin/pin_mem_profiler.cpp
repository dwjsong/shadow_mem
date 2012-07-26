#include "pin.H"
#include <iostream>
#include <fstream>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <map>
#include <set>
#include <string.h>
#include <map>

#include "syscall_handle.h"
#include "inst_handle.h"
#include "shadow_map.h"
#include "pin_mem_profiler.h"

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "profiler.out", "specify trace file name");

// insert code before & after malloc
// insert code after free
VOID Image(IMG img, VOID *v)
{
    RTN mallocRtn = RTN_FindByName(img, MALLOC);
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);

        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore,
                       IARG_ADDRINT, MALLOC,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(mallocRtn);
    }

    RTN freeRtn = RTN_FindByName(img, FREE);
    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)BeforeFree,
                       IARG_ADDRINT, FREE,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_InsertCall(freeRtn, IPOINT_AFTER, (AFUNPTR)AfterFree, IARG_END);
        RTN_Close(freeRtn);
    }
}

// print stat
VOID Fini(INT32 code, VOID *v)
{
	int total = stack_count.read + heap_count.read + global_count.read + other_count.read;
	TraceFile << dec;
	TraceFile << "Read" << endl;
	TraceFile.width(10);
	TraceFile << "Stack  : " << stack_count.read << " (" << (float)100 * stack_count.read / total << "%)" << endl;
	TraceFile.width(10);
	TraceFile << "Heap   : " << heap_count.read << " (" << (float)100 * heap_count.read / total << "%)" << endl;
	TraceFile.width(10);
	TraceFile << "	Success : " << heap_suc << endl;
	TraceFile.width(10);
	TraceFile << "	Fail    : " << heap_fail << endl;
	TraceFile.width(10);
	TraceFile << "Global : " << global_count.read << " (" << (float)100 * global_count.read / total << "%)" << endl;
	TraceFile.width(10);
	TraceFile << "Other  : " << other_count.read << " (" << (float)100 * other_count.read / total << "%)" << endl;
	TraceFile.width(10);
	TraceFile << "Total : " << total << " (100%)" << endl;
	TraceFile << "Write" << endl;
	TraceFile.width(10);
	TraceFile << "Stack  : " << stack_count.write << " (" << (float)100 * stack_count.write/ total << "%)" << endl;
	TraceFile.width(10);
	TraceFile << "Heap   : " << heap_count.write << " (" << (float)100 * heap_count.write / total << "%)" << endl;
	TraceFile.width(10);
	TraceFile << "Global : " << global_count.write << " (" << (float)100 * global_count.write / total << "%)" << endl;
	TraceFile.width(10);
	TraceFile << "Other  : " << other_count.write << " (" << (float)100 * other_count.write / total << "%)" << endl;
	TraceFile.width(10);
	TraceFile.close();
}

int init()
{
	pid = PIN_GetPid();
	printf("pid %d\n",pid);
    read_map();

    TraceFile.open(KnobOutputFile.Value().c_str());
//    TraceFile << x86 << "\n";
    reserveShadowMemory();
    
    TraceFile << hex;
    TraceFile.setf(ios::showbase);
   
    // Trace memory read & write
    INS_AddInstrumentFunction(inst_check, 0);
    IMG_AddInstrumentFunction(Image, 0);

    // insert code before and after malloc 
    // insert code before free
    PIN_AddFiniFunction(Fini, 0);

	PIN_AddSyscallEntryFunction(syscall_enter, NULL);
	PIN_AddSyscallExitFunction(syscall_exit, NULL);


	return 0;
}

int main(int argc, char *argv[])
{ 
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
    }

	init();

    PIN_StartProgram();
    
    freeShadowMemory();
    return 0;
}
