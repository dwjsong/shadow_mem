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
#include <signal.h>

#include "syscall_handle.h"
#include "inst_handle.h"
#include "shadow_map.h"
#include "pin_mem_profiler.h"

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "profiler.out", "specify trace file name");

// print stat
VOID Fini(INT32 code, VOID *v)
{
	int total = stack_count.read + heap_count.read + global_count.read + other_count.read;

	TraceFile << dec;
/*
    cout << "==============================" << endl;
	cout << "Read" << endl;
	cout << "Stack  : " << stack_count.read << " (" << (float)100 * stack_count.read / total << "%)" << endl;
	cout << "Heap   : " << heap_count.read << " (" << (float)100 * heap_count.read / total << "%)" << endl;
	cout << "	Success : " << heap_success.read << endl;
	cout << "	Fail    : " << heap_fail.read << endl;
	cout << "Global : " << global_count.read << " (" << (float)100 * global_count.read / total << "%)" << endl;
	cout << "Other  : " << other_count.read << " (" << (float)100 * other_count.read / total << "%)" << endl;
	cout << "Total : " << total << " (100%)" << endl;
    cout << "==============================" << endl;

    total = stack_count.write + heap_count.write + global_count.write + other_count.write;

	cout << "Write" << endl;
	cout << "Stack  : " << stack_count.write << " (" << (float)100 * stack_count.write/ total << "%)" << endl;
	cout << "Heap   : " << heap_count.write << " (" << (float)100 * heap_count.write / total << "%)" << endl;
	cout << "	Success : " << heap_success.write << endl;
	cout << "	Fail    : " << heap_fail.write << endl;
	cout << "Global : " << global_count.write << " (" << (float)100 * global_count.write / total << "%)" << endl;
	cout << "Other  : " << other_count.write << " (" << (float)100 * other_count.write / total << "%)" << endl;
    cout << "Total : " << total << " (100%)" << endl;
    cout << "==============================" << endl;
	*/
    TraceFile << "==============================" << endl;
	TraceFile << "Read" << endl;
	TraceFile << "Stack  : " << stack_count.read << " (" << (float)100 * stack_count.read / total << "%)" << endl;
	TraceFile << "Heap   : " << heap_count.read << " (" << (float)100 * heap_count.read / total << "%)" << endl;
	TraceFile << "	Success : " << heap_success.read << endl;
	TraceFile << "	Fail    : " << heap_fail.read << endl;
	TraceFile << "Global : " << global_count.read << " (" << (float)100 * global_count.read / total << "%)" << endl;
	TraceFile << "Other  : " << other_count.read << " (" << (float)100 * other_count.read / total << "%)" << endl;
	TraceFile << "Total : " << total << " (100%)" << endl;
    TraceFile << "==============================" << endl;

    total = stack_count.write + heap_count.write + global_count.write + other_count.write;

	TraceFile << "Write" << endl;
	TraceFile << "Stack  : " << stack_count.write << " (" << (float)100 * stack_count.write/ total << "%)" << endl;
	TraceFile << "Heap   : " << heap_count.write << " (" << (float)100 * heap_count.write / total << "%)" << endl;
	TraceFile << "	Success : " << heap_success.write << endl;
	TraceFile << "	Fail    : " << heap_fail.write << endl;
	TraceFile << "Global : " << global_count.write << " (" << (float)100 * global_count.write / total << "%)" << endl;
	TraceFile << "Other  : " << other_count.write << " (" << (float)100 * other_count.write / total << "%)" << endl;
    TraceFile << "Total : " << total << " (100%)" << endl;
    TraceFile << "==============================" << endl;
	TraceFile.close();
}

void sig_handler(int sig)
{
	printf("False Access to Shadow Memory Detected! Exiting\n");
	exit(0);
}

int main(int argc, char *argv[])
{ 
	signal(SIGSEGV, sig_handler);
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
    }
	bufid = PIN_DefineTraceBuffer(sizeof(struct memref), BUFFER_SIZE, BufferFull, 0);

    pid = PIN_GetPid();
    read_map();

	TraceFile.open(KnobOutputFile.Value().c_str());
    
    TraceFile << hex;
    TraceFile.setf(ios::showbase);
   
    // Trace memory read & write
    INS_AddInstrumentFunction(load_store_inst, 0);

    PIN_AddFiniFunction(Fini, 0);

    //Syscall instrumentation
    PIN_AddSyscallEntryFunction(syscall_enter, NULL);
    PIN_AddSyscallExitFunction(syscall_exit, NULL);

    reserveShadowMemory();

    PIN_StartProgram();
    
    return 0;
}
