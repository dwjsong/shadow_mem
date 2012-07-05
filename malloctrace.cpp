#include "pin.H"
#include <iostream>
#include <fstream>
#include <sys/syscall.h>                                                                                                                                                     
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
      
void *shadow_addr;

#define MALLOC "malloc"
#define FREE "free"
#define MMAP "mmap"

#if __x86_64__
	int x86 = 64;
#else
	int x86 = 64;
#endif

std::ofstream TraceFile;
int malloc_size;
const unsigned long virtMemUpper = 1024 * 1024 * 32;//(1ULL << 44);
typedef VOID * ( *FP_MALLOC )( size_t );

struct mem_addr {
	int *addr;
	int size;
};

int count;
struct mem_addr arr[100];

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "malloctrace.out", "specify trace file name");

int *reserve_addr = 0;

void reserveShadowMemory()
{
	size_t size = virtMemUpper / 8;

	for (int i = 0; i < 1024; i++) {
		shadow_addr = (void *)syscall(__NR_mmap, reserve_addr, size, 
					PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANON | MAP_FIXED | MAP_NORESERVE,
					-1, 0);
		reserve_addr = reserve_addr + size;
//		TraceFile << shadow_addr << "\n";
//		TraceFile << reserve_addr << "\n";
	}
	
}

void freeShadowMemory()
{
	int *addr = 0;
	size_t size = virtMemUpper / 8;

	for (int i = 0; i < 1024; i++) {
		int ret = syscall(__NR_munmap, addr, size);

		if (ret < 0) {
			printf("Shadow Memory at %d Free Failed!\n", *addr);
		}
		TraceFile << "Free " << addr << "\n";
	}
}

int markMalloc(int *addr, int size)
{
//	TraceFile << "Malloc " << addr << " " << size << "\n";
	arr[count].addr = addr;
	arr[count].size = size;
	count++;

	return 0;
}

int unmarkMalloc(int *addr)
{
	for (int i = 0; i < count; i++)
		if (arr[i].addr == addr) {
			arr[i] = arr[--count];
			return 0;
		}
	return -1;
}

// write argument 
VOID Arg1Before(CHAR * name, ADDRINT size)
{
	TraceFile << name << "(" << size << ")" << endl;
	malloc_size = size;
}

VOID BeforeFree(CHAR * name, ADDRINT addr)
{
	unmarkMalloc((int *)addr);
}


// write return address
VOID MallocAfter(ADDRINT ret)
{
//    TraceFile << malloc_size << "  returns " << ret << endl;
	markMalloc((int *)ret, malloc_size);
}

VOID Image(IMG img, VOID *v)
{
    RTN mallocRtn = RTN_FindByName(img, MALLOC);
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);

        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before,
                       IARG_ADDRINT, MALLOC,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(mallocRtn);
    }
    /*

    RTN mmapRtn = RTN_FindByName(img, MMAP);
    {
        RTN_Open(mmapRtn);

        RTN_InsertCall(mmapRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(mmapRtn);
    }
    */

    RTN freeRtn = RTN_FindByName(img, FREE);
    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)BeforeFree,
                       IARG_ADDRINT, FREE,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_Close(freeRtn);
    }
}

VOID Fini(INT32 code, VOID *v)
{
    TraceFile.close();
}

VOID RecordMemRead(VOID * ip, VOID * addr)
{
	for (int i = 0; i < count; i++) {
		if (arr[i].addr <= addr && addr < arr[i].addr + arr[i].size) {
			TraceFile << "R " << arr[i].addr << " " << addr << endl;
		}
	}
}

VOID RecordMemWrite(VOID * ip, VOID * addr)
{
	for (int i = 0; i < count; i++) {
		if (arr[i].addr <= addr && addr < arr[i].addr + arr[i].size) {
			TraceFile << "W " << arr[i].addr << " " << addr << endl;
		}
	}
}

VOID Instruction(INS ins, VOID *v)
{
	UINT32 memOperands = INS_MemoryOperandCount(ins);

	for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
		if (INS_MemoryOperandIsRead(ins, memOp)) {
			 INS_InsertPredicatedCall(
			         ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
		       		 IARG_INST_PTR,
		                 IARG_MEMORYOP_EA, memOp,
		                 IARG_END);
		}
		if (INS_MemoryOperandIsWritten(ins, memOp)) {
			 INS_InsertPredicatedCall(
			         ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
		       		 IARG_INST_PTR,
		                 IARG_MEMORYOP_EA, memOp,
		                 IARG_END);
		}
	}
}

VOID *newMalloc( FP_MALLOC orgFuncptr, UINT32 arg0, ADDRINT returnIp )
//inline void *newMalloc(size_t size)
{
//	void *retAddr;
	void *v = orgFuncptr(arg0);

//	retAddr = malloc(size);
//	cout << "what\n";
//	retAddr = (void *)syscall(__NR_mmap, reserve_addr, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS, -1, 0);
//	reserve_addr = reserve_addr + size;
//	cout << retAddr << endl;

//	retAddr = malloc(size);
//	return retAddr;
	return v;
}

VOID ImageLoad(IMG img, VOID *v)
{
	RTN rtn = RTN_FindByName(img, "malloc");

	if (RTN_Valid(rtn)) {
		PROTO proto_malloc = PROTO_Allocate(PIN_PARG(void *), CALLINGSTD_DEFAULT,
	                                             "malloc", PIN_PARG(int), PIN_PARG_END());
       		RTN_ReplaceSignatureProbed(rtn, AFUNPTR(newMalloc),
	                                   IARG_PROTOTYPE, proto_malloc,
	                                   IARG_ORIG_FUNCPTR,
	                                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
	                                   IARG_RETURN_IP,
	                                   IARG_END);
		PROTO_Free(proto_malloc);
	}
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc,argv) )
    {
    }
    TraceFile.open(KnobOutputFile.Value().c_str());
    TraceFile << x86 << "\n";
    TraceFile << "Start\n";
    reserveShadowMemory();
    TraceFile << "Setup\n";
    
    TraceFile << hex;
    TraceFile.setf(ios::showbase);
    
    INS_AddInstrumentFunction(Instruction, 0);
//    IMG_AddInstrumentFunction(ImageLoad, 0);
    IMG_AddInstrumentFunction(Image, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
//    PIN_StartProgramProbed();
    
    TraceFile << "HAHAHAHA\n";
    freeShadowMemory();
    return 0;
}
