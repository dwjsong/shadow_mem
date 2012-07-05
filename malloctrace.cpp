#include "pin.H"
#include <iostream>
#include <fstream>
#include <sys/syscall.h>                                                                                                                                                     
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <map>
#include <pthread.h>
#include <set>
      
void *shadow_addr;

#define MALLOC "malloc"
#define FREE "free"
#define MMAP "mmap"

#if __x86_64__
	int x86 = 64;
#else
	int x86 = 64;
#endif

pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

std::ofstream TraceFile;
int malloc_size;
const unsigned long virtMemUpper = 1024 * 1024 * 32;//(1ULL << 44);
typedef VOID * ( *FP_MALLOC )( size_t );
int readSuccess, readFail;
int writeSuccess, writeFail;
set<char *> mem_set;

struct mem_addr {
	int *addr;
	int size;
};

int count;
struct mem_addr arr[1000];

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

int markMalloc(char *addr, int size)
{
	char *new_addr;

//	pthread_rwlock_wrlock(&rwlock);

	for (char i = 0; i < size; i++) {
		new_addr = (addr + i);
		if (!mem_set.count(new_addr)) {
			mem_set.insert(new_addr);
		}
//		TraceFile << (short*)new_addr << endl;
	}
//	pthread_rwlock_unlock(&rwlock);

	return 0;
}

int unmarkMalloc(char *addr)
{
//	pthread_rwlock_wrlock(&rwlock);
	mem_set.erase(addr);
//	pthread_rwlock_unlock(&rwlock);	

	return -1;
}

// write argument 
VOID Arg1Before(CHAR * name, ADDRINT size)
{
	TraceFile << name << "(" << size << ")" << endl;
	malloc_size = size;
}

// erase address when free
VOID BeforeFree(CHAR * name, ADDRINT addr)
{
	unmarkMalloc((char *)addr);
}

// write return address
VOID MallocAfter(ADDRINT ret)
{
	markMalloc((char *)ret, malloc_size);
}

// insert code before & after malloc
// insert code after free
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
	TraceFile << dec;
	TraceFile << "Read Success : " << readSuccess << endl;
	TraceFile << "Read Fail : " << readFail << endl;
	TraceFile << "Write Success : " << writeSuccess << endl;
	TraceFile << "Write Fail: " << writeFail << endl;
	TraceFile.close();
}

VOID RecordMemRead(VOID * ip, VOID * addr)
{
	// read lock
//	pthread_rwlock_rdlock(&rwlock);
	if (mem_set.count((char *)addr))
		readSuccess++;
	else
		readFail++;
//	pthread_rwlock_rdlock(&rwlock);
}

VOID RecordMemWrite(VOID * ip, VOID * addr)
{
//	pthread_rwlock_rdlock(&rwlock);
	if (mem_set.count((char *)addr))
		writeSuccess++;
	else
		writeFail++;
//	pthread_rwlock_rdlock(&rwlock);
}

// check memory read & write
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

// custom malloc to allocate memory address at 4GB (after shadow memory)
VOID *newMalloc( FP_MALLOC orgFuncptr, UINT32 arg0, ADDRINT returnIp )
//inline void *newMalloc(size_t size)
{
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

// if malloc is called run custom malloc
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
    pthread_rwlock_init(&rwlock, NULL);
    
    TraceFile << hex;
    TraceFile.setf(ios::showbase);
   
    // Trace memory read & write
    INS_AddInstrumentFunction(Instruction, 0);
//    IMG_AddInstrumentFunction(ImageLoad, 0);

    // insert code before and after malloc 
    // insert code before free
    IMG_AddInstrumentFunction(Image, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
//    PIN_StartProgramProbed();
    
    freeShadowMemory();
    return 0;
}
