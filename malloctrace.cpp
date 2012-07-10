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

#define EXPAND_STACK "expand_stack"
#define MALLOC "malloc"
#define FREE "free"
#define MMAP "mmap"
#define STACK "[stack]"
#define HEAP "[heap]"

#if __x86_64__
	int x86 = 64;
#else
	int x86 = 32;
#endif

int isMalloced;
pid_t pid;
std::ofstream TraceFile;
int malloc_size;
const unsigned long virtMemUpper = 1024 * 1024 * 3;//(1ULL << 44);
typedef VOID * ( *FP_MALLOC )( size_t );
int readSuccess, readFail;
int writeSuccess, writeFail;

struct range {
	int lower;
	int upper;
};

struct mov_count {
	int read;
	int write;
};

struct mov_count stack_count;
struct mov_count other_count;
struct mov_count heap_count;
struct mov_count global_count;

struct range heap_range;
struct range stack_range;
struct range global_range;

int count;
int no_free;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "malloctrace.out", "specify trace file name");

unsigned int offset = 0x20000000;
unsigned int pos = 0x20000000;
void *reserve_addr = (void *)pos;
void *shadow_addr;

void read_map()
{
	fstream proc_map;
	struct range temp;
	char buff[10];
	char name[20] = "/proc/";
	char line[256];
	char previous_line[256];

	sprintf(buff, "%d", pid);
	strncpy(name + 6, buff, strlen(buff));
	strcat(name, "/maps");
	
//	cout << name << endl;
	proc_map.open (name);

	while (!proc_map.eof()) {
		proc_map.getline(line, 256);
		int len = strlen(line);
//		cout << line << endl;
		if (strncmp(line + len - strlen(STACK), STACK, strlen(STACK)) == 0) {
			sscanf(line, "%x-%x", &temp.lower, &temp.upper);

			if (stack_range.lower != temp.lower ||
				stack_range.upper != temp.upper) {
				stack_range = temp;
//				cout << "Stack Range" << endl;
//				cout << hex;
//				cout << stack_range.lower << " " << stack_range.upper << endl;
			}

		}
		else if (strncmp(line + len - strlen(HEAP), HEAP, strlen(HEAP)) == 0) {
			sscanf(previous_line, "%x-%x", &temp.lower, &temp.upper);
			if (global_range.lower != temp.lower ||
				global_range.upper != temp.upper) {
				global_range = temp;
			}
			sscanf(line, "%x-%x", &temp.lower, &temp.upper);
			if (heap_range.lower != temp.lower ||
				heap_range.upper != temp.upper) {
				heap_range = temp;
//				cout << "Heap Range" << endl;
//				cout << heap_range.lower << " " << heap_range.upper << endl;
			}
		}
		strcpy(previous_line, line);
	}
	proc_map.close();
}

void reserveShadowMemory()
{
	size_t size = virtMemUpper / 8;

	for (int i = 0; i < 1024; i++) {
		shadow_addr = mmap(reserve_addr, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
//		TraceFile << "addr " << shadow_addr << endl;
		pos += size;
//		cout << "pos " << pos << endl;
		reserve_addr = (void *) pos;
//		cout << "reserve " << reserve_addr << endl;
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
	//		printf("Shadow Memory at %d Free Failed!\n", *addr);
		}
//		TraceFile << "Free " << addr << "\n";
	}
}

int markMalloc(int addr, int size)
{
	unsigned long tmp_addr;
	unsigned long new_addr;
	unsigned long *temp_addr;

	tmp_addr = addr;
	for (int i = 0; i < size; i++) {
		new_addr = ((tmp_addr + i) >> 3) + offset;
		temp_addr = (unsigned long *)new_addr;
		*temp_addr = *temp_addr * 2 + 1;

	}
//	pthread_rwlock_unlock(&rwlock);

	return 0;
}

int unmarkMalloc(int addr)
{
	int size = 10;
	unsigned long tmp_addr;
	unsigned long new_addr;
	unsigned long *temp_addr;

	tmp_addr = addr;
	for (int i = 0; i < size; i += 8) {
		new_addr = ((tmp_addr + i) >> 3) + offset;
		temp_addr = (unsigned long *)new_addr;
		if (i + 8 < size) {
			*temp_addr = 0;
		}
		else {
			*temp_addr = *temp_addr << (i + 8 - size);
		}
	}

	return -1;
}

// write argument 
VOID Arg1Before(CHAR * name, ADDRINT size)
{
	if (!isMalloced) {
		TraceFile << name << "(" << size << ")" << endl;
//		cout << name << "(" << size << ")" << endl;
		malloc_size = size;
		isMalloced = 1;
	}
}

// erase address when free
VOID BeforeFree(CHAR * name, ADDRINT addr)
{
	if (addr) {
//		TraceFile << name << "(" << addr << ")" << endl;
//		cout << name << "(" << addr << ")" << endl;
		unmarkMalloc(addr);
//		read_map();
		no_free = 1;
	}
	else {
	}
}

// write return address
VOID MallocAfter(ADDRINT ret)
{
	if (isMalloced) {
		TraceFile << " returns " << ret << endl;
//		cout << " returns " << ret << endl;
		isMalloced = 0;
		markMalloc((int)ret, malloc_size);
		read_map();
	}
}

VOID AfterFree()
{
	if (no_free) {
//		cout << "Stack Increase" << endl;
		read_map();
		no_free = 0;
	}
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
        RTN_InsertCall(freeRtn, IPOINT_AFTER, (AFUNPTR)AfterFree, IARG_END);
        RTN_Close(freeRtn);
    }
}

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

VOID DoLoad(REG reg, ADDRINT * addr)
{
	if (stack_range.upper > (int)addr && (int)addr > stack_range.lower) {
		stack_count.read++;
	}
	else if (heap_range.upper > (int)addr && (int)addr > heap_range.lower) {
		heap_count.read++;
	}
	else if (global_range.upper > (int)addr && (int)addr > global_range.lower) {
		global_count.read++;
	}
	else {
//	TraceFile << "Read " << addr << " to " << REG_StringShort(reg) << endl;
		other_count.read++;
	}

//    TraceFile << "Load addr " << addr << " to " << REG_StringShort(reg) << endl;
}

VOID DoStore(REG reg, ADDRINT * addr)
{
	if (stack_range.upper > (int)addr && (int)addr > stack_range.lower) {
		stack_count.write++;
//		TraceFile << stack_range.lower << " " << addr  << " " << stack_range.upper << endl;
	}
	else if (heap_range.upper > (int)addr && (int)addr > heap_range.lower) {
		heap_count.write++;
	}
	else if (global_range.upper > (int)addr && (int)addr > global_range.lower) {
		global_count.write++;
	}
	else {
	//TraceFile << "Store " << REG_StringShort(reg) << " to " << addr << endl;
		other_count.write++;
	}
//		TraceFile << "Store " << REG_StringShort(reg) << " to " << addr << endl;
}


VOID EmulateLoad(INS ins, VOID* v)
{

    if (INS_Opcode(ins) == XED_ICLASS_MOV &&
        INS_IsMemoryWrite(ins) && 
        INS_OperandIsMemory(ins, 0) &&
        INS_OperandIsReg(ins, 1))
    {
        INS_InsertCall(ins,
                       IPOINT_BEFORE,
                       AFUNPTR(DoStore),
                       IARG_UINT32,
                       REG(INS_OperandReg(ins, 1)),
                       IARG_MEMORYWRITE_EA,
                       IARG_END);

        // Delete the instruction
//        INS_Delete(ins);
    }
    // Find the instructions that move a value from memory to a register
    if (INS_Opcode(ins) == XED_ICLASS_MOV &&
        INS_IsMemoryRead(ins) && 
        INS_OperandIsReg(ins, 0) &&
        INS_OperandIsMemory(ins, 1))
    {
        // op0 <- *op1
        INS_InsertCall(ins,
                       IPOINT_BEFORE,
                       AFUNPTR(DoLoad),
                       IARG_UINT32,
                       REG(INS_OperandReg(ins, 0)),
                       IARG_MEMORYREAD_EA,
                       IARG_END);

    //    INS_Delete(ins);
    }
//    /*
}

int main(int argc, char *argv[])
{ 
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
    }

    pid = PIN_GetPid();
    cout << "pid " << pid << endl;
    read_map();

    TraceFile.open(KnobOutputFile.Value().c_str());
    TraceFile << x86 << "\n";
    reserveShadowMemory();
    
    TraceFile << hex;
    TraceFile.setf(ios::showbase);
    cout << hex;
   
    // Trace memory read & write
    INS_AddInstrumentFunction(EmulateLoad, 0);
    IMG_AddInstrumentFunction(Image, 0);

    // insert code before and after malloc 
    // insert code before free
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
//    PIN_StartProgramProbed();
    
    freeShadowMemory();
    return 0;
}
