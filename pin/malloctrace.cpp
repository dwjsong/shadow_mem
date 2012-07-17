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
int no_free;
pid_t pid;
std::ofstream TraceFile;
int malloc_size;
const unsigned long virtMemUpper = 1024 * 1024 * 3;//(1ULL << 44);
typedef VOID * ( *FP_MALLOC )( size_t );

struct range {
	int lower;
	int upper;
};

struct mov_count {
	int read;
	int write;
};

map<unsigned long, int> mlc_size;

struct mov_count stack_count;
struct mov_count other_count;
struct mov_count heap_count;
struct mov_count global_count;

struct range heap_range;
struct range stack_range;
struct range global_range;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "malloctrace.out", "specify trace file name");

unsigned int offset = 0x20000000;
unsigned int pos = 0x20000000;
void *reserve_addr = (void *)pos;
void *shadow_addr;

// read /proc/pid/maps to get memory mapping
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
	
	proc_map.open (name);

	while (!proc_map.eof()) {
		proc_map.getline(line, 256);
		int len = strlen(line);
		// Get Stack Size
		if (strncmp(line + len - strlen(STACK), STACK, strlen(STACK)) == 0) {
			sscanf(line, "%x-%x", &temp.lower, &temp.upper);

			if (stack_range.lower != temp.lower ||
				stack_range.upper != temp.upper) {
				stack_range = temp;
			}

		}
		// Get Global & Heap Size
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
			}
		}
		strcpy(previous_line, line);
	}
	proc_map.close();
}

// reserve memory from 0x2000000
void reserveShadowMemory()
{
	size_t size = virtMemUpper / 8;

	for (int i = 0; i < 1024; i++) {
		shadow_addr = mmap(reserve_addr, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		pos += size;
		reserve_addr = (void *) pos;
	}
	
}

// remove shadow memory
void freeShadowMemory()
{
	int *addr = 0;
	size_t size = virtMemUpper / 8;

	for (int i = 0; i < 1024; i++) {
		int ret = syscall(__NR_munmap, addr, size);

		if (ret < 0) {
			printf("Shadow Memory at %d Free Failed!\n", *addr);
		}
	}
}

// mark malloc
int markMalloc(int addr, int size)
{
	char wh;
	unsigned long tmp_addr;
	unsigned long new_addr;
	unsigned char *temp_addr;

	tmp_addr = addr;
	// mark shadow memory bit by bit
	for (int i = 0; i < size; i++) {
		new_addr = ((tmp_addr + i) >> 3) + offset;
		temp_addr = (unsigned char *)new_addr;
		wh = (tmp_addr + i) & 7;
		*temp_addr = *temp_addr | (1 << wh);
	}

	return 0;
}

// unmark malloc
int unmarkMalloc(int addr, int size)
{
	unsigned long tmp_addr;
	unsigned long new_addr;
	unsigned char *temp_addr;

	tmp_addr = addr;
	// unmark shadow memory by byte
	for (int i = 0; i < size; i += 8) {
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

// write argument 
VOID Arg1Before(CHAR * name, ADDRINT size)
{
	if (!isMalloced) {
		malloc_size = size;
		isMalloced = 1;
	}
}

// erase address when free
VOID BeforeFree(CHAR * name, ADDRINT addr)
{
	if (addr) {
		unmarkMalloc(addr, mlc_size.find(addr)->second);
		mlc_size.erase(addr);
		no_free = 1;
	}
}

// write return address
VOID MallocAfter(ADDRINT ret)
{
	if (isMalloced) {
		isMalloced = 0;
		mlc_size[ret] = malloc_size;
		markMalloc((int)ret, malloc_size);
		read_map();
	}
}

// after free
// check if memory mapping has changed
VOID AfterFree()
{
	if (no_free) {
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

// load count
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
		other_count.read++;
	}
}

// store count
VOID DoStore(REG reg, ADDRINT * addr)
{
	if (stack_range.upper > (int)addr && (int)addr > stack_range.lower) {
		stack_count.write++;
	}
	else if (heap_range.upper > (int)addr && (int)addr > heap_range.lower) {
		heap_count.write++;
	}
	else if (global_range.upper > (int)addr && (int)addr > global_range.lower) {
		global_count.write++;
	}
	else {
		other_count.write++;
	}
}


// if the instruction is load
VOID EmulateLoad(INS ins, VOID* v)
{
    // Find the instructions that move a value from a register to memory
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

    }
    // Find the instructions that move a value from memory to a register
    if (INS_Opcode(ins) == XED_ICLASS_MOV &&
        INS_IsMemoryRead(ins) && 
        INS_OperandIsReg(ins, 0) &&
        INS_OperandIsMemory(ins, 1))
    {
        INS_InsertCall(ins,
                       IPOINT_BEFORE,
                       AFUNPTR(DoLoad),
                       IARG_UINT32,
                       REG(INS_OperandReg(ins, 0)),
                       IARG_MEMORYREAD_EA,
                       IARG_END);

    }
}

int main(int argc, char *argv[])
{ 
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
    }

    pid = PIN_GetPid();
    read_map();

    TraceFile.open(KnobOutputFile.Value().c_str());
    TraceFile << x86 << "\n";
    reserveShadowMemory();
    
    TraceFile << hex;
    TraceFile.setf(ios::showbase);
   
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
