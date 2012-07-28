#ifndef __SHADOW_MAP_H__
#define __SHADOW_MAP_H__

#include <map>
#include "pin.H"

#define STACK "[stack]"
#define HEAP "[heap]"

extern pid_t pid;
extern int isMalloced;
extern int no_free;
extern int malloc_size;
static const unsigned long shadowMemSize = 1024 * 1024 * 128 * 3;//(1ULL << 44);
typedef VOID * ( *FP_MALLOC )( size_t );

struct range {
	unsigned long lower;
	unsigned long upper;

	void *lower_addr;
	void *upper_addr;
};

struct mov_count {
	unsigned long read;
	unsigned long write;
};

static map<unsigned long, int> mlc_size;

extern struct mov_count stack_count;
extern struct mov_count other_count;
extern struct mov_count heap_count;
extern struct mov_count global_count;

extern struct range heap_range;
extern struct range stack_range;
extern struct range global_range;

extern unsigned int offset;

extern int doingMalloc;

extern int heap_suc;
extern int heap_fail;

extern struct range heap;

int checkShadowMap(int addr, int size);
void read_map();
void reserveShadowMemory();
void freeShadowMemory();
int markMalloc(unsigned long addr, int size);
int unmarkMalloc(unsigned long addr, int size);
VOID MallocBefore(CHAR * name, ADDRINT size);
VOID BeforeFree(CHAR * name, ADDRINT addr);
VOID MallocAfter(ADDRINT ret);
VOID AfterFree();
VOID Image(IMG img, VOID *v);

#endif
