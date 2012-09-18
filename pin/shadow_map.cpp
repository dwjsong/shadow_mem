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
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>

#include <map>
#include "inst_handle.h"
#include "shadow_map.h"

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

pid_t pid;

struct access_count stack_count;
struct access_count other_count;
struct access_count heap_count;
struct access_count global_count;

struct access_count tot_count[4];

struct access_count heap_success;
struct access_count heap_fail;

struct range heap_range;
struct range stack_range;
struct range global_range;

struct range heap;

unsigned int offset = 0x20000000;
unsigned long free_addr = 0;

struct rlimit limit;

int byte_size = 4;

int malloc_size;
int no_free;

char area[786432];

// read /proc/pid/maps to get memory mapping
void read_map()
{
	ifstream proc_map;
	struct range temp;
	char buff[10];
	char name[20] = "/proc/";
	char line[256];
	char previous_line[256];

	sprintf(buff, "%d", pid);
	strncpy(name + 6, buff, strlen(buff));
	strcat(name, "/maps");
	
	proc_map.open(name);

	getrlimit(RLIMIT_STACK, &limit);

//	printf("limit %d %d\n", limit.rlim_cur, limit.rlim_max);
	global_range.lower = 0x8048000;
	global_range.lower_addr = (void *)global_range.lower;

	while (!proc_map.eof()) {
		proc_map.getline(line, 256);
		int len = strlen(line);
//		printf("%s\n",line);
		// Get Stack Size

		if (strncmp(line + len - strlen(STACK), STACK, strlen(STACK)) == 0) {
			sscanf(line, "%p-%p", &temp.lower_addr, &temp.upper_addr);
//			printf("%s\n",line);
//			printf("%p %p\n", temp.lower_addr, temp.upper_addr);

			temp.lower = (unsigned long)temp.lower_addr;
			temp.upper = (unsigned long)temp.upper_addr;

//			if (stack_range.upper != temp.upper) {
				stack_range = temp;
				stack_range.lower = stack_range.upper - limit.rlim_cur;
				stack_range.lower_addr = (void *)stack_range.lower;

				for (unsigned long i = stack_range.lower / 4096; i < stack_range.upper / 4096; i++)
					area[i] = 3;
//				printf("%p %p\n",stack_range.lower_addr, stack_range.upper_addr);
//				scanf("%d",&t);
//			}

		}
		// Get Global & Heap Size
//		else 
		if (strncmp(line + len - strlen(HEAP), HEAP, strlen(HEAP)) == 0) {
			sscanf(previous_line, "%p-%p", &temp.lower_addr, &temp.upper_addr);

			temp.lower = (unsigned long long)temp.lower_addr;
			temp.upper = (unsigned long long)temp.upper_addr;

//			if (global_range.lower != temp.lower ||
			if (global_range.upper != temp.upper) {
				global_range.upper = temp.upper;
				global_range.upper_addr = temp.upper_addr;
//				global_range = temp;
			}
			sscanf(line, "%p-%p", &temp.lower_addr, &temp.upper_addr);

			temp.lower = (unsigned long long)temp.lower_addr;
			temp.upper = (unsigned long long)temp.upper_addr;

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
	void *protect_addr;

	offset = (int) mmap((void *)offset, shadowMemSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	protect_addr = (void *)((offset >> 3) + offset);

	if (mprotect(protect_addr, shadowMemSize / 8, PROT_NONE) < 0) {
		printf("Shadow Memory Protection Error\n");
	}
}

// remove shadow memory
void freeShadowMemory()
{
	int ret = syscall(__NR_munmap, (void *)offset, shadowMemSize);

	if (ret < 0)
		printf("Shadow Memory at %p Free Failed!\n", (void *)offset);
}

int checkShadowMap(unsigned long addr, int size)
{
	int i = 0;
	int ct = 0;
	char wh;
	unsigned char *shadow_addr;

/*
	if (addr % 8 && size > 8) {
		shadow_addr = (unsigned char *) ((addr >> 3) + offset);
		clr = ((8 - (addr % 8)) > size) ? (8 - (addr % 8)) : size;
		*shadow_addr = (*shadow_addr << clr) >> clr;

		i = clr;
	}

	for (; i < size - 8; i += 8) {
		shadow_addr = (unsigned char *) (((addr + i) >> 3) + offset);
		*shadow_addr = 0;
	}

	if (i < size) {
		shadow_addr = (unsigned char *) (((addr + i) >> 3) + offset);
		*shadow_addr = (*shadow_addr >> (size - i)) << (size - i);
	}
	*/
//	shadow_addr = (unsigned char *) (((addr) >> 3) + offset);
	/*
	for (int i = 0; i < size; i++) {
		//byte-location

		//bit-position
		wh = (addr + i) & 7;

		//checking for bit-value
		wh = (*shadow_addr >> wh) & 1;
		ct += wh;
	}
		*/
	return ct;
}

int printShadowMap(unsigned long addr, int size)
{
	int ct = 0;
	char wh;
	unsigned char *shadow_addr;

	for (int i = 0; i < size; i++) {
		//byte-location
		shadow_addr = (unsigned char *) (((addr + i) >> 3) + offset);

		//bit-position
		wh = (addr + i) & 7;

		//checking for bit-value
		wh = (*shadow_addr >> wh) & 1;
		printf("print shadow %p %d\n", (void *)shadow_addr, *shadow_addr);
		ct += wh;
	}
	return ct;
}

// mark allocation
/*
 * JIKK: want to make this code inlinable
 */
int markAlloc(unsigned long addr, int size)
{
	char wh;
	unsigned char *shadow_addr;

//	return 0;
/*
	// unmark till 8 byte align
	if (addr % 8) { 
		shadow_addr = (unsigned char *) ((addr >> 3) + offset);
		clr = ((8 - (addr % 8)) > size) ? (8 - (addr % 8)) : size;
		*shadow_addr = (*shadow_addr << clr) >> clr;

		i = clr;
	}

	// unmark by byte ( 1 byte shadow mem = 8 byte )
	for (; i < size - 8; i += 8) {
		shadow_addr = (unsigned char *) (((addr + i) >> 3) + offset);
		*shadow_addr = 0;
	}

	// unmark leftovers
	if (i < size) {
		shadow_addr = (unsigned char *) (((addr + i) >> 3) + offset);
		*shadow_addr = (*shadow_addr >> (size - i)) << (size - i);
	}
*/
	for (int i = 0; i < size; i++) {
		//getting byte-location
		shadow_addr = (unsigned char *) (((addr + i) >> 3) + offset);	

		//getting bit-position
		wh = (addr + i) & 7;
		*shadow_addr = *shadow_addr | (1 << wh);
	}
	return 0;
}

// unmark deallocation
int unmarkAlloc(unsigned long addr, int size)
{
	int i = 0;
	int clr;
	unsigned char *shadow_addr;

//	return 0;
	if (addr % 8 && size > 8) {
		shadow_addr = (unsigned char *) ((addr >> 3) + offset);
		clr = ((8 - (addr % 8)) > size) ? (8 - (addr % 8)) : size;
		*shadow_addr = (*shadow_addr << clr) >> clr;

		i = clr;
	}

	for (; i < size - 8; i += 8) {
		shadow_addr = (unsigned char *) (((addr + i) >> 3) + offset);
		*shadow_addr = 0;
	}

	if (i < size) {
		shadow_addr = (unsigned char *) (((addr + i) >> 3) + offset);
		*shadow_addr = (*shadow_addr >> (size - i)) << (size - i);
	}

	return 0;
}

