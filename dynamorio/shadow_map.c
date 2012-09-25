#include "profiler.h"

static void read_map()
{
	int i;
	int buff_size;
	int read_size = 32;
	int made_line;
	int prev_line_size;
	FILE *proc_map;
	char buff[10];
	char name[20] = "/proc/";
	char line[256];
	char prev_line[256];
	char temp_line[256];
	struct rlimit limit;
	struct rlimit rl;
	struct rlimit rl2;

	pid = getpid();
	sprintf(buff, "%d", pid);
	strncpy(name + 6, buff, strlen(buff));
	strcat(name, "/maps");
	
	proc_map = fopen(name, "r");

	getrlimit(RLIMIT_STACK, &limit);

	global_range.lower = 0x8048000;
	global_range.lower_addr = (void *)global_range.lower;
	buff_size = fread(line, 1, read_size, proc_map);
	prev_line_size = 0;

	made_line = 0;

	for (i = buff_size - 1; i >= 0; i--)
		if (line[i] == '\n') {
			strncpy(prev_line + prev_line_size, line, i);
			prev_line[prev_line_size + i] = '\x0';
			made_line = 1;
			break;
		}
		else if (i == 0) {
			strncpy(prev_line, line, buff_size);
			prev_line_size = buff_size;
			prev_line[buff_size] = '\x0';
			made_line = 0;
		}

	while (buff_size == read_size) {
		buff_size = fread(line, 1, read_size, proc_map);
	//	buff_size = fgets(line, read_size, proc_map);

		for (i = buff_size - 1; i >= 0; i--)
			if (line[i] == '\n') {
				strncpy(prev_line + prev_line_size, line, i);
				prev_line[prev_line_size + i] = '\x0';
				prev_line_size += i;
				
				if (!strncmp(prev_line + prev_line_size - strlen(STACK), STACK, strlen(STACK))) {

					sscanf(prev_line, "%x-%x", (unsigned int *)&stack_range.lower, (unsigned int *)&stack_range.upper);
//					stack_range.upper = VG_(strtoull16)(temp_s2, NULL);

					getrlimit(RLIMIT_STACK, &rl);
					getrlimit(RLIMIT_DATA, &rl2);
					stack_range.lower = stack_range.upper - rl.rlim_cur;

					stack_range.lower_addr = (void *)stack_range.lower;
					stack_range.upper_addr = (void *)stack_range.upper;

//					heap_range.upper = stack_range.lower;
//					heap_range.upper_addr  = (void *)heap_range.upper;

//					dr_fprintf(STDERR, "stack %x %x\n", stack_range.lower, stack_range.upper);
				}
				strcpy(temp_line, prev_line);
				i++;
				strncpy(prev_line, line + i, buff_size - i);
				prev_line_size = buff_size - i;

				break;
			}
			else if (i == 0) {
				strncpy(prev_line + prev_line_size, line, buff_size);
				prev_line_size += buff_size;
				prev_line[prev_line_size] = '\x0';
				made_line = 0;
			}
	}

	fclose(proc_map);
}

static void reserve_shadow_map()
{
	void *protect_addr;
	
	offset = (unsigned long) mmap((void *)offset, shadowMemSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	protect_addr = (void *)((offset >> 3) + offset);
	if (mprotect(protect_addr, shadowMemSize / 8, PROT_NONE) < 0) {
		dr_fprintf(STDERR, "Shadow Memory Protection Error\n");
	}
}

int check_alloc(unsigned long addr, int size)
{
	int i, ct = 0;
	char wh;
	unsigned char *shadow_addr;

	for (i = 0; i < size; i++) {
		//byte-location
		shadow_addr = (unsigned char *) (((addr + i) >> 3) + offset);

//		if (i % 8 == 0)
//			dr_fprintf(STDERR, "check shadow_addr %x %d\n", shadow_addr, *shadow_addr);

		//bit-position
		wh = (addr + i) & 7;

		//checking for bit-value
		wh = (*shadow_addr >> wh) & 1;
		ct += wh;
	}
	return ct;
}

int markAlloc(unsigned long addr, int size)
{
	int i;
	char wh;
	unsigned char *shadow_addr;

	for (i = 0; i < size; i++) {
		//byte-location
		shadow_addr = (unsigned char *) (((addr + i) >> 3) + offset);

		//bit-position
		wh = (addr + i) & 7;

		//marking 
		*shadow_addr = *shadow_addr | (1 << wh);
		/*
		if (i % 8 == 0)
			dr_fprintf(STDERR, "mark shadow_addr %x %d\n", shadow_addr, *shadow_addr);
		*/
	}
	return 0;
}

int unmarkAlloc(unsigned long addr, int size)
{
	int i = 0;
	int clr;
	unsigned char *shadow_addr;

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
