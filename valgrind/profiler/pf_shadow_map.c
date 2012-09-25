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

void check_mem_map()
{
	Int i;
	Int buff_size;
	Int pid;
	Int fd;
	Int prev_line_size;
	Int read_size = 32;
	Int made_line;
	SysRes res;
	Char buff[10];
	Char name[20] = "/proc/";
	Char line[256];
	Char prev_line[256];
	Char temp_s[16];
	Char temp_s2[16];
	struct vki_rlimit rl;
	struct vki_rlimit rl2;
	Char temp_line[256];
	
	pid = VG_(getpid)();
	VG_(sprintf)(buff, "%d", pid);
	VG_(strncpy)(name + 6, buff, VG_(strlen)(buff));
	VG_(strcat)(name, "/maps");

//	VG_(printf)("pid = %s %d\n", name, pid);

	res = VG_(open)(name, 0, 0);
	fd = (Int) sr_Res(res);

	buff_size = VG_(read)(fd, line, read_size);
	prev_line_size = 0;

	made_line = 0;
	for (i = buff_size - 1; i >= 0; i--)
		if (line[i] == '\n') {
			VG_(strncpy)(prev_line + prev_line_size, line, i);
			prev_line[prev_line_size + i] = '\x0';
			made_line = 1;
			break;
		}
		else if (i == 0) {
			VG_(strncpy)(prev_line, line, buff_size);
			prev_line_size = buff_size;
			prev_line[buff_size] = '\x0';
			made_line = 0;
		}


	while (buff_size == read_size) {

		buff_size = VG_(read)(fd, line, read_size);

		for (i = buff_size - 1; i >= 0; i--)
			if (line[i] == '\n') {
				VG_(strncpy)(prev_line + prev_line_size, line, i);
				prev_line[prev_line_size + i] = '\x0';
				prev_line_size += i;
				
				if (!VG_(strncmp)(prev_line + prev_line_size - VG_(strlen)(STACK), STACK, VG_(strlen)(STACK))) {

					VG_(strncpy)(temp_s, temp_line, 8);
					
					VG_(strncpy)(temp_s2, temp_line + 9, 8);
					stack_range.upper = VG_(strtoull16)(temp_s2, NULL);

					VG_(getrlimit(VKI_RLIMIT_STACK, &rl));
					VG_(getrlimit(VKI_RLIMIT_DATA, &rl2));
					stack_range.lower = stack_range.upper - rl.rlim_cur;

					stack_range.lower_addr = (void *)stack_range.lower;
					stack_range.upper_addr = (void *)stack_range.upper;

				}
				VG_(strcpy)(temp_line, prev_line);
				VG_(strncpy)(prev_line, line + ++i, buff_size - i);
				prev_line_size = buff_size - i;

				break;
			}
			else if (i == 0) {
				VG_(strncpy)(prev_line + prev_line_size, line, buff_size);
				prev_line_size += buff_size;
				prev_line[prev_line_size] = '\x0';
				made_line = 0;
			}
//		VG_(printf)("%d\n", buff_size);
	}

	VG_(close)(name);
}

void reserve_shadow_memory()
{
	reserve_map = VG_(am_shadow_alloc)(map_size);

//	VG_(printf)("reserve %p\n", reserve_map);
}

void free_shadow_memory()
{
	VG_(am_munmap_valgrind)(reserve_map, map_size);
}

Int check_map(ULong addr, Int size)
{
	Int i;
	Int ct = 0;
	Char wh;
	Addr idAddr;
	UChar *t;
	UChar data;
	Int tt = 0;

	idAddr = ((addr) >> 3) + reserve_map;
	t = idAddr;
	data = *t;
	for (i = 0; i < size; i++) {

		wh = (addr + i) & 7;

		tt  = ((data >> wh) & 1);

		ct += tt;
	}
	return ct;
}

Int unmark_alloc(ULong addr, Int size)
{
	Int i = 0;
	Int clr;
	Addr idAddr;
	UChar *t;

	if (addr % 8 && size > 8) {
		idAddr = (addr >> 3) + reserve_map;
		t = idAddr;

		clr = ((8 - (addr % 8)) > size) ? (8 - (addr % 8)) : size;
		*t = (*t << clr) >> clr;

		i = clr;
	}

	for (; i < size - 8; i += 8) {
		idAddr = ((addr + i) >> 3) + reserve_map;
		t = idAddr;
		*t = 0;
	}

	if (i < size) {
		idAddr = ((addr + i) >> 3) + reserve_map;
		t = idAddr;
		*t = (*t >> (size - i)) << (size - i);
	}

	return 0;
}

Int mark_alloc(ULong addr, Int size)
{
	Int i;
	Char wh;
	UChar *t;
	Addr idAddr;

	for (i = 0; i < size; i++) {

		idAddr = ((addr + i) >> 3) + reserve_map;

		wh = (addr + i) & 7;

		t = idAddr;

		*t = *t | (1 << wh);
	}
	return 0;
}

