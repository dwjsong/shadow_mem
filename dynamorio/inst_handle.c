#include "profiler.h"

/*
static void trace_load(unsigned long addr, int size)
{
	addr_buf[buf_pos] = (void *)addr;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
}

static void trace_store(unsigned long addr, int size)
{
	addr_buf[buf_pos] = (void *)addr;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
}
static void trace_load(unsigned long addr, int size)
{
	int count = 0;
	unsigned long addr_val = (unsigned long) addr;

	
	addr_buf[buf_pos] = (void *)addr;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
	if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.read += size;
		heap_success.read += count;
		heap_fail.read += size - count;
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else {
		other_count.read += size;
	}
}

static void trace_store(unsigned long addr, int size)
{
	int count = 0; 
	unsigned long addr_val = (unsigned long) addr;

	addr_buf[buf_pos] = (void *)addr;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
	if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.write += size;
		heap_success.write += count;
		heap_fail.write += size - count;
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else {
		other_count.write += size;
	}
}

*/
static void trace_load(unsigned long addr, int size)
{
	int count;
	unsigned long addr_val = (unsigned long) addr;

	
//	dr_printf("r g %p h %p %p s %p %p a %p s %d\n", global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
	addr_buf[buf_pos] = (void *)addr;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
	if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.read += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
		heap_count.read += size;
		count = check_alloc(addr, size);
		heap_success.read += count;
		heap_fail.read += size - count;
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.read += size;
	}
	else {
		other_count.read += size;
	}
}

static void trace_store(unsigned long addr, int size)
{
	int count; 
	unsigned long addr_val = (unsigned long) addr;

	addr_buf[buf_pos] = (void *)addr;
	buf_pos++;
	buf_pos = buf_pos & MODUL;
	if (global_range.upper > addr_val && addr_val > global_range.lower) {
		global_count.write += size;
	}
	else if (heap_range.upper > addr_val && addr_val > heap_range.lower) {
//		dr_fprintf(STDERR, "w g %p h %p %p s %p %p a %p s %d\n", global_range.upper_addr, heap_range.lower_addr, heap_range.upper_addr, stack_range.lower_addr, stack_range.upper_addr, (void *)addr, size);
		heap_count.write += size;
		count = check_alloc(addr, size);
		heap_success.write += count;
		heap_fail.write += size - count;
	}
	else if (stack_range.upper > addr_val && addr_val > stack_range.lower) {
		stack_count.write += size;
	}
	else {
		other_count.write += size;
	}
}

static void
memtrace(void *drcontext)
{
    per_thread_t *data;
    int num_refs;
    mem_ref_t *mem_ref;
//#ifdef READABLE_TRACE
    int i;
//#endif

    data      = drmgr_get_tls_field(drcontext, tls_index);
    mem_ref   = (mem_ref_t *)data->buf_base;
    num_refs  = (int)((mem_ref_t *)data->buf_ptr - mem_ref);

//#ifdef READABLE_TRACE
    for (i = 0; i < num_refs; i++) {
		if (mem_ref->write) {
			trace_store((unsigned long)mem_ref->addr, mem_ref->size);
		}
		else {
			trace_load((unsigned long)mem_ref->addr, mem_ref->size);
		}
//        dr_fprintf(data->log, "%c%d:"PFX"\n",
//                   mem_ref->write ? 'w' : 'r', mem_ref->size, mem_ref->addr);
        ++mem_ref;
    }
	/*
#else
    dr_write_file(data->log, data->buf_base,
                  (size_t)(data->buf_ptr - data->buf_base));
#endif
*/

    memset(data->buf_base, 0, MEM_BUF_SIZE);
    data->num_refs += num_refs;
    data->buf_ptr   = data->buf_base;
}

/* clean_call dumps the memory reference info to the log file */
static void
clean_call(void)
{
    void *drcontext = dr_get_current_drcontext();
    memtrace(drcontext);
}

/* event_bb_insert calls instrument_mem to instrument every
 * application memory reference.
 */
static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb,
                instr_t *instr, bool for_trace, bool translating,
                void *user_data)
{
    int i;
    if (instr_get_app_pc(instr) == NULL)
        return DR_EMIT_DEFAULT;
    if (instr_reads_memory(instr)) {
        for (i = 0; i < instr_num_srcs(instr); i++) {
            if (opnd_is_memory_reference(instr_get_src(instr, i))) {
                instrument_mem(drcontext, bb, instr, i, false);
            }
        }
    }
    if (instr_writes_memory(instr)) {
        for (i = 0; i < instr_num_dsts(instr); i++) {
            if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
                instrument_mem(drcontext, bb, instr, i, true);
            }
        }
    }
    return DR_EMIT_DEFAULT;
}

/*
 * instrument_mem is called whenever a memory reference is identified.
 * It inserts code before the memory reference to to fill the memory buffer
 * and jump to our own code cache to call the clean_call when the buffer is full.
 */
static void
instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where, 
               int pos, bool write)
{
//    instr_t *instr, *call, *restore;
    instr_t *instr;
    opnd_t   ref, opnd1, opnd2;
    reg_id_t reg1 = DR_REG_XAX; /* We can optimize it by picking dead reg */
    reg_id_t reg2 = DR_REG_XCX; /* reg2 must be ECX or RCX for jecxz */

//	uint flags, dead;

    /* Steal the register for memory reference address *
     * We can optimize away the unnecessary register save and restore 
     * by analyzing the code and finding the register is dead. 
     */

    if (write)
       ref = instr_get_dst(where, pos);
    else
       ref = instr_get_src(where, pos);


    dr_save_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
    dr_save_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);


///*
	// reg2 = buf_pos
    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_ABSMEM((byte *)&buf_pos, OPSZ_4);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

	// reg1 = &buffer
    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_INTPTR(buffer);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

	// reg1 = reg1 + reg2 * sizeof(mem_ref_t)
	// 		= buffer + buf_pos * sizeof(mem_ref_t)
	// 		= buffer[buf_pos]
    opnd1 = opnd_create_reg(reg1);
    opnd2 = opnd_create_base_disp(reg1, reg2, sizeof(mem_ref_t), 0, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

	// buffer[buf_pos].write = write
    opnd1 = OPND_CREATE_MEMPTR(reg1, offsetof(mem_ref_t, write));
    opnd2 = OPND_CREATE_INT32(write);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

	// buffer[buf_pos].size = mem_size 
    opnd1 = OPND_CREATE_MEMPTR(reg1, offsetof(mem_ref_t, size));
    opnd2 = OPND_CREATE_INT32(drutil_opnd_mem_size_in_bytes(ref, where));
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

	// buffer[buf_pos].addr = addr;
    opnd1 = OPND_CREATE_MEMPTR(reg1, offsetof(mem_ref_t, addr));
    drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg2, reg1);
    opnd2 = opnd_create_reg(reg2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
/*	
    opnd1 = OPND_CREATE_ABSMEM((byte *)&buf_pos, OPSZ_4);
    instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = OPND_CREATE_ABSMEM((byte *)&buf_pos, OPSZ_4);
    opnd2 = OPND_CREATE_INT32(0x00001fff);
    instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
	*/

	dr_save_arith_flags_to_xax(drcontext, ilist, where);	

    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_ABSMEM((byte *)&buf_pos, OPSZ_4);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(reg2);
    instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_INT32(0x00001fff);
    instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = OPND_CREATE_ABSMEM((byte *)&buf_pos, OPSZ_4);
    opnd2 = opnd_create_reg(reg2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

	dr_restore_arith_flags_from_xax(drcontext, ilist, where);

    dr_restore_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
    dr_restore_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);
}

