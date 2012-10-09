/* ******************************************************************************
 * Copyright (c) 2011 Massachusetts Institute of Technology  All rights reserved.
 * Copyright (c) 2008 VMware, Inc.  All rights reserved.
 * ******************************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Code Manipulation API Sample:
 * inscount.c
 *
 * Reports the dynamic count of total number of instructions executed.
 * Illustrates how to perform performant clean call.
 * Demonstrates effect of clean call optimization and auto-inlining with
 * different -opt_cleancall value.
 */

#include "dr_api.h"

#ifdef WINDOWS
# define DISPLAY_STRING(msg) dr_messagebox(msg)
#else
# define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
#endif

#define NULL_TERMINATE(buf) buf[(sizeof(buf)/sizeof(buf[0])) - 1] = '\0'


#define TESTALL(mask, var) (((mask) & (var)) == (mask))
#define TESTANY(mask, var) (((mask) & (var)) != 0)
/* we only have a global count */
static uint64 global_count;
/* A simple clean call that will be automatically inlined because it has only 
 * one argument and contains no calls to other functions.
 */
//static void inscount(uint num_instrs) { new_count += num_instrs; }
static void event_exit(void);
static dr_emit_flags_t event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                                         bool for_trace, bool translating);

DR_EXPORT void 
dr_init(client_id_t id)
{
    /* register events */
    dr_register_exit_event(event_exit);
    dr_register_bb_event(event_basic_block);

    /* make it easy to tell, by looking at log file, which client executed */
    dr_log(NULL, LOG_ALL, 1, "Client 'inscount' initializing\n");
#ifdef SHOW_RESULTS
    /* also give notification to stderr */
    if (dr_is_notify_on()) {
# ifdef WINDOWS
        /* ask for best-effort printing to cmd window.  must be called in dr_init(). */
        dr_enable_console_printing();
# endif
        dr_fprintf(STDERR, "Client inscount is running\n");
    }
#endif
}

static void 
event_exit(void)
{
#ifdef SHOW_RESULTS
    char msg[512];
    int len;
    len = dr_snprintf(msg, sizeof(msg)/sizeof(msg[0]),
                      "Instrumentation results: %llu instructions executed\n",
                      global_count);
    DR_ASSERT(len > 0);
    NULL_TERMINATE(msg);
    DISPLAY_STRING(msg);
#endif /* SHOW_RESULTS */
}

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating)
{
    instr_t *instr, *first = instrlist_first(bb), *point = NULL;
    uint num_instrs;
	uint flags;
    

    for (instr  = first, num_instrs = 0;
         instr != NULL;
         instr = instr_get_next(instr)) {
        num_instrs++;

/*
		flags = instr_get_arith_flags(instr);
		if (TESTALL(EFLAGS_WRITE_6, flags) && !TESTANY(EFLAGS_READ_6, flags)) {
			point = instr;
			for (; instr != NULL; instr = instr_get_next(instr))
				num_instrs++;
			break;
		}
		*/
    }
	
	if (point == NULL) {
		dr_save_reg(drcontext, bb, first, DR_REG_XAX, SPILL_SLOT_1);
		dr_save_arith_flags_to_xax(drcontext, bb, first);
	}
//	else first = point;

    instrlist_meta_preinsert
        (bb, first,
         INSTR_CREATE_add(drcontext, OPND_CREATE_ABSMEM
                               ((byte *)&global_count, OPSZ_4), OPND_CREATE_INT32(num_instrs)));

    instrlist_meta_preinsert
        (bb, first,
         INSTR_CREATE_adc(drcontext, OPND_CREATE_ABSMEM
                               ((byte *)&global_count + 4, OPSZ_4), OPND_CREATE_INT32(0)));

	if (point == NULL) {
		dr_restore_arith_flags_from_xax(drcontext, bb, first);
		dr_restore_reg(drcontext, bb, first, DR_REG_XAX, SPILL_SLOT_1);
	}

/*
    dr_insert_clean_call(drcontext, bb, instrlist_first(bb), 
                         (void *)inscount, false , 1,
                         OPND_CREATE_INT32(num_instrs));
						 */

    return DR_EMIT_DEFAULT;
}
