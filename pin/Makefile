CXXFLAGS	+= -Wall -c -fomit-frame-pointer -O3	\
		   -fno-strict-aliasing -fno-stack-protector	\
		   -DBIGARRAY_MULTIPLIER=1 -DUSING_XED		\
		   -DTARGET_IA32 -DHOST_IA32 -DTARGET_LINUX	\
		   # -DHUGE_TLB -mtune=core2
CXXFLAGS2	+= -Wl,--hash-style=sysv \
		   -shared -Wl,-Bsymbolic -Wl,--version-script=$(PIN_HOME)/source/include/pintool.ver
ARGFLAGS2	= -lpin -lxed -ldwarf -lelf -ldl 
H_INCLUDE	+= -I$(PIN_HOME)/source/include		\
		   -I$(PIN_HOME)/source/include/gen		\
		   -I$(PIN_HOME)/extras/xed2-ia32/include	\
		   -I$(PIN_HOME)/extras/components/include

L_INCLUDE	+= -L$(PIN_HOME)/source/tools/Lib/	\
		   -L$(PIN_HOME)/source/tools/ExtLib/	\
		   -L$(PIN_HOME)/extras/xed2-ia32/lib	\
		   -L$(PIN_HOME)/ia32/lib	\
		   -L$(PIN_HOME)/ia32/lib-ext	

SOBJS		= pin_mem_profiler.so
OBJS		= inst_handle.o syscall_handle.o shadow_map.o pin_mem_profiler.o
LIB		= pin_mem_profiler.a 

all: check_pin $(LIB) $(SOBJS)

check_pin:
ifndef PIN_HOME
	$(error "Please Set PIN_HOME Environment")
endif

$(LIB): $(OBJS)
#	$(AR) $(ARFLAGS) $(@) $(OBJS)

syscall_handle.o: syscall_handle.cpp syscall_handle.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

inst_handle.o: inst_handle.cpp inst_handle.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

shadow_map.o: shadow_map.cpp shadow_map.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

pin_mem_profiler.so: pin_mem_profiler.o
	$(CXX) $(CXXFLAGS2) $(L_INCLUDE) -o $(@) $(OBJS) $(ARGFLAGS2)

pin_mem_profiler.o: pin_mem_profiler.cpp pin_mem_profiler.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)


clean:
	-rm -rf $(OBJDIR) *.o *.so
