include $(top_srcdir)/Makefile.tool.am

EXTRA_DIST = docs/pf-manual.xml

#----------------------------------------------------------------------------
# profiler-<platform>
#----------------------------------------------------------------------------

noinst_PROGRAMS  = profiler-@VGCONF_ARCH_PRI@-@VGCONF_OS@
if VGCONF_HAVE_PLATFORM_SEC
noinst_PROGRAMS += profiler-@VGCONF_ARCH_SEC@-@VGCONF_OS@
endif

NONE_SOURCES_COMMON = pf_main.c

profiler_@VGCONF_ARCH_PRI@_@VGCONF_OS@_SOURCES      = \
	$(NONE_SOURCES_COMMON)
profiler_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
profiler_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CFLAGS       = \
	$(AM_CFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
profiler_@VGCONF_ARCH_PRI@_@VGCONF_OS@_DEPENDENCIES = \
	$(TOOL_DEPENDENCIES_@VGCONF_PLATFORM_PRI_CAPS@)
profiler_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDADD        = \
	$(TOOL_LDADD_@VGCONF_PLATFORM_PRI_CAPS@)
profiler_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDFLAGS      = \
	$(TOOL_LDFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
profiler_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LINK = \
	$(top_builddir)/coregrind/link_tool_exe_@VGCONF_OS@ \
	@VALT_LOAD_ADDRESS_PRI@ \
	$(LINK) \
	$(profiler_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CFLAGS) \
	$(profiler_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDFLAGS)

if VGCONF_HAVE_PLATFORM_SEC
profiler_@VGCONF_ARCH_SEC@_@VGCONF_OS@_SOURCES      = \
	$(NONE_SOURCES_COMMON)
profiler_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
profiler_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CFLAGS       = \
	$(AM_CFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
profiler_@VGCONF_ARCH_SEC@_@VGCONF_OS@_DEPENDENCIES = \
	$(TOOL_DEPENDENCIES_@VGCONF_PLATFORM_SEC_CAPS@)
profiler_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDADD        = \
	$(TOOL_LDADD_@VGCONF_PLATFORM_SEC_CAPS@)
profiler_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDFLAGS      = \
	$(TOOL_LDFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
profiler_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LINK = \
	$(top_builddir)/coregrind/link_tool_exe_@VGCONF_OS@ \
	@VALT_LOAD_ADDRESS_SEC@ \
	$(LINK) \
	$(profiler_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CFLAGS) \
	$(profiler_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDFLAGS)
endif


