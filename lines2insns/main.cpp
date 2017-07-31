/* lines2insns - determine the positions of machine instructions
 * corresponding to memory accesses in the given source locations.
 *
 * See 'lines2insns --help' for usage details.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * Copyright (C) 2014, Eugene Shatokhin <eugene.shatokhin@rosalab.ru>
 *
 * 2014		Initial implementation.
 *
 * 2015		Convenience features: section-to-area conversions, etc.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <stdexcept>
#include <sstream>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <getopt.h>
#include <libgen.h>	/* basename() */

#include <libelf.h>
#include <dwarf.h>
#include <elfutils/libdwfl.h>

#include <common/insn.h>
#include <common/util.h>

#include "config_lines2insns.h"
/* ====================================================================== */

#define APP_USAGE \
 "Usage:\n" \
 "\t" APP_NAME " [options] <module_file> < <source_locations> " \
 "> <insn_locations>\n" \
 "Execute \'" APP_NAME " --help\' for more information.\n\n"

#define APP_HELP \
 APP_NAME " [options] <module_file> [debug_info_file]\n\n" \
 APP_NAME " reads the list of source locations for a kernel or a given\n" \
 "kernel module from stdin and outputs the list of machine instructions\n" \
 "corresponding to these locations that may access memory to stdout.\n\n" \
 "" \
 "If the debug info for a kernel module is kept in a separate file,\n" \
 "two files should be specified: the first one should contain the code\n" \
 "of the module and the second one - the debug info for it.\n\n" \
 "" \
 "Each input line must have the following format:\n\n" \
 "<path_to_source_file>:<line_no>[:{read|write}]\n\n" \
 "" \
 "Examples:\n\n" \
 "examples/sample_target/cfake.c:173:read\n" \
 "test.c:144\n" \
 "test2/test2.c:55:write\n\n" \
 "" \
 APP_NAME " reads the list of sections and debug info from the given file.\n" \
 "" \
 "The tool outputs the list of the corresponding machine instructions\n" \
 "in the following format, one per line:\n\n" \
 "[<module>:]{init|core}+0xoffset\n\n" \
 "" \
 "'init' and 'core' are the two main areas of the loaded kernel or\n" \
 "module. 'core' contains all code sections, without gaps, in the\n" \
 "order they appear in the ELF file (*.ko or vmlinu*) except *.init.text*\n" \
 "sections, which belong to 'init' area and go in order too.\n\n" \
 "" \
 "If the given file is a module, its name without .ko followed by\n" \
 "a colon (with '-' characters replaced by underscores like the kernel\n" \
 "does) will be output first. No such prefix will be output for the\n" \
 "kernel proper or the built-in modules.\n\n" \
 "" \
 "Example:\n\n" \
 "$ echo 'my-driver/main.c:126' | " APP_NAME " my-driver.ko my-driver.ko.debug\n" \
 "my_driver:core+0x568\n" \
 "my_driver:core+0x575\n\n" \
 "" \
 "Options:\n\n" \
 "" \
 "--help\n\t" \
 "Show this help and exit.\n\n" \
 "" \
 "--with-stack\n\t" \
 "By default, %esp/%rsp-based memory accesses are not output. This option\n\t" \
 "tells " APP_NAME " to output such instructions too.\n" \
 "" \
 "--with-locked\n\t" \
 "By default, locked operations are not output. This option tells\n\t" \
 APP_NAME " to output such instructions too.\n" \
 "" \
 "--no-filter\n\t" \
 "Output all found instructions, without filtering. Debugging feature.\n\t" \
 "Among other things, this overrides '--with-stack' and '--with-locked'.\n" \
 "" \
 "-v, --verbose\n\t" \
 "Output more messages to stderr about what is being done.\n\n" \
 "" \
 "The following two options are provided for convenience.\n\n" \
 "--section-to-area\n\t" \
 "In this mode, the tool converts the addresses specified as\n\t" \
 "\"[<module>:]section+0xoffset_in_section\" in each line from stdin\n\t" \
 "to " \
 "\"[<module>:]{init|core}+0xoffset_in_init_or_core_area\" and outputs\n\t" \
 "to stdout. Note that unlike modules, only .text section is considered\n\t" \
 "for the kernel proper.\n" \
 "" \
 "--area-to-section\n\t" \
 "The reverse of --section-to-area.\n"
/* ====================================================================== */

using namespace std;
/* ====================================================================== */

/* See the command-line options. */
static bool with_stack = false;
static bool with_locked = false;
static bool verbose = false;
static bool no_filter = false;
static bool section_to_area = false;
static bool area_to_section = false;

/* 1 if the module is built for x86-64, 0 otherwise (32-bit x86, because
 * only x86 architecture is currently supported here). */
static int is_module_x64 = 0;

/* Name of the kernel module (the part before .ko), empty for the kernel
 * proper (vmlinu*). */
static string kmodule_name;
static bool
is_kernel_image()
{
	return kmodule_name.empty();
}

/* The path to the module's file specified by the user. */
static string kmodule_path;
/* The path to the file containing the debug info. */
static string dbg_path;
/* ====================================================================== */

/* Same as strstarts() from the kernel. */
static bool
starts_with(const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}
/* ====================================================================== */

static void
show_usage()
{
	cerr << APP_USAGE;
}

static void
show_help()
{
	cout << APP_HELP;
}

static bool
extract_kmodule_name()
{
	static string kernel_image = "vmlinu";

	/* basename() needs a string that can be changed. */
	char *str = strdup(kmodule_path.c_str());
	if (str == NULL) {
		cerr << "Not enough memory." << endl;
		return false;
	}

	string kmodule_file = basename(str);
	free(str);

	if (starts_with(kmodule_file.c_str(), kernel_image.c_str())) {
		/* A kernel image. */
		return true;
	}

	/* Get the module name w/o any extensions. */
	size_t pos = kmodule_file.find_first_of(".");
	kmodule_name = kmodule_file.substr(0, pos);

	/* Within the kernel, all modules have dashes replaced with
	 * underscores in their names. */
	for (size_t i = 0; i < kmodule_name.size(); ++i) {
		if (kmodule_name[i] == '-')
			kmodule_name[i] = '_';
	}
	return true;
}

/* Process the command line arguments. Returns true if successful, false
 * otherwise. */
static bool
process_args(int argc, char *argv[])
{
	int c;
	string module_dir = ".";

	struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"with-stack", no_argument, NULL, 's'},
		{"with-locked", no_argument, NULL, 'l'},
		{"no-filter", no_argument, NULL, 'n'},
		{"verbose", no_argument, NULL, 'v'},
		{"section-to-area", no_argument, NULL, 'e'},
		{"area-to-section", no_argument, NULL, 'a'},
		{NULL, 0, NULL, 0}
	};

	while (true) {
		int index = 0;
		c = getopt_long(argc, argv, "v", long_options, &index);
		if (c == -1)
			break;  /* all options have been processed */

		switch (c) {
		case 0:
			break;
		case 'h':
			show_help();
			exit(EXIT_SUCCESS);
			break;
		case 's':
			with_stack = true;
			break;
		case 'l':
			with_locked = true;
			break;
		case 'n':
			no_filter = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 'e':
			section_to_area = true;
			break;
		case 'a':
			area_to_section = true;
			break;
		case '?':
			/* Unknown option, getopt_long() should have already
			printed an error message. */
			return false;
		default:
			assert(false); /* Should not get here. */
		}
	}

	if (optind == argc) {
		cerr << "Please specify the file of the kernel or module."
			<< endl;
		return false;
	}

	if (section_to_area && area_to_section) {
		cerr << "--section-to-area and --area-to-section "
			<< "should not be specified at the same time."
			<< endl;
		return false;
	}

	kmodule_path = argv[optind];
	if (optind + 1 < argc) {
		dbg_path = argv[optind + 1];
	}
	else {
		dbg_path = kmodule_path;
	}
	return extract_kmodule_name();
}
/* ====================================================================== */

/* It is not needed for libdw to search itself for the files with debug
 * info. So, a stub is used instead of the default callback of this kind. */
static int
find_debuginfo(Dwfl_Module *mod __attribute__ ((unused)),
	       void **userdata __attribute__ ((unused)),
	       const char *modname __attribute__ ((unused)),
	       GElf_Addr base __attribute__ ((unused)),
	       const char *file_name __attribute__ ((unused)),
	       const char *debuglink_file __attribute__ ((unused)),
	       GElf_Word debuglink_crc __attribute__ ((unused)),
	       char **debuginfo_file_name __attribute__ ((unused)))
{
	return -1; /* as if found nothing */
}

/* .find_elf callback should not be called by libdw because we use
 * dwfl_report_elf() to inform the library about the file with debug info.
 * The callback is still provided in case something in libdw expects it to
 * be. */
static int
find_elf(Dwfl_Module *mod __attribute__ ((unused)),
	 void **userdata __attribute__ ((unused)),
	 const char *modname __attribute__ ((unused)),
	 Dwarf_Addr base __attribute__ ((unused)),
	 char **file_name __attribute__ ((unused)),
	 Elf **elfp __attribute__ ((unused)))
{
	return -1; /* as if found nothing */
}

/* A wrapper around a handle to libdw/libdwfl that closes the handle on
 * exit. */
class DwflWrapper
{
	Dwfl *dwfl_handle;
	Dwfl_Callbacks cb;

public:
	/* An object to access DWARF info of the kernel module. */
	Dwfl_Module *dwfl_mod;

	Elf *e;
	GElf_Addr bias;

public:
	DwflWrapper()
	{
		cb.section_address = dwfl_offline_section_address;
		cb.find_debuginfo = find_debuginfo;
		cb.find_elf = find_elf;

		dwfl_handle = dwfl_begin(&cb);
		if (dwfl_handle == NULL) {
			throw runtime_error(string(
				"Failed to initialize DWARF facilities: ") +
				dwfl_errmsg(-1));
		}
	}

	~DwflWrapper()
	{
		dwfl_end(dwfl_handle);
	}

	Dwfl *get_handle() const
	{
		return dwfl_handle;
	}
};

DwflWrapper wr_dwfl;

/* A wrapper around the ELF object with the code that closes the handle
 * when destroyed. */
class ElfWrapper
{
public:
	int fd;
	Elf *e;
public:
	ElfWrapper(const string &path) {
		errno = 0;
		fd = open(path.c_str(), O_RDONLY, 0);
		if (fd == -1) {
			ostringstream err;
			err << "Failed to open \"" << path << "\": " <<
				strerror(errno) << endl;
			throw runtime_error(err.str());
		}

		e = elf_begin(fd, ELF_C_READ, NULL);
		if (e == NULL) {
			close(fd);
			ostringstream err;
			err << "elf_begin() failed for " << path << ": " <<
				elf_errmsg(-1) << endl;
			throw runtime_error(err.str());
		}

		if (elf_kind(e) != ELF_K_ELF) {
			elf_end(e);
			close(fd);
			throw runtime_error(
				string("Not an ELF object file: ") + path);
		}
	}

	~ElfWrapper() {
		elf_end(e);
		close(fd);
	}
private:
	ElfWrapper(); /* Prohibit the use of the default ctor. */
};
/* ====================================================================== */

struct InsnInfo
{
	/* Offset of the instruction in the section it belongs to. */
	unsigned int offset;

	/* The access type of interest. */
	EAccessType atype;

	friend bool operator<(const InsnInfo &left, const InsnInfo &right)
	{
		if (left.offset < right.offset)
			return true;

		if (left.offset == right.offset && left.atype < right.atype)
			return true;

		return false;
	}
};

/* Instruction locations in the given ELF section and other data for that
 * section. */
struct SectionInfo
{
	/* Name of the section. */
	string name;

	/* Start offset of this section in the area ('init' or 'core') it
	 * belongs to.
	 * Valid only for the modules, not for the kernel image. */
	unsigned int start_offset;

	/* Virtual address of the section when the binary is executed. */
	GElf_Addr sh_addr;

	/* Size of the section. */
	unsigned int sh_size;

	/* true if the section belongs to 'init' area, false otherwise. */
	bool belongs_to_init;

	/* The instructions in this section corresponding to the input
	 * source lines. */
	set<InsnInfo> insns;

	/* Returns whether the address lies within this section. */
	bool contains(Dwarf_Addr addr) {
		return (addr >= sh_addr && addr < sh_addr + sh_size);
	}
};

/* map: section_index => section_info */
typedef map<unsigned int, SectionInfo> TSectionMap;
static TSectionMap sections;

/* Index of .text section, needed for the processing the kernel image. */
unsigned int text_idx = 0;
/* ====================================================================== */

static void
do_load_dwarf_info(int fd)
{
	/* dwfl_report_*() functions close the file descriptor passed there
	 * if successful, so make a duplicate first. */
	int dwfl_fd = dup(fd);
	if (dwfl_fd < 0) {
		throw runtime_error(
			"Failed to duplicate a file descriptor.");
	}

	wr_dwfl.dwfl_mod = my_dwfl_report_elf(
		wr_dwfl.get_handle(), kmodule_name.c_str(),
		dbg_path.c_str(), dwfl_fd, 0 /* base address */);

	if (wr_dwfl.dwfl_mod == NULL) {
		/* Not always an error but worth notifying the user.
		 * Missing debug info, perhaps? */
		cerr << "No debug info is present in or can be loaded from "
			<< dbg_path << ". " << dwfl_errmsg(-1) << endl;
		close(dwfl_fd);
		return;
	}

	dwfl_report_end(wr_dwfl.get_handle(), NULL, NULL);

	wr_dwfl.e = dwfl_module_getelf(wr_dwfl.dwfl_mod, &wr_dwfl.bias);
	if (wr_dwfl.e == NULL) {
		throw runtime_error(string(
			"Error while processing DWARF info: ") +
			dwfl_errmsg(-1));
	}
}

static void
load_dwarf_info()
{
	ElfWrapper wr_elf(dbg_path);
	do_load_dwarf_info(wr_elf.fd);
}
/* ====================================================================== */

/* Obtain the virtual address of the given section from the file with
 * the debug info. We cannot just use the sh_addr from the ELF file with
 * the code: the file with debug info may have it relocated in a special
 * way. We need that relocated value to query the debug info and looking
 * for the relevant binary code. */
static GElf_Addr
get_dw_sh_addr(const string &sh_name)
{
	Elf *e = wr_dwfl.e;
	Elf_Scn *scn;
	GElf_Shdr shdr;
	size_t sh_str_index;
	char *name;

	if (elf_getshdrstrndx(e, &sh_str_index) != 0) {
		ostringstream err;
		err << "elf_getshdrstrndx() failed: " << elf_errmsg(-1);
		throw runtime_error(err.str());
	}

	scn = NULL;
	while ((scn = elf_nextscn(e, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) != &shdr) {
			ostringstream err;
			err << "Failed to retrieve section header: "
				<< elf_errmsg(-1);
			throw runtime_error(err.str());
		}

		name = elf_strptr(e, sh_str_index, shdr.sh_name);
		if (name == NULL) {
			ostringstream err;
			err << "Failed to retrieve section name: "
				<< elf_errmsg(-1);
			throw runtime_error(err.str());
		}

		if (sh_name != name)
			continue;

		return shdr.sh_addr;
	}

	cerr << "Failed to find the virtual address of the section "
	     << sh_name << ", assuming 0." << endl;
	return 0;
}

static void
process_elf_sections(Elf *e)
{
	size_t sh_str_index;
	Elf_Scn *scn;
	size_t idx;
	GElf_Shdr shdr;
	GElf_Ehdr ehdr;
	char *name;

	/* Find the architecture the module was built for. */
	if (gelf_getehdr(e, &ehdr) == NULL) {
		ostringstream err;
		err << "gelf_getehdr() failed: " << elf_errmsg(-1);
		throw runtime_error(err.str());
	}

	if (ehdr.e_machine == EM_386) {
		is_module_x64 = 0;
		if (verbose) {
		cerr << "Module is built for 32-bit x86 architecture."
			<< endl;
		}
	}
	else if (ehdr.e_machine == EM_X86_64) {
		is_module_x64 = 1;
		if (verbose) {
		cerr << "Module is built for 64-bit x86 architecture."
			<< endl;
		}
	}
	else {
		ostringstream err;
		err << "The module is built for unsupported architecture: "
		 << "e_machine is " << ehdr.e_machine
		 << " in the ELF header." << endl;
		throw runtime_error(err.str());
	}

	if (elf_getshdrstrndx(e, &sh_str_index) != 0) {
		ostringstream err;
		err << "elf_getshdrstrndx() failed: " << elf_errmsg(-1);
		throw runtime_error(err.str());
	}

	unsigned long mask = SHF_ALLOC | SHF_EXECINSTR;
	unsigned int init_offset = 0;
	unsigned int core_offset = 0;

	scn = NULL;
	while ((scn = elf_nextscn(e, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) != &shdr) {
			ostringstream err;
			err << "Failed to retrieve section header: "
				<< elf_errmsg(-1);
			throw runtime_error(err.str());
		}

		name = elf_strptr(e, sh_str_index, shdr.sh_name);
		if (name == NULL) {
			ostringstream err;
			err << "Failed to retrieve section name: "
				<< elf_errmsg(-1);
			throw runtime_error(err.str());
		}

		if ((shdr.sh_flags & mask) != mask)
			continue;

		idx = elf_ndxscn(scn);
		bool is_init = starts_with(name, ".init");

		if (is_init) { /* 'init' area */
			sections[idx].belongs_to_init = true;
			sections[idx].start_offset = init_offset;
		}
		else { /* 'core' area */
			sections[idx].start_offset = core_offset;
		}

		sections[idx].name = string(name);
		if (sections[idx].name == ".text")
			text_idx = idx;

		sections[idx].sh_addr = get_dw_sh_addr(sections[idx].name);
		sections[idx].sh_size = (unsigned int)shdr.sh_size;

		if (verbose) {
			cerr << "Setting the offset for section \""
				<< name << "\" (#" << idx << "), "
				<< (is_init ? "'init'" : "'core'")
				<< " area, size: "
				<< sections[idx].sh_size << ".";

			if (is_kernel_image()) {
				cerr << " Start address: " << hex <<
					shdr.sh_addr << dec
					<< ", alignment: "
					<< (unsigned int)shdr.sh_addralign;
			}
			cerr << endl;
		}


		if (is_init) {
			init_offset += (unsigned int)shdr.sh_size;
		}
		else {
			core_offset += (unsigned int)shdr.sh_size;
		}
	}
}
/* ====================================================================== */

static void
output_insns(const SectionInfo &si)
{
	unsigned int prev_offset = (unsigned int)(-1);

	set<InsnInfo>::const_iterator it;
	for (it = si.insns.begin(); it != si.insns.end(); ++it) {
		/* Do not output the same insns more than once: it is not
		 * needed now to keep separate records for different access
		 * types. */
		if (it->offset == prev_offset)
			continue;

		prev_offset = it->offset;

		if (!is_kernel_image())
			cout << kmodule_name << ":";
		cout << (si.belongs_to_init ? "init+0x" : "core+0x") << hex
			<< si.start_offset + it->offset << dec << endl;
	}
}
/* ====================================================================== */

/* Check the instruction and add it to si.insns if it should be processed.
 *
 * The following kinds of instructions should not be processed:
 * - the instructions that do not actually access memory;
 * - (if requested) %esp/%rsp-based accesses;
 * - (if requested) locked operations. */
static void
process_insn(struct insn *insn, SectionInfo &si, unsigned int offset,
	     EAccessType atype)
{
	InsnInfo ii = {
		.offset = offset,
		.atype = atype,
	};

	if (no_filter) {
		si.insns.insert(ii);
		return;
	}

	EAccessType at = AT_BOTH;
	if (!is_tracked_memory_access(insn, &at, with_stack, with_locked)) {
		if (verbose) {
			cerr << "Skipping the instruction at "
				<< si.name << "+0x"
				<< hex << offset << dec <<
	" : no memory accesses or they should not be processed."
				<< endl;
		}
		return;
	}
	else if ((atype == AT_READ && at == AT_WRITE) ||
		 (atype == AT_WRITE && at == AT_READ)) {
		if (verbose) {
			cerr <<
			"Mismatching access types for the instruction at "
				<< si.name
				<< "+0x" << hex << offset << dec
				<< ", skipping it." << endl;
		}
		return;
	}

	si.insns.insert(ii);
	return;
}

/* Check if the insn at si.name+0xoffset is for src_file:line. */
static bool
same_file_line(const SectionInfo &si, unsigned int offset,
	       string src_file, int line)
{
	Dwarf_Addr addr = (Dwarf_Addr)offset + wr_dwfl.bias + si.sh_addr;
	Dwfl_Line *dw_line = dwfl_module_getsrc(wr_dwfl.dwfl_mod, addr);
	if (dw_line == NULL)
		return false; /* No DWARF info for the insn, OK. */

	const char *got_src;
	int got_line = -1;
	int col;
	got_src = dwfl_lineinfo(dw_line, &addr, &got_line, &col, NULL, NULL);

	if (got_src == NULL || got_line == -1)
		return false; /* Again, no DWARF info for the insn, OK. */

	if (line == got_line && src_file == got_src) {
		if (verbose) {
			cerr << "The insn at " << si.name << "+0x"
				<< hex << offset << dec
				<< " will be considered too." << endl;
		}
		return true;
	}
	return false;
}

/* Decode and filter the instructions starting from si.name+0xoffset in the
 * given data chunk ('data'). Add the insns corresponding to src_file:line
 * to si.insns. At least, the first insn is for src_file:line. */
static void
decode_and_filter(unsigned int offset, Elf_Data *data, SectionInfo &si,
		  string src_file, int line, EAccessType at)
{
	struct insn insn;
	unsigned char *start_addr =
		(unsigned char *)data->d_buf +
			(offset - (unsigned int)data->d_off);
	unsigned char *end_addr =
		(unsigned char *)data->d_buf + data->d_size;

	while (start_addr < end_addr) {
		insn_init(&insn, start_addr, end_addr - start_addr,
			  is_module_x64);
		insn_get_length(&insn);  /* Decode the instruction */
		if (insn.length == 0) {
			ostringstream err;
			err << "Failed to decode the instruction at "
				<< si.name
				<< "+0x" << hex << offset << dec
				<< " in the binary file.";
			throw runtime_error(err.str());
		}

		process_insn(&insn, si, offset, at);

		start_addr += insn.length;
		offset += insn.length;

		if (!same_file_line(si, offset, src_file, line))
			break;
	}
}

/* Gets the section index (in the return value) and the offset (in 'offset')
 * for the given address.
 * Throws if not found; returns (GElf_Word)(-1) if this address should be
 * skipped.
 *
 * 'msg_prefix' - a prefix for error/info messages.
 *
 * [NB] For a kernel image, the function only checks .text section and skips
 * addresses from other sections (that is not considered an error).
 * The debug info contains absolute addresses in this case.
 *
 * For the modules, it checks all code sections.
 * The addresses in the debug info are relative there. */
static GElf_Word
get_section_and_offset(Dwarf_Addr addr, unsigned int &offset,
		       const string &msg_prefix)
{
	if (is_kernel_image()) {
		SectionInfo &si = sections[text_idx];
		if (!si.contains(addr)) {
			if (verbose) {
				cerr << msg_prefix
					<< ": the instruction at "
					<< hex << addr << dec
		<< " is outside of the kernel's .text section. Skipping."
					<< endl;
			}
			return (GElf_Word)(-1);
		}

		offset = (unsigned int)(addr - si.sh_addr);
		return (GElf_Word)text_idx;
	}

	/* A module rather than a kernel image.
	 *
	 * When used for some kernel modules, libdw/libdwfl 0.159 behaves in
	 * a way different from what one would expect. As a result, one
	 * cannot use dwfl_module_relocate_address() to find the section the
	 * address belongs to like eu-addr2line does, for example. The
	 * function may not find the section because the addresses of
	 * __ksymtab_gpl, __kcrctab, __kcrctab_gpl sections in the array of
	 * sections (internal to libdwfl) are not relocated properly.
	 * Or, perhaps, something else is needed for libdw to properly load
	 * the module and avoid this problem - not sure what exactly.
	 *
	 * So we just search the our array of sections explicitly.
	 * There are only a few sections with the code, so a plain linear
	 * search will be enough. */
	TSectionMap::iterator it;
	for (it = sections.begin(); it != sections.end(); ++it) {
		SectionInfo &si = it->second;
		if (si.contains(addr)) {
			offset = (unsigned int)(addr - si.sh_addr);
			return it->first;
		}
	}

	return -1;
}

static void
find_insns(Elf *e, string src_file, int line, EAccessType at)
{
	Dwfl_Line **lines = NULL;
	size_t nlines = 0;
	int col = 0;

	/* Create the prefix for the messages first. */
	ostringstream os;
	os << src_file << ":" << line << ":" << col << ": ";
	string prefix = os.str();

	int ret = dwfl_module_getsrc_file(
		wr_dwfl.dwfl_mod, src_file.c_str(), line, col,
		&lines, &nlines);

	if (ret != 0) {
		/* Try the base name of the file, if it is different
		 * from the given name. */
		size_t pos = src_file.find_last_of("/");
		if (pos == string::npos) {
			return;
		}
		string basename = src_file.substr(pos + 1);
		if (basename.empty()) {
			return;
		}

		if (verbose) {
			cerr << prefix
				<< "no data found, looking for data for "
				<< basename << "..." << endl;
		}
		ret = dwfl_module_getsrc_file(
			wr_dwfl.dwfl_mod, basename.c_str(), line, col,
			&lines, &nlines);
		if (ret != 0) {
			if (verbose) {
				cerr << prefix << "no data found for "
					<< basename << " either."
					<< endl;
			}
			return;
		}
	}

	for (size_t inner = 0; inner < nlines; ++inner) {
		Dwarf_Addr addr;
		const char *file = dwfl_lineinfo(
			lines[inner], &addr, &line, &col, NULL, NULL);
		if (file == NULL)
			continue;

		unsigned int offset = 0;
		GElf_Word sec_idx = get_section_and_offset(addr, offset,
							   prefix);
		if (sec_idx == (GElf_Word)(-1))
			continue;

		SectionInfo &sec = sections[sec_idx];

		/* [NB] If there are two or more consecutive insns for the
		 * same file:line in the source, 'addr' is the address of
		 * the first one of them. We have to find the others: decode
		 * the insns one by one, starting from 'addr' and check if
		 * they belong to the same file:line. */
		Elf_Scn *scn = elf_getscn(e, (size_t)sec_idx);
		if (scn == NULL) {
			ostringstream err;
			err << prefix
		<< "failed to find the section data for the instruction: "
			<< elf_errmsg(-1) << endl;
			throw runtime_error(err.str());
		}

		/* Each section may have 0 or more data chunks (usually, a
		 * single chunk for a code section but we should not rely
		 * on that), process them all. */
		Elf_Data *data = NULL;
		bool found = false;
		while ((data = elf_getdata(scn, data)) != NULL) {
			if(!data->d_buf) {
				ostringstream err;
				err << "There is no code in section \""
					<< sec.name
					<< "\" in the binary file.";
				throw runtime_error(err.str());
			}

			if (offset < (unsigned int)data->d_off ||
			    offset >= (unsigned int)(data->d_off +
						     data->d_size)) {
				continue;
			}
			found = true;

			decode_and_filter(offset, data, sec,
					  string(file), line, at);
			break;
		}

		if (!found) {
			ostringstream err;
			err << "Failed to find the instruction at "
				<< sec.name << "+0x"
				<< hex << (unsigned int)addr << dec
				<< " in the binary file.";
			throw runtime_error(err.str());
		}
	}
	free(lines); /* See line2addr test in elfutils */
}

static string sep = " \t\n\r";

static void
process_input_line(Elf *e, const string &str)
{
	/* trim first */
	size_t first = str.find_first_not_of(sep);
	if (first == string::npos)
		return; /* empty string */

	size_t last = str.find_last_not_of(sep);
	assert(first <= last);

	string s = str.substr(first, last - first + 1);
	size_t pos = s.find_first_of(':');
	if (pos == string::npos) {
		throw runtime_error(string("Invalid input line: ") + str);
	}

	EAccessType at = AT_BOTH;
	string fpath = s.substr(0, pos);
	string str_line;

	s = s.substr(pos + 1);
	if (s.empty())
		throw runtime_error(string("Invalid input line: ") + str);

	pos = s.find_first_of(':');
	if (pos == string::npos) {
		/* No access type specified */
		str_line = s;
	}
	else {
		str_line = s.substr(0, pos);
		string str_atype = s.substr(pos + 1);

		if (str_atype == "read") {
			at = AT_READ;
		}
		else if (str_atype == "write") {
			at = AT_WRITE;
		}
		else {
			throw runtime_error(string(
				"Invalid access type in the input line: ")
				+ str);
		}
	}

	char *rest = NULL;
	int line_no = (int)strtol(str_line.c_str(), &rest, 10);
	if (rest == NULL || rest[0] != 0)
		throw runtime_error(string("Invalid input line: ") + str);

	find_insns(e, fpath, line_no, at);
}

static void
process_input(Elf *e)
{
	string str;
	while (getline(cin, str)) {
		process_input_line(e, str);
	}
}
/* ====================================================================== */

/* [NB] See the description of --section-to-area and --area-to-section.
 * Parses the input line 'str_line', extracts the name of the module
 * (module_name, empty string if not specified), name of the section or
 * area (returned in 'sa') and the offset.
 * Throws std::runtime_error on error.
 * Returns false if this input line is empty and should be skipped, true
 * otherwise. */
static bool
parse_addr_line(const string &str_line, string &module_name, string &sa,
		unsigned int &offset)
{
	string str = str_line;

	size_t first = str.find_first_not_of(sep);
	if (first == string::npos)
		return false;

	size_t last = str.find_last_not_of(sep);
	assert(first <= last);

	str = str.substr(first, last - first + 1);
	size_t pos = str.find_first_of(':');

	if (pos != string::npos) {
		module_name = str.substr(0, pos);
		str = str.substr(pos + 1);
	}
	else {
		module_name = string();
	}

	pos = str.find_first_of('+');
	if (pos == string::npos || pos == 0 || pos == str.length() ||
	    str[pos + 1] != '0')
		throw runtime_error(
			string("Invalid input line: ") + str_line);

	sa = str.substr(0, pos);

	char *rest = NULL;
	unsigned long val = strtoul(str.substr(pos + 1).c_str(), &rest, 16);
	offset = (unsigned int)val;
	if ((unsigned long)offset != val) {
		ostringstream err;
		err << str_line << ": offset is too large.";
		throw runtime_error(err.str());
	}

	return true;
}

static void
convert_to_section_offset(const string &str_line, const string &area,
			  unsigned int offset)
{
	bool is_init = (area == "init");
	if (!is_init && area != "core") {
		ostringstream err;
		err << "Invalid name of the area in " << str_line
			<< " (\"" << area << "\")"
			<< ", should be \"init\" or \"core\".";
		throw runtime_error(err.str());
	}

	if (is_kernel_image()) {
		if (is_init) {
			cerr <<
"Processing the \"init\" area of the kernel image is not supported." << endl;
			return;
		}

		const SectionInfo &si = sections[text_idx];
		if (offset >= si.sh_size) {
			cerr << str_line <<
": the offset is not within the .text section of the kernel." << endl;
			return;
		}

		cout << ".text+0x" << hex << offset << dec << "\n";
		return;
	}

	TSectionMap::iterator it;
	for (it = sections.begin(); it != sections.end(); ++it) {
		const SectionInfo &si = it->second;
		if (is_init != si.belongs_to_init)
			continue;

		if (offset >= si.start_offset &&
		    offset < si.start_offset + si.sh_size) {
			cout << kmodule_name << ":" << si.name << "+0x"
				<< hex << offset - si.start_offset << dec
				<< "\n";
			return;
		}
	}

	throw runtime_error(str_line + string(": failed to find section."));
}

static void
convert_to_area_offset(const string &str_line, const string &section,
		       unsigned int offset)
{
	if (is_kernel_image()) {
		if (section != ".text") {
			throw runtime_error(
	"Only .text section can be processed for the kernel image.");
		}

		const SectionInfo &si = sections[text_idx];
		if (offset >= si.sh_size) {
			ostringstream err;
			err << str_line
	<< ": the offset is not within the .text section of the kernel.";
			throw runtime_error(err.str());
		}

		cout << "core+0x" << hex << offset << dec << "\n";
		return;
	}

	TSectionMap::iterator it;
	for (it = sections.begin(); it != sections.end(); ++it) {
		const SectionInfo &si = it->second;
		if (si.name != section)
			continue;

		if (offset >= si.sh_size) {
			ostringstream err;
			err << str_line
				<< ": the offset is not within the \""
				<< si.name << "\" section of "
				<< kmodule_name;
			throw runtime_error(err.str());
		}

		cout << kmodule_name << ":"
			<< (si.belongs_to_init ? "init+0x" : "core+0x")
			<< hex << offset + si.start_offset << dec << "\n";
		return;
	}

	ostringstream err;
	err << str_line
		<< ": failed to find section \"" << section
		<< "\" in " << kmodule_name;
	throw runtime_error(err.str());
}

static void
do_convert()
{
	string str;
	while (getline(cin, str)) {
		string sa;
		string module_name;
		unsigned int offset = 0;

		if (!parse_addr_line(str, module_name, sa, offset))
			continue;

		for (size_t i = 0; i < module_name.size(); ++i) {
			if (module_name[i] == '-')
				module_name[i] = '_';
		}

		if (module_name != kmodule_name) {
			if (verbose) {
				cerr << "Mismatching name of the module (\""
					<< module_name << "\") in "
					<< str << endl;
			}
			continue;
		}

		if (section_to_area)
			convert_to_area_offset(str, sa, offset);
		else if (area_to_section)
			convert_to_section_offset(str, sa, offset);
		else
			assert(false);
	}
	return;
}
/* ====================================================================== */

int
main(int argc, char *argv[])
{
	if (argc == 1) {
		show_usage();
		return EXIT_FAILURE;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		cerr << "Failed to initialize libelf: " << elf_errmsg(-1)
			<< endl;
		return EXIT_FAILURE;
	}

	if (!process_args(argc, argv))
		return EXIT_FAILURE;

	if (verbose) {
		cerr << "Turn off filtering: " << no_filter << endl;
		cerr << "With stack: " << with_stack << endl;
		cerr << "With locked: " << with_locked << endl;
		cerr << "Module: " << kmodule_path << endl;
		cerr << "File with debug info: " << dbg_path << endl;
		cerr << "Is kernel image? " << is_kernel_image() << endl;
		cerr << "Module name: " << kmodule_name << endl;
	}

	try {
		ElfWrapper wr_elf(kmodule_path);
		load_dwarf_info();

		/* We need both the Elf object for the file with the code and
		 * the one from the dwfl module. The latter has set virtual
		 * addresses for the sections (sh_addr) appropriately.
		 * We cannot reopen the binary and use its Elf object:
		 * sh_addr will be 0. This way we can miss some insns,
		 * because sh_addr is needed when looking for all the insns
		 * for a given src_file:line. */

		/* Find which area each section belongs to and what offset
		 * the section has there. Populate 'sections' map. */
		process_elf_sections(wr_elf.e);

		if (section_to_area || area_to_section) {
			do_convert();
			return EXIT_SUCCESS;
		}
		else {
			/* Normal mode. Process the input, populate and
			 * filter the sets of instructions of interest. */
			process_input(wr_elf.e);
		}

		/* Output the results, sorted by offset, init area first. */
		bool found = false;
		TSectionMap::iterator it;
		for (it = sections.begin(); it != sections.end(); ++it) {
			if (it->second.belongs_to_init) {
				found = (found || !it->second.insns.empty());
				output_insns(it->second);
			}
		}

		/* 'core' area */
		for (it = sections.begin(); it != sections.end(); ++it) {
			if (!it->second.belongs_to_init) {
				found = (found || !it->second.insns.empty());
				output_insns(it->second);
			}
		}

		if (!found) {
			cerr << "No instructions found." << endl;
			return EXIT_FAILURE;
		}
	}
	catch (runtime_error &e) {
		cerr << e.what() << endl;
		return EXIT_FAILURE;
	}
	return 0;
}
