/*                                                                        */
/*                  OpenPOWER fsp-trace Project                           */
/* Contributors Listed Below - COPYRIGHT 2004, 2010.                      */
/* [+] International Business Machines Corp.                              */
/*                                                                        */
/*                                                                        */
/* Licensed under the Apache License, Version 2.0 (the "License");        */
/* you may not use this file except in compliance with the License.       */
/* You may obtain a copy of the License at                                */
/*                                                                        */
/*     http://www.apache.org/licenses/LICENSE-2.0                         */
/*                                                                        */
/* Unless required by applicable law or agreed to in writing, software    */
/* distributed under the License is distributed on an "AS IS" BASIS,      */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or        */
/* implied. See the License for the specific language governing           */
/* permissions and limitations under the License.                         */
/*                                                                        */

/******************************************************************************
 * fsp-trace.c
 * Contains fsp-trace post-processor.  Used to fetch, parse, and format traces.
 *****************************************************************************/


/* Change Log *****************************************************************/
/*                                                                            */
/* 10/26/05  Created by Artur Hisamov (artur.hisamov@auriga.ru)               */
/* End Change Log *************************************************************/

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <error.h>
#include <argp.h>
#include <execinfo.h> /* for backtrace* */
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "trace_adal.h"
#include "adal_common.h"


int g_process = 0;		// global flag for signal handling
extern int g_verbose_level;


#define TRACE_DEFAULT_VERBOSE_LEVEL TRACE_LVL1
#define DEFAULT_STRINGFILE	"trexStringFile"

const char *argp_program_version = "fsp-trace " ARCH;
const char *argp_program_bug_address = "ivan@de.ibm.com";
error_t argp_err_exit_status = EINVAL;
char doc[] = "fsp-trace -- Used to retrieve and view fsp trace buffers";

static struct argp_option options[] = {
	{"address",	'a', "IP",	0, "IP Address of CRP (X86 Only)", 0},
	{"binary",	'b',  0,	0, "Dump binary buffers to file (don't process it). "
					"Use for timing critical situations", 0},
	{"comps",	'c', "'C1 C2 ..'", 0, "Retrieve only specified trace buffers", 0},
	{"debug",	'd', "COMP:LV",	0, "Set COMP debug trace to LV (1=on, 0=off)", 0},
	{"file_name",	'f', 0,		0, "Display File Name with each trace", 0},
	{"date/time",	'k', 0,		0, "Convert timestamps to date/time format", 0},
	{"console",	'l', "COMP:LV",	0, "Set COMP console trace to LV (1=on, 0=off)", 0},
	{"nosort",	'n', 0,		0, "Do not sort trace buffers by timestamp", 0},
	{"output_dir",	'o', "DIR/FILE", 0, "Write output to DIR/tracBINARY or DIR/tracMERG "
					"or FILE (default: to stdout)", 0},
	{"process",	'p', 0,		0, "run in process mode, continuously collecting trace", 0},
	{"daemon",	'P', 0,		0, "process mode (like -p), but run in background", 0},
	{"reset",	'r', 0,		0, "Reset all trace buffers on system", 0},
	{"stringfile",	's', "StrFile",	0, "Location of trexStringFile", 0},
	{"tail",	't', "NUM",	0, "Only show last NUM traces", 0},
	{"verbose",	'v', "LV",	0, "Internal trace level for fsp-trace", 0},
	{"format",	'F', "",	0, "time format in strftime mode", 0},
	{0, 0, 0, 0, 0, 0}
};

const char args_doc[] = "-s <stringfile> [trac<COMP>...|tracBINARY|tracARCHIVE]";

struct arguments {
	char *address;
	int32_t binary;
	char *comps[256];
	int32_t debug;
	int32_t console;
	int32_t filename;
	int32_t date;
	int32_t tformat;
	int32_t nosort;
	char *output_dir;
	int32_t output_is_dir;
	int32_t process;
	int32_t reset;
	int32_t tail;
	int32_t verbose;

	//int32_t stringfile_ver;
	uint32_t comp_count;
	char *debug_comp;
	char *console_comp;
	int32_t file_count;
	uint32_t stringfile_count;
	char ** input_files;
	char ** string_files;
	char *input_dir;
	int has_version;
	int files_given;
};


static int is_buffer_in_list(const char *i_file_name, char *comps[], int32_t comp_count);
static error_t parse_opt(int key, char *arg, struct argp_state *state);
static int is_tracBINARY(char *file);
static int is_smartDump(char *file);
static void sig_handler(int);


void _toupper_string(char *text)
{
	size_t j;

	for (j = 0; j < strlen(text); j++) {
		text[j] = toupper(text[j]);
	}
}


/* help function for parse_opt: split "COMP:LV" argument */
static inline int parse_comp_lv(char *arg, char **pcomp, int *lv)
{
	int len;
	char *p = strchr(arg, ':'), *newbuf;

	if (p == NULL) {
		/* maybe old sytnax: -d BUFFER lvl */
		TRACED("old syntax for -d/-c: COMP LV w/o ':' (%s)\n", arg);
		*pcomp = strdup(arg);
		if (pcomp == NULL) {
			TRACEE("out of memory copying comp name");
			return ENOMEM;
		}
		_toupper_string(*pcomp);
		return EAGAIN; /* needs more data */
	} 
	len = (int) (p - arg);
	newbuf = (char *) malloc(len + 1);
	if (newbuf == NULL) {
		TRACEE("out of memory copying comp name");
		return ENOMEM;
	}
	memcpy(newbuf, arg, len);
	newbuf[len] = 0;
	_toupper_string(newbuf);
	*lv = atoi(p + 1);
	*pcomp = newbuf;
	return 0;
}

static inline int parse_add_comp_name(struct arguments *args, char *names)
{
	char *p, *p2 = names, *comp;
	int len;

	do {
		if (args->comp_count >= sizeof(args->comps)/sizeof(char *)) {
			TRACEE("Too many components given (max=%zu).\n",
				sizeof(args->comps)/sizeof(char *));
			return ENOMEM;
		}
		p = strchr(p2, ' ');
		len = p ? p - p2 : (int)strlen(p2);	/* p==0: last value */

		comp = (char *) malloc(len + 1);
		if (comp == NULL) {
			TRACEE("out of memory copying stringfile name");
			return ENOMEM;
		}
		memcpy(comp, p2, len);
		comp[len] = 0;
		_toupper_string(comp);

		args->comps[args->comp_count] = comp;
		args->comp_count++;
		p2 = p ? p + 1 : 0; /* p is zero in last loop run */
		TRACEV("option -c: buffer name %s\n", args->comps[args->comp_count - 1]);
	} while (p != NULL);
	return 0;
}

/*!
 * @brief Parse the arguments passed into fsp-trace
 *
 * @param key The parameter
 * @param arg Argument passed to parameter
 * @param state Location to put information on paameters 
 *
 * @return tracRC_t  t_rc
*/
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct stat l_statbuf;
	struct arguments *args = state->input;
	int ret;
	static char last_option;

	if (!(key & 0xffffff00) && isprint(key)) {
		TRACEV(" option '%c' found\n", key);
	}

	/* this is ugly: need to maintain support for old fsp-trace syntax:
	 * options "-d COMP LV"  "-l COMP LV"  "-c COMP1 COMP2 COMP3"
	 */
	if (last_option) {
		/* continuing one of -d/-l/-c */
		if (key == ARGP_KEY_ARG) {
			/* a non-option value */
			if (last_option == 'd' || last_option == 'l') {
				/* need a number, parse option */
				char *endptr;
				int level;

				level = strtol(arg, &endptr, 10);
				if (*endptr != 0) {
					/* extra text after number */
					TRACEE("cannot read -%c level (%s)\n",
						last_option, arg);
					return EINVAL;
				}
				if (last_option == 'd') {
					args->debug = level;
				} else if (last_option == 'l') {
					args->console = level;
				} else {
					TRACEE("INTERNAL ERROR: bad value for last_option (-%c)\n",
						last_option);
					return EINVAL;
				}
				TRACEV("found level %d for -%c (old syntax)\n",
					level, last_option);
				/* done with arg and -d/l option */
				last_option = 0;
				return 0;
			}
			if (last_option == 'c') {
				/* arg is a buffer/component name */
				/* keep last_option, there might be more names */
				return parse_add_comp_name(args, arg);
			}
			TRACEE("INTERNAL ERROR: last_option = %c\n", last_option);
			return EINVAL;
		} else if (last_option != 'c') {
			/* an option or end-of-args. number for -d/-l is missing */
			TRACEE("option requires two arguments -- %c\n", last_option);
			last_option = 0;
			return EINVAL;
			/* in -c case we fall through, disabling -c mode.
			 * -c without args won't be detected as an error.
			 * this is the price for supporting a broken interface */
		}
		last_option = 0;
	}

	switch (key) {
	case 'k': args->date = 1; break;
	case 'n': args->nosort = 1; break;
	case 'f': args->filename = 1; break;
	case 'p': args->process = 1; break;
	case 'P': args->process = 2; break;
	case 'b': args->binary = 1; break;
	case 'r': args->reset = 1; break;
	case 'F':
		args->tformat = 1;
		memcpy(g_time_format, arg, strlen(arg));
		break;

	case 'o':
		args->output_dir = (char *) calloc(1, strlen(arg) + 2);
		strcpy(args->output_dir, arg);

		/* if output_dir doesn't exist or isn't a directory take 
		 * it as filename to write output to */
		ret = stat(arg, &l_statbuf);
		if (ret < 0) {
			args->output_is_dir = 0;
		} else if (S_ISDIR(l_statbuf.st_mode)) {
			args->output_is_dir = 1;
		} else {
			args->output_is_dir = 0;
		}
		TRACED(" -o is given. (output:%s %s)\n", arg, args->output_is_dir ? "(dir)" : "");
		break;

	case 's':
		if (args->stringfile_count >= sizeof(args->string_files)/sizeof(char *)) {
			TRACEE("too many stringfiles given (max=%zu)\n",
				sizeof(args->string_files)/sizeof(char *));
			return ENOMEM;
		}
		args->string_files[args->stringfile_count] = strdup(arg);
		if (args->string_files[args->stringfile_count] == NULL) {
			TRACEE("out of memory copying stringfile name");
			return ENOMEM;
		}
		TRACEV(" -s is given. (stringfile:%s)\n", arg);
		args->stringfile_count++;
		break;

	case 'v':
		args->verbose = atoi(arg);
		switch (args->verbose) {
		case 0: g_verbose_level = TRACE_LVL0; break;
		case 1: g_verbose_level = TRACE_LVL1; break;
		case 2: g_verbose_level = TRACE_LVL2; break;
		case 3: g_verbose_level = TRACE_LVL3; break;
		case 4: g_verbose_level = TRACE_LVL4; break;
		case 5: g_verbose_level = TRACE_LVL5; break;
		default: g_verbose_level = TRACE_LVL_ALL; break;
		}
		TRACEI("Set verbose level to %d (mask:0x%X)\n", args->verbose, g_verbose_level);
		break;

	case 'd':
		ret = parse_comp_lv(arg, &args->debug_comp, &args->debug);
		if (ret == EAGAIN) {
			last_option = 'd';
			TRACEV("found option -d buffer=%s, no level (old syntax)\n",
				args->debug_comp);
		} else if (ret) {
			return ret;
		} else {
			TRACEV("found option -d buffer=%s level=%u)\n", 
				args->debug_comp, args->debug);
		}
		break;

	case 'l':
		ret = parse_comp_lv(arg, &args->console_comp, &args->console);
		if (ret == EAGAIN) {
			last_option = 'l';
			TRACEV("found option -l buffer=%s, no level (old syntax)\n",
				args->console_comp);
		} else if (ret) {
			return ret;
		} else {
			TRACEV("found option -l buffer=%s level=%u)\n", 
				args->console_comp, args->console);
		}
		break;

	case 'c':
		ret = parse_add_comp_name(args, arg);
		if (ret)
			return ret;
		/* set last_option, there might be more names */
		last_option = 'c';
		break;

	case ARGP_KEY_ARG:
		TRACED("arg is given: %s\n", arg);
		/* input file, pipe or dir? */
		ret = stat(arg, &l_statbuf);
		if (ret < 0) {
			TRACEPE("cannot find source file %s", arg);
			return EINVAL;
		}

		if (S_ISDIR(l_statbuf.st_mode)) {
			/* directory given, look for tracBINARY */
			char *fullpath;
			TRACEI("Will use tracBINARY as input in %s\n", arg);
			if (args->input_dir) {
				TRACEE("Two input directories not supported\n");
				return EINVAL;
			}

			fullpath = (char *) malloc(strlen(arg) + 
				sizeof("tracBINARY") + 1);
			if (fullpath == NULL) {
				TRACEE("out of memory for tracBIANRY filename");
				return EINVAL;
			}
			sprintf(fullpath, "%s/tracBINARY", arg);

			ret = stat(fullpath, &l_statbuf);
			if (ret < 0) {
				TRACEPE("cannot find tracBINARY file in %s", 
					arg);
				free(fullpath);
				return EINVAL;
			}

			ret = is_tracBINARY(fullpath);
			if (ret == 0) {
				TRACEE("File %s: bad type or version\n", fullpath);
				free(fullpath);
				return EINVAL;
			} else if (ret < 0) {
				TRACEE("File %s: cannot read or empty\n", fullpath);
				free(fullpath);
				return ENOENT;
			}
			args->input_dir = fullpath;
			args->files_given++;

		} else if (S_ISREG(l_statbuf.st_mode)) {
			args->files_given++;
			/* a regular file. tracBINARY or raw buffer? */
			ret = is_tracBINARY(arg);
			if (ret < 1) {
				/* not tracBINARY or not readable/empty */
				ret = is_smartDump(arg);
				if (ret < 1) {
					TRACEE("file %s: not an fsp-trace file (Incorrect Version?)\n", arg);
					/* don't return an error or rest of args is ignored.
					 * should we add to list so message gets printed to outfile? */
					return 0; /* EINVAL */
				}
			}

			TRACEI("Use %s as input.\n", arg);

			args->input_files[args->file_count] = strdup(arg);
			if (args->input_files[args->file_count] == NULL) {
				TRACEE("out of memory for tracebuffer filename");
				return EINVAL;
			}
			args->file_count++;
		} else {
			TRACEE("Unknown Argument %s\n", arg);
			return ARGP_ERR_UNKNOWN;
		}
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

void show_version(void)
{
	return;
}

/*!
 * @brief check if a file is a tracBINARY file
 *
 * done by reading first byte. this has to be 0x02 (version of tracBINARY file)
 * this is a lousy test, but probably good enough
 * 1 == is, 0 == is not, -1 cannot open/read/empty
 */
int is_tracBINARY(char *file)
{
	char ver;
	int fd, ret;

	if (file == 0)
		return 0;
	
	fd = open(file, O_RDONLY);
	if (fd < 0)
		return -1;

	do {
		ret = read(fd, &ver, 1);
	} while (ret < 0 && errno == EINTR);
	close(fd);
	if (ret <= 0)
		return -1;

	if (ver != 2)
		return 0;

	return 1;
}

/*!
 * @brief check if a file is a "smartDump", i.e. contains fsptrace buffers
 * 1 == is, 0 == is not, -1 cannot open/read/empty
 */
int is_smartDump(char *file)
{
	trace_buf_head_t head;
	int32_t rc, fd, time_flg;
	
	if (!file)
		return -1;
	

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return -1;

	do {
		rc = read(fd, &head, sizeof(trace_buf_head_t));
	} while (rc < 0 && errno == EINTR);
	if (rc <= 0) {
		TRACEPE("read %zu bytes of %s = %d, %d",
			sizeof(trace_buf_head_t), file, rc, errno);
		return -1;
	}

	if (rc != sizeof(trace_buf_head_t)) {
		TRACEPE("Cannot read from the file %s", file);
		close(fd);
		return -1;
	}

	/* checking fsptrace buffer header:
	 * byte version: 1
	 * byte header_length: sizeof(trace_buf_head_t) == 32
	 * byte time_flag: 0-3
	 * byte endian_flag: 'b'/'l'
	 */
	if (head.ver != 1) {
		TRACEI("Wrong 'smartdump' header format. (ver=0x%X)\n", head.ver);
		close(fd);
		return 0;
	}

	if ( head.hdr_len != sizeof(struct trace_buf_head_v1) &&
	     head.hdr_len != sizeof(struct trace_buf_head_v2) ) {
		TRACEI("Wrong 'smartdump' header format. (hdr_len=0x%X)\n", head.hdr_len);
		close(fd);
		return 0;
	}

	time_flg = head.time_flg & ~TRACE_TIME_EPOCH; /* bit 7 is "epoch" marker */
	if (time_flg != TRACE_TIME_REAL &&
	    time_flg != TRACE_TIME_50MHZ &&
	    time_flg != TRACE_TIME_167MHZ &&
	    time_flg != TRACE_TIME_200MHZ &&
	    time_flg != TRACE_TIME_TIMESPEC &&
	    head.time_flg  != TRACE_TIME_UNKNOWN) {
		TRACEI("Wrong 'smartdump' header format. (time_flg=0x%X)\n", head.time_flg);
		close(fd);
		return 0;
	}

	if (head.endian_flg != 'B' && head.endian_flg != 'b' &&
	    head.endian_flg != 'L' && head.endian_flg != 'l') {
		TRACEI("Wrong 'smartdump' header format. (endian_flg=0x%X)\n", head.endian_flg);
		close(fd);
		return 0;
	}

	close(fd);
	return 1;
}


/*!
 * @brief lookup name in list
 *
 * @return 1 if name is in list or list empty, 0 else
*/
int is_buffer_in_list(const char *name, char *list[], int32_t count)
{
	int32_t i;
	int ret = 0;

	TRACEF("(name=%s, count=%d\n", name, count);
	if (!list || !list[0]) {
		/* list empty. return 1 as empty list means "get all" */
		ret = 1;
	} else {
		for (i = 0; i < count; i++) {
			if (list[i] != NULL && !strcasecmp(name, list[i])) {
				ret = 1;
				break;
			}
		}
	}
	return ret;
}


void sig_handler(int i_signal)
{

	TRACEI("Received signal %d\n", i_signal);

	if (i_signal == 11) {
		/* gdb sometimes doesn't print all stack-entries from core.
		 * backtrace() helped here.
		 * enable this in main() by uncommenting sighandler install.
		 * you might need to remove -O* from Makefile
		 */
		void *callstack[10];
		backtrace(callstack, 10);
		backtrace_symbols_fd(callstack, 10, 2);
		abort();
	}

	/* we react on all signals the same way: exit gracefully */
#if 0
//doesn't work: read(16384) might return 4096 instead of -1+EINTR
	if (g_process) {
		/* we are running as a process so let daemon close pipe and exit */
		g_process=0;
		return;
	}
#endif
	exit(i_signal);
}


trace_strings_t read_stringfiles(struct arguments *args)
{
	int flags = TRACE_OVERWRITE | TRACE_VERBOSE;
	trace_strings_t strings, tmp_str;
	uint32_t i;

	if (args->stringfile_count == 0) {
		/* no stringfile given, use default name */
		TRACEI("Using stringfile %s\n", DEFAULT_STRINGFILE);
		strings = trace_adal_read_stringfile(0, DEFAULT_STRINGFILE,
			flags);
		if (strings == 0) {
			TRACEE("cannot read stringfile '%s'\n", DEFAULT_STRINGFILE);
		}
		return strings;
	}
	strings = 0;
	for (i = 0; i < args->stringfile_count; i++) {
		TRACEI("Using stringfile %s\n", args->string_files[i]);
		tmp_str = trace_adal_read_stringfile(strings, args->string_files[i], 
			flags);
		if (tmp_str == 0) {
			TRACEE("cannot read stringfile '%s'\n", args->string_files[i]);
			trace_adal_free_strings(strings);
			return 0;
		}
		strings = tmp_str;
	}
	return strings;
}

/* build output filename in newly allocated memory
 * if "file" is given "dirorfile/file" is returned,
 * otherwise just "dirorfile"
 */
char * build_output_filename(const char *dirorfile, const char *file)
{
	char *outfile;
	size_t namelen;

	namelen = strlen(dirorfile) + 1;
	if (file) {
		namelen += 1 + strlen(file);
	}
	if (namelen >= FILENAME_MAX -1) {
		if (file == NULL)
			file = "[NULL]";
		TRACEE("dir/file name too long: %s/%s\n", dirorfile, file);
		return 0;
	}
	outfile = malloc(namelen);
	if (outfile == NULL) {
		TRACEE("out of memory for output filename");
		return 0;
	}
	strcpy(outfile, dirorfile);
	if (file) {
		strcat(outfile, "/");
		strcat(outfile, file);
	}
	return outfile;
}

/* run in process mode as daemon */
int do_daemon(struct arguments *args, trace_strings_t strings)
{
	char *outfile = NULL;
	int flags;
	int fdout = 1;
	int ret = 0;
	trace_timeref_t timeref;

	memset(&timeref, 0, sizeof(timeref));

	TRACEI("Run fsp-trace as a daemon.\n");

	if (args->output_dir) {
		if (!args->output_is_dir) {
			outfile = build_output_filename(args->output_dir, 0);
		} else {
			outfile = build_output_filename(args->output_dir, 
				args->binary ? "/tracBINARY" : "/tracMERG");
		}
		if (outfile == NULL) {
			TRACEE("cannot get output filename\n");
			return -EINVAL;
		}
		fdout = open(outfile, O_RDWR | O_CREAT | O_APPEND, 0666);
		if (fdout < 0) {
			/* no file no trace! */
			TRACEPE("Error opening file %s to write traces to", outfile);
			ret = fdout;
			goto free_out;
		}
		if (args->binary) {
			/* if file is new (empty) write header,
			 * if file isn't empty check header */
			struct stat filestat;
			const char tracBINARY_ver = 2;
			
			ret = fstat(fdout, &filestat);
			if (ret < 0) {
				TRACEE("Stat failed for outfile '%s'.\n", outfile);
				goto free_out;
			}
			if (filestat.st_size > 0) {
				if (is_tracBINARY(outfile) < 1) {
					TRACEE("Invalid tracBINARY file %s.\n", outfile);
					ret = -ENOENT;
					goto free_out;
				}
				lseek(fdout, 0, SEEK_END);
			} else {
				write(fdout, &tracBINARY_ver, sizeof(tracBINARY_ver));
			}
		}
		free(outfile);
		outfile = 0;
	}
	/* else fdout = 1 (stdout) */

	if (args->comp_count) {
		uint32_t i;
		
		trace_adal_setpipe(-1, -1); /* turn all off except ... */
		for (i = 0; i < args->comp_count; i++) {
			trace_adal_setpipe_name(args->comps[i], 127);
		}
	} else {
		trace_adal_setpipe(-1, 127); /* turn all on */
	}

	if (args->process > 1) {
		/* daemonize, but don't close stdout */
		ret = daemon(0, 1);
		if (ret < 0) {
			ret = errno;
			TRACEPE("daemoizing failed");
			goto free_out;
		}
	}

	g_process = 1;

    	printf("spawned process pid: %d\n",getpid() );

	flags = TRACE_PREPEND_BUFFERNAME | TRACE_VERBOSE | TRACE_DONTSTOP;
	if (args->binary)
		flags |= TRACE_BINARY;
	if (args->filename)
		flags |= TRACE_FILENAME;
	while (1) {
		ret = trace_adal_print_pipe(-1, fdout, strings, &timeref, flags);
		if (ret < 0)
			break;
		if (!g_process) {
			/* we got a signal (Ctrl-C?), call adal once again */
			flags &= ~TRACE_DONTSTOP;
		}
	}
      free_out:
	if (fdout > 2) {
		close(fdout);
	}
	free(outfile);
	return ret;
}

/* process a tracBINARY file
 * returns < 0 on error
 */
int do_file_binary(struct arguments *args, const char *file, 
	trace_strings_t strings, int fdout)
{
	int fd, flags;
	int ret = 0;

	TRACEI("tracBINARY is given.\n");

	fd = open(file, O_RDONLY);
	if (fd == -1) {
		TRACEPE("Cannot open file %s.\n", file);
		return -errno;
	}

	flags = TRACE_PREPEND_BUFFERNAME | TRACE_VERBOSE;
	if (args->filename)
		flags |= TRACE_FILENAME;
	if (args->tformat)
		flags |= TRACE_TIME_STRFTIME | TRACE_TIMEOFDAY;
	if (args->date)
		flags |= TRACE_TIMEOFDAY | TRACE_SET_TIMEOFDAY;

	ret = trace_adal_print_pipe(fd, fdout, strings, 0,
					flags);

	close(fd);
	return ret;
}

int main(int32_t argc, char *argv[])
{
	int flags = 0;
	int ret=0, mainret=0;
	int valid_cnt = 0;
	int i, j;
	int fd;
	struct stat file_stat;
	struct iovec *vec_ptr;
	trace_strings_t strings = 0;
	int fdout = 1; /* default output stdout */
	char *outfile;

	struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0};
	struct arguments args;
	struct sigaction sig;
	struct stat filestat;

	trace_buf_list_t *listp;
	trace_buf_list_t *ptr;

	sig.sa_handler = sig_handler;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;

	if (sigaction(SIGTERM, &sig, 0)) {
		TRACEPE("Register for SIGTERM failed");
		exit(1);
	}

	if (sigaction(SIGINT, &sig, 0)) {
		TRACEPE("Register for SIGINT failed");
		exit(1);
	}

	if (sigaction(SIGQUIT, &sig, 0)) {
		TRACEPE("Register for SIGQUIT failed");
		exit(1);
	}
#if 0
	/* sig handler for SIGSEGV. usually default is ok, but sometimes
	 * our own handler provided more information. kept here for debug
	 */
	if (sigaction(SIGSEGV, &sig, 0)) {
		TRACEPE("Register for SIGSEGV failed");
		exit(1);
	}
#endif
	memset(&args, 0, sizeof(args));
	g_verbose_level = TRACE_DEFAULT_VERBOSE_LEVEL;

	/* avoid error message if called w/o args and no stringfile */
#ifndef __powerpc__
	if (argc == 1) {
		int fd = open(DEFAULT_STRINGFILE, O_RDONLY);
		if (fd < 0) {
			argp_help(&argp, stderr, ARGP_HELP_STD_USAGE, "fsp-trace");
			return EAGAIN;
		}
		close(fd);
	}
#endif

	/* create memory for maximum number of input files. */
	args.input_files = (char **) malloc(argc * sizeof(char *));
	args.string_files = (char **) malloc(argc * sizeof(char *));
	if (!args.input_files || !args.string_files) {
		error(EXIT_FAILURE, errno, "create memory for parsing input files");
	}

	memset(args.input_files,  0, argc * sizeof(char *));
	memset(args.string_files, 0, argc * sizeof(char *));

	/* get arguments/options */
	if (argp_parse(&argp, argc, argv, ARGP_IN_ORDER, 0, &args) != 0) {
		error(EXIT_FAILURE, errno, "parse cmdline");
	}

	/* -d: changing device driver debug level */
	if (args.debug_comp != 0) {
		TRACEI("Set debug level (%s:%d).\n", args.debug_comp, args.debug);
		ret = trace_adal_setdebug_name(args.debug_comp, args.debug);
		if (ret < 0) {
			trace_desc_t td;
			ret = trace_adal_init_buffer(&td, args.debug_comp, 0);
			if (ret < 0 && errno != EAGAIN) {
				TRACEPE("cannot access buffer '%s' to set debug level",
					args.debug_comp);
				return -ret;
			}
			ret = trace_adal_setdebug(td, args.debug);
			if (ret < 0) {
				TRACEPE("cannot set debug level for buffer '%s'",
					args.debug_comp);
			}
		}
		return -ret;
	}

	/* -r: reset/empty all trace buffers */
	if (args.reset == 1) {
		TRACEI("Reset all trace buffers on system.\n");
		ret = trace_adal_clear_buffs();
		if (ret < 0) {
			TRACEPE("cannot reset buffers");
		}
		return -ret;
	}

	/* -c: Set per-buffer console trace */
	if (args.console_comp != 0) {
		TRACEI("Set console level (%s:%d).\n", args.console_comp, args.console);
		ret = trace_adal_setconsole_name(args.console_comp, args.console);
		if (ret < 0) {
			trace_desc_t td;
			ret = trace_adal_init_buffer(&td, args.console_comp, 0);
			if (ret < 0 && errno != EAGAIN) {
				TRACEPE("cannot access buffer '%s' to set console level",
					args.console_comp);
				return -ret;
			}
			ret = trace_adal_setconsole(td, args.console);
			if (ret < 0) {
				TRACEPE("cannot set console level for buffer '%s'",
					args.console_comp);
			}
		}
		return -ret;
	}

	if ((args.input_dir) && (args.file_count > 0)) {
		TRACEE("Error - Do not support both input directory and input files\n");
		exit(1);
	}

	/* if not binary mode (-b) read stringfile */
	if (!args.binary) {
		strings = read_stringfiles(&args);
		if (strings == 0) {
			return ENOENT;
		}
	} else {
		TRACEI("Binary mode.\n");
		if (args.output_dir == NULL && isatty(1)) {
			TRACEE("not writing out binary data to a terminal\n");
			return EPERM;
		}
	}


	/* daemon mode - reading from pipe */
	if (args.process) {
		mainret = do_daemon(&args, strings);
		goto out;
	}

	/* processing from driver (ioctl) or files.
	 * open output first */
	if (args.output_dir) {
		int openflags = O_RDWR | O_CREAT;
		if (!args.output_is_dir) {
			/* file given by user */
			outfile = build_output_filename(args.output_dir, 0);
			/* with append we'd have to check the type of the file,
			 * therefore we overwrite the file */
			openflags |= O_TRUNC;
		} else {
			/* read from files/driver. write smartdump or ascii */
			outfile = build_output_filename(args.output_dir, 
				args.binary ? "/tracARCHIVE" : "/tracMERG");
			openflags |= O_APPEND;
		}
		fdout = open(outfile, openflags, 0666);
		if (fdout < 0) {
			/* no file no trace! */
			TRACEPE("Error opening file %s to write traces to", outfile);
			mainret = fdout;
			goto out;
		}
		/* when writing binary we need to check type of file */
		if (args.binary) {
			ret = is_smartDump(outfile);
			if (ret == 0) {
				TRACEE("file '%s' is no a fsp-trace buffer file, cannot append\n",
					outfile);
				mainret = EINVAL;
				goto out;
			}
		}
	} else {
		/* not output target given, use stdout */
		fdout = 1;
	}

	if (args.input_dir) {
		/* handle tracBINARY files from given directory */
		ret = do_file_binary(&args, args.input_dir, strings, fdout);
		if (ret < 0) {
			mainret = -ret;
			goto out;
		}
	}


	if (args.files_given) {
		/* input files can be tracebuffers, smartdumps or tracBINARY */
		struct iovec buf_vec[args.file_count];

		memset(buf_vec, 0, sizeof(struct iovec) * args.file_count);
		valid_cnt = 0;
		for (i = 0; i < args.file_count; i++) {
			ret = is_tracBINARY(args.input_files[i]);
			if (ret == 1) {
				ret = do_file_binary(&args, 
					args.input_files[i], strings, fdout);
				if (ret < 0) {
					mainret = -ret;
					goto out;
				}
				continue;
			}

			/* not tracBINARY */
			ret = is_smartDump(args.input_files[i]);
			if (ret < 1) {
				TRACEE("%s: format not recognized,  skipping\n",
					args.input_files[i]);
				continue;
			}
			/* a smartdump or individual buffer. read file */
			fd = open(args.input_files[i], O_RDONLY);
			if (fd < 0) {
				TRACEPE("cannot open file '%s'", args.input_files[i]);
				mainret = errno;
				goto out;
			}
			if (fstat(fd, &file_stat) < 0) {
				/* is_smartDump but not stat??? */
				TRACEPE("cannot stat file '%s'", args.input_files[i]);
				mainret = errno;
				goto out;
			}
			vec_ptr = &buf_vec[valid_cnt];
			vec_ptr->iov_len = file_stat.st_size;
			vec_ptr->iov_base = (char *) malloc(vec_ptr->iov_len);
			if (vec_ptr->iov_base == NULL) {
				TRACEPE("malloc failed for buffer size %zu",
					vec_ptr->iov_len);
				mainret = ENOMEM;
				goto out;
			}

			ret = read(fd, vec_ptr->iov_base, vec_ptr->iov_len);
			if (ret < 0) {
				TRACEPE("Failed to read file %s", args.input_files[i]);
				free(vec_ptr->iov_base);
				close(fd);
				continue;
			}

			close(fd);
			valid_cnt++;
		}

		flags = TRACE_PREPEND_BUFFERNAME | TRACE_VERBOSE;
		if (args.filename)
			flags |= TRACE_FILENAME;
		if (!args.nosort)
			flags |= TRACE_MIX_BUFFERS;
		if (args.tformat)
			flags |= TRACE_TIME_STRFTIME | TRACE_TIMEOFDAY;
		if (args.date)
			flags |= TRACE_TIMEOFDAY | TRACE_SET_TIMEOFDAY;

		if (args.file_count)
			trace_adal_print_buffers(buf_vec, valid_cnt, fdout,
				strings, 0, flags);

		for (i = 0; i < valid_cnt; i++) {
			if (buf_vec[i].iov_base)
				free(buf_vec[i].iov_base);
		}

		if (args.file_count + (!!args.input_dir) < args.files_given) {
			/* files given that are not valid trace buffers.
			 * don't return success, something went wrong */
			TRACEE("failed to parse all files (skipped %d files)\n",
				args.files_given - args.file_count);
			mainret = EINVAL;
		}

	} else if (!args.input_dir) {
		/* read from driver through ioctl if no files/dir given*/
		int bufnum = trace_adal_getbufs(0, 0);
		struct iovec *buf_vec;

		if (bufnum < 0) {
			/* hack: if adal fails and no arg given print usage */
			if (argc == 1) {
				argp_help(&argp, stderr, ARGP_HELP_STD_USAGE, "fsp-trace");
				return EAGAIN;
			}
			fprintf(stderr, "cannot get number of buffers from device driver\n");
			mainret = -bufnum;
			goto out;
		}
		if (bufnum == 0) {
			printf("no trace buffers active.\n");
			mainret = 0;
			goto out;
		}
		listp = (trace_buf_list_t *) malloc(bufnum * sizeof(trace_buf_list_t));
		if (listp == NULL) {
			TRACEE("out of memory for buffer list\n");
			mainret = ENOMEM;
			goto out;
		}
		ret = trace_adal_getbufs(bufnum, listp);
		if (ret < 0 || ret != bufnum) {
			TRACEE("cannot get list of buffers from driver\n");
			mainret = ENOENT;
			goto out;
		}
		
		buf_vec = (struct iovec *) malloc(sizeof(struct iovec) * bufnum);
		if (buf_vec == NULL) {
			TRACEE("out of memory for buffer vector");
			mainret = ENOMEM;
			goto out;
		}

		ptr = listp;	// current buffer
		valid_cnt = 0;	// valid buffers count 

		for (i = 0; i < bufnum; i++, ptr++) {
			/* should we get this buffer? */
			char *bufpnt;
			
			if (!is_buffer_in_list(ptr->name, args.comps, args.comp_count)) {
				continue;
			}

			bufpnt = (char *) malloc(ptr->size);
			if (bufpnt == NULL) {
				TRACEPE("out of memory for buffer '%s' (size:%zu)",
					ptr->name, ptr->size);
				free(listp);
				mainret = ENOMEM;
				goto out;
			}

			/* read the buffer from driver */
			ret = trace_adal_read(ptr->name, ptr->size, (void *) bufpnt);
			if (ret < 0) {
				TRACEE("cannot read buffer '%s'\n", ptr->name);
				free(bufpnt);
				continue;
			}

			/* binary mode: just write to output file */
			if (args.binary) {
				write(fdout, bufpnt, ret);
				free(bufpnt);
				continue;
			}

			vec_ptr = &buf_vec[valid_cnt];
			vec_ptr->iov_len = ret; /* use size returned from driver */
			vec_ptr->iov_base = bufpnt;
			valid_cnt++;
		}

		free(listp);
		if (args.binary) {
			TRACEI("%d buffers read.\n", valid_cnt);
			mainret = 0;
			goto out;
		}

		if (valid_cnt == 0) {
			TRACEE("no buffer was found/read.\n");
			free(buf_vec);
			mainret = ENOENT;
			goto out;
		}
		


		flags = TRACE_PREPEND_BUFFERNAME;

		if (args.tformat)
			flags |= TRACE_TIME_STRFTIME | TRACE_TIMEOFDAY;
		if (args.date)
			flags |= TRACE_TIMEOFDAY | TRACE_SET_TIMEOFDAY;
		if (args.filename)
			flags |= TRACE_FILENAME;
		if (!args.nosort)
			flags |= TRACE_MIX_BUFFERS;
		if (args.verbose)
			flags |= TRACE_VERBOSE;

		ret = trace_adal_print_buffers(buf_vec, valid_cnt, fdout,
					strings, 0, flags);
		if( ret < 0 ) {
			mainret = -ret;
			TRACEE("Print buffer error.\n");
		}
		
		TRACEI("%d traces read.\n", ret);

		for (j = 0; j < valid_cnt; j++)
			free(buf_vec[j].iov_base);
		free(buf_vec);
	}

      out:
	// free memory
	trace_adal_free_strings(strings);
	if (args.input_files) free(args.input_files);
	if (args.string_files) free(args.string_files);

	if (fdout > 2) {
		close( fdout );
		if( stat( outfile, &filestat ) == 0 && filestat.st_size == 0 )
		{
			TRACEI("%s file (fd:%d size:%d)\n", outfile, (int)fdout, (int)filestat.st_size)
			//remove( outfile );
		}
		else
		{
			TRACEI("%s file writed\n", outfile)
		}
	}
	return mainret;
}

