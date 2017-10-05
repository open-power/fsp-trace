/*                                                                        */
/*                  OpenPOWER fsp-trace Project                           */
/* Contributors Listed Below - COPYRIGHT 2004,2012                        */
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

/* need lldiv_t which is in C99 */
#define _ISOC99_SOURCE
#include <byteswap.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#define __USE_GNU
#endif
#include <search.h>
#include <string.h>

#include "adal_common.h"
#include "trace_adal.h"

#define CONVERT_TIME_UNKNOWN 2

#define FSP_PIPE_CHUNK_SIZE		64*1024
#define MAX_FORMAT_STRINGS_COUNT	96*1024
#define TIMEREF_STRING_FSP1		0x18afc5f5
#define TIMEREF_STRING			0x04556a8a
#define TRACE_MAX_SIZE			16*1024
#define TRACE_MAX_BUF_SIZE		512
#define DEFAULT_TIME_FORMAT		"%Y-%m-%d %H:%M:%S"

#define TRACE_MIN_SIZE (sizeof(trace_entry_stamp_t)+sizeof(trace_entry_head_t)+sizeof(uint32_t))

extern int g_verbose_level;
char g_time_format[DEFAULT_FMT_SZ] = "";

/*
 * @brief default value for time
 */
#define	DEFAULT_TIME_FLAG	TRACE_TIME_REAL

// struct for string file "magic cookie"
typedef struct sf_magic_cookie {
	uint32_t ver;		/* version */
	char date[32];		/* date of creation - timestamp string */
	char build[128];	/* build ID */
} sf_magic_cookie_t;

/* struct for trace entry */
typedef struct trace_entry_i {
	trace_entry_stamp_t stamp;
	trace_entry_head_t head;
	char *bufname;		// for pipes
	char *data;
} trace_entry_i_t;


typedef struct parse_tracebuf_entry {
	trace_buf_head_t head;		//tracebuffer header
	int swap_flg;
	size_t te_max;			//trace_entry max nr
	size_t te_cnt;			//trace_entry count
	trace_entry_i_t **entries;	//ptr to entries
} parse_tracebuf_t;


/* struct for string file entry */
typedef struct sf_entry {
//      int32_t         hash;
	char hash_str[16];
	char *format_str;
	char *file;
} sf_entry_t;

/* struct for trace entry */
typedef struct {
	struct hsearch_data htab;
	size_t filled;
	sf_entry_t **entries;
} trace_strings_i;

//----------------------------------------------------------------------------
// Local function definition
//----------------------------------------------------------------------------
static int parse_trace_data(char *outbuf, const size_t buf_size,
			    const trace_entry_i_t * trace_ent,
			    const trace_strings_i *strings, char ** file,
			    const int32_t swap_flg);
static int get_format_by_hash(const trace_strings_i *strings, const uint32_t hash, char **format, char **file);
static int get_format_by_hashstr(const trace_strings_i *strings, char *hashstr, char **format, char **file);
static void ppctimebase2timestamp(uint32_t * io_sec, uint32_t * io_usec, uint32_t frequency);
static int locate_timeref(trace_entry_i_t *, trace_timeref_t *, int);
static int convert_time( uint32_t *tbh, uint32_t *tbl, uint32_t time_flg, trace_timeref_t *tmref );
static int buf_size_valid(uint32_t);



//  formated output of trace headers
static void print_trace_struct(trace_entry_i_t * tent)
{
	/* show timestamps, tid; TE_size; TE_type, TE_hash, src_line (trace_adal.h) */
	TRACER ("\n  tbh:\t\t0x%08X (%u)\n  tbl:\t\t0x%08X (%u)\n  tid:\t\t0x%08X (%u)\n"
	        "\n  te_size:\t0x%04X (%u)"
		"\n  tag:\t\t0x%04X (%u)\n  hash nr:\t0x%08X (%u)\n  src line:\t0x%08X (%u)"
		"\n----------------------------------------\n",
		 tent->stamp.tbh, tent->stamp.tbh, tent->stamp.tbl, tent->stamp.tbl, tent->stamp.tid, tent->stamp.tid,
		 tent->head.length, tent->head.length,
		 tent->head.tag, tent->head.tag, tent->head.hash, tent->head.hash, tent->head.line, tent->head.line);
}

// 1 - big
// 0 - little
static int is_big_endian(void)
{
	uint32_t i = 0x89abcdef;
	unsigned short word;
	memcpy(&word, &i, sizeof(unsigned short));
	return word == 0x89ab;
}



static inline uint32_t fsptrace_timebase_frequency(unsigned int flag)
{
	switch (flag) {
		case TRACE_TIME_50MHZ:
			return 50000000;
		case TRACE_TIME_200MHZ:
			return 200000000;
		case TRACE_TIME_167MHZ:
		default:
			return 166666667;
	}
}


/*!
 * @brief Parse "magic cookie" from string file.
 *  Example (v2):
 *  FSP_TRACE_v2|||Wed Nov  2 13:48:04 2005|||BUILD:/home/bawidama/dev/fsp/apps-ibm-fsp/adals/fsptrace
 *
 * @param str String for parsing
 * @param sf_magic Struct for output values. Contain version, timestamp string, build id.
 *  Supported versions are numeric from 0 to 2^32;
 *
 * @return 0 on success, !0 on error.
 */
static int parse_sf_magic_cookie(char *str, sf_magic_cookie_t * sf_magic)
{
	char *pstr, *pstr2;
	size_t len;
	int ret = -1;

	const char *delim = "|||";
	const char *eyecatch = "#FSP_TRACE_v";

	TRACEF("E\n");
	if (str == NULL || sf_magic == NULL)
		return -1;


	// looking for version
	pstr = strstr(str, eyecatch);
	if (!pstr) {
		TRACEI("Unable to determine 'magic cookie' (eyecatch)\n");
		goto out;
	}
	pstr += strlen(eyecatch);

	memset(sf_magic, 0, sizeof(sf_magic_cookie_t));
	sf_magic->ver = atoi(pstr);

	pstr = strstr(pstr, delim);
	if (pstr == 0) {
		TRACEI("Unable to determine 'magic cookie' (ver)");
		goto out;
	}
	pstr += strlen(delim);

	// looking for timestamp
	pstr2 = strstr(pstr, delim);
	len = pstr2 - pstr;
	if (pstr2 != 0) {
		if (len >= sizeof(sf_magic->date)) {
			TRACEI("Unable to determine 'magic cookie' (timestamp).\n");
			goto out;
		}
		memcpy(sf_magic->date, pstr, len);
		sf_magic->date[len] = 0;
	} else {
		// version founded
		sf_magic->date[0] = 0;
		sf_magic->build[0] = 0;
		ret = 0;
		goto out;
	}


	// looking for build id
	pstr = pstr2 + strlen(delim);
	len = strlen(pstr);
	if (pstr2 != 0) {
		if (len >= sizeof(sf_magic->build)) {
			TRACEI("Unable to determine 'magic cookie' (build).\n");
			goto out;
		}
		memcpy(sf_magic->build, pstr, len);
		sf_magic->build[len] = 0;
		if (sf_magic->build[len-1] == '\n')
			sf_magic->build[len-1] = 0;
	} else	{
		// version and timestamp found
		sf_magic->build[0] = 0;
	}

	ret = 0;

out:
	TRACEF("L\n");
	return ret;
}



/*!
 * @brief Parse entry string from string_file.
 *  Example (v2):
 *  688650299||trace with 4 params %d %d %d %d||test/trace_test_c.c
 *
 * @param str String for parsing.
 * @param sf_entry Struct for output values. Contain id, format string, string length, source filename.
 *  If format string is 0 (not allocated), then outputs just string length value.
 *
 * @return 0 on error, !0 on success.
 */
static int parse_sf_entry_v2(char *str, sf_entry_t * sf_entry)
{
	char *pstr, *pstr2;
	size_t len;
	int ret = 0;

	const char *delim = "||";

	memset(sf_entry, 0 , sizeof(sf_entry_t));

	if (str == NULL || sf_entry == NULL) {
		TRACEI("Wrong params.\n");
		goto out;
	}
	// Looking for hash
	pstr = str;
	pstr2 = strstr(pstr, delim);
	len = pstr2 - pstr;
	if (pstr2 == 0 || len >= sizeof(sf_entry->hash_str)) {
		TRACEI("Unable to determine id.\n");
		goto out;
	}
	memcpy(sf_entry->hash_str, pstr, len);
	sf_entry->hash_str[len] = 0;

	// Looking for format string
	pstr = pstr2 + strlen(delim);
	pstr2 = strstr(pstr, delim);
	len = pstr2 - pstr;
	if (pstr2 == 0 || len <= 0) {
		TRACEI("Unable to determine format string.\n");
		goto out;
	}

	sf_entry->format_str = (char *) malloc(len + 1);
	if (!sf_entry->format_str) {
		TRACEPE("malloc error");
		goto out;
	}
	//printf("  format_str (%u): %x\n",len + 1,sf_entry->format_str);

	memcpy(sf_entry->format_str, pstr, len);
	sf_entry->format_str[len] = 0;

	// Looking for filename
	pstr = pstr2 + strlen(delim);
	len = strlen(pstr);
	if (len <= 1) {
		TRACEI("Unable to determine filename.\n");
		sf_entry->file = 0;
	}

	if( pstr[len-1] == '\n' )
		pstr[len-1] = 0;

	sf_entry->file = (char *) malloc(len + 1);
	if (!sf_entry->file) {
		TRACEPE("malloc error");
		goto out;
	}

	memcpy(sf_entry->file, pstr, len);
	sf_entry->file[len] = 0;

	TRACED("Hash:%s format:%s(%"PRIuPTR") file:%s(%"PRIuPTR")\n", sf_entry->hash_str,
	       sf_entry->format_str, (uintptr_t) sf_entry->format_str, sf_entry->file,
	       (uintptr_t) sf_entry->file);

	ret = 1;

out:
	if (ret == 0 && sf_entry != NULL) {
		if (sf_entry->format_str) {
			free(sf_entry->format_str);
			sf_entry->format_str = 0;
		}
		if (sf_entry->file) {
			free(sf_entry->file);
			sf_entry->file = 0;
		}
	}
	return ret;
}


/*!
 * @brief Reads a trace string file and adds the information to "strings".

 *
 * @param strings Holds information about trace format strings.
 * @param infile File where the stringfile will be read from.
 * @param flags Can be:
 *	TRACE_IGNORE_VERSION If set the stringfile is not checked for a magic header line.
 *		If not set and the check fails the file is not read and an error is returned
 *	TRACE_OVERWRITE If a string read from infile has the same id as a string that is already in
 *		strings but the string itself is different, the one from infile replaces
 *		(overwrites) the conflicting one in strings. Without this flag such a conflict
 *		is treated as error and an error returned.
 *	TRACE_VERBOSE When this is set some messages are printed to STDERR. The messages eg. tell
 *		about checking the file header (TRACE_CHECK_VERSION), about string
 *		conflicts and a summary about how much strings have been read. There is no
 *		formal definition of these messages.
 *
 * @return on success a pointer to a trace_strings_t structure will be returned.
 *  On error 0 will be returned and errno set accordingly.
 */
trace_strings_t trace_adal_read_stringfile(trace_strings_t i_strings,
					   const char *infile, int flags)
{
	FILE *fp = 0;
	char str[4096];
	char *ptmp, *pstr;
	int first, do_free = 0;
	sf_magic_cookie_t sf_magic;
	sf_entry_t *pent = 0;
	int verbose = flags & TRACE_VERBOSE;
	int l_errno = 0;
	trace_strings_i * strings = (trace_strings_i *) i_strings;

	ENTRY hentry, *hep;
	struct hsearch_data *htab;


	TRACEF("E\n");
	if (infile == NULL || *infile == 0) {
		TRACEE("Invalid parameters\n");
		errno = EINVAL;
		return 0;
	}
	if (strings == NULL) {
		strings = (trace_strings_i *) malloc(sizeof(*strings));
		if (strings == 0) {
			TRACEE("out of memory for strings object\n");
			errno = ENOMEM;
			return 0;
		}
		do_free = 1;
		memset(strings, 0, sizeof(trace_strings_i));
	}
	htab = &(strings->htab);
	if (!strings->entries) {
		/* initialize struct */
		TRACEI("Creating hashtable.\n");
		memset(htab, 0, sizeof(struct hsearch_data));
		if (hcreate_r(MAX_FORMAT_STRINGS_COUNT, htab) == 0) {
			TRACEPE("hcreate_r failed");
			l_errno = ENOMEM;
			goto error;
		}
		strings->entries = (sf_entry_t **) malloc(MAX_FORMAT_STRINGS_COUNT * sizeof(sf_entry_t *));
		if (!strings->entries) {
			TRACEE("out of memory for string pointers\n");
			l_errno = ENOMEM;
			goto error;
		}
	}

	fp = fopen(infile, "r");
	if (!fp) {
		TRACEPE("cannot open stringfile '%s'", infile);
		l_errno = errno;
		goto error;
	}
	// Read "magic cookie"
	pstr = fgets(str, sizeof(str), fp);
	if (!pstr) {
		TRACEE("cannot read from stringfile '%s'\n", infile);
		l_errno = EINVAL;
		goto error;
	}
	// Parse "magic cookie"
	memset(&sf_magic, 0, sizeof(sf_magic));
	sf_magic.ver = 2;
	if (parse_sf_magic_cookie(str, &sf_magic)) {
		if (!(flags & TRACE_IGNORE_VERSION)) {
			TRACEE("stringfile magic cookie not found or corrupted.\n");
			l_errno = EINVAL;
			goto error;
		} else {
			if (verbose) {
				TRACEI("stringfile magic cookie not found or corrupted.\n");
			}
		}
	} else {
		if (verbose) {
			TRACEI("Got stringfile magic cookie. Version: %u Date: %s Build: %s\n",
			       sf_magic.ver, sf_magic.date, sf_magic.build);
		}
		if (flags & TRACE_IGNORE_VERSION) {
			if (verbose) {
				TRACED("Ignore magic cookie (TRACE_IGNORE_VERSION is given).\n");
			}
			sf_magic.ver = TRACE_IGNORE_VERSION;
		} else if (sf_magic.ver != 2) {
			TRACEE("stringfile '%s' has Unknown version %d\n",
			       infile, sf_magic.ver);
			l_errno = EINVAL;
			goto error;
		}
	}

	first = 1;
	// Continously read string by string until the end
	while (fgets(str, sizeof(str), fp) != NULL) {
		// Check entries count
		if (strings->filled >= MAX_FORMAT_STRINGS_COUNT) {
			if (verbose)
				TRACEE("Too many strings (%zu), using only %u\n",
				       strings->filled, MAX_FORMAT_STRINGS_COUNT);
			break;
		}

		// allocate mem for entry structure
		pent = strings->entries[strings->filled] =
			(sf_entry_t *) malloc(sizeof(sf_entry_t));
		if (pent == 0) {
			TRACEE("out of memory for strings pointer list");
			l_errno = errno;
			goto error;
		}
		strings->filled++;

		if (parse_sf_entry_v2(str, pent) == 0) {
			free(pent);
			strings->filled--;
			if (first)
				TRACEI("Can't parse stringfile entry: '%s'\n", str);
			first = 0;
			continue;
		}
		// generate hash-array
		hentry.key = pent->hash_str;
		hentry.data = (void *) pent;

		if (get_format_by_hashstr(strings, pent->hash_str, &ptmp, 0) >= 0) {
			if (!strcmp(pent->format_str, ptmp)) {
				/* same string, same hash */
				TRACED("string occurs twice. id:%s string:%s\n",
				       pent->hash_str, ptmp);
				continue;
			}
			if (flags & TRACE_OVERWRITE) {
				TRACEI("Two strings have the same id. Overwrite old format string by new. id:%s old:%s new:%s.\n",
				       pent->hash_str, pent->format_str, ptmp);
				first = 0;
			} else {
				TRACEI("Two strings have the same id. Skip the stringfile. id:%s old:%s new:%s\n",
				       pent->hash_str, pent->format_str, ptmp);
				l_errno = EAGAIN;
				goto error;
			}
		}
		if (hsearch_r(hentry, ENTER, &hep, htab) == 0) {
			TRACEPE("Can't add an entry to the hash table (hash:%"PRIuPTR")",
				(uintptr_t) hentry.key);
			l_errno = ENOMEM;
			goto error;
		}
		TRACED("entered hash %s text '%s'\n", hentry.key, pent->format_str);
	}

	if (verbose)
		TRACEI("Got %zu strings from stringfile.\n", strings->filled);

	/* success */
	l_errno = 0;

error:
	if (fp)
		fclose(fp);

	if (l_errno) {
		if (do_free) {
			/* error: free strings only if allocated by us */
			trace_adal_free_strings((trace_strings_t) strings);
			free(strings);
		}
		/* return 0 on error */
		strings = NULL;
		errno = l_errno;
	}

	TRACEF("L\n");
	return (trace_strings_t) strings;
}


/*!
 * @brief Deallocates the memory allocated with trace_adal_read_stringfile() for "strings".
 *
 * @param strings Has to point to a trace_string_t structure that holds information about trace format strings.
 */
void trace_adal_free_strings(trace_strings_t i_strings)
{
	sf_entry_t *pent;
	size_t i;
	trace_strings_i * strings = (trace_strings_i *) i_strings;

	if (strings == NULL)
		return;

	TRACEF("E\n");

	if (strings->entries) {
		for (i = 0; i < strings->filled; i++) {
			pent = strings->entries[i];
			if (pent != 0) {
				free(pent->format_str);
				free(pent->file);
				free(pent);
			}
		}
		free(strings->entries);

		hdestroy_r(&(strings->htab));
	}
	strings->filled = 0;
	TRACEF("L\n");
	return;
}



static int32_t set_swap_flag(parse_tracebuf_t * parse_hdr)
{
	unsigned char local_endian = (is_big_endian()? 'B' : 'L');

	if (parse_hdr->head.endian_flg == local_endian) {
		parse_hdr->swap_flg = 0;
	} else if (parse_hdr->head.endian_flg == (is_big_endian()? 'L' : 'B')) {
		parse_hdr->swap_flg = 1;
	} else {
		TRACEE("Trace hdr endianess %u\n", parse_hdr->head.endian_flg);
		if (buf_size_valid(parse_hdr->head.size)) {
			parse_hdr->swap_flg = 0;
			TRACEE("  guessing host endianess\n");
		} else if (buf_size_valid(bswap_32(parse_hdr->head.size))) {
			parse_hdr->swap_flg = 1;
			TRACEE("  guessing non-host endianess\n");
		} else {
			/* return -1 to fail, returning 0 will loop forever */
			TRACEE("  invalid size (0x%08x)\n", parse_hdr->head.size);
			return -1;
		}
	}

	return 0;
}


/* getting buf_head from beginning of buffer
 * return 0 if ok, -1 on error
 * return sz if tracebuffer is unused (ver = 0)
 * */
static int fill_parse_header(char * data, size_t sz, parse_tracebuf_t * parse_hdr)
{
	int32_t rc = -1, idx;
	trace_buf_head_t * buf_head = &(parse_hdr->head);

	if (sz < sizeof(struct trace_buf_head_v1)) {
		TRACEE("sz[%zu] < buf_head_sz\n", sz);
		goto exit_gbh;
	}

	/* fill parse_hdr with v1. (v2+ data fields unneeded). */
	memcpy(buf_head, data, sizeof(struct trace_buf_head_v1));

	if (parse_hdr->head.ver != TRACE_BUFFER_VERSION) {
		if (!parse_hdr->head.ver) {
			rc = set_swap_flag(parse_hdr);
			if (rc) return rc;

			/* tracebuffer isn't used, return tracebuffer header size. */
			return (parse_hdr->swap_flg) ? bswap_32(parse_hdr->head.size) : parse_hdr->head.size;
		}
		TRACEE("Trace hdr version %u\n", parse_hdr->head.ver);
	}

	if ((parse_hdr->head.hdr_len != (unsigned char) sizeof(struct trace_buf_head_v1)) &&
	    (parse_hdr->head.hdr_len != (unsigned char) sizeof(struct trace_buf_head_v2))) {
		TRACEE("Trace hdr size %u, expected = %zu or %zu\n", parse_hdr->head.hdr_len,
			sizeof(struct trace_buf_head_v1),  sizeof(struct trace_buf_head_v2));
		goto exit_gbh;
	}

	if (convert_time(0, 0, parse_hdr->head.time_flg, 0)) {
		TRACEE("Trace hdr timing flag %u\n", parse_hdr->head.time_flg);
		goto exit_gbh;
	}

	/* reset rc (for failures) */
	rc = set_swap_flag(parse_hdr);
	if (rc) goto exit_gbh;
	rc = -1;

	for (idx = 0; idx < TRACE_MAX_COMP_NAME_SIZE; idx++) {
		if (!parse_hdr->head.comp[idx]) break;
		if (!isprint(parse_hdr->head.comp[idx])) {
			TRACEE("Trace hdr name is invalid\n");
			goto exit_gbh;
		}
	}

	if (parse_hdr->swap_flg) {
		/* performing endian swap for necessary fields */
		parse_hdr->head.size = bswap_32(parse_hdr->head.size);
		parse_hdr->head.times_wrap = bswap_32(parse_hdr->head.times_wrap);
		parse_hdr->head.next_free = bswap_32(parse_hdr->head.next_free);
	}

	if (sz < parse_hdr->head.size) {
		TRACEE("sz(%zu) < buf_head.sz(%u)\n", sz, parse_hdr->head.size);
		goto exit_gbh;
	}

	if (parse_hdr->head.next_free > parse_hdr->head.size) {
		TRACEE("tracebuffer - wrap offset too big (%u, size=%u)\n",
		       parse_hdr->head.next_free, parse_hdr->head.size);
		goto exit_gbh;
	}
	rc = 0;

exit_gbh:
	return rc;
}


/*******************************************************************************
   Function saves single trace entry.  First, find size of trace.  The trace
   size is word-aligned (as opposed to being packed).  If the trace seems valid,
   copy the data to tent, update the ptrace ptr, swap any necessary fields, and
   get out of dodge.

   Parameters.
   	@data: 		ptr to beginning of trace data, i.e after header.
	@ptrace:	ptr to last byte of trace.
	@tent:		Trace Entry parsing pointer.
	@swp:		binary flag.  Do we need to endian swap data.

 Returns pointer to next trace.
*******************************************************************************/

static char *get_trace(char *data, char *ptrace, trace_entry_i_t * tent, uint32_t swp)
{
	uint32_t trace_sz = 0;
	size_t head_size = sizeof(trace_entry_stamp_t) + sizeof(trace_entry_head_t);

	if (ptrace <= data || !tent)
		return 0;

	/* save trace size (ptrace points last byte of chained size) */
	TRACEI("ptrace - sizeof(trace_sz), sizeof(trace_sz) %"PRIuPTR" %zu \n", (uintptr_t)ptrace - sizeof(trace_sz), sizeof(trace_sz));
	memcpy(&trace_sz, ptrace - sizeof(trace_sz), sizeof(trace_sz));
	if (swp) trace_sz = bswap_32(trace_sz);

	if (trace_sz % 4) { //corrupted
		TRACEI("TE is unaligned : %u. Skip.\n", trace_sz);
		return 0;
	}

	if ((unsigned long) ptrace < (unsigned long) trace_sz) {
		TRACEE("TE is too big. Skip\n");
		return 0;
	}

    	if (!trace_sz || (ptrace - trace_sz) < data) {
	//	TRACEI("Last, wrapped, or corrupted TE. Done");
		return 0;
	}

	/* update TE ptr */
	ptrace -= trace_sz;

	/* save, swap, trace_ent ptr. */
	memcpy(tent, ptrace, head_size);
	tent->data = ptrace + head_size;
	if (swp) {
		tent->stamp.tbh = bswap_32(tent->stamp.tbh);
		tent->stamp.tbl = bswap_32(tent->stamp.tbl);
		tent->stamp.tid = bswap_32(tent->stamp.tid);

		tent->head.length = bswap_16(tent->head.length);
		tent->head.tag = bswap_16(tent->head.tag);
		tent->head.hash = bswap_32(tent->head.hash);
		tent->head.line = bswap_32(tent->head.line);
	}

	/* trace_sz includes trace header and chain size */
	if (tent->head.length + head_size > trace_sz - 4) {
		/* trace entry truncated by device driver */
		tent->head.length = trace_sz - head_size - 4;
	}

	return ptrace;
}



// getting trace from tracBINARY pipe buffer
// ptrace must locate begin of the trace
// return pointer to next trace
// Note: the buffername isn't copied but just linked with a pointer into the trace_ent structure,
// so you can't use it after 'data' memory release!
static char *get_pipe_trace(char *data, size_t size, trace_entry_i_t * trace_ent, uint32_t swap)
{
	if (data == 0 || trace_ent == 0)
		return 0;

	size_t head_size = sizeof(trace_entry_stamp_t) + sizeof(trace_entry_head_t);
	char *pos = data;
	char *data_end = data + size;
	char *ret = 0;

	if (size <= head_size + 2) {
		/* too small (header + zero-terminated buffer name,
		 * maybe need to read next chunk */
		TRACED("Trace from pipe too small (%zu)\n", size);
		return 0;
	}
	if (strnlen(data, TRACE_MAX_COMP_NAME_SIZE) >= TRACE_MAX_COMP_NAME_SIZE) {
		TRACEE("Trace component name corrupted: %.15s\n", data);
		return 0;
	}
	pos = strchr(data, 0) + 1;

	trace_ent->bufname = data;
	memcpy(trace_ent, pos, head_size);
	pos += head_size;

	TRACED("data: 0x%"PRIuPTR" data_end: 0x%"PRIuPTR" pos: 0x%"PRIuPTR" trace_ent->head.length: 0x%X swap:%d\n", (uintptr_t)data, (uintptr_t)data_end, (uintptr_t)pos, (int)trace_ent->head.length, (int)swap);
	if (swap) {
		trace_ent->stamp.tbh = bswap_32(trace_ent->stamp.tbh);
		trace_ent->stamp.tbl = bswap_32(trace_ent->stamp.tbl);
		trace_ent->stamp.tid = bswap_32(trace_ent->stamp.tid);

		trace_ent->head.length = bswap_16(trace_ent->head.length);
		trace_ent->head.tag = bswap_16(trace_ent->head.tag);
		trace_ent->head.hash = bswap_32(trace_ent->head.hash);
		trace_ent->head.line = bswap_32(trace_ent->head.line);
	}

	if ((pos + trace_ent->head.length) > data_end) {
		TRACED("Trace is cuted(body), skip. (trace_ent->head.length: %d)\n", trace_ent->head.length);
		return 0;
	}

	trace_ent->data = pos;
	ret = pos + trace_ent->head.length;
	return ret;
}

/* unwrap buffer
 * return 0 if ok, -1 on error */
static int unwrap_buf(char *data, size_t size, uint32_t part1_size)
{
	if (!data) return -1;

	int part2_size = size - part1_size;
	char *temp = (char *) malloc(size);
	if (!temp) return -1;

	memcpy(temp, data, part1_size);
	memmove(data, data + part1_size, part2_size);
	memcpy(data + part2_size, temp, part1_size);

	free(temp);
	return 0;
}


// unallocate entries list
// parse_hdr - first entry
static void free_entries_list(parse_tracebuf_t * parse_hdr)
{
	if (!parse_hdr)
		return;

	if (parse_hdr->entries && parse_hdr->te_cnt) {
		unsigned int i;
		for(i=0; i < parse_hdr->te_cnt; i++) {
			free(parse_hdr->entries[i]);
		}
		free(parse_hdr->entries);
	}
}

/* return 0 if ok, -1 on error */
static int time2epoch(uint32_t * sec, uint32_t * usec, trace_timeref_t * timeref)
{
	int ret = 0;

	if (!sec || !usec) {
		ret = -1;
		goto out;
	}

	if (!timeref) {
		goto out;
	}
	TRACED("tod=%u.%06u runtime=%u.%06u\n", (unsigned)timeref->tod.tv_sec,
	       (unsigned)timeref->tod.tv_usec,
	       timeref->time_stamp.high, timeref->time_stamp.low);
	TRACEV("%x.%08x  ", *sec, *usec);

	/* timeref contains a pair of tod/stamp values. tod is the unix time
	 * (number of seconds) when the ppc tick counter had the value that
	 * was stored in stamp. The stamp value is already converted to seconds
	 * + microseconds since-boot as is the stamp in sec/usec params.
	 * Therefore we calculate the tod of the trace as:
	 *     sec/usec + timeref.tod - timeref.stamp
	 */

	*sec  += (timeref->tod.tv_sec - timeref->time_stamp.high);
	*usec += (timeref->tod.tv_usec - timeref->time_stamp.low);

	if ( *usec > 2000000) {
		/* underflow, usec is in fact negative */
		*usec = *usec + 1000000;
		*sec = *sec - 1;
	} else if ( *usec > 1000000) {
		/* overflow */
		*usec = *usec - 1000000;
		*sec = *sec + 1;
	}
	TRACEV("  ->  %u.%06u\n", *sec, *usec);
out:
	return ret;
}

static int buf_size_valid(uint32_t size) {
	if (size & 3) return 0;
	if (size < sizeof(struct trace_buf_head_v1)) return 0;
	if (size > sizeof(struct trace_buf_head_v2)) return 0;
	if (size > 128*1024) return 0; /* need to change if >128k supported */
	return 1;
}


/*
 * @brief The buffer parsing - getting all traces
 * There is no memory allocation for the trace body - used pointer to the given buffer.
 *
 * @param data  -- pointer to list of unparsed tracebuffers in a single file
 * @param size  -- size of tracebuffer
 * @param parse_hdr -- buffer struct to fill with hdr, trace entries
 *
 * @return number of bytes read or -1 if error.
 */
static int parse_tracebuffer(char *data, size_t sz, parse_tracebuf_t * parse_hdr, trace_timeref_t * time, int * found_time)
{
	int32_t idx, rc = -1;
	char *ptrace;
	unsigned char local_endian_flg = (is_big_endian()? 'B' : 'L');

	if (!data || !parse_hdr || !sz) {
		return 0;
	}

	parse_hdr->entries = 0;
	parse_hdr->te_cnt = 0;

	TRACEF("E\n");

	/* copy tracebuffer hdr into parse_header */
	rc = fill_parse_header(data, sz, parse_hdr);
	if (rc) goto exit_ptb;

	TRACER("\n------------------------------------\n"
		 "buf_head\n"
		 "------------------------------------\n"
		 "  ver:\t\t0x%02X (%u)\n"
		 "  hdr_len:\t0x%02X (%u)\n"
		 "  time_flg:\t0x%02X (%u)\n"
		 "  endian_flg:\t0x%02X (%c)\n"
		 "* local_end_flg:0x%02X (%c)\n"
		 "  comp:\t\t%s\n"
		 "  size:\t\t0x%08X (%u)\n"
		 "  times_wrap:\t0x%08X (%u)\n"
		 "  next_free:\t0x%08X (%u)\n"
		 "------------------------------------\n",
		 parse_hdr->head.ver, parse_hdr->head.ver,
		 parse_hdr->head.hdr_len, parse_hdr->head.hdr_len,
		 parse_hdr->head.time_flg, parse_hdr->head.time_flg,
		 parse_hdr->head.endian_flg, parse_hdr->head.endian_flg,
		 local_endian_flg, local_endian_flg,
		 parse_hdr->head.comp,
		 parse_hdr->head.size, parse_hdr->head.size,
		 parse_hdr->head.times_wrap, parse_hdr->head.times_wrap,
		 parse_hdr->head.next_free, parse_hdr->head.next_free);

	if (parse_hdr->head.times_wrap) {
		unwrap_buf(data + parse_hdr->head.hdr_len,
			   parse_hdr->head.size - parse_hdr->head.hdr_len,
			   parse_hdr->head.next_free - parse_hdr->head.hdr_len);
		parse_hdr->head.next_free = parse_hdr->head.size;
	}
	//print_dump(data,sz);

	/* initialize parse_hdr.  Set list sz to max, malloc mem. */
	parse_hdr->te_max = parse_hdr->head.size / TRACE_MIN_SIZE;
	parse_hdr->entries = (trace_entry_i_t **) malloc(sizeof(void *) * parse_hdr->te_max);
	if (!parse_hdr->entries) {
		TRACEE("OOM - TE ptrs\n");
		rc = -ENOMEM;
		goto exit_ptb;
	}

	// looking for the end of the last trace
	ptrace = data + parse_hdr->head.next_free;

	/* fill TE array from end. */
	idx = (int) parse_hdr->te_max - 1;
	while (1) {
		trace_entry_i_t * tent = (trace_entry_i_t *) malloc(sizeof(trace_entry_i_t));
		if (!tent) {
			TRACEE("OOM - TE struct\n");
			rc = -ENOMEM;
			goto error;
		}

		ptrace = get_trace(data + parse_hdr->head.hdr_len, ptrace, tent, parse_hdr->swap_flg);
		if (!ptrace) {
			/* done */
			free(tent);
			break;
		}

		tent->bufname = parse_hdr->head.comp;
		parse_hdr->entries[idx] = tent;
		idx--;
		if (idx < 0) {
			/* shouldn't happen! - hand over what we have so far */
			TRACEE("too many trace entries in buffer, aborting\n");
			break;
		}
		print_trace_struct(tent);

		if (*found_time == 0) {
			*found_time = locate_timeref(tent, time, parse_hdr->swap_flg);
		}
	}

	if (idx < (int) parse_hdr->te_max - 1) {
		/* found at least one trace_entry, */
		int found = parse_hdr->te_max-1 - idx;
		if (idx >= 0) {
			/* move found trace_entries to begining of list. */
			memmove(parse_hdr->entries, parse_hdr->entries+idx+1, found * sizeof(void*));
		}
		parse_hdr->te_cnt = found;
	} else {
		free(parse_hdr->entries);
		parse_hdr->entries = 0;
		parse_hdr->te_max = 0;
	}
	TRACEF("L\n");
	return parse_hdr->head.size;

error:
	free_entries_list(parse_hdr);
exit_ptb:
	TRACEF("L\n");
	return rc;
}

/* return 1 on ok, 0 on error */
static int locate_timeref(trace_entry_i_t *parse_hdr, trace_timeref_t *timeref, int swp)
{
	int ret = 0;

	if (!parse_hdr || !timeref) {
		goto out;
	}

	//printf("tag:0x%X hash:0x%X\n", parse_hdr->head.tag, parse_hdr->head.hash);
	// try to locate the TIMEREF trace
	if(parse_hdr->head.tag == TRACE_COMP_TRACE && (parse_hdr->head.hash == TIMEREF_STRING || parse_hdr->head.hash == TIMEREF_STRING_FSP1)) {
		uint32_t *pint = (uint32_t *) parse_hdr->data;

		if (swp) {
			timeref->time_stamp.high = bswap_32(pint[2]);
			timeref->time_stamp.low = bswap_32(pint[3]);
			timeref->tod.tv_sec = bswap_32(pint[0]);
			timeref->tod.tv_usec = bswap_32(pint[1]);
			if (parse_hdr->head.hash != TIMEREF_STRING) {
				timeref->frequency = bswap_32(pint[4]);
			} else {
				/* should be from FSP0, assume 200MHz */
				timeref->frequency = 200000000;
			}
		} else {
			timeref->tod.tv_sec = pint[0];
			timeref->tod.tv_usec = pint[1];
			timeref->time_stamp.high = pint[2];
			timeref->time_stamp.low = pint[3];
			if (parse_hdr->head.hash != TIMEREF_STRING) {
				timeref->frequency = pint[4];
			} else {
				/* should be from FSP0, assume 200MHz */
				timeref->frequency = 200000000;
			}
		}

		/* fix bad freq value */
		if (timeref->frequency == 167666667)
			timeref->frequency = 166666667;

		if (timeref->frequency)
			ppctimebase2timestamp((uint32_t*)&(timeref->time_stamp.high), (uint32_t*)&(timeref->time_stamp.low), timeref->frequency);
		//printf("time1: %x.%x   ***   %x.%x   ***   freq:%X\n", (uint32_t)timeref->time_stamp.high, (uint32_t)timeref->time_stamp.low, timeref->tod.tv_sec, timeref->tod.tv_usec, timeref->frequency);

		ret = 1;
	}
out:
	TRACED("found? %d\n", ret);
	return ret;
}


// convert PPC timebase 64 bit value to timestamp - sec,usec
// tbh and tbl can be 0, then function just validate the time_flg value
// return:
//  0 - ok, the time has been converted
//  CONVERT_TIME_UNKNOWN - unknown value of time_flg, the time has not been converted
static int convert_time(uint32_t *tbh, uint32_t *tbl, uint32_t time_flg, trace_timeref_t *tmref )
{
	int ret = 0;
	int epoch_flg = 0;

	// save and reset epoch flag
	epoch_flg = time_flg & TRACE_TIME_EPOCH;
	if( time_flg != TRACE_TIME_UNKNOWN )
		time_flg &= ~TRACE_TIME_EPOCH;

	// convert
	switch( time_flg ) {
	case TRACE_TIME_REAL:
	case TRACE_TIME_TIMESPEC:
		break;

	case TRACE_TIME_50MHZ:
	case TRACE_TIME_200MHZ:
	case TRACE_TIME_167MHZ:
		/* convert the reference 64 bit ppc time stamp to sec/usec */
		if (tbh && tbl)
			ppctimebase2timestamp(tbh, tbl, fsptrace_timebase_frequency(time_flg));

		/* make the time epoch-based if it isn't already */
		if (!epoch_flg)
			time2epoch(tbh, tbl, tmref);
		break;

	case TRACE_TIME_UNKNOWN:

		if (tmref && tbh && tbl) {
			/* convert the reference 64 bit ppc time stamp to sec/usec */
			ppctimebase2timestamp(tbh, tbl, fsptrace_timebase_frequency(tmref->frequency));
			/* make the time epoch-based */
			time2epoch(tbh, tbl, tmref);
		}

		break;

	default:
		ret = CONVERT_TIME_UNKNOWN;
		break;
	}

	// restore epoch flag
	if( time_flg != TRACE_TIME_UNKNOWN )
		time_flg |= epoch_flg;

	return ret;
}


// compare traces by time
// return:  <0 - pent1 < pent2
//           0 - pent1 = pent2
//          >0 - pent1 > pent2
static int trace_list_compare(trace_entry_i_t * pent1, trace_entry_i_t * pent2)
{
	if (pent1 == 0 || pent2 == 0)
		return 0;

	register uint32_t tbh1 = pent1->stamp.tbh;
	register uint32_t tbl1 = pent1->stamp.tbl;
	register uint32_t tbh2 = pent2->stamp.tbh;
	register uint32_t tbl2 = pent2->stamp.tbl;

	if (tbh1 > tbh2)
		return 1;
	if (tbh1 < tbh2)
		return -1;
	if (tbl1 > tbl2)
		return 1;
	if (tbl1 < tbl2)
		return -1;
	return 0;
}

/* merge sort: merge two sorted arrays into one big sorted array */
static int trace_array_merge_sort(parse_tracebuf_t * buf1,
				  parse_tracebuf_t * buf2,
				  trace_entry_i_t *** array_out, size_t *sizeout)
{
	trace_entry_i_t **pout;
	size_t i1, i2, size1, size2;

	size1 = buf1->te_cnt;
	size2 = buf2->te_cnt;

	i1 = 0;
	i2 = 0;
	pout = (trace_entry_i_t **) malloc(sizeof(void*) * (size1 + size2));
	if (pout == NULL) {
		TRACEE("out of memory merge-sorting trace lists\n");
		return -ENOMEM;
	}
	*array_out = pout;
	while(i1 < size1 && i2 < size2) {
		if (trace_list_compare(buf1->entries[i1], buf2->entries[i2]) < 0) {
			*pout = buf1->entries[i1];
			pout++;
			i1++;
		} else {
			*pout = buf2->entries[i2];
			pout++;
			i2++;
		}
	}
	while(i1 < size1) {
		*pout++ = buf1->entries[i1++];
	}
	while(i2 < size2) {
		*pout++ = buf2->entries[i2++];
	}
	*sizeout = size1 + size2;

	return 0;
}


static int trace_output_get_format(int flags, char *head_fmt, size_t head_size,
				   char *entry_fmt, size_t entry_size,
				   char *foot_fmt, size_t foot_size)
{
	// Output format: "   timestamp  |  tid  | [comp]  | line | message | [comp] | [filename]"
	//                "   %08u.%06u  |  %5u  | [%-16s] |  %4u |    %s   | [%-16s]|    [%s]   "

	char *head_caption = " %s\n";
	char *head_timestamp = " Sec    Usec   ";
	char *head_timeofday = " Sec    Usec              ";
	char *head_comp_pre = " Comp            ";
	char *head_comp_app = " Comp            ";
	char *head_tid = "   PID";
	char *head_message = " Entry Data";
	char *head_filename = " Filename  ";
	char *head_line = " Line";

	char *entry_timestamp = "%1$08u.%2$09u";
	char *entry_timeofday = "%1$s.%2$06u";
	char *entry_comp_pre = "|%3$-16s";
	char *entry_comp_app = "|%3$-16s";
	char *entry_tid = "|%4$5u";
	char *entry_message = "|%5$s";
	char *entry_filename = "|%6$s";
	char *entry_line = "|%7$4u";

	// output templates
	char *delim =
		"-------------------------------------------------------------------------------\n";
	char *foot = " %u traces read.\n";
	char *empty = "";

	// strftime
	if (flags & TRACE_TIME_STRFTIME) {
		entry_timeofday = "%1$s";
		entry_comp_pre = "|%2$-16s";
		entry_comp_app = "|%2$-16s";
		entry_tid = "|%3$5u";
		entry_message = "|%4$s";
		entry_filename = "|%5$s";
		entry_line = "|%6$4u";
	}

	// comp prepend
	if (!(flags & TRACE_PREPEND_BUFFERNAME)) {
		entry_comp_pre = empty;
		head_comp_pre = empty;
	}
	// comp append
	if (!(flags & TRACE_APPEND_BUFFERNAME)
	    || (flags & TRACE_PREPEND_BUFFERNAME)) {
		entry_comp_app = empty;
		head_comp_app = empty;
	}
	// filename
	if (!(flags & TRACE_FILENAME)) {
		entry_line = "|%6$4u";
		if (flags & TRACE_TIME_STRFTIME)
			entry_line = "|%5$4u";
		entry_filename = empty;
		head_filename = empty;
	}

	// timeofday
	if (flags & TRACE_TIMEOFDAY) {
		entry_timestamp = empty;
		head_timestamp = empty;
	} else {
		entry_timeofday = empty;
		head_timeofday = empty;
	}


	// Output format: "  |    timestamp  \| [comp]  \|  tid  \| message \| [comp] \| [filename]"
	//                "%c|   %08u.%09u  \|  [%s]   \|  %5u  \|    %s   \|  [%s]  \|    [%s]   "
	if (entry_fmt) {
		if (snprintf(entry_fmt, entry_size, "%s%s%s%s%s%s%s%s\n",
			     entry_timestamp, entry_timeofday, entry_tid, entry_comp_pre,
			     entry_line, entry_message, entry_comp_app, entry_filename) < 0 ) {
			*entry_fmt = 0;
			return -1;
		}
	}

	if (head_fmt) {
		if( snprintf(head_fmt, head_size, "%sTRACEBUFFER:%s%s%s%s%s%s%s%s%s%s\n%s",
			     delim, head_caption, delim, head_timestamp,
			     head_timeofday, head_tid, head_comp_pre, head_line,
			     head_message, head_comp_app, head_filename, delim) < 0 ) {
			*head_fmt = 0;
			return -1;
		}
	}

	if (foot_fmt) {
		if( snprintf(foot_fmt, foot_size, "%s%s", delim, foot) < 0 ) {
			*foot_fmt = 0;
			return -1;
		}
	}
	return 0;
}

static int trace_output(FILE* fp, char *fmt, ...)
{
	va_list arg_ptr;
	int ret;

	if (fmt == 0)
		return -EINVAL;
	va_start(arg_ptr, fmt);
	ret = vfprintf(fp, fmt, arg_ptr);
	va_end(arg_ptr);
	return ret;
}


// Formating and output of traces
// flags - flags from print_buffers
static int trace_output_entry(FILE *fp, char *entry_fmt,
			      trace_entry_i_t * trace_ent,
			      trace_strings_i *strings, int swap_flg,
			      int flags, char *time_format)
{
	char buf[TRACE_MAX_SIZE];
	char *nextstr;
	char *curstr = buf;
	char *file = 0;
	char timestr[DEFAULT_FMT_SZ];
	char *storage_format;
	int ret, written = 0;
	time_t gtime = 0;

	// parse message
	if (parse_trace_data(buf, sizeof(buf), trace_ent, strings, &file, swap_flg) == -1) {
		TRACED("parse_trace_data failed.\n");
		return -EINVAL;
	}

	curstr = buf;
	if (flags & TRACE_TIME_STRFTIME) {

		storage_format = malloc(DEFAULT_FMT_SZ);
		memset(storage_format, 0, DEFAULT_FMT_SZ);
		memcpy(storage_format, time_format, DEFAULT_FMT_SZ);

		char *p = storage_format;
		while ((p = strchr(p, '%')) != NULL) {
			int n, m;
			unsigned pres, scale;

			p++;
			if (*p == '%') {
				p++;
				continue;
			}
			n = strspn(p, "0123456789");
			if (p[n] != 'N') {
				p += n;
				continue;
			}
			/* We have "%[nnn]N" */
			p[-1] = '\0';
			p[n] = '\0';
			scale = 1;
			pres = 9;
			if (n) {
				pres = atoi(p);
				if (pres == 0)
					pres = 9;
				m = 9 - pres;
				while (--m >= 0)
					scale *= 10;
			}

			m = p - storage_format;
			p += n + 1;
			asprintf(&storage_format, "%s%0*u%s", storage_format,
				pres, (unsigned)trace_ent->stamp.tbl / scale, p);
			p = storage_format + m;
		}
		gtime = trace_ent->stamp.tbh;
		strftime(timestr, sizeof(timestr), storage_format,
			 gmtime(&gtime));
		free(storage_format);

	}

	else if (flags & TRACE_TIMEOFDAY) {
		gtime = trace_ent->stamp.tbh;
		strftime(timestr, sizeof(timestr), DEFAULT_TIME_FORMAT,
			  gmtime(&gtime));
	}

	do {
		nextstr = strchr(curstr, '\n');
		if (nextstr != 0)
			*nextstr = '\0';

		if (flags & TRACE_TIME_STRFTIME)
				ret = trace_output(fp, entry_fmt,
				   timestr, trace_ent->bufname,
				   TRACE_TID_TID(trace_ent->stamp.tid), curstr,
				   file, trace_ent->head.line);
		else if (flags & TRACE_TIMEOFDAY)
			ret = trace_output(fp, entry_fmt,
				   timestr, 0, trace_ent->bufname,
				   TRACE_TID_TID(trace_ent->stamp.tid), curstr,
				   file, trace_ent->head.line);
		else
			ret = trace_output(fp, entry_fmt,
				   (char *)((uintptr_t)trace_ent->stamp.tbh),
				   trace_ent->stamp.tbl, trace_ent->bufname,
				   TRACE_TID_TID(trace_ent->stamp.tid), curstr,
				   file, trace_ent->head.line);
		if (ret < 0)
			return ret;
		written += ret;
		if (nextstr == NULL)
			break;
		curstr = nextstr + 1;
	}
	while ((uintptr_t) curstr != 1);	// curstr = strchr( curstr, '\n') + 1;

	return written;
}


static void ppctimebase2timestamp(uint32_t * io_sec, uint32_t * io_usec, uint32_t frequency)
{
	unsigned long long longlong;
	lldiv_t div;

	TRACEV("%08x.%08x ", *io_sec, *io_usec);
	/* make one 64 bit timestamp */
	longlong = *io_sec;
	longlong <<= 32;	/* cannot use *io_sec<<32 as this would be 0 */
	longlong += *io_usec;
	div = lldiv(longlong, frequency);
	/* quot is number of seconds */
	*io_sec = (uint32_t) div.quot;
	/* rem is number of ticks left in unfinished second */
	/* translate to usecs, the divide by frequency */
	longlong = div.rem * 1000000;
	div = lldiv(longlong, frequency);
	*io_usec = (uint32_t) div.quot;
	TRACEV(" =>  %u.%06u  (%u)\n", *io_sec, *io_usec, frequency);
}


static int trace_output_vbuf(int outfile, parse_tracebuf_t ** parse_hdr,
			     int buf_count, trace_strings_i *strings,
			     trace_timeref_t * timeref, int flags, int mixed,
			     char *time_format)
{
	//TODO: timeofday support, filename output support

	if (parse_hdr == 0 || buf_count < 0)
		return -EINVAL;

	int i=0, ret=0, traces_count = 0;
	int outfile_dup;

	char head_fmt[1024];
	char entry_fmt[1024];
	char foot_fmt[1024];
	size_t zheader_size = 256;
	char temp[zheader_size];
	FILE* fp;

	int binary = flags & TRACE_BINARY;

	TRACEI("(%d, %p, %d, %p, %p, %d, %d\n", outfile, *parse_hdr, buf_count,
	       strings, timeref, flags, mixed);

	/* fclose shouldn't close outfile, therefore we need to dup */
	if (outfile != -1) {
		outfile_dup = dup(outfile);
		if (outfile_dup < 0) {
			TRACEPE("dup of %d failed", outfile);
			return -errno;
		}
		fp = fdopen(outfile_dup, "a");
		if( fp == NULL ) {
			TRACEPE("fdopen of %d failed", outfile_dup);
			ret = -errno;
			close(outfile_dup);
			return ret;
		}
	}

	TRACEI("Output %d buffers in %s format to fd:%d\n", buf_count, binary?"binary":"ascii", outfile);

	if (flags & TRACE_TIMEOFDAY)
	{
		TRACEI("Time converting (time_flg:%d)\n", parse_hdr[i]->head.time_flg);
		ret = convert_time( 0, 0, parse_hdr[i]->head.time_flg, 0 );
		if( ret == CONVERT_TIME_UNKNOWN )
		{
			TRACEE("Time format unknown(%u), -k option is disabled.\n", parse_hdr[i]->head.time_flg);
			flags &= ~TRACE_TIMEOFDAY;
		} else if( timeref == 0 ) {
			TRACEE("Timeref has not given and has not founded in buffer, -k option is disabled.\n");
			flags &= ~TRACE_TIMEOFDAY;
		}
	}


	// get output formats for header, entry and footer
	if (!binary) {
		if (trace_output_get_format(flags, head_fmt, sizeof(head_fmt),
					    entry_fmt, sizeof(entry_fmt),
					    foot_fmt, sizeof(foot_fmt)) == -1) {
			TRACEE("Cannot get output format\n");
			ret = -EAGAIN;
			goto out;
		}
	}

	// process every buffer
	for (i = 0; i < buf_count; i++) {
		unsigned int tidx;
		trace_entry_i_t *trace_ent;
		// output header
		if (!binary && outfile != -1) {
			snprintf(temp, zheader_size, "%s wrapped:%d size:%d",
				parse_hdr[i]->head.comp,
				parse_hdr[i]->head.times_wrap,
				parse_hdr[i]->head.size);
			ret = trace_output(fp, head_fmt, mixed ? "Mixed buffer"
					   : temp);
			if (ret < 0)
				goto out;
			TRACEI("%d buffer header output done\n", i);
		}

		// get the first entry
		if (parse_hdr[i]->entries == 0) {
			if (outfile != -1) {
				ret = fprintf(fp, "Buffer is empty.\n");
				if (ret < 0)
					goto out;
			}
			continue;
		}

		// output traces one by one
		for(tidx = 0; tidx < parse_hdr[i]->te_cnt; tidx++) {
			trace_ent = parse_hdr[i]->entries[tidx];
			//print_trace_struct(trace_ent);	//debug only

			ret = convert_time( &(trace_ent->stamp.tbh),
					    &(trace_ent->stamp.tbl),
					    parse_hdr[i]->head.time_flg,
					    timeref);
			if (outfile != -1) {
				ret = trace_output_entry(fp, entry_fmt,
							 trace_ent, strings,
							 parse_hdr[i]->swap_flg,
							 flags,
							 time_format);
				if (ret < 0)
					goto out;
			}
			traces_count++;
		}
		TRACEI("Buffer %d traces output done\n", i);
	}

	// output footer (one for all buffers)
out:
	if (outfile != -1) {
		if (ret == 0)
			ret = trace_output(fp, foot_fmt, traces_count);
		fclose(fp);
	}
	TRACEI("Footer output done\n");
	if (ret < 0)
		return ret;
	return traces_count;
}


/*!
 * @brief Parses a trace buffer, splits it into the trace entries and writes the traces formatted to the file "outfile".
 *
 * @param vec Points to a list (nr = vecsize) of struct iovec elements.  Each with pointer to trace buffer array.
 * @param outfile File descriptor where the traces should be written to using the "write" system call.
 *	If outfile is "-1" no output is generated. This can be used to check if a buffer is valid
 *	and to look for timref values from a TIMEREF trace.
 * @param strings Has to point to a trace_string_t structure that holds information about trace format strings.
 *	This structure has to be created with trace_adal_read_stringfile().
 * @param timeref Has to contain a pointer to a trace_timeref_t structure (cf. Section 1.5.4.2, "Trace with time reference
 *	and timebase information") if one of the flags TRACE_TIMEOFDAY and TRACE_SET_TIMEOFDAY is set.
 *	This structure contains a pair of time values and the timestamp frequency. These are used to translate the
 *	timestamp of the traces into timeofday values. If the timeref is 0 timestamp translation is only possible if a
 *	trace buffer contains a TIMEREF trace entry. Traces read and formatted prior to reading this trace entry are
 *	shown with untranslated timestamps.
 * @param flags Defines the output. It is the "OR"'ed value of some of the following flags:
 *	- TRACE_MIX_BUFFERS
 *		When multiple buffers are given the traces of all buffers are sorted by timestamp and printed as one list.
 *		If this flag is not given the traces are printed separatly for each trace buffers (i.e. grouped by buffer).
 *	- TRACE_PREPEND_BUFFERNAME
 *		Show the name of a trace buffer for each trace. The buffer name will be inserted between timestamp and trace text.
 *		Only one of TRACE_APPEND_BUFFERNAME and TRACE_PREPEND_BUFFERNAME can be given.
 *	- TRACE_APPEND_BUFFERNAME
 *		Show the name of a trace buffer for each trace. The buffer name will be appended at the end of the line
 *		(after	trace	text).	Only one of TRACE_APPEND_BUFFERNAME and TRACE_PREPEND_BUFFERNAME can be given.
 *	- TRACE_TIMEOFDAY
 *		When set timestamps are translated to timeofday values (date/time). This needs "timeref" to be given.
 *		If timeref is not given the timestamps are treated as if the PPC timebase counter was started at epoch time
 *		(i.e. the printed timestamp will be the time since FSP boot time).
 *	- TRACE_SET_TIMEOFDAY If a TIMEREF trace is found in a trace buffer and timeref is a valid
 *		pointer the values from the TIMEREF trace are written to timeref. This flag is independent of TRACE_TIMEOFDAY.
 *	- TRACE_FILENAME
 *		Show the name of the source file that contains the trace statement for each trace.
 *		(at the end of the line, after buffer name if this is printed too).
 *	- TRACE_VERBOSE When this is set some messages are printed to STDERR. The messages
 *		eg. tell about the processed trace buffers (version, size ...), number of
 *		traces in them etc. There is no formal definition of these messages.
 *
 * @return on success the number of traces written is returned. On failure a value <0 is returned.
 */
int trace_adal_print_buffers(const struct iovec *vec, size_t vecsize,
			     int outfile, const trace_strings_t strings,
			     trace_timeref_t * timeref, int flags)
{
	if (!vec || !vecsize)
		return -1;

	parse_tracebuf_t **parse_hdr;	/* struct for parsing tracebuffer, holds [buffers]->entries */
	int traces_count = 0;		/* from print func, returned if succ */
	size_t buffers_count = 0;	/* the number of buffers in parse_hdr */
	size_t output_count = 0;	/* number of used buffers in parse_hdr */
	size_t list_size = vecsize;	/* length of parse_hdr */
	size_t i;			/* loop var for parse_hdr[i] */
	int ret = 0;			/* function return value */
	trace_timeref_t tmref;		/* to hold time translation info */
	int have_timeref = 0;		/* do we have info in tmref? */

	TRACEF("E\n");
	TRACED("Buffer count: %zu\n", vecsize);

	if (timeref) {
		memcpy(&tmref, timeref, sizeof(trace_timeref_t));
		have_timeref = 1;
	} else {
		memset(&tmref, 0, sizeof(tmref));
	}

	/* allocate memory for parse_tracebuf list */
	parse_hdr = (parse_tracebuf_t **) malloc(list_size * sizeof(void*));
	if (!parse_hdr) {
		TRACEE("OOM - parsed buffer list");
		ret = -ENOMEM;
		goto out;
	}

	/* walk files parsing tracebuffers */
	for (i = 0; i < vecsize; i++, vec++) {
		unsigned int bytes_read = 0;
		int parts = 0;

		if (!vec) {
			TRACED("vec now empty.");
			ret = -ENOENT;
			goto out;
		}

		/* read vec->iov_len of tracefile */
		while (bytes_read < vec->iov_len) {
			int32_t rc;

			if (buffers_count > list_size)
				abort();

			/* increase parse_hdr list if needed */
			if (buffers_count == list_size) {
				void * p = realloc(parse_hdr, (list_size + 16)*sizeof(void *));
				if (!p) {
					TRACEE("OOM - grow parsed buffer list");
					ret = -ENOMEM;
					goto out_free;
				}
				parse_hdr = (parse_tracebuf_t **) p;
				memset(parse_hdr+buffers_count, 0, 16*sizeof(void *));
				list_size += 16;
			}

			/* allocate memory for next buffer header */
			parse_hdr[buffers_count] = (parse_tracebuf_t *) malloc(sizeof(parse_tracebuf_t));
			if (!parse_hdr[buffers_count]) {
				TRACEE("OOM - preparing to parse buffer");
				ret = -ENOMEM;
				goto out_free;
			}

			/* clear parse_hdr, fill with trace entries. rc = bytes read */
			memset(parse_hdr[buffers_count], 0, sizeof(parse_tracebuf_t));
			rc = parse_tracebuffer((char *)vec->iov_base + bytes_read,
						    vec->iov_len - bytes_read,
						    parse_hdr[buffers_count],
						    &tmref, &have_timeref);
			if (rc < 0) {
				TRACEE("Parsing failed for buffer %zu after %d parts.\n", i, parts);
				free(parse_hdr[buffers_count]);
				break;
			}

			if (have_timeref) {
				if ((flags & TRACE_SET_TIMEOFDAY) && timeref ) {
					/* copy found timeref back to caller */
					memcpy(timeref, &tmref, sizeof(trace_timeref_t));
				}
			}

			TRACEI("Parsed comp '%s' (%d/%zu bytes)\n",
				parse_hdr[buffers_count]->head.comp, rc,
				vec->iov_len);

			parts++;
			buffers_count++;
			bytes_read += rc;
		}
		TRACEI("buffer %zu had %d parts (%zu bytes left)\n",
		       i, parts, vec->iov_len - bytes_read);
	}
	output_count = buffers_count;
	TRACEI("%zu buffers parsed.\n", output_count);

	if (buffers_count > 1 && (flags & TRACE_MIX_BUFFERS)) {
		// Merge the buffers.
		// Create one common list of traces.
		// Hint: As we need to sort common list in reverse( from max to min)  order so let's link
		// buffers smart - a buffer with a minimal time of the first trace place at the start of
		// the list and so for. It should speed up further sorting, especially if the buffers
		// are not overlaped by time.

		//TODO: generate common caption

		trace_entry_i_t **mergedlist;
		size_t mergedsize;

		TRACEI("Mix %zu buffers to one.\n", output_count);

		for (i = 1; i < buffers_count; i++) {
			/* merge i. buffer with previous merged (in [0]) */
			ret = trace_array_merge_sort(
				parse_hdr[0], parse_hdr[i],
				&mergedlist, &mergedsize);
			if (ret < 0)
				goto out_free;
			/* put merged list in list index/buffer 0 */
			free(parse_hdr[0]->entries);
			parse_hdr[0]->entries = mergedlist;
			parse_hdr[0]->te_cnt = mergedsize;
			parse_hdr[0]->te_max = mergedsize;
			/* free i. list */
			free(parse_hdr[i]->entries);
			parse_hdr[i]->entries = 0;
		}

		output_count = 1;	// now we have one big list
	}

	/* output buffer(s) */
	if (output_count > 0 && outfile != -1) {
		traces_count = trace_output_vbuf(outfile, parse_hdr, output_count,
						 (trace_strings_i *) strings,
						 (flags & TRACE_TIMEOFDAY) ? &tmref : 0,
						 flags, flags &TRACE_MIX_BUFFERS,
						 g_time_format);
	}

out_free:
	// free memory
	// output_count can be not equal to buffers_count if
	// TRACE_MIX_BUFFERS flag specified
	for (i = 0; i < output_count; i++)
		free_entries_list(parse_hdr[i]);

	for (i = 0; i < buffers_count; i++)
		free(parse_hdr[i]);

	free(parse_hdr);
out:
	TRACEF("L >> ret=%d\n", ret);
	return ret < 0 ? ret : traces_count;
}


// get format string by hash value
static int get_format_by_hash(const trace_strings_i *strings, const uint32_t hash, char **format, char **file)
{
	ENTRY hentry, *hep;
	char hashstr[16];

	if (strings == 0 || hash == 0)
		return -EINVAL;

	snprintf(hashstr, sizeof(hashstr), "%u", hash);
	hentry.key = hashstr;
	hentry.data = 0;

	if (hsearch_r(hentry, FIND, &hep, (struct hsearch_data *) &(strings->htab)) == 0) {
		TRACED("Search failed (hash:%s)\n", hentry.key);
		return -ENOENT;
	}

	if( format )
		*format = ((sf_entry_t *) hep->data)->format_str;
	if( file )
		*file = ((sf_entry_t *) hep->data)->file;

	return 0;
}

// get format string by hash value
static int get_format_by_hashstr(const trace_strings_i *strings, char *hashstr, char **format, char **file)
{
	ENTRY hentry, *hep;

	if (strings == 0 || hashstr == 0)
		return -EINVAL;

	hentry.key = hashstr;
	hentry.data = 0;

	if (hsearch_r(hentry, FIND, &hep, (struct hsearch_data *) &(strings->htab)) == 0) {
		TRACED("Search failed (hash:%s)\n", hentry.key);
		return -ENOENT;
	}
	if( format )
		*format = ((sf_entry_t *) hep->data)->format_str;
	if( file )
		*file = ((sf_entry_t *) hep->data)->format_str;

	return 0;
}

typedef union {
		uint64_t u64;
		uint32_t u32;
		unsigned short u16;
		float f32;
		char *s;
} args;


/*!
 * @brief Input data vector is assumed to be in packed form.  Characters are
 *  treated as 1 byte, and strings are assumed to consist of string literals
 *  instead of char * pointers. \n
 *  All short (16 bit) and char(8bit) values are assumed to be type cast to 32
 *  bits before they were placed into the data vector.  Therefore support for
 *  the 'h' modifier is not included and the 'l' modifier is essentially ignored.
 *  To indicate a 64 bit value the 'L' modifier must be specified.
 *
 *  Now supported : string(%s), 32 bit integers(c,d,i,o,u,x,X), 64 bit
 *  integers(%ll = %L with c,d,i,o,u,x,X), pointers(%p), floats(%f).
 *
 *  Unsupported : double/long double (%lf, %Lf, %n)
 *
 * @param io_dest Pointer to destination buffer for the formatted string.
 * @param dest_size Size of the dest buffer.
 * @param i_fmt Formatting parameters to apply to the data vector.
 * @param i_vparms Pointer to packed data vector to be formatted.
 * @param i_swap Endian byte swap flag.
 *
 * @return Length of the final formatted string pointed to by io_dest.
 */
static int32_t trexMyVsnprintf(char *io_dest, size_t dest_size,
			       const char *i_fmt, char *i_vparms,
			       uint32_t i_vparms_size, uint32_t i_swap)
{
	//  Local Variables
	int longflag = 0;	/* =1 if "L" specified */
	uint8_t len_args = 9;
	args pargs[len_args];
	int argnum = 0;
	const char *fmtstring = i_fmt;
	char ch, *p, *vparms_end;
	uint32_t uint32_empty = 0;

	uint8_t fields[len_args]; /* 64bit fields*/
	uint32_t len_sfmt[len_args]; /* massive of lens of printable elements */
	uint32_t len_fmt = 0; /* len of not formatted string */
	uint8_t i;
	char tmpdata[dest_size]; /* temp data for copy */
	uint32_t prev_size = 0; /* previous size of not formatted string*/
	uint32_t prev_size_fmtd = 0; /* previous size of formatted string */
	uint32_t size = 0; /* size of formatted string */

	memset(fields, 0, len_args);
	memset(len_sfmt, 0, sizeof(uint32_t) * len_args);

	vparms_end = i_vparms + i_vparms_size - 1;
	for (ch = 1; ch; ch = *i_fmt++, len_fmt++) {
		if (argnum > 8)
			break;

		if (ch != '%')
			continue;
		// skip %
		ch = *i_fmt++;
		len_fmt++;
		// check for '%%'
		if (ch == '%') {
			continue;
		}
		// skip optional flags, search for format specifier
		while (1) {

			if (ch == 'l' && i_fmt[0] == 'l') {
				longflag = 1;
				i_fmt++;	// skip first l, second is skipped below
				len_fmt++;
			} else if (ch == 'L') {
				longflag = 1;
			} else if (!strchr("-+0123456789#lLw. 'Ihjzt", ch)) {
				break;
			}
			ch = *i_fmt++;	// skip optional char
			len_fmt++;
		}

		switch (ch)	// diouxXeEfFgGaAcpn
		{
		case 's':
			/* use marker if no data left in trace entry */
			len_sfmt[argnum] = len_fmt;
			if (i_vparms >= vparms_end) {
				pargs[argnum].s = "[[NODATA]]";
				break;
			}

			/* make sure string is zero-terminated */
			p = i_vparms;
			while (*p) {
				if (p >= vparms_end) {
					*(vparms_end) = 0;
					break;
				}
				p++;
			}

			fields[argnum] = TYPE_STRING;
			if (!*i_vparms) { /* empty string */
				pargs[argnum].s = "";
				i_vparms += 4; /* word aligned */
			} else {
				uint32_t tmpint;
				pargs[argnum].s = i_vparms;
				/* increase iv_parms by multiple of 4. we can't
				 * align i_vparms to a multiple of 4 as
				 * i_vparms isn't garanteed to be aligned */
				tmpint = strlen(i_vparms) + 1;
				tmpint = (tmpint + 3) & ~3;
				i_vparms += tmpint;
			}
			break;
		case 'p':
		case 'c':
		case 'd':
		case 'i':
		case 'o':
		case 'u':
		case 'x':
		case 'X':
			len_sfmt[argnum] = len_fmt;
			if (i_vparms > vparms_end) {
				pargs[argnum].u32 =  uint32_empty;
			} else {
				if (longflag) {
					pargs[argnum].u64 = *(uint64_t *) i_vparms;
					i_vparms += sizeof(uint64_t);
					/* Do endian swap if neccessary. */
					if (i_swap)
						pargs[argnum].u64 = bswap_64(pargs[argnum].u64);
					fields[argnum] = TYPE_UINT64;
					longflag = 0;
				} else {
					pargs[argnum].u32 = *(uint32_t *) i_vparms;
					i_vparms += sizeof(uint32_t);
					/* Do endian swap if neccessary. */
					if (i_swap)
						pargs[argnum].u32 = bswap_32(pargs[argnum].u32);
				}
			}
			break;
		case 'e':
		case 'f':
		case 'E':
		case 'F':
		case 'g':
		case 'G':
		case 'a':
		case 'A':
                        if (longflag) {
                            TRACEE("unsupported double/long-double value in trace found: %s\n",
                                    fmtstring);
                            goto out;
                        }

			len_sfmt[argnum] = len_fmt;
			pargs[argnum].f32 = *(float*) i_vparms;
			i_vparms += sizeof(float);

			fields[argnum] = TYPE_FLOAT;

			if (i_swap){
				pargs[argnum].f32 = bswap_32(pargs[argnum].f32);
			}

			break;
		default:
			TRACEE("unsupported format specifier in trace found: %c\n",
                                    ch);
			goto out;
		}		// switch(ch) between % and fmt
		argnum++;
	}			/* End of for loop */

	/*
	* We go on arguments and fill it with 32/64 bit
	* elements after we add tail.
	*/
	for (i = 0; i < argnum; i++) {
		memset(tmpdata, 0, dest_size);
		memcpy(tmpdata, &fmtstring[prev_size], len_sfmt[i] - prev_size);

		if (fields[i] == TYPE_UINT64) {
			size = snprintf(NULL, 0, tmpdata, pargs[i].u64);
			if ((prev_size_fmtd + size + 1) > dest_size) {
				snprintf(&io_dest[prev_size_fmtd],
					 dest_size - prev_size_fmtd, tmpdata,
					 pargs[i].u64);
				goto out;
			}
			snprintf(&io_dest[prev_size_fmtd], size + 1, tmpdata, pargs[i].u64);
		} else if (fields[i] == TYPE_FLOAT) {
			size = snprintf(NULL, 0, tmpdata, pargs[i].f32);
			if ((prev_size_fmtd + size + 1) > dest_size) {
				snprintf(&io_dest[prev_size_fmtd],
					 dest_size - prev_size_fmtd, tmpdata,
					 pargs[i].f32);
				goto out;
			}
			snprintf(&io_dest[prev_size_fmtd], size + 1, tmpdata, pargs[i].f32);
		} else if (fields[i] == TYPE_STRING) {
			/* pointer size/value is different for x86/x86_64 */
			if (__WORDSIZE == 32) {
				size = snprintf(NULL, 0, tmpdata, pargs[i].u32);
				if ((prev_size_fmtd + size + 1) > dest_size) {
					snprintf(&io_dest[prev_size_fmtd],
						 dest_size - prev_size_fmtd, tmpdata,
						 pargs[i].u32);
					goto out;
				}
				snprintf(&io_dest[prev_size_fmtd], size + 1, tmpdata, pargs[i].u32);
			} else {
				size = snprintf(NULL, 0, tmpdata, pargs[i].u64);
				if ((prev_size_fmtd + size + 1) > dest_size) {
					snprintf(&io_dest[prev_size_fmtd],
						 dest_size - prev_size_fmtd, tmpdata,
						 pargs[i].u64);
					goto out;
				}
				snprintf(&io_dest[prev_size_fmtd], size + 1, tmpdata, pargs[i].u64);
			}
		} else {
			size = snprintf(NULL, 0, tmpdata, pargs[i].u32);
			if ((prev_size_fmtd + size + 1) > dest_size) {
				snprintf(&io_dest[prev_size_fmtd],
					 dest_size - prev_size_fmtd, tmpdata,
					 pargs[i].u32);
				goto out;
			}
			snprintf(&io_dest[prev_size_fmtd], size + 1, tmpdata, pargs[i].u32);
		}
		prev_size_fmtd += size;
		prev_size = len_sfmt[i];
	}

	memset(tmpdata, 0, dest_size);
	memcpy(tmpdata, &fmtstring[prev_size], dest_size - prev_size);

	size = snprintf(NULL, 0, tmpdata);
	if ((prev_size_fmtd + size + 1) > dest_size) {
		snprintf(&io_dest[prev_size_fmtd], dest_size - prev_size_fmtd, tmpdata);
		goto out;
	}

	snprintf(&io_dest[prev_size_fmtd], dest_size - prev_size, tmpdata);

out:
	return (strlen(io_dest));
}



/*!
 * @brief Format some data as hex values
 *
 * @param destbuf       where to write the hex string to
 * @param destbuflen    sizeof destination buffer
 * @param srcbuf        pointer to data to format
 * @param srcbuflen     amount of data to format
 *
 * @return <0 for error, 0 else
 */
static int data_to_hexstring(char *destbuf, size_t destbuflen,
			     const char *srcbuf, size_t srcbuflen, int fl_order)
{
	uint32_t l_counter = 0;
	uint32_t l_written;
	uint32_t l_itr = 0;
	int32_t i;
	const char spaces[] = "                                                  ";	// 50 SPC

	if (destbuf == 0 || destbuflen == 0)
		return -EINVAL;

	if (srcbuflen == 0) {
		*destbuf = 0;
		return -ENOENT;
	}

	while (l_counter < srcbuflen) {
		// check avaiable space in buffer
		if (l_itr + 10 + 40 + 1 + 16 + 2 > destbuflen) {
			fprintf(stderr, "data_to_hexstring: buffer too small (%d)\n", l_counter);
			return -E2BIG;
		}
		// Display 16 bytes in Hex with 1 space in between
		l_written = 0;
		if (fl_order)
			l_written += sprintf(&destbuf[l_itr], "~[0x%04X] ", l_counter);
		l_itr += 10;
		for (i = 0; i < 16 && l_counter < srcbuflen; i++) {
			l_written +=
				sprintf(&destbuf[l_itr], "%02X", (unsigned char) srcbuf[l_counter]);
			l_itr += 2;
			l_counter++;

			if (!(l_counter % 4)) {
				l_written += sprintf(&destbuf[l_itr], " ");
				l_itr += 1;
			}
		}

		// Padd with spaces
		sprintf(&destbuf[l_itr], "%s", spaces + l_written);	// fill to 40 chars
		l_itr += (50 - l_written);

		// Display ASCII
		l_written = 0;
		sprintf(&destbuf[l_itr++], "*");
		for (; i > 0; i--) {
			//TRACED("2bin_data = %s, new char = %c\n",bin_data,entry_data[l_counter-i]);
			if (isprint(srcbuf[l_counter - i])) {
				l_written +=
					sprintf(&destbuf[l_itr], "%c",
						(unsigned char) srcbuf[l_counter - i]);
				l_itr += 1;
			} else {
				l_written += sprintf(&destbuf[l_itr], ".");
				l_itr += 1;
			}
		}
		sprintf(&destbuf[l_itr], "%-s", spaces + l_written + 24);	// fill to 16 chars
		l_itr += 16 - l_written;
		sprintf(&destbuf[l_itr], "*\n");
		l_itr += 2;
	}
	destbuf[l_itr - 1] = 0;

	return 0;
}


/*!
 * @brief Trace parsing
 *
 * @param outbuf		where to write the hex string to
 * @param buf_size		sizeof destination buffer
 * @param trace_ent		pointer to data to format
 * @param strings
 * @param file			filename pointer from stringfile entry
 * @param swap_flg		to swap or not to swap...
 *
 * @return <0 for error, 0 else
 */
static int parse_trace_data(char *outbuf, const size_t buf_size,
			    const trace_entry_i_t * trace_ent,
			    const trace_strings_i *strings, char ** file,
			    const int32_t swap_flg)
{
	if (outbuf == 0 || buf_size == 0 || trace_ent == 0 || strings == 0) {
		TRACEE("Invalid parameters");
		return -1;
	}

	char *format = 0;
	char *data = 0;
	uint32_t len = 0;
	int ret = 0;
	/* TODO : get rid of this factor '5', need to compute correctly for
	trexMyVsnprintf, data_to_hexstring.
	*/
	const int data_size = trace_ent->head.length * 5 + TRACE_MAX_BUF_SIZE;
	int i;
	int written;

	trace_entry_head_t *head = (trace_entry_head_t *) & (trace_ent->head);
	/* set a default */
	if (file) *file = "--no-file-info--";


	data = (char *) calloc(1, data_size );
	if( data == 0 )
	{
		TRACEPE("Cannot allocate memory");
		return -ENOMEM;
	}

	switch (head->tag) {
	case TRACE_COMP_TRACE:	// full printf style trace: 0x434f
		if (head->hash == TIMEREF_STRING)	// 0x04556a8a
		{
			// a string with time reference information
			format = "TIME REFERENCE tod=%lu.%06lus timebase: high=0x%lx low=0x%lx";
		} else if (head->hash == TIMEREF_STRING_FSP1)	// 0x18afc5f5
		{
			// a string with time reference and timebase information
			format =
				"TIME REFERENCE tod=%lu.%06lus timebase: high=0x%lx low=0x%lx freq=%luHz";
		} else {
			if (get_format_by_hash(strings, head->hash, &format, file) != 0) {
				TRACEI("Can't find format for hash %u (TRACE_COMP_TRACE)\n",
				       head->hash);
				goto no_hash;
			}
		}

		len = trexMyVsnprintf(data, data_size, format, trace_ent->data, trace_ent->head.length, swap_flg);
		if( len+1 > buf_size )
		{
			TRACEE("The trace data is too big! (%d)\n", len);
			ret = -E2BIG;
			goto out;
		}
		strncpy(outbuf, data, buf_size);

		break;

	case TRACE_FIELDTRACE:	// contains only 32bit values: 0x4654
	case TRACE_DEBUGTRACE:	// contains only 32bit values: 0x4454
		if (get_format_by_hash(strings, head->hash, &format, file) != 0) {
			TRACEI("Can't find format for hash %u (TRACE_DEBUGTRACE)\n", head->hash);
			goto no_hash;
		}

		len = trexMyVsnprintf(data, data_size, format, trace_ent->data, trace_ent->head.length, swap_flg);
		if( len+1 > buf_size )
		{
			TRACEE("The trace data is too big! (%d)\n", len);
			ret = -E2BIG;
			goto out;
		}
		strncpy(outbuf, data, buf_size);
		break;
	default:
	case TRACE_FIELDBIN:	// a binary trace of type field (non-debug): 0x4644
	case TRACE_DEBUGBIN:	// a binary trace of type debug: 0x4644
	case TRACE_BINARY_TRACE:	// 0x4249
		if (get_format_by_hash(strings, head->hash, &format, file) != 0)
			format = 0;

		data_to_hexstring(data, data_size, trace_ent->data, trace_ent->head.length, 1);

		if (format)
			snprintf(outbuf, buf_size, "%s\n%s", format, data);
		else
			strncpy(outbuf, data, buf_size);
		break;

	case TRACE_FIELDSTRING:	// a string trace of type field (non-debug): 0x4653 = "FS"
	case TRACE_DEBUGSTRING:	// a string trace of type debug: 0x4453 = "DS"
		if (trace_ent->head.length > buf_size) {
			TRACEE("The trace data is too big! (%d)\n", trace_ent->head.length);
			ret = -E2BIG;
			goto out;
		}
		/* copy string, replacing newlines */
		for (i = 0; i < trace_ent->head.length-1; i++) {
			char c = trace_ent->data[i];
			if (c == 0)
				break;
			if (c == '\n')
				c = ' ';
			*outbuf++ = c;
		}
		/* force a terminating zero */
		*outbuf = 0;
		break;


		// a trace about droped traces: 0xFF42
	case TRACE_INTERNAL_BLOCKED:
		if (head->hash != 0) {
			TRACEI("Unknown hash value for TRACE_INTERNAL_BLOCKED");
		}

		format = "@@@ INTERNAL: %lu TRACES HAVE BEEN DROPPED";
		len = trexMyVsnprintf(data, data_size, format, trace_ent->data, trace_ent->head.length, swap_flg);
		if( len+1 > buf_size )
		{
			TRACEE("The trace data is too big! (%d)\n", len);
			ret = -E2BIG;
			goto out;
		}
		strncpy(outbuf, data, buf_size);
		break;
	}
	goto out;

no_hash:
	data_to_hexstring(data, data_size, trace_ent->data,
			  trace_ent->head.length, 1);
	written = snprintf(outbuf, buf_size - 2,
			   "!!! NO STRING NO TRACE !!! for hash=%u", head->hash);
	if (trace_ent->head.length) {
		strcpy(outbuf + written, "\n");
		/* don't want to fill whole big buffer, don't use strncpy */
		strncat(outbuf + written + 1, data,
			buf_size - written);
	}

out:
	free(data);
	return ret;
}

/* try to get endianess of pipe file.
 * we need to check the "stamp" of the first trace entry.
 * the first byte of the timestamp would give us a hint, but it's not really
 * reliable. Instead we check the "tid" field. Linux uses 16bit PIDs, a PID
 * bigger than 2^16 means we need to swap.
 * returns 1 if byte-swap is needed
 *         0 if no byte-swap needed
 *        -1 on error
 */
int get_pipe_swap_heuristic(int fd)
{
	char buf[TRACE_MAX_COMP_NAME_SIZE+sizeof(trace_entry_stamp_t)+1];
	trace_entry_stamp_t *stamp;
	char *p;
	int pos = lseek(fd, 0, SEEK_CUR);
	int ret;

	/* read start of file with first component name and entry stamp */
	ret = read(fd, buf, sizeof(buf));
	/* rewind to old position */
	pos = lseek(fd, pos, SEEK_CUR);

	if (ret < (int) sizeof(buf)) {
		/* a file smaller than buf doesn't contain a full trace entry,
		 * no need to check */
		return -1;
	}
	/* look for start of stamp, skip buf name */
	for(p = buf; (p <= buf+TRACE_MAX_COMP_NAME_SIZE) && *p; p++) ;
	if (*p) {
		/* end of component name not found */
		return -1;
	}

	stamp = (void *) (p+1);
	if (TRACE_TID_TID(stamp->tid) <= 0xffff) {
		/* a valid PID. no swap necessary */
		return 0;
	}
	if (TRACE_TID_TID(bswap_32(stamp->tid)) <= 0xffff) {
		/* PID is valid if we endian-swap it */
		return 1;
	}
	/* PID not valid, maybe we can guess from timestamp:
	 * MSB should be zero (FSP would have to run 13.7 years!) */
	if (*(p+1) != 0) {
		/* first stamp bytes is LSB of second long, must swap */
		return 1;
	}
	/* don't know which endian we have */
	return -1;
}

/*!
 * @brief Reads traces from the trace device driver's pipe or a file. Writes the traces to the file descriptor outfile
 *	either binary for formatted. The traces will be read from the pipe or the file in chunks to limit memory consumption.
 *	If the input for this function is a file the whole file will be read and printed. If the input is the trace
 *	pipe one chunk of data will be read and printed. If the trace pipe buffer isn't full yet the function will sleep
 *	to wait for the buffer to fill. If the next chunk of data should be read from the pipe the function has to be called again.
 *	This way the user of this function can handle eg. keyboard input or open a new file to keep the file size below a limit.
 *	If fd contains -1 traces are read from the trace pipe. If fd contains a valid file descriptor traces are read from
 *	this file. The file should have been created with this function with the TRACE_BINARY flag set.
 *
 * @param outfile Is a file descriptor where the traces should be written to using the "write(2)" system call. If out-
 *	file is "-1" no output is generated. This can be used to check if a buffer is valid and to look for timref values
 *	from a TIMEREF trace.
 * @param strings Has to point to a trace_string_t structure that holds information about trace format strings. This struc-
 *	ture can be created and filled with trace_adal_read_stringfile(). strings is ignored if the TRACE_BINARY
 *	flag is set.
 * @param timeref Has to contain a pointer to a trace_timeref_t structure (cf. Section 1.5.4.2, "Trace with time reference
 *	and timebase information") if one of the flags TRACE_TIMEOFDAY and TRACE_SET_TIMEOFDAY is set.
 *	This structure contains a pair of time values and the timestamp frequency. These are used to translate the
 *	timestamp of the traces into timeofday values. If the timeref is 0 timestamp translation is only possible if a
 *	trace buffer contains a TIMEREF trace entry. Traces read and formatted prior to reading this trace entry are
 *	shown with untranslated timestamps.
 * @param flags Defines the output. It is the "OR"'ed value of some of the following flags:
 *	- TRACE_TIME_????? Specifies the format of the timestamp value of the traces. See time_flg
 *		for the possible time flags. At least one of these has to be given for version 2 of the trace pipe.
 *		For pipe versions 3 and above this flag will not be needed and might even be ignored.
 *	- TRACE_BINARY The traces read from the pipe are not formatted and written in binary format to the file.
 *	- TRACE_PREPEND_BUFFERNAME, TRACE_APPEND_BUFFERNAME The trace pipe always can contain traces from different trace buffers,
 *		trace_adal_print_pipe works always in TRACE_MIX_BUFFERS mode. One of these two flags should be given
 *		to show the buffer a trace was written to (which will correspond to the component that issued the trace).
 *		Ignored if TRACE_BINARY is set.
 *	- TRACE_TIMEOFDAY When set timestamps are translated to timeofday values (date/time). This
 *		needs timeref to be given. If timeref is not given the timestamps are
 *		treated as if the PPC timebase counter was started at epoch time. Ignored if TRACE_BINARY is set.
 *	- TRACE_SET_TIMEOFDAY If a TIMEREF trace is found in a trace buffer and timeref is a valid
 *		pointer the values from the TIMEREF trace are written to timeref.This flag is independent of TRACE_TIMEOFDAY.
 *	- TRACE_FILENAME Show the name of the source file that contains the trace statement for
 *		each trace. Ignored if TRACE_BINARY is set.
 *	- TRACE_VERBOSE When this is set some messages are printed to STDERR. The messages
 *		eg. tell about the source for the traces (file/pipe), number of traces read etc.
 *		There is no formal definition of these messages.
 *	- TRACE_DONTSTOP When set the trace pipe isn't turned off after processing the buffer.
 *		Uses static memory, function isn't re-entrant with this option.
 * @ return on success the number of traces written is returned.  On failure a value <0 is returned.
 */
int trace_adal_print_pipe(int fd, int outfile, const trace_strings_t strings,
			  trace_timeref_t * timeref, int flags)
{
	/* chunksize: should be bigger than max entry size
	 * but this is a load-time config option of the device driver
	 */
	size_t chunksize = FSP_PIPE_CHUNK_SIZE;

	int pipefd = -1;	// pipe fd
	static int saved_pipefd=-1;	// pipefd from last call w/ TRACE_DONTSTOP flag
	int outfile_dup;
	int readed;		// bytes count
	char *tracebuf = 0;	// buffer for chunk
	char *ptrace;		// temp pointer
	char *curpos;		// pointer to current position in buffer
	int total_entries = 0;	// entries count
	trace_entry_i_t ent;	// trace entry
	unsigned int partsize;		// used for partially read support
	unsigned int readsize;		// used for partially read support
	unsigned long foffset;
	FILE *fp;

	int ret = 0;
	char *fl_on = "1", *fl_off = "0";

	// buffers for output formats
	char head_fmt[512];
	char entry_fmt[128];
	char foot_fmt[512];

	int fl_swap = 1;	// TODO: how to determine???
	int fl_pipe = (fd == -1);
	int fl_time = DEFAULT_TIME_FLAG;

	int fl_timeofday_is_disabled = 0;

	trace_timeref_t tmref, *ptmref = 0;
	struct stat file_stat;

	TRACEF("E\n");

	if (!(flags & TRACE_BINARY)) {
		/* fclose shouldn't close outfile, therefore we need to dup */
		outfile_dup = dup(outfile);
		if (outfile_dup < 0) {
			TRACEPE("dup of %d failed", outfile);
			return -errno;
		}
		fp = fdopen(outfile_dup, "a");
		if( fp == NULL ) {
			TRACEPE("fdopen of %d failed", outfile_dup);
			close(outfile_dup);
			return -errno;
		}
	} else {
		fp = NULL;
	}

	if (flags & TRACE_TIMEOFDAY) {
		if( timeref != 0 ) {
			memcpy(&tmref, timeref, sizeof(trace_timeref_t));
			ptmref = &tmref;
		} else {
			ret = convert_time( 0, 0, fl_time, 0 );
			if( ret == CONVERT_TIME_UNKNOWN ) {
				TRACEE("Timeref has not given and time format unknown(%d), -k option is disabled.\n", fl_time);
				flags &= ~TRACE_TIMEOFDAY;
				fl_timeofday_is_disabled = 1;
			}
		}
	}

	// get output formats for header, entries and footer
	if (!(flags & TRACE_BINARY)) {
		if( trace_output_get_format(fl_timeofday_is_disabled ? flags & ~TRACE_TIMEOFDAY : flags, head_fmt, sizeof(head_fmt),
					    entry_fmt, sizeof(entry_fmt), foot_fmt, sizeof(foot_fmt)) == -1 ) {
			TRACEE("Cannot get output format\n");
			ret = -EAGAIN;
			goto out;
		}
	}

	/* open pipe */
	if (fl_pipe) {
		if (saved_pipefd >= 0) {
			/* is there an open and active pipe from last call? */
			struct stat sbuf;

			if (fstat(saved_pipefd, &sbuf) < 0) {
				TRACEE("pipe not open anymore, traces might be lost");
				saved_pipefd = -1;
			} else {
				pipefd = saved_pipefd;
			}
		}
		/* if no open pipe (not opened or closed) open now */
		if (pipefd < 0) {
			/* turn the pipe on */
			pipefd = open(TRACE_PIPE_NAME, O_RDWR);
			if (pipefd < 0) {
				ret = -errno;
				TRACEPE("Can't open %s", TRACE_PIPE_NAME);
				goto out;
			}
			if (write(pipefd, fl_on, strlen(fl_on)) < 0) {
				ret = -errno;
				TRACEPE("Failed to turn on trace daemon");
				close(pipefd);
				goto out;
			}
			TRACEI("Pipe %s opened.\n", TRACE_PIPE_NAME);
			saved_pipefd = pipefd;
		}
		fl_swap = 0;
	} else {
		pipefd = fd;
		fl_swap = get_pipe_swap_heuristic(pipefd);
		if (fl_swap < 0) {
			TRACEE("Cannot get endianess of pipe file, assuming big endian\n");
			fl_swap = !is_big_endian();
		}
		TRACEI("Read from pipe file.\n");
	}


	// allocate buffer for chunk
	tracebuf = (char *) malloc(chunksize);
	if (!tracebuf) {
		ret = -ENOMEM;
		TRACEPE("malloc failed for binary buffer size %zu", chunksize);
		goto out_close;
	}
	// output header
	if (!fl_pipe && !(flags & TRACE_BINARY)) {
		ret = trace_output(fp, head_fmt, "tracBINARY");
		if (ret < 0)
			goto out_close;

		// make sure we read at beginning (skip version byte)
		lseek(pipefd, 1, SEEK_SET);
		foffset = 1;
	} else {
		// make sure we read at beginning
		lseek(pipefd, 0, SEEK_SET);
		foffset = 0;
	}

	partsize = 0;
	readsize = chunksize;

	// read pipe by chunks
	// partsize - size of previous unparsed part, if last entry is read partially, else = 0
	while ((readed = read(pipefd, tracebuf + partsize, readsize)) > 0) {
		TRACEI("Got from pipe %d bytes (foffset=%lx) (left=%u)\n",
		       readed, foffset, partsize);
		if (flags & TRACE_BINARY) {
			foffset += readed;
			ret = write(outfile, tracebuf, readed);
			if (ret < 0) {
				ret = -errno;
				goto out_close;
			}
			fdatasync(outfile);
			ret = fstat(outfile, &file_stat);
			if (ret < 0) {
				ret = -errno;
				goto out_close;
			}
			posix_fadvise(outfile, 0, file_stat.st_size, POSIX_FADV_DONTNEED);
			if (fl_pipe)
				break;
			continue;
		}
		/* we actually have more bytes in buffer than just read */
		readsize = readed + partsize;
		ptrace = curpos = tracebuf;

		/* read and print trace by trace */
		while ((ptrace =
			get_pipe_trace(ptrace, readsize - (ptrace - tracebuf),
				       &ent, fl_swap)) != 0 && ptrace <= tracebuf + readsize) {
			print_trace_struct(&ent);	// debug only
			foffset += ptrace - curpos;

			TRACEV("Pipe trace num: %d pos:0x%lX(%ld) left=%td\n",
			       total_entries, foffset, foffset, readsize - (ptrace - tracebuf) );
			// locate timeref trace
			if (!ptmref && (locate_timeref(&ent, &tmref, fl_swap) == 1)) {
				ptmref = &tmref;
				// if TRACE_TIMEOFDAY flag was turned off before so restore it and assign a new entry format
				if( fl_timeofday_is_disabled ) {
					flags &= TRACE_TIMEOFDAY;
					if( trace_output_get_format(flags, 0, 0, entry_fmt, sizeof(entry_fmt), 0, 0) == -1 ) {
						TRACEE("Cannot get output format\n");
						continue;
					}
					fl_timeofday_is_disabled = 0;
				}

				if( flags & TRACE_SET_TIMEOFDAY && timeref) {
					memcpy( timeref, &tmref, sizeof(trace_timeref_t));
				}
			}

			// save current position
			curpos = ptrace;

			// convert time to sec.usec format
			ret = convert_time( &ent.stamp.tbh, &ent.stamp.tbl, fl_time, ptmref );

			//output entry
			ret = trace_output_entry(fp, entry_fmt, &ent,
						 (trace_strings_i *) strings, fl_swap,
						 flags,
						 g_time_format);
			if (ret < 0)
				goto out_close;

			total_entries++;
		}

		// from the pipe just read the one chunk and return
		if (fl_pipe)
			break;

		// last entry readed partially?
		if ((unsigned int)(curpos - tracebuf) < readsize) {
			partsize = readsize - (curpos - tracebuf);
			readsize = chunksize - partsize;
			memmove(tracebuf, curpos, partsize);
		} else {
			partsize = 0;
			readsize = chunksize;
		}
	}
	if (readed < 0) {
		ret = -errno;
		if (errno != EINTR)
			TRACEPE("Read from pipe(%d) failed", pipefd);
	}

out_close:
	/* close pipe if we shouldn't keep it open */
	if (fl_pipe && !(flags & TRACE_DONTSTOP)) {
		/* turn the pipe off */
		if (write(pipefd, fl_off, strlen(fl_off)) < 0) {
			ret = -errno;
			TRACEPE("Failed to turn off trace daemon");
		}
		close(pipefd);
		TRACEI("Pipe is closed.\n");
		saved_pipefd = -1;
	}

out:
	if (tracebuf)
		free(tracebuf);

	TRACEF("L");

	if (fp)
		fclose(fp);
	return ret;
}
