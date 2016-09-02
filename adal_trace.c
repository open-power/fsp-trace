/*                                                                        */
/*                  OpenPOWER fsp-trace Project                           */
/* Contributors Listed Below - COPYRIGHT 2004, 2010, 2012                 */
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

/* need _GNU_SOURCE for strnlen */
#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "adal_common.h"
#include "trace_adal.h"


#define TRAC_TEMP_BUFFER_SIZE 1024


static int32_t fd = -1;
static trace_desc_t td_invalid = -42;
static trace_desc_t td_uninit  = -42;
extern int g_verbose_level;


int32_t trace_adal_init_buffer(trace_desc_t *, const char *, const size_t);


void __attribute__ ((constructor)) adal_trace_initialize(void)
{
	fd = open(TRACE_FULL_DEVICE_NAME, O_RDWR);
	if (fd < 0) {
		//fprintf(stderr, "Can't open device %d", errno);
		errno = ENODEV;
		return;
	}

	/* private buffers for trace descriptor debug data. */
	trace_adal_init_buffer(&td_uninit, "TD_UNINIT", 4096);
	trace_adal_init_buffer(&td_invalid, "TD_INVALID", 4096);
}

void __attribute__ ((destructor)) adal_trace_exit(void)
{
	close(fd);
}



static void trace_uninited_td(const trace_desc_t td, uint32_t l, uint32_t hash)
{
	trace_entry_t entry;

	entry.h.tag    = TRACE_FIELDSTRING;
	entry.h.line   = l;
	entry.h.hash   = 0;
	entry.h.length = sprintf((char *)entry.args, "td:%d hash:%u", td, hash);
	trace_adal_write(td_uninit, sizeof(trace_entry_head_t) + entry.h.length, TRACE_FIELD, (void *) &entry);
}


static int32_t trac_check_size(int32_t i_size, uint16_t i_cur_length)
{
    int32_t rc = 0;

    if ((uint32_t)(i_cur_length + i_size) <= ((uint32_t)TRAC_TEMP_BUFFER_SIZE - sizeof(trace_entry_head_t)))
    {
        rc = 0;
    }
    else
    {
        //printf("We hit an error!\n");
        errno = EMSGSIZE;
        rc = -1;
    }

    return rc;
}



/**
 * trace_adal_init_buffer - create a tracebuffer and/or get a descriptor for it
 * @o_td: the descriptor for the buffer will be written to *o_td
 * @comp: the name of the buffer that should be created/looked up
 * @size: the size of the buffer, ignored if buffer exists
 */

int32_t trace_adal_init_buffer(trace_desc_t * o_td, const char *comp, const size_t size)
{
        int32_t rc = 0;
        int32_t ret2 = 0;
        char name[TRACE_MAX_COMP_NAME_SIZE];  // must point to 16 char byte name
        trace_set_buffer_t set_buffer;

        *o_td = -1; // default to invalid
        memset(name, 0, TRACE_MAX_COMP_NAME_SIZE);

        if (strlen(comp) > (TRACE_MAX_COMP_NAME_SIZE - 1)) {
                rc = TRACE_INIT_BUFF_NAME_ERR;
                strcpy(name,"BADN");
        } else {
                strcpy(name, comp);
        }

        toupper_string(name);
        set_buffer.comp = name;
        set_buffer.size = size;
        set_buffer.td = o_td;
        ret2 = ioctl(fd, TRACE_SET_BUFFER, &set_buffer);

        if (ret2 < 0) {
                /* report first error if there was one */
                if (!rc) rc = TRACE_INIT_BUFF_IOCTL_ERR;
        }

	if (*o_td <= 0) {
		/* TD idx is DEFAULT or non-existant. */
		char data_buffer[TRAC_TEMP_BUFFER_SIZE];
		trace_entry_head_t *entry = (trace_entry_head_t *)data_buffer;
		entry->tag    = TRACE_FIELDSTRING;
		entry->length = sprintf((char *)entry->args,
				"ret:%d ret2:%d o_td:%d name:%s ",
				rc, ret2, *o_td, set_buffer.comp);
		trace_adal_write(td_invalid,
				sizeof(trace_entry_head_t) + entry->length,
				TRACE_FIELD, (void *)entry);
	}

        return rc;
}



/*!
 * @brief Let device driver know that you are done tracing for this comp.
 *
 * @param td Free this trace descriptor
 *
 * @return Always return 0
 */
int32_t trace_adal_free(trace_desc_t * io_td)
{
	int32_t ret = 0;

	/* set TD to default TD */
	*io_td = TRACE_DEFAULT_TD;

	return (ret);

}

static int32_t set_config(const trace_desc_t td, const char *name,
	int32_t level, int ioctl_cmd)
{
	struct trace_set_config set_config;
	int ret;
	
	set_config.newlevel = level;
	if (name != NULL) {
		set_config.u.name = name;
	} else {
		set_config.u.td = td;
	}

	ret = ioctl(fd, ioctl_cmd, &set_config);
	if (ret < 0) {
		ret = TRACE_SETDEBUG_IOCTL_ERR;
	}
	return ret;
}


int32_t trace_adal_set_threshold(const int32_t level)
{
	return ioctl(fd, TRACE_SET_THRESHOLD, level);
}


/*!
 * @brief Turn off/on components debug traces
 *
 * @param td Assigned trace descriptor.
 * @param level If 0 only field traces will be active. If > 0 debug traces
 *              with level <= 'level' will be active.
 *
 * @return 0 for success, negative value for failure.
 * @retval #TRACE_SETDEBUG_IOCTL_ERR error from device driver, errno set
 * @retval #TRACE_SETDEBUG_INV_PARM_ERR second parm must be TRACE_DEBUG_ON or TRACE_DEBUG_OFF
 */
int32_t trace_adal_setdebug(const trace_desc_t td, const int32_t level)
{
	return set_config(td, 0, level, TRACE_SET_DEBUG);
}


/*!
 * @brief Set console level for the trace buffer specified by td
 *
 * @param td Assigned trace descriptor.
 * @param level If -1 no traces will be written to console. If 0 only field
 *              traces will be written to console. If > 0 debug traces
 *              with level <= 'level' will be written to console too.
 *              Only active debug traces will be shown on console
 *              (cf. trace_adal_setdebug).
 *
 * @return 0 for success, negative value for failure.
 * @retval #TRACE_SETDEBUG_IOCTL_ERR error from device driver, errno set
 * @retval #TRACE_SETDEBUG_INV_PARM_ERR second parm must be TRACE_DEBUG_ON or TRACE_DEBUG_OFF
 */
int32_t trace_adal_setconsole(const trace_desc_t td, const int32_t level)
{
	return set_config(td, 0, level, TRACE_SET_CONSOLE);
}


/*!
 * @brief Set pipe level for the trace buffer specified by td
 *
 * @param td Assigned trace descriptor.
 * @param level If -1 no traces will be written to pipe. If 0 only field
 *              traces will be written to pipe. If > 0 debug traces
 *              with level <= 'level' will be written to pipe too.
 *              Only active debug traces will be written to pipe
 *              (cf. trace_adal_setdebug).
 *
 * @return 0 for success, negative value for failure.
 * @retval #TRACE_SETDEBUG_IOCTL_ERR error from device driver, errno set
 * @retval #TRACE_SETDEBUG_INV_PARM_ERR second parm must be TRACE_DEBUG_ON or TRACE_DEBUG_OFF
 */
int32_t trace_adal_setpipe(const trace_desc_t td, const int32_t level)
{
	return set_config(td, 0, level, TRACE_SET_PIPE);
}

/* as above, but with buffer names */
int32_t trace_adal_setdebug_name(const char *name, const int32_t level)
{
	return set_config(0, name, level, TRACE_SET_DEBUG);
}

int32_t trace_adal_setconsole_name(const char *name, const int32_t level)
{
	return set_config(0, name, level, TRACE_SET_CONSOLE);
}

int32_t trace_adal_setpipe_name(const char *name, const int32_t level)
{
	return set_config(0, name, level, TRACE_SET_PIPE);
}

/*!
 * @brief Write a trace with the data given by "data" to the buffer specified by "td".
 *
 * @param td Assigned trace descriptor.
 * @param level Debug level (0 for field trace).
 * @param data Data to write to buffer.
 * @param size Size of data.
 *
 * @return 0 for success, negative value for failure.
 * @retval #TRACE_WRITE_IOCTL_ERR error from device driver, errno set
 */ 
int32_t trace_adal_write(const trace_desc_t i_td, const size_t i_esize,
			 const int32_t i_debug, const void *i_entry)
{
	trace_iovec_t do_traceiovec;

	do_traceiovec.base = i_entry;
	do_traceiovec.size = i_esize;
	do_traceiovec.fromuser = 1;
	
	return trace_adal_writev(i_td, i_debug, 1, &do_traceiovec);
}



/**
 * trace_adal_write2 - write a trace that consists of two data blocks
 * @i_td: a trace descirptor for the buffer where the trace should be written too
 * @i_debug: whether this is a field or debug trace
 * @i_esize: the size of the first part of the trace entry
 * @i_entry: pointer to the first part of the trace data
 * @i_datasize: the size of the second part of the trace entry
 * @i_data: pointer to the second part of the trace data
 */
int32_t trace_adal_write2(const trace_desc_t i_td, const int32_t i_debug,
                          const size_t i_esize,const void *i_entry,
                          const size_t i_datasize,const void *i_data)
{
        trace_iovec_t do_traceiovec[2];

        do_traceiovec[0].base = i_entry;
        do_traceiovec[0].size = i_esize;
        do_traceiovec[0].fromuser = 1;

        do_traceiovec[1].base = i_data;
        do_traceiovec[1].size = i_datasize;
        do_traceiovec[1].fromuser = 1;

	return trace_adal_writev(i_td, i_debug, 2, do_traceiovec);
}


/*!
 * @brief Write a trace with the data in the vector "iov" with "count" elements to the buffer 
 *	specified by "td".
 *
 * @param td Assigned trace descriptor.
 * @param level Debug level (0 for field trace).
 * @param count Items count.
 * @param iov Vector.
 *
 * @return 0 for success, negative value for failure.
 * @retval #TRACE_WRITEV_IOCTL_ERR error from device driver, errno set
 * @retval #TRACE_WRITEV_NOT_INIT trace device isn't opened, call trace_adal_init_buffer before
 */
int32_t trace_adal_writev(const trace_desc_t td, const int32_t level,
			  const size_t count, const struct trace_iovec * iov)
{
	int32_t ret = 0;
	trace_do_tracev_t do_tracev;

	do_tracev.td = td;
	// translate fsp-trace-1 debug constants to fsp-trace-2 debug level
	do_tracev.level = level;
	do_tracev.size = count * sizeof(trace_iovec_t);
	do_tracev.iovec = iov;	// must be ptr to the iovec strct.

	//printf("base[%x]  size[%d]  fromuser[%d]\n", iov->base, iov->size, iov->fromuser);   
	//print_dump(iov->base, iov->size);
	ret = ioctl(fd, TRACE_DO_TRACEV, &do_tracev);
	if (ret < 0) {
		ret = TRACE_WRITE_IOCTL_ERR;
	}
	//printf("ioctl(fd:%d, TRACE_DO_TRACEV, do_tracev:%x): ret[%d]  td[%d]  level[%d]  size[%d]\n", fd, (uint32_t)&do_tracev, ret, do_tracev.td, do_tracev.level, do_tracev.size);	
	

	return (ret);
}


/**
 * trace_adal_getbufs - get list of registered trace buffers
 * @i_lsize: size of buffer for list
 * @o_listp: memory area to write trace buffer list to
 * Description: Reads list of trace buffers. Writes a list of trace_buf_list_t
 *              entries. Returns the number of available trace buffers. If more
 *              than i_lsize buffers are available only this amount of entries
 *              are written to o_listp. It is valid to call with i_lsize=0 to
 *              the number of available buffers.
 */
int32_t trace_adal_getbufs(const size_t i_lsize, trace_buf_list_t * o_listp)
{
	int32_t ret = 0;
	trace_getbufs_t getbufs;

	TRACEF("E\n");

	getbufs.size = i_lsize;
	getbufs.list = o_listp;

	ret = ioctl(fd, TRACE_GET_BUFNAMES, &getbufs);
	if (ret < 0) {
		TRACEPE("ioctl(TRACE_GET_BUFNAMES) failed");
		ret = TRACE_GETBUFS_IOCTL_ERR;
	}

	TRACEF("L\n");
	return ret;
}



/**
 * trace_adal_getbufs - get list of registered trace buffers
 * @i_comp: name of a trace buffer
 * Description: Deletes a trace buffer.
 */
int32_t trace_adal_delete_buffer(const char *i_comp)
{
        int32_t ret = 0;
        char name[16]; /* must point to 16 char byte name */

	TRACEF("E\n");

        strcpy(name,i_comp);
        toupper_string(name);
        ret = ioctl(fd,TRACE_DELETE_BUFFER,name);
        if(ret < 0) {
                ret = TRACE_DELETE_IOCTL_ERR;
        }

	TRACEF("L\n");
        return(ret);
}



/*** trace_adal_read ***********************************************************
 *** trace_adal_read_differ ****************************************************
 * Copy the contents of tracebuffer 'comp' to buffer 'buff' with a max size of
 * 'size'.  trace_read_delta, will find the difference from the last time
 * trace_read_delta was run.
 ******************************************************************************/

inline static int32_t adal_trace_read(const char * comp, const size_t size, void * buff, unsigned long cmd)
{
	int32_t rc = 0;
	trace_read_buffer_t tracebuffer;
	char name[16];

	strncpy(name, comp, 16);
	name[15] = 0;
	toupper_string(name);

	tracebuffer.comp = name;
	tracebuffer.size = size;
	tracebuffer.data = buff;

	rc = ioctl(fd, cmd, &tracebuffer);
	if (rc < 0) rc = TRACE_READ_IOCTL_ERR;

	return rc;
}

int32_t trace_adal_read(const char * comp, const size_t size, void * buff)
{
	return adal_trace_read(comp, size, buff, TRACE_READ_BUFFER);
}

int32_t trace_adal_read_diff(const char * comp, const size_t size, void * buff)
{
	return adal_trace_read(comp, size, buff, TRACE_READ_DELTA);
}

int32_t trace_adal_read_recent(const char * comp, const size_t size, void * buff)
{
	return adal_trace_read(comp, size, buff, TRACE_READ_RECENT);
}


/**
 * trace_adal_write_ints - write a trace, data consists of a number of int values (32bit)
 * @i_td: a trace descirptor for the buffer where the trace should be written too
 * @i_debug: whether this is a field or debug trace
 * @line: source line number of trace
 * @nargs: number of int values
 * @hash: The hash/trace-id for this trace
 * @p1: the first int value
 * @p2: the second int value
 * @p3: the third int value
 * @p4: the fourth int value
 * @p5: the fifth int value
 * @p6: the sixth int value
 * @p7: the seventh int value
 * @p8: the eight int value
 * @p9: the nineth int value
 * Description: Writes a trace. Doesn't parse format string. printf args have to
 *              fit into an int (32bit). Number of int values has to be given.
 */
int32_t trace_adal_write_ints(const trace_desc_t i_td, const int32_t i_debug,
		uint32_t line, int nargs, uint32_t hash, uint32_t p1, uint32_t p2,
		uint32_t p3, uint32_t p4, uint32_t p5, uint32_t p6, uint32_t p7, 
		uint32_t p8, uint32_t p9)
{
	return trace_adal_write_ints9(i_td, ((i_debug & 0xff) << 24) | ((nargs & 0xff) << 16) | line,
		hash, p1, p2, p3, p4, p5, p6, p7,p8, p9);
}

/* function for 0..5 argument traces. on PPC upto 8 func params fit in
 * registers, this function doesn't need to put params on the stack.
 * uses ioctl directly (not adal) to reduce number of calls
 */
int32_t trace_adal_write_ints5(const trace_desc_t i_td, const uint32_t i_dln, 
		uint32_t hash, uint32_t p1, uint32_t p2,
		uint32_t p3, uint32_t p4, uint32_t p5)
{
	trace_do_tracev_t do_tracev;
	trace_iovec_t do_traceiovec;
	trace_entry_t entry;
	int32_t ret = 0;
	union {  uint32_t u;
		struct { uint8_t tag, nargs; uint16_t line; } s;
	} opt;

	opt.u = i_dln;
	entry.h.tag    = opt.s.tag ? TRACE_DEBUGTRACE : TRACE_FIELDTRACE;
	entry.h.line   = opt.s.line;
	entry.h.length = sizeof(uint32_t) * opt.s.nargs;
	entry.h.hash   = hash;
	switch(opt.s.nargs) {
		case 5: entry.args[4]= p5; /*fall through*/
		case 4: entry.args[3]= p4; /*fall through*/
		case 3: entry.args[2]= p3; /*fall through*/
		case 2: entry.args[1]= p2; /*fall through*/
		case 1: entry.args[0]= p1; /*fall through*/
		default: ;
	}

	if (i_td <= 0) {
		trace_uninited_td(i_td, opt.s.line, hash);
	}

	do_tracev.td = i_td;
	do_tracev.level = opt.s.tag;
	do_tracev.size = sizeof(trace_iovec_t);  // unless more than one
	do_tracev.iovec = &do_traceiovec;  // must be ptr to the iovec strct.

	do_traceiovec.base = (void *) &entry;
	do_traceiovec.size = sizeof(trace_entry_head_t) + entry.h.length;
	do_traceiovec.fromuser = 1;

	/* we will check validity of trace descriptor in device driver */
	ret = ioctl(fd,TRACE_DO_TRACEV,&do_tracev);
	if(ret < 0)
	{
		ret = TRACE_WRITE_IOCTL_ERR;
	}

	return(ret);
}

/* 9 parameter version version of write_ints. the last 4 will be put on the
 * stack which makes this function more expensive (slower)
 */
int32_t trace_adal_write_ints9(const trace_desc_t i_td, const uint32_t i_dln, 
		uint32_t hash, uint32_t p1, uint32_t p2,
		uint32_t p3, uint32_t p4, uint32_t p5, uint32_t p6, uint32_t p7, 
		uint32_t p8, uint32_t p9)
{
	trace_do_tracev_t do_tracev;
	trace_iovec_t do_traceiovec;
	trace_entry_t entry;
	int32_t ret = 0;
	union {  uint32_t u;
		struct { uint8_t tag, nargs; uint16_t line; } s;
	} opt;

	opt.u = i_dln;
	entry.h.tag    = opt.s.tag ? TRACE_DEBUGTRACE : TRACE_FIELDTRACE;
	entry.h.line   = opt.s.line;
	entry.h.length = sizeof(uint32_t) * opt.s.nargs;
	entry.h.hash   = hash;
	switch(opt.s.nargs) {
		case 9: entry.args[8]= p9; /*fall through*/
		case 8: entry.args[7]= p8; /*fall through*/
		case 7: entry.args[6]= p7; /*fall through*/
		case 6: entry.args[5]= p6; /*fall through*/
		case 5: entry.args[4]= p5; /*fall through*/
		case 4: entry.args[3]= p4; /*fall through*/
		case 3: entry.args[2]= p3; /*fall through*/
		case 2: entry.args[1]= p2; /*fall through*/
		case 1: entry.args[0]= p1; /*fall through*/
		default: ;
	}

	if (i_td <= 0) {
		trace_uninited_td(i_td, opt.s.line, hash);
	}

	do_tracev.td = i_td;
	do_tracev.level = opt.s.tag;
	do_tracev.size = sizeof(trace_iovec_t);  // unless more than one
	do_tracev.iovec = &do_traceiovec;  // must be ptr to the iovec strct.

	do_traceiovec.base = (void *) &entry;
	do_traceiovec.size = sizeof(trace_entry_head_t) + entry.h.length;
	do_traceiovec.fromuser = 1;

	/* we will check validity of trace descriptor in device driver */
	ret = ioctl(fd,TRACE_DO_TRACEV,&do_tracev);
	if(ret < 0)
	{
		ret = TRACE_WRITE_IOCTL_ERR;
	}

	return(ret);
}


/**
 * trace_adal_write_all - write a trace, parsing the format string for data count and types
 * @i_td: a trace descirptor for the buffer where the trace should be written too
 * @i_hash: The hash/trace-id for this trace
 * @i_fmt: the printf format string
 * @i_line: source line number of trace
 * @i_type: whether this is a field or debug trace
 * Description: Writes a trace. Parses the format string for % format specifiers to get
 *              the number and types of parameters. Supports %d,%u,%p,%x and %s.
 */
int32_t trace_adal_write_all(const trace_desc_t i_td,const trace_hash_val i_hash,
                     const char *i_fmt,
                     const uint32_t i_line, const int32_t i_type,...)
{
        va_list ap;
        uint8_t ch;
        uint32_t tmpuint;
        uint64_t tmpulong;
        int32_t longflag = 0;   /* =1 if ulonglong of long double (ll/L) */
        int32_t precision = 0;    /* Format precision */
        int32_t l_cast = 0, len;
        char *tmpcharptr = NULL;
        char data_buffer[TRAC_TEMP_BUFFER_SIZE];
        trace_entry_head_t *entry = (trace_entry_head_t *)data_buffer;
        char *wptr = (char *) (entry+1);
        int32_t ret = 0;
        trace_iovec_t do_traceiovec;
        const char *fmt_start = i_fmt;
	int32_t counter = 0;

	if (i_td <= 0) {
		trace_uninited_td(i_td, i_line, i_hash);
		return TRACE_WRITE_ALL_BAD_TD;
	}

        memset(entry,0,TRAC_TEMP_BUFFER_SIZE);

        entry->tag    = TRACE_COMP_TRACE;
        entry->line   = i_line;
        entry->length = 0;
        entry->hash = i_hash;

        va_start(ap, i_type);
        for (;;)
        {
                switch (ch = *i_fmt++)
                {
                case 0:
                    goto out;
                    break;
                case '%':
                    /* Increment past the % */
                    ch = *i_fmt++;

                    if((ch == '-') || (ch == '+'))
                    {
                            /* ignore left/right allignment */
                            ch = *i_fmt++;
                    }

                    /* Handle width for hex */
                    for (; ch >= '0' && ch <= '9'; )
                    {
                            ch = *i_fmt++;
                    } /* End for */

                    /* Skip "." and get precision  */
                    precision = 0;
                    if (ch == '.')
                    {
                            ch = *i_fmt++;
                            for (precision=0; ch >= '0' && ch <= '9'; )
                            {
                                    precision = (precision * 10) + (ch - '0');
                                    ch = *i_fmt++;
                            } /* End for */
                    }
                    if (ch == '#')
                    {
                            // ignore # formatting
                            ch = *i_fmt++;
                    }

                    /* check for "z" */
                    if (ch == 'z')
                    {
                            // handle '%zu' same as '%u' so just ignore the z
                            ch = *i_fmt++;
                    }

                    /* Check for "l" */
                    if (ch == 'l')
                    {
                            /* all 16 bit values will be cast to 32 bit by the trace
                             * functions so the 'l' flag is redundant.
                             * Check for second l (ll => 64bit) */
                            ch = *i_fmt++;
                            if (ch == 'l') {
                                    // ll -> 64bit
                                    longflag = 1;
                                    ch = *i_fmt++;
                            }
                    }

                    /* Check for "L"/"j"/"q" (64bit int or long double) */
                    if (ch == 'L' || ch == 'j' || ch == 'q')
                    {
                            longflag = 1;
                            ch = *i_fmt++;
                    }

                    /* Check for "w" */
                    if (ch == 'w')
                    {
                            ch = *i_fmt++;
                    }
                    switch (ch)
                    {
                    case 'c':
			counter++;
                        l_cast = va_arg(ap,int32_t);
                        if (trac_check_size(4, entry->length) == 0) {
                                memcpy(wptr, &l_cast, 4);
                                wptr += 4;
                                entry->length += 4;
                        } else {
                                ret = -E2BIG;
                                goto error;
                        }
                        break;
                    case 's':
			counter++;
                        tmpcharptr = va_arg(ap, char *);
                        if (tmpcharptr == NULL) {
                                /* put "NUL" into buffer (only 4 bytes!) */
                                if(trac_check_size(4, entry->length) == 0) {
                                        memcpy(wptr, "NUL", 4);
                                        wptr += 4;
                                        entry->length += 4;
                                } else {
                                        /* buffer full, not even 4 bytes fit anymore! */
                                        ret = -E2BIG;
                                        goto error;
                                }
                                break;
                        }
                        len = strnlen(tmpcharptr, precision ? precision
                                                : TRAC_TEMP_BUFFER_SIZE);
                        if (trac_check_size(len+1, entry->length) == 0) {
                                memcpy(wptr, tmpcharptr, len);
                                /* manually add terminating zero in case
                                 * precision given (%.4s, no 0 available) */
                                wptr[len++] = 0;
                                /* data size needs to be a multiple of four,
                                 * fill with 0 */
                                while(len & 3)
                                        wptr[len++] = 0;
                                wptr += len;
                                entry->length += len;
                        } else if (trac_check_size(4, entry->length) == 0) {
                                /* string is too long, store just the terminating zero */
                                *(int *) wptr = 0;
                                wptr += 4;
                                entry->length += 4;
                        } else {
                                /* buffer full, not even 4 bytes fit anymore! */
                                ret = -E2BIG;
                                goto error;
                        }
                        break;
                    case 'p': /* longflag not valid for p, but who cares? */
                    case 'd':
                    case 'i':
                    case 'x':
                    case 'X':
                    case 'u':
                    case 'o':
                        if (longflag)
                        {
                                if(trac_check_size(sizeof(uint64_t),
                                                   entry->length) == 0)
                                {
					counter++;
                                        tmpulong = va_arg(ap, uint64_t);
                                        memcpy(wptr, &tmpulong, 8);
                                        wptr += 8;
                                        entry->length += 8;
                                        break;
                                }
                        } else {
                                if(trac_check_size(sizeof(uint32_t),
                                                   entry->length) == 0)
                                {
					counter++;
                                        tmpuint = va_arg(ap, uint32_t);
                                        memcpy(wptr, &tmpuint, 4);
                                        wptr += 4;
                                        entry->length += 4;
                                        break;
                                }
                        }
                        ret = -E2BIG;
                        goto error;
                    case 'f':
                    case 'F':
                    case 'e':
                    case 'E':
                    case 'g':
                    case 'G':
                    case 'a':
                    case 'A':
			counter++;
                        /* Ignore floating point */
                        if (longflag)
                        {
                                va_arg(ap, long double);
                        }
                        else
                        {
                                va_arg(ap, double);
                        }
                        break;
                    default: {}
                    }

		    if (counter > MAX_ARGS) {
				errno = E2BIG;
				ret -= 1;
				goto error;
		    }
                    break;

                }
        }

      out:
        /* all data is now in entry */
        do_traceiovec.base = (void *) entry;
        do_traceiovec.size = sizeof(trace_entry_head_t) + entry->length;
        do_traceiovec.fromuser = 1;

        ret = trace_adal_writev(i_td, i_type == TRACE_FIELD ? TRACE_FIELD
                : TRACE_DEBUG, 1, &do_traceiovec);

        goto out2;

      error:
        entry->tag    = TRACE_FIELDSTRING;
        entry->line   = i_line;
        entry->hash   = 0;
	if (counter > MAX_ARGS) {
		entry->length = sprintf((char *) entry->args, ">>TOO MANY ARGS (max args %i, hash %u)<<",
			MAX_ARGS, i_hash);
	} else {
		entry->length = sprintf((char *) entry->args, ">>TRACE TOO BIG (max %u, at pos %ti, hash %u)<<",
			TRAC_TEMP_BUFFER_SIZE, i_fmt-fmt_start, i_hash);
	}
        trace_adal_write(i_td,(sizeof(trace_entry_head_t) + entry->length),
                TRACE_FIELD, (void *)(entry));

      out2:
        return(ret);
}


int32_t trace_adal_clear_buffs(void)
{
        int32_t rc = 0;

        rc = ioctl(fd, TRACE_CLEAR_BUFFERS, NULL);
        if (rc < 0) rc = TRACE_CLEAR_IOCTL_ERR;

        return rc;
}
