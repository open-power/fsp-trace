/*                                                                        */
/*                  OpenPOWER fsp-trace Project                           */
/* Contributors Listed Below - COPYRIGHT 2004, 2012.                      */
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

/*!
 * \file trace_adal.c
 * \brief Contains all code to interface with FSP trace device driver.
 *
 * Please see doxygen output from corresponding .h file for more information
 * on functions.
 *
 * Error handling: I print out a message if the error is found in the ADAL.
 *                 If the error is found in the device driver then the proper
 *                 error will be returned but no error message will be printed
 *                 by ADAL.  The device driver will use printk to provide more
 *                 details on these errors.  Please see trace_doc.lyx for all
 *                 possible return codes.
*/

/* Change Log *****************************************************************/
/*                                                                            */
/* ch#  Bugzilla #  Userid    Date      Description                           */
/* --- ----------  --------  --------  ---------------------------------------*/
/* n/a  n/a         andrewg  09/23/02  Created                                */
/* End Change Log *************************************************************/

/*----------------------------------------------------------------------------*/
/* Includes                                                                   */
/*----------------------------------------------------------------------------*/
/* define GUN_SOURCE for pthread_mutexattr_settype() */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "trace_adal.h"
#include <stdarg.h>
#include <stdlib.h>
/*----------------------------------------------------------------------------*/
/* Constants                                                                  */
/*----------------------------------------------------------------------------*/
#define TRAC_TEMP_BUFFER_SIZE 4096
/*----------------------------------------------------------------------------*/

#ifdef __cplusplus
extern "C" {
#endif

/*----------------------------------------------------------------------------*/
/* Globals                                                                    */
/*----------------------------------------------------------------------------*/
static const char copyright [] __attribute__((unused))
                               __attribute__((section (".comment"))) =
	"Licensed under the Apache License, Version 2.0.\n";


static int fd = -1;
/*----------------------------------------------------------------------------*/
/* Code                                                                       */
/*----------------------------------------------------------------------------*/

static int32_t trace_adal_init_fd(void)
{
        /* small window if multi-threaded: might open device twice.
         * doesn't really hurts */
        if(fd < 0) {
                /* Open the device driver */
                fd = TEMP_FAILURE_RETRY(open(TRACE_FULL_DEVICE_NAME,O_RDWR));
                if(fd < 0)
                {
                        return(TRACE_INIT_FD_ERR);
                }
        }
        return(0);

}

static inline void toupper_string(char *text)
{
        unsigned int j;
        for(j=0;j < strlen(text);j++)
        {
                text[j] = toupper(text[j]);
        }
}

static int32_t trac_check_size(int32_t i_size, uint16_t i_cur_length)
{
    int32_t ret = 0;

    if((uint32_t)(i_cur_length + i_size) <=
       ((uint32_t)TRAC_TEMP_BUFFER_SIZE - sizeof(trace_entry_head_t)))
    {
        ret = 0;
    }
    else
    {
        //printf("We hit an error!\n");
        ret = -1;
    }
    return(ret);
}

/**
 * trace_adal_init_buffer - create a tracebuffer and/or get a descriptor for it
 * @o_td: the descriptor for the buffer will be written to *o_td
 * @i_comp: the name of the buffer that should be created/looked up
 * @i_size: the size of the buffer, ignored if buffer exists
 */
int32_t trace_adal_init_buffer(trace_desc_t *o_td,const char *i_comp,
                               const size_t i_size)
{
        /*--------------------------------------------------------------------*/
        /*  Local Variables                                                   */
        /*--------------------------------------------------------------------*/
        int32_t ret = 0;
        int32_t ret2 = 0;
        char name[TRACE_MAX_COMP_NAME_SIZE];  /* must point to 16 char byte name */
        trace_set_buffer_t set_buffer;

        /*--------------------------------------------------------------------*/
        /*  Code                                                              */
        /*--------------------------------------------------------------------*/

        *o_td = -1; /* default to invalid */

        if(fd<0) { /* open trace device if not yet done */
                ret = trace_adal_init_fd();
		if (ret) return(ret);
        }

        memset(name,0,TRACE_MAX_COMP_NAME_SIZE);

        if(strlen(i_comp) > (TRACE_MAX_COMP_NAME_SIZE - 1))
        {
                ret = TRACE_INIT_BUFF_NAME_ERR;
                strcpy(name,"BADN");
        }
        else
        {
                strcpy(name,i_comp);
        }
        toupper_string(name);
        set_buffer.comp = name;
        set_buffer.size = i_size;
        set_buffer.td = o_td;
        ret2 = ioctl( fd, TRACE_SET_BUFFER,&set_buffer);
        
        if(ret2 < 0)
        {
                /* report first error if there was one */
                if(ret == 0)
                {
                        ret = TRACE_INIT_BUFF_IOCTL_ERR;
                }
        }

        return(ret);
}

/**
 * trace_adal_setdebug - set debug level for a tracebuffer
 * @i_td: descriptor of a trace buffer to set the debug level
 * @i_enable_debug: one of TRACE_DEBUG_ON or TRACE_DEBUG_OFF to enable or disable debug traces
 */
int32_t trace_adal_setdebug(const trace_desc_t i_td,
                            const int32_t i_enable_debug)
{
        /*--------------------------------------------------------------------*/
        /*  Local Variables                                                   */
        /*--------------------------------------------------------------------*/
        int32_t ret = 0;


        /*--------------------------------------------------------------------*/
        /*  Code                                                              */
        /*--------------------------------------------------------------------*/

        if(fd<0) { /* open trace device if not yet done */
                ret = trace_adal_init_fd();
		if (ret) return(ret);
        }
    	/* we will check validity of trace descriptor in device driver */

        if((i_enable_debug == TRACE_DEBUG_OFF) ||
           (i_enable_debug == TRACE_DEBUG_ON))
        {
                ret = ioctl(fd, TRACE_SET_DEBUG,&i_td,&i_enable_debug);
                if(ret < 0)
                {
                        ret = TRACE_SETDEBUG_IOCTL_ERR;
                }
        }
        else
        {
                ret = TRACE_SETDEBUG_INV_PARM_ERR;
        }
        
        return(ret);

}

/**
 * trace_adal_write - write a trace that consists of one data block
 * @i_td: a trace descirptor for the buffer where the trace should be written too
 * @i_esize: the size of the trace entry
 * @i_debug: whether this is a field or debug trace
 * @i_entry: pointer to the trace data
 */
int32_t trace_adal_write(const trace_desc_t i_td,const size_t i_esize,
                          const int32_t i_debug,const void *i_entry )
{
        return trace_adal_write2(i_td, i_debug, i_esize, i_entry, 0, 0);
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
        /*--------------------------------------------------------------------*/
        /*  Local Variables                                                   */
        /*--------------------------------------------------------------------*/
        int32_t ret = 0;
        trace_do_tracev_t do_tracev;
        trace_iovec_t do_traceiovec[2];


        /*--------------------------------------------------------------------*/
        /*  Code                                                              */
        /*--------------------------------------------------------------------*/

        if(fd<0) { /* fail if trace device not open */
                return(TRACE_WRITE_NOT_INIT);
        }
    	/* we will check validity of trace descriptor in device driver */

        do_tracev.td = i_td;
        /* translate fsp-trace-1 debug constants to fsp-trace-2 debug level */
        do_tracev.level = i_debug; // TRACE_FIELD=0 now! == TRACE_FIELD ? 0 : 1;
        do_tracev.size = 2 * sizeof(trace_iovec_t);
        do_tracev.iovec = do_traceiovec;  // must be ptr to the iovec strct.
        
        do_traceiovec[0].base = i_entry;
        do_traceiovec[0].size = i_esize;
        do_traceiovec[0].fromuser = 1;

        do_traceiovec[1].base = i_data;
        do_traceiovec[1].size = i_datasize;
        do_traceiovec[1].fromuser = 1;
        
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
        /*------------------------------------------------------------------------*/
        /*  Local Variables                                                       */
        /*------------------------------------------------------------------------*/
        va_list ap;
        uint8_t ch;
        int32_t tmpint;
        uint32_t tmpuint;
        uint64_t tmpulong;
        int32_t longflag = 0;   /* =1 if ulonglong or long double (ll/L) */
        int32_t wideflag = 0;   /* =1 if "w" specified */
        int32_t precision=0;    /* Format precision */
        int32_t width;          /* Format width */
        int32_t l_cast = 0;
        uint32_t tmp = 0;
        char *tmpcharptr = NULL;
        char data_buffer[TRAC_TEMP_BUFFER_SIZE];
        trace_entry_head_t *entry = (trace_entry_head_t *)data_buffer;
        int32_t ret = 0;
        const char *fmt_start = i_fmt;

        /*--------------------------------------------------------------------*/
        /*  Code                                                              */
        /*--------------------------------------------------------------------*/

        if(fd<0) { /* fail if trace device not open */
                return(TRACE_WRITE_NOT_INIT);
        }

        if(i_td < 0)
        {
                return(TRACE_WRITE_ALL_BAD_TD);
        }

        memset(entry,0,TRAC_TEMP_BUFFER_SIZE);

        entry->tag    = TRACE_COMP_TRACE;
        entry->line   = i_line;
        entry->length = 0;
        entry->hash = i_hash;

        va_start(ap,i_type);
        for (;;)
        {
                //printf("in the for loop....%s\n",i_fmt);
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
                    for (width=0; ch >= '0' && ch <= '9'; )
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
                                    ch = *i_fmt++;
                            } /* End for */
                    }
                    if (ch == '#')
                    {
                            // ignore # formatting
                            ch = *i_fmt++;
                    }

                    /* Check for "l" */
                    if (ch == 'l')
                    {
                            // all 16 bit values will be cast to 32 bit by the trace
                            // functions so the 'l' flag is redundant.
                            // Check for second l (ll => 64bit)
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
                            wideflag = 1;
                            ch = *i_fmt++;
                    }
                    switch (ch)
                    {
                    case 'c':
                        l_cast = va_arg(ap,int32_t);
                        if(trac_check_size(sizeof(int32_t),
                                           entry->length) == 0)
                        {
                                memcpy(&(entry->args[entry->length/4]),&l_cast,4);
                                entry->length += 4;
                        } else {
                                ret = -E2BIG;
                                goto error;
                        }
                        break;
                    case 's':
                        tmp = entry->length;
                        tmpcharptr = va_arg(ap, char *);
                        if(tmpcharptr == NULL)
                        {
                                /* NULL pointer, store "NUL" (one L to fit into 4 bytes) */
                                if(trac_check_size(strlen("NUL")+1,
                                                   entry->length) == 0)
                                {
                                        trace_adal_copy_string("NUL",&(entry->args[entry->length/4]),
                                                               (&tmp));
                                        entry->length = tmp;
                                } else {
                                        /* buffer full, not even 4 bytes fit anymore! */
                                        ret = -E2BIG;
                                        goto error;
                                }
                                break;
                        }
                        if(trac_check_size(strlen(tmpcharptr)+1,
                                           entry->length) == 0)
                        {
                                trace_adal_copy_string(tmpcharptr,&(entry->args[entry->length/4]),
                                                       (&tmp));
                                entry->length = tmp;
                        } else if (trac_check_size(4, entry->length) == 0) {
                                /* string is too long, store just the terminating zero */
                                entry->args[entry->length/4] = 0;
                                entry->length += 4;
                        } else {
                                /* buffer full, not even 4 bytes fit anymore! */
                                ret = -E2BIG;
                                goto error;
                        }
                        break;
                    case 'p':
                        tmpint = va_arg(ap, int32_t);
                        if(trac_check_size(sizeof(int32_t),
                                           entry->length) == 0)
                        {
                                memcpy(&(entry->args[entry->length/4]),&tmpint,4);
                                entry->length += 4;
                        } else {
                                ret = -E2BIG;
                                goto error;
                        }
                        break;
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
                                        tmpulong = va_arg(ap, uint64_t);
                                        memcpy(&(entry->args[entry->length/4]),&tmpulong,8);
                                        entry->length += 8;
                                        break;
                                }
                        }
                        else
                        {
                                if(trac_check_size(sizeof(uint32_t),
                                                   entry->length) == 0)
                                {
                                        tmpuint = va_arg(ap, uint32_t);
                                        memcpy(&(entry->args[entry->length/4]),&tmpuint,4);
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
                        /* Ignore floating point */
                        if (longflag)
                        {
                                double dTmp;
                                dTmp = va_arg(ap, long double);
                        }
                        else
                        {
                                float fTmp;
                                fTmp = va_arg(ap, double);
                        }
                        break;
                    default: {}
                    }
                    break;

                }
        }

    out:

        /* all data is now in entry */

        if(i_type == TRACE_FIELD)
        {
                ret = trace_adal_write(i_td,(sizeof(trace_entry_head_t) +
                                            entry->length),TRACE_FIELD,
                                      (void *)(entry));
        }
        else
        {
                ret = trace_adal_write(i_td,(sizeof(trace_entry_head_t) +
                                            entry->length),TRACE_DEBUG,
                                       (void *)(entry));
        }
        goto out2;
        
    error:
        entry->tag    = TRACE_FIELDSTRING;
        entry->line   = i_line;
        entry->length = 0;
        entry->hash   = 0;
        entry->length = sprintf((char *) entry->args, ">>TRACE TOO BIG (max %u, at pos %u, hash %u)<<",
                TRAC_TEMP_BUFFER_SIZE, i_fmt-fmt_start, i_hash);
        trace_adal_write(i_td,(sizeof(trace_entry_head_t) + entry->length),
                TRACE_FIELD, (void *)(entry));
        
    out2:
        return(ret);
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

int32_t trace_adal_write_ints5(const trace_desc_t i_td, const uint32_t i_dln, 
                              uint32_t hash, uint32_t p1, uint32_t p2,
                              uint32_t p3, uint32_t p4, uint32_t p5)
{
        /*--------------------------------------------------------------------*/
        /*  Local Variables                                                   */
        /*--------------------------------------------------------------------*/
        trace_do_tracev_t do_tracev;
        trace_iovec_t do_traceiovec;
        trace_entry_t entry;
        int32_t ret = 0;
        union {  uint32_t u;
                 struct { uint8_t tag, nargs; uint16_t line; } s;
        } opt;

        /*--------------------------------------------------------------------*/
        /*  Code                                                              */
        /*--------------------------------------------------------------------*/

        if(fd<0) { /* fail if trace device not open */
                return(TRACE_WRITE_NOT_INIT);
        }
        /* we will check validity of trace descriptor in device driver */

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

int32_t trace_adal_write_ints9(const trace_desc_t i_td, const uint32_t i_dln, 
                              uint32_t hash, uint32_t p1, uint32_t p2,
                              uint32_t p3, uint32_t p4, uint32_t p5, uint32_t p6, uint32_t p7, 
                              uint32_t p8, uint32_t p9)
{
        /*--------------------------------------------------------------------*/
        /*  Local Variables                                                   */
        /*--------------------------------------------------------------------*/
        trace_do_tracev_t do_tracev;
        trace_iovec_t do_traceiovec;
        trace_entry_t entry;
        int32_t ret = 0;
        union {  uint32_t u;
                 struct { uint8_t tag, nargs; uint16_t line; } s;
        } opt;

        /*--------------------------------------------------------------------*/
        /*  Code                                                              */
        /*--------------------------------------------------------------------*/

        if(fd<0) { /* fail if trace device not open */
                return(TRACE_WRITE_NOT_INIT);
        }
        /* we will check validity of trace descriptor in device driver */

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
 * trace_adal_free - release buffer descriptor
 * @io_td: a trace descirptor for a buffer. will be invalidated (set to TRACE_DEFAULT_TD)
 * Description: Release a buffer descriptor. Currently only sets the descriptor variable
 *              to a default value. Might do some bookkeeping in the future.
 */
int32_t trace_adal_free(trace_desc_t *io_td)
{
        /*--------------------------------------------------------------------*/
        /*  Local Variables                                                   */
        /*--------------------------------------------------------------------*/
        int32_t ret = 0;


        /*--------------------------------------------------------------------*/
        /*  Code                                                              */
        /*--------------------------------------------------------------------*/

        /* just set their trace descriptor to default */
        *io_td = TRACE_DEFAULT_TD;

        return(ret);

}

/**
 * trace_adal_read - read a trace buffer
 * @i_comp: name of a trace buffer
 * @i_size: size of output buffer
 * @o_buff: memory area to write trace buffer to
 * Description: Reads a trace buffer. If the buffer is bigger than i_size bytes
 *              an error is returned.
 */
int32_t trace_adal_read(const char *i_comp,const size_t i_size, void *o_buff)
{
        /*--------------------------------------------------------------------*/
        /*  Local Variables                                                   */
        /*--------------------------------------------------------------------*/
        int32_t ret = 0;
        trace_read_buffer_t read_buffer;
        char name[16]; /* must point to 16 char byte name */

        /*--------------------------------------------------------------------*/
        /*  Code                                                              */
        /*--------------------------------------------------------------------*/

        if(fd<0) { /* open trace device if not yet done */
                ret = trace_adal_init_fd();
		if (ret) return(ret);
        }

        strcpy(name,i_comp);
        toupper_string(name);

        read_buffer.comp = name;
        read_buffer.size = i_size;
        read_buffer.data = o_buff;

        ret = ioctl(fd,TRACE_READ_BUFFER,&read_buffer);
        if(ret < 0)
        {
                ret = TRACE_READ_IOCTL_ERR;
        }

        return(ret);
        
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
int32_t trace_adal_getbufs(const size_t i_lsize,
                           trace_buf_list_t *o_listp)
{
        /*--------------------------------------------------------------------*/
        /*  Local Variables                                                   */
        /*--------------------------------------------------------------------*/
        int32_t ret = 0;
        trace_getbufs_t getbufs;

        /*--------------------------------------------------------------------*/
        /*  Code                                                              */
        /*--------------------------------------------------------------------*/

        if(fd<0) { /* open trace device if not yet done */
                ret = trace_adal_init_fd();
		if (ret) return(ret);
        }

        getbufs.size = i_lsize;
        getbufs.list = o_listp;

        ret = ioctl(fd,TRACE_GET_BUFNAMES,&getbufs);
        if(ret < 0)
        {
                ret = TRACE_GETBUFS_IOCTL_ERR;
        }

        return(ret);

}

/**
 * trace_adal_getbufs - get list of registered trace buffers
 * @i_comp: name of a trace buffer
 * Description: Deletes a trace buffer.
 */
int32_t trace_adal_delete_buffer(const char *i_comp)
{
        /*--------------------------------------------------------------------*/
        /*  Local Variables                                                   */
        /*--------------------------------------------------------------------*/
        int32_t ret = 0;
        char name[16]; /* must point to 16 char byte name */

        /*--------------------------------------------------------------------*/
        /*  Code                                                              */
        /*--------------------------------------------------------------------*/

        if(fd<0) { /* open trace device if not yet done */
                ret = trace_adal_init_fd();
		if (ret) return(ret);
        }

        strcpy(name,i_comp);
        toupper_string(name);
        ret = ioctl(fd,TRACE_DELETE_BUFFER,name);
        if(ret < 0)
        {
                ret = TRACE_DELETE_IOCTL_ERR;
        }

        return(ret);
}

trace_hash_val trace_adal_hash(const char *i_str,const uint32_t i_key)
{
    /*------------------------------------------------------------------------*/
    /*  Local Variables                                                       */
    /*------------------------------------------------------------------------*/

    /*------------------------------------------------------------------------*/
    /*  Code                                                                  */
    /*------------------------------------------------------------------------*/

    register uint32_t l_length;
    register uint32_t l_a,l_b,l_c,l_len;

    l_c = i_key;

    //printf("str = %s, size = %d\n",i_str,strlen(i_str));

    /* Set up the internal state */
    l_len = strlen(i_str);
    l_length = l_len;


    l_a = l_b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
    //printf ("a = %d, b = %d, c = %d\n",l_a,l_b,l_c);
    /*---------------------------------------- handle most of the key */
    while (l_len >= 12)
    {
            l_a += (i_str[0] +((unsigned int)i_str[1]<<8) +
                   ((unsigned int)i_str[2]<<16) +((unsigned int)i_str[3]<<24));
            l_b += (i_str[4] +((unsigned int)i_str[5]<<8) +
                   ((unsigned int)i_str[6]<<16) +((unsigned int)i_str[7]<<24));
            l_c += (i_str[8] +((unsigned int)i_str[9]<<8) +
                   ((unsigned int)i_str[10]<<16)+((unsigned int)i_str[11]<<24));
            //printf ("a = %d, b = %d, c = %d\n",l_a,l_b,l_c);
            TRAC_HASH_MIX(l_a,l_b,l_c);
            i_str += 12; l_len -= 12;
    }
    //printf ("a = %d, b = %d, c = %d\n",l_a,l_b,l_c);
    /*------------------------------------- handle the last 11 bytes */
    l_c += l_length;
    switch(l_len)              /* all the case statements fall through */
    {
    case 11: l_c+=((unsigned int)i_str[10]<<24); /*fall through*/
    case 10: l_c+=((unsigned int)i_str[9]<<16);  /*fall through*/
    case 9 : l_c+=((unsigned int)i_str[8]<<8);   /*fall through*/
        /* the first byte of l_c is reserved for the l_length */
    case 8 : l_b+=((unsigned int)i_str[7]<<24);  /*fall through*/
    case 7 : l_b+=((unsigned int)i_str[6]<<16);  /*fall through*/
    case 6 : l_b+=((unsigned int)i_str[5]<<8);   /*fall through*/
    case 5 : l_b+=i_str[4];                      /*fall through*/
    case 4 : l_a+=((unsigned int)i_str[3]<<24);  /*fall through*/
    case 3 : l_a+=((unsigned int)i_str[2]<<16);  /*fall through*/
    case 2 : l_a+=((unsigned int)i_str[1]<<8);   /*fall through*/
    case 1 : l_a+=i_str[0];                      /*fall through*/
        /* case 0: nothing left to add */
    }
    TRAC_HASH_MIX(l_a,l_b,l_c);
    /*-------------------------------------------- report the result */
    //printf("i_str = %s, len = %d, hash = %d\n",i_str,strlen(i_str),l_c);
    return ((trace_hash_val)l_c);

}

int32_t trace_adal_copy_string(const char *i_str,void *o_loc,uint32_t *o_offset)
{
    /*------------------------------------------------------------------------*/
    /*  Local Variables                                                       */
    /*------------------------------------------------------------------------*/
    int32_t ret = 0;
    int32_t boundary;
    int32_t len;
   

    /*------------------------------------------------------------------------*/
    /*  Code                                                                  */
    /*------------------------------------------------------------------------*/
    strcpy((char *)o_loc,i_str);
    len = strlen(i_str) + 1;
    boundary = len % 4;

    if(boundary != 0)
    {
            *o_offset += len + (4 - boundary);
    }
    else
    {
            *o_offset += len;
    }
     
    return(ret);
}

int32_t trace_adal_clear_buffs(void)
{
        /*------------------------------------------------------------------------*/
        /*  Local Variables                                                       */
        /*------------------------------------------------------------------------*/
        int32_t ret = 0;


        /*------------------------------------------------------------------------*/
        /*  Code                                                                  */
        /*------------------------------------------------------------------------*/

        if(fd<0) { /* open trace device if not yet done */
                ret = trace_adal_init_fd();
		if (ret) return(ret);
        }

        ret = ioctl(fd,TRACE_CLEAR_BUFFERS,NULL);
        if(ret < 0)
        {
                ret = TRACE_CLEAR_IOCTL_ERR;
        }
        return(ret);
}
#ifdef __cplusplus
}
#endif
