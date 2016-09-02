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

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
typedef u_int32_t u32 ;
typedef u_int8_t u8 ;
#include "jhash.h"


#include "trace_adal.h"

int g_verbose_level = 0;

static const char copyright[] __attribute__ ((unused))
    __attribute__ ((section(".info"))) =
	"Licensed under the Apache License, Version 2.0.\n";


trace_hash_val trace_adal_hash(const char *i_str, const uint32_t i_key)
{
	return hashlittle(i_str,strlen(i_str),i_key);
}


// print data dump with template:
// [00000000]  00000000 00000000 00000000 00000000   *................*
void print_dump(const char *src, int len)
{

#define LINEDATALEN 16
	unsigned char databuf[LINEDATALEN];	// max len of dump line is at this time 72 chars
	unsigned char strbuf[(LINEDATALEN) + 1];
	int i, cnt = 0;
	unsigned long realaddr = 0;

	if (len <= 0) {
	return;
	}
	for (cnt = 16; (cnt - 16) < len; realaddr += 16, src += 16, cnt += 16) {
		if (cnt > len) {
			int b2c = len - (cnt - 16);

			memcpy(databuf, src, b2c);
			memcpy(strbuf, src, len - (cnt - 16));
			memset(databuf + (len - (cnt - 16)), 0, (LINEDATALEN) - (len - (cnt - 16)));
			memset(strbuf + (len - (cnt - 16)), ' ',
			       (LINEDATALEN) - (len - (cnt - 16)));
		} else {
			memset(databuf, 0, LINEDATALEN);
			memcpy(databuf, src, LINEDATALEN);
			memset(strbuf, 0, (LINEDATALEN));
			memcpy(strbuf, src, LINEDATALEN);
		}
		strbuf[LINEDATALEN] = 0;

		for (i = 0; i < LINEDATALEN; i++) {	// make strbuf printable
			if (!isprint(strbuf[i])) {
				strbuf[i] = '.';
			}
		}

		printf("^[0x%08lx] %02x%02x%02x%02x %02x%02x%02x%02x "
		       "%02x%02x%02x%02x %02x%02x%02x%02x * %s *\n",
		       realaddr, databuf[0], databuf[1], databuf[2], databuf[3],
		       databuf[4], databuf[5], databuf[6], databuf[7],
		       databuf[8], databuf[9], databuf[10], databuf[11],
		       databuf[12], databuf[13], databuf[14], databuf[15], strbuf);
	}
}
