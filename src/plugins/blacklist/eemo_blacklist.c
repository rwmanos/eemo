/* $Id$ */

/*
 * Copyright (c) 2010-2011 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of SURFnet bv nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * The Extensible Ethernet Monitor (EEMO)
 */

#include "config.h"
#include "eemo.h"
#include "eemo_log.h"
#include "eemo_blacklist.h"
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include "uthash.h"
#include "dns_parser.c"

/* This is a structure that can be hashed,
 * it is used to store blacklisted elements */
struct hashstructure
{
	char *hashelement;
	UT_hash_handle hh;         /* makes this structure hashable */
};

/* Configuration */
int	blacklist_mod    = 0;
char*	logging_file_name		= NULL;
FILE*	logging_file			= NULL;
struct	hashstructure *hashtable 	= NULL;    /* important! initialize the HASH TABLE */
int	testcount 			= 0;
char*	temp_answer			= NULL;

/* Convert the rdata of a DNS answer that contains an IP address to string. */
void qtypeA_to_string ( eemo_dns_rr* rr, char* rv )
{
	snprintf ( rv, 16, "%d.%d.%d.%d",
	           ( * ( ( unsigned int* ) rr->rdata ) & 0xff000000 ) >> 24,
	           ( * ( ( unsigned int* ) rr->rdata ) & 0x00ff0000 ) >> 16,
	           ( * ( ( unsigned int* ) rr->rdata ) & 0x0000ff00 ) >> 8,
	           ( * ( ( unsigned int* ) rr->rdata ) & 0x000000ff ) );
}

/* Initialize the module */
short eemo_blacklist_initialize ( int temp_blacklist_mod, char* blacklist_file_name, char* temp_logging_file_name )
{
	// Variables used to read and load the blacklist file.
	FILE * blacklist_file 	= NULL;
	char * line 		= NULL;
	size_t line_length 	= 0;
	ssize_t read;

	logging_file_name = temp_logging_file_name;
	blacklist_mod = temp_blacklist_mod;

	/* If an IP-based blacklist is used, a variable to temporarily store
	 * the IP address of every DNS answer in needed. */
	if ( blacklist_mod == 1 )
	{
		temp_answer = ( char* ) malloc ( 16 * sizeof ( char ) ); /* 4x 3 digits + 3x '.' + \0 */
	}

	// Open the log file.
	logging_file = fopen ( logging_file_name, "w" );
	if ( logging_file == NULL )
	{
		ERROR_MSG ( "Failed to open '%s' for writing", logging_file_name );
		return 0;
	}
	INFO_MSG ( "Writing infected nodes to: '%s'", logging_file_name );

	// Open the file that contains the malicious elements.
	blacklist_file = fopen ( blacklist_file_name, "r" );
	if ( blacklist_file == NULL )
	{
		ERROR_MSG ( "Failed to open '%s' for reading", blacklist_file_name );
		return 0;
	}

	// Total number of loaded blacklisted elements.
	int sum_loaded_elements = 0;

	// Read the file and insert the malicious elements to the hash table.
	while ( ( read = getline ( &line, &line_length, blacklist_file ) ) != -1 )
	{
		// Remove the newline character at the end of each line.
		line[strcspn ( line, "\r\n" )] = 0;

		// Allocate memory for each element.
		char *tempelement;
		tempelement = ( char * ) malloc ( sizeof ( char ) * line_length );
		strncpy ( tempelement, line, line_length );

		// Check if the value is already inserted in the hash table.
		struct hashstructure *s;
		HASH_FIND_STR ( hashtable, tempelement, s );
		if ( s != NULL )
		{
			ERROR_MSG ( "collision between '%s' AND '%s'", line, s->hashelement );
			ERROR_MSG ( "Verify that '%s' does not contain dublicate entries", blacklist_file_name );
			/* blacklists regularly do not contain duplicate entries and the file might
			 * be corrupted. However, the termination can be safely removed. */
			return 0;
		}
		else
		{
			// Insert the blacklisted element to the hash table.
			struct hashstructure *d;
			d = ( struct hashstructure* ) malloc ( sizeof ( struct hashstructure ) );
			d->hashelement = tempelement;
			HASH_ADD_KEYPTR ( hh, hashtable, d->hashelement, strlen ( d->hashelement ), d );

			sum_loaded_elements++;
		}
	}

	// Verify that the file is still open and close it.
	if ( blacklist_file == NULL )
	{
		ERROR_MSG ( "File '%s' has closed unexpectedly", blacklist_file_name );
		return 0;
	}
	fclose ( blacklist_file );
	INFO_MSG ( "%d blacklisted elements were loaded successfully", sum_loaded_elements );
	return 1;
}

/* Uninitialize the DNS query counter module */
void eemo_blacklist_uninitialize ( eemo_conf_free_string_array_fn free_strings )
{
	fprintf ( logging_file, "Total inspected packets: %d\n", testcount );

	// Verify that the file is still open and close it.
	if ( logging_file == NULL )
	{
		ERROR_MSG ( "File '%s' has closed unexpectedly", logging_file_name );
	}
	fclose ( logging_file );

	// Free the memory of the hash table.
	struct hashstructure *current, *tmp;
	HASH_ITER ( hh, hashtable, current, tmp )
	{
		HASH_DEL ( hashtable, current ); /* delete it (users advances to next) */
		free ( current->hashelement );
		free ( current );
	}
	free ( logging_file_name );
	free ( temp_answer );
}

/* Handle DNS query packets and log the blacklisted elements*/
eemo_rv eemo_blacklist_handleqr ( eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* dns_packet )
{
	testcount++;

	// Check if the packet is a query and
	if ( !dns_packet->qr_flag )
	{
		// Verify that a domain-based blacklist is used.
		if ( blacklist_mod == 0 )
		{
			// Validate the packet
			if ( !dns_packet->is_valid )
			{
				return ERV_SKIPPED;
			}

			if ( logging_file == NULL )
			{
				ERROR_MSG ( "File '%s' has closed unexpectedly", logging_file_name );
			}

			// Iterate for every requested domain in the query.
			eemo_dns_query* query_it = NULL;
			LL_FOREACH ( dns_packet->questions, query_it )
			{
				// Check if the domain is in the blacklist.
				struct hashstructure *s; // s: output pointer
				HASH_FIND_STR ( hashtable, query_it->qname, s );
				if ( s != NULL )
				{
					fprintf ( logging_file, "query for blacklisted domain: %s , from %s\n", query_it->qname, ip_info.ip_src );
					break;
				}
				//fflush(logging_file);
			}
		}
	}
	else
	{
		// Verify that an IP-based blacklist is used.
		if ( blacklist_mod == 1 )
		{
			// Validate the packet
			if ( !dns_packet->is_valid )
			{
				return ERV_SKIPPED;
			}

			if ( logging_file == NULL )
			{
				ERROR_MSG ( "File '%s' has closed unexpectedly", logging_file_name );
			}

			if ( dns_packet->answers != NULL )
			{
				// Iterate for every RR in the DNS answer.
				eemo_dns_rr* temp_rr;
				LL_FOREACH ( dns_packet->answers, temp_rr )
				{
					if ( temp_rr->type == DNS_QTYPE_A )
					{
						struct hashstructure *s; // s: output pointer
						temp_answer[0] = '\0';
						qtypeA_to_string ( temp_rr, temp_answer );
						if ( temp_answer[0] == '\0' )
						{
							DEBUG_MSG ( "Answer is empty" );
						}
						else
						{
							// Check if the IP is in the blacklist.
							HASH_FIND_STR ( hashtable, temp_answer, s );
							if ( s != NULL )
							{
								fprintf ( logging_file, "query for blacklisted IP: \"%s\", from: \"%s\"\n", temp_answer, ip_info.ip_src );
								DEBUG_MSG ( "Malicious answer: \"%s\"", temp_answer );
							}
						}
					}
				}
				//fflush(logging_file);
			}
		}
	}
	return ERV_HANDLED;
}

