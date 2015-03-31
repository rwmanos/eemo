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

/* This is a structure that can be hashed,
 * it is used to store blacklisted domains */
struct domainhash
{
	const char *domainname;
	UT_hash_handle hh;         /* makes this structure hashable */
};

/* Configuration */
char*	logging_file_name		= NULL;
FILE*	logging_file			= NULL;
struct 	domainhash *domainhashtable 	= NULL;    /* important! initialize the HASH TABLE */
int 	testcount 			= 0;


/* Initialize the module */
short eemo_blacklist_initialize ( char* blacklist_file_name, char* temp_logging_file_name )
{
	// Variables used to read and load blacklist file
	FILE * blacklist_file 	= NULL;
	char * line 		= NULL;
	size_t len 		= 0;
	ssize_t read;

	logging_file_name = temp_logging_file_name;

	// Open the log file.
	logging_file = fopen ( logging_file_name, "w" );
	if ( logging_file == NULL )
	{
		ERROR_MSG ( "Failed to open %s for writing", logging_file_name );
		return 0;
	}
	INFO_MSG ( "Writing infected nodes to: %s", logging_file_name );

	// Total number of loaded domains.
	int sum_loaded_domains = 0;

	// Open the file that contains the malicious domains.
	blacklist_file = fopen ( blacklist_file_name, "r" );
	if ( blacklist_file == NULL )
	{
		ERROR_MSG ( "Failed to open %s for reading", blacklist_file_name );
		return 0;
	}

	// Read the file and insert the malicious domains to the hash table.
	while ( ( read = getline ( &line, &len, blacklist_file ) ) != -1 ) {

		// Remove the newline character at the end of each line.
		line[strcspn ( line, "\r\n" )] = 0;

		// Allocate memory for each domain name.
		char *tempdomain;
		tempdomain = ( char * ) malloc ( sizeof ( char ) * len );
		strncpy ( tempdomain, line, len );

		// Check if the value is already inserted in the hash table.
		struct domainhash *s;
		HASH_FIND_STR ( domainhashtable, tempdomain, s );
		if ( s != NULL ) {
			ERROR_MSG ( "collision between %s AND %s", line, s->domainname );
			ERROR_MSG ( "Verify that '%s' does not contain dublicate entries" );
			return 0;
		}

		// Insert the domain name to the hash table.
		struct domainhash *d;
		d = ( struct domainhash* ) malloc ( sizeof ( struct domainhash ) );
		d->domainname = tempdomain;
		HASH_ADD_KEYPTR ( hh, domainhashtable, d->domainname, strlen ( d->domainname ), d );

		//
		sum_loaded_domains++;
	}

	// Verify that the file is still open and close it.
	if ( blacklist_file == NULL ) {
		ERROR_MSG ( "File '%s' has closed unexpectedly", blacklist_file_name );
		return 0;
	}
	fclose ( blacklist_file );
	INFO_MSG ( "%d blacklisted domains were loaded successfully", sum_loaded_domains );
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
	struct domainhash *current, *tmp;
	HASH_ITER ( hh, domainhashtable, current, tmp ) {
		HASH_DEL ( domainhashtable, current ); /* delete it (users advances to next) */
		free ( current );
	}
	free ( logging_file_name );
}

/* Handle DNS query packets and log the blacklisted domain*/
eemo_rv eemo_blacklist_handleqr ( eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* dns_packet )
{
	eemo_dns_query* query_it = NULL;

	// Check if the packet is a query.
	if ( !dns_packet->qr_flag )
	{
		// Validate the packet
		if ( !dns_packet->is_valid )
		{
			return ERV_SKIPPED;
		}
		testcount++;

		if ( logging_file == NULL )
			ERROR_MSG ( "File '%s' has closed unexpectedly", logging_file_name );
		// This should return an error.

		// Iterate for every requested domain in the query.
		LL_FOREACH ( dns_packet->questions, query_it )
		{
			// Check if the domain is in the blacklist.
			struct domainhash *s; // s: output pointer
			HASH_FIND_STR ( domainhashtable, query_it->qname, s );
			if ( s != NULL )
			{
				fprintf ( logging_file, "query for blacklisted domain: %s , from %s\n", query_it->qname, ip_info.ip_src );
				break;
			}
			//fflush(logging_file);
		}
	}
	return ERV_HANDLED;
}

