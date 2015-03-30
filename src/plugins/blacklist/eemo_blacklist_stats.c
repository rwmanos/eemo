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
#include "eemo_blacklist_stats.h"
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include "uthash.h"

/* This is a structure that can be hashed,
 * it is used to store blacklisted domains */
struct domainhash
{
	char domainname[DOMAINLENGTH]; 
	UT_hash_handle hh;         /* makes this structure hashable */
};

/* Configuration */
char** 	stat_ips 		= NULL;
int 	stat_ipcount 		= 0;
char*	log_file		= NULL;
int	stat_append		= 0;
int	stat_reset		= 1;
struct 	domainhash *domainhashtable = NULL;    /* important! initialize the HASH TABLE */
int 	testcount 		= 0;
/* Statistics file */
FILE*	stat_fp			= NULL;

/* Signal handler for alarms & user signals */
void signal_handler(int signum)
{
	if (signum == SIGUSR1)
	{
		DEBUG_MSG("Received user signal");
	}
	else if (signum == SIGALRM)
	{
		DEBUG_MSG("Received automated alarm");
	}
	
	/* Set the new alarm if necessary */
	if (signum == SIGALRM)
	{
		//alarm(stat_emit_interval);
	}
}

/* Initialise the DNS query counter module */
void eemo_blacklist_stats_init(char** ips, int ipcount, char* blacklist_file, int emit_interval, char* stats_file, int append_file, int reset)
{
	int i = 0;

	// Variables used to read and load blacklist file
	FILE * loadblacklist;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	stat_ips = ips;
	stat_ipcount = ipcount;
	//stat_blacklist = blacklist;
	//stat_blacklistcount = blacklistcount;

	INFO_MSG("Listening to %d IP addresses", stat_ipcount);

	for (i = 0; i < stat_ipcount; i++)
	{
		INFO_MSG("Listening for queries to IP %s", ips[i]);
	}

	//stat_emit_interval = emit_interval;
	//INFO_MSG("Signal every %d seconds", emit_interval);

	log_file = stats_file;

	INFO_MSG("Writing infections to the file called %s", log_file);

	stat_append = append_file;

	//INFO_MSG("Will %soverwrite the file when new statistics are available", stat_append ? "not " : "");

	stat_reset = reset;

	//INFO_MSG("Will %sreset statistics once they have been written to file", stat_reset ? "" : "not ");

	stat_fp = fopen(log_file, "w");

	if (stat_fp != NULL)
	{
		INFO_MSG("Opened file: %s ", log_file);
	}
	else
	{
		ERROR_MSG("Failed to open %s for writing", log_file);
	}
	
	// Open the file that contains the malicious domains
	loadblacklist = fopen(blacklist_file, "r");

	int sum_loaded_domains = 0;
	if (loadblacklist != NULL)
	{
		while ((read = getline(&line, &len, loadblacklist)) != -1) {
			sum_loaded_domains++;
			//printf("Retrieved line of length %zu :\n", read);
			//printf("%s", line);

			// Remove the newline character at the end of each line.
			line[strcspn(line, "\r\n")] = 0;

			// Check if the value is already inserted in the hash table. 
			struct domainhash *s;
			HASH_FIND_STR( domainhashtable, line, s);
			if (s != NULL)	
				ERROR_MSG("collision between %s AND %s", line, s->domainname);
			
			// Add the domain to the hash table.
			struct domainhash *d;
			d = (struct domainhash*) malloc(sizeof(struct domainhash));
			strncpy(d->domainname, line, DOMAINLENGTH-1);
			d->domainname[DOMAINLENGTH-1] = '\0'; // just in case that len > DOMAINLENGTH
			HASH_ADD_STR( domainhashtable, domainname, d);  /* domainname: name of key field */
		}
		INFO_MSG("%d blacklisted domains were loaded", sum_loaded_domains);
	}
	else
	{
		ERROR_MSG("Failed to open %s for reading", blacklist_file);
	}
	
	/* Register signal handler */
	signal(SIGUSR1, signal_handler);
	signal(SIGALRM, signal_handler);

	/* Set the alarm */
	//alarm(stat_emit_interval);
}

/* Uninitialise the DNS query counter module */
void eemo_blacklist_stats_uninit(eemo_conf_free_string_array_fn free_strings)
{
	/* Unregister signal handlers */
	alarm(0);
	signal(SIGUSR1, SIG_DFL);
	signal(SIGALRM, SIG_DFL);
	

	fprintf(stat_fp, "Total inspected packets: %d\n", testcount);
	/* Close the file */
	if (stat_fp != NULL)
	{
		fclose(stat_fp);
		DEBUG_MSG("Closed %s", log_file);
	}
	else
	{
		INFO_MSG("File %s was not open", log_file);
	}

	// Free the memory of the hash table.
	struct domainhash *current, *tmp;
	HASH_ITER(hh, domainhashtable, current, tmp) {
		HASH_DEL(domainhashtable, current);  /* delete it (users advances to next) */
		free(current);            /* free it */
	}

	(free_strings)(stat_ips, stat_ipcount);
	free(log_file);
}

/* Handle DNS query packets and log the blacklisted domain*/
eemo_rv eemo_blacklist_stats_handleqr(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* dns_packet)
{
	eemo_dns_query* query_it = NULL;

	if (!dns_packet->qr_flag)
	{
		/* This is a query */

		/* Count only valid queries */
		if (!dns_packet->is_valid)
		{
			return ERV_SKIPPED;
		}
		testcount++;

		struct domainhash *s;
		if (stat_fp == NULL)
			ERROR_MSG("Failed to open %s for writing", log_file);

		// Iterate for every requested domain in the query.
		LL_FOREACH(dns_packet->questions, query_it)
		{
			// Check if the domain is in the blacklist.
			HASH_FIND_STR( domainhashtable, query_it->qname, s );  /* s: output pointer */
			if (s != NULL) 
			{
				fprintf(stat_fp, "query for blacklisted domain: %s , from %s\n", query_it->qname, ip_info.ip_src);
			} 
			fflush(stat_fp);
		}
	}
	return ERV_HANDLED;
}

