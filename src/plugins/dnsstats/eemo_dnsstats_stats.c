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
 * DNS statistics plug-in query counter code
 */

#include "config.h"
#include "eemo.h"
#include "eemo_log.h"
#include "eemo_dnsstats_stats.h"
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#define IP_ANY	"*"

/* The counters */

/* Query classes */
struct
{
	unsigned long long IN;
	unsigned long long CS;
	unsigned long long CH;
	unsigned long long HS;
	unsigned long long ANY;
	unsigned long long UNSPECIFIED;
	unsigned long long UNKNOWN;
}
qclass_ctr;

/* Query types */
struct
{
	unsigned long long UNSPECIFIED;
	unsigned long long A;
	unsigned long long AAAA;
	unsigned long long AFSDB;
	unsigned long long APL;
	unsigned long long CERT;
	unsigned long long CNAME;
	unsigned long long DHCID;
	unsigned long long DLV;
	unsigned long long DNAME;
	unsigned long long DNSKEY;
	unsigned long long DS;
	unsigned long long HIP;
	unsigned long long IPSECKEY;
	unsigned long long KEY;
	unsigned long long KX;
	unsigned long long LOC;
	unsigned long long MX;
	unsigned long long NAPTR;
	unsigned long long NS;
	unsigned long long NSEC;
	unsigned long long NSEC3;
	unsigned long long NSEC3PARAM;
	unsigned long long PTR;
	unsigned long long RRSIG;
	unsigned long long RP;
	unsigned long long SIG;
	unsigned long long SOA;
	unsigned long long SPF;
	unsigned long long SRV;
	unsigned long long SSHFP;
	unsigned long long TA;
	unsigned long long TKEY;
	unsigned long long TSIG;
	unsigned long long TXT;
	unsigned long long ANY;
	unsigned long long AXFR;
	unsigned long long IXFR;
	unsigned long long OPT;
	unsigned long long UNKNOWN;
}
qtype_ctr;

/* IP types */
struct
{
	unsigned long long V4;
	unsigned long long V6;
}
iptype_ctr;

/* Transmission protocol types */
struct
{
	unsigned long long UDP;
	unsigned long long TCP;
}
proto_ctr;

/* EDNS0 */
struct
{
	unsigned long long EDNS0_NO;
	unsigned long long EDNS0_BELOW_512;
	unsigned long long EDNS0_512_TO_999;
	unsigned long long EDNS0_1000_TO_1499;
	unsigned long long EDNS0_1500_TO_1999;
	unsigned long long EDNS0_2000_TO_2499;
	unsigned long long EDNS0_2500_TO_2999;
	unsigned long long EDNS0_3000_TO_3499;
	unsigned long long EDNS0_3500_TO_3999;
	unsigned long long EDNS0_4000_TO_4499;
	unsigned long long EDNS0_ABOVE_4500;
	unsigned long long EDNS0_DO_SET;
	unsigned long long EDNS0_DO_UNSET;
}
edns0_ctr;

/* Configuration */
char** 	stat_ips 		= NULL;
int 	stat_ipcount 		= 0;
int	stat_emit_interval	= 0;
char*	stat_file		= NULL;
int	stat_append		= 0;
int	stat_reset		= 1;

/* Statistics file */
FILE*	stat_fp			= NULL;

/* Signal handler for alarms & user signals */
void signal_handler(int signum)
{
	unsigned long long EDNS0_TOTAL 		= 0;
	unsigned long long EDNS0_PCT_ON 	= 0;
	unsigned long long EDNS0_PCT_OFF	= 0;
	unsigned long long EDNS0_PCT_LT_512	= 0;
	unsigned long long EDNS0_PCT_512_999	= 0;
	unsigned long long EDNS0_PCT_1000_1499	= 0;
	unsigned long long EDNS0_PCT_1500_1999	= 0;
	unsigned long long EDNS0_PCT_2000_2499	= 0;
	unsigned long long EDNS0_PCT_2500_2999	= 0;
	unsigned long long EDNS0_PCT_3000_3499	= 0;
	unsigned long long EDNS0_PCT_3500_3999	= 0;
	unsigned long long EDNS0_PCT_4000_4499	= 0;
	unsigned long long EDNS0_PCT_GT_4500	= 0;
	unsigned long long EDNS0_PCT_DO_SET	= 0;
	unsigned long long EDNS0_PCT_DO_UNSET	= 0;
	unsigned long long QUERY_TOTAL		= 0;

	if (signum == SIGUSR1)
	{
		DEBUG_MSG("Received user signal to dump statistics");
	}
	else if (signum == SIGALRM)
	{
		DEBUG_MSG("Received automated alarm to dump statistics");
	}

	/* Open the file for writing if necessary */
	if (!stat_append)
	{
		stat_fp = fopen(stat_file, "w");
	}

	if (stat_fp != NULL)
	{
		/* Calculate the EDNS0 percentages */
		EDNS0_TOTAL =	edns0_ctr.EDNS0_BELOW_512 +
				edns0_ctr.EDNS0_512_TO_999 +
				edns0_ctr.EDNS0_1000_TO_1499 +
				edns0_ctr.EDNS0_1500_TO_1999 +
				edns0_ctr.EDNS0_2000_TO_2499 +
				edns0_ctr.EDNS0_2500_TO_2999 +
				edns0_ctr.EDNS0_3000_TO_3499 +
				edns0_ctr.EDNS0_3500_TO_3999 +
				edns0_ctr.EDNS0_4000_TO_4499 +
				edns0_ctr.EDNS0_ABOVE_4500;
		
		QUERY_TOTAL =	iptype_ctr.V4 + iptype_ctr.V6;

		EDNS0_PCT_ON		= (EDNS0_TOTAL * 100) 			/ QUERY_TOTAL;
		EDNS0_PCT_OFF		= ((QUERY_TOTAL - EDNS0_TOTAL) * 100) 	/ QUERY_TOTAL;
		EDNS0_PCT_LT_512	= (edns0_ctr.EDNS0_BELOW_512 * 100)	/ EDNS0_TOTAL;
		EDNS0_PCT_512_999	= (edns0_ctr.EDNS0_512_TO_999 * 100)	/ EDNS0_TOTAL;
		EDNS0_PCT_1000_1499	= (edns0_ctr.EDNS0_1000_TO_1499 * 100)	/ EDNS0_TOTAL;
		EDNS0_PCT_1500_1999	= (edns0_ctr.EDNS0_1500_TO_1999 * 100)	/ EDNS0_TOTAL;
		EDNS0_PCT_2000_2499	= (edns0_ctr.EDNS0_2000_TO_2499 * 100)	/ EDNS0_TOTAL;
		EDNS0_PCT_2500_2999	= (edns0_ctr.EDNS0_2500_TO_2999 * 100)	/ EDNS0_TOTAL;
		EDNS0_PCT_3000_3499	= (edns0_ctr.EDNS0_3000_TO_3499 * 100)	/ EDNS0_TOTAL;
		EDNS0_PCT_3500_3999	= (edns0_ctr.EDNS0_3500_TO_3999 * 100)	/ EDNS0_TOTAL;
		EDNS0_PCT_4000_4499	= (edns0_ctr.EDNS0_4000_TO_4499 * 100)	/ EDNS0_TOTAL;
		EDNS0_PCT_GT_4500	= (edns0_ctr.EDNS0_ABOVE_4500 * 100)	/ EDNS0_TOTAL;
		EDNS0_PCT_DO_SET	= (edns0_ctr.EDNS0_DO_SET * 100)	/ EDNS0_TOTAL;
		EDNS0_PCT_DO_UNSET	= (edns0_ctr.EDNS0_DO_UNSET * 100)	/ EDNS0_TOTAL;

		/* Write the statistics to the file */
		fprintf(stat_fp, ""
		"qclass_ctr_UNSPECIFIED:%llu "
		"qclass_ctr_IN:%llu "
		"qclass_ctr_CS:%llu "
		"qclass_ctr_CH:%llu "
		"qclass_ctr_HS:%llu "
		"qclass_ctr_ANY:%llu "
		"qclass_ctr_UNKNOWN:%llu "
		"qtype_ctr_UNSPECIFIED:%llu "
		"qtype_ctr_A:%llu "
		"qtype_ctr_AAAA:%llu "
		"qtype_ctr_AFSDB:%llu "
		"qtype_ctr_APL:%llu "
		"qtype_ctr_CERT:%llu "
		"qtype_ctr_CNAME:%llu "
		"qtype_ctr_DHCID:%llu "
		"qtype_ctr_DLV:%llu "
		"qtype_ctr_DNAME:%llu "
		"qtype_ctr_DNSKEY:%llu "
		"qtype_ctr_DS:%llu "
		"qtype_ctr_HIP:%llu "
		"qtype_ctr_IPSECKEY:%llu "
		"qtype_ctr_KEY:%llu "
		"qtype_ctr_KX:%llu "
		"qtype_ctr_LOC:%llu "
		"qtype_ctr_MX:%llu "
		"qtype_ctr_NAPTR:%llu "
		"qtype_ctr_NS:%llu "
		"qtype_ctr_NSEC:%llu "
		"qtype_ctr_NSEC3:%llu "
		"qtype_ctr_NSEC3PARAM:%llu "
		"qtype_ctr_PTR:%llu "
		"qtype_ctr_RRSIG:%llu "
		"qtype_ctr_RP:%llu "
		"qtype_ctr_SIG:%llu "
		"qtype_ctr_SOA:%llu "
		"qtype_ctr_SPF:%llu "
		"qtype_ctr_SRV:%llu "
		"qtype_ctr_SSHFP:%llu "
		"qtype_ctr_TA:%llu "
		"qtype_ctr_TKEY:%llu "
		"qtype_ctr_TSIG:%llu "
		"qtype_ctr_TXT:%llu "
		"qtype_ctr_ANY:%llu "
		"qtype_ctr_AXFR:%llu "
		"qtype_ctr_IXFR:%llu "
		"qtype_ctr_OPT:%llu "
		"qtype_ctr_UNKNOWN:%llu "
		"iptype_ctr_V4:%llu "
		"iptype_ctr_V6:%llu "
		"proto_ctr_TCP:%llu "
		"proto_ctr_UDP:%llu "
		"edns0_ctr_EDNS0_NO:%llu "
		"edns0_ctr_EDNS0_BELOW_512:%llu "
		"edns0_ctr_EDNS0_512_TO_999:%llu "
		"edns0_ctr_EDNS0_1000_TO_1499:%llu "
		"edns0_ctr_EDNS0_1500_TO_1999:%llu "
		"edns0_ctr_EDNS0_2000_TO_2499:%llu "
		"edns0_ctr_EDNS0_2500_TO_2999:%llu "
		"edns0_ctr_EDNS0_3000_TO_3499:%llu "
		"edns0_ctr_EDNS0_3500_TO_3999:%llu "
		"edns0_ctr_EDNS0_4000_TO_4499:%llu "
		"edns0_ctr_EDNS0_ABOVE_4500:%llu "
		"edns0_ctr_EDNS0_DO_SET:%llu "
		"edns0_ctr_EDNS0_DO_UNSET:%llu "
		"EDNS0_TOTAL:%llu "
		"EDNS0_PCT_ON:%llu "
		"EDNS0_PCT_OFF:%llu "
		"EDNS0_PCT_LT_512:%llu "
		"EDNS0_PCT_512_999:%llu "
		"EDNS0_PCT_1000_1499:%llu "
		"EDNS0_PCT_1500_1999:%llu "
		"EDNS0_PCT_2000_2499:%llu "
		"EDNS0_PCT_2500_2999:%llu "
		"EDNS0_PCT_3000_3499:%llu "
		"EDNS0_PCT_3500_3999:%llu "
		"EDNS0_PCT_4000_4499:%llu "
		"EDNS0_PCT_GT_4500:%llu "
		"EDNS0_PCT_DO_SET:%llu "
		"EDNS0_PCT_DO_UNSET:%llu "
		"QUERY_TOTAL:%llu\n",
		qclass_ctr.UNSPECIFIED,
		qclass_ctr.IN,
		qclass_ctr.CS,
		qclass_ctr.CH,
		qclass_ctr.HS,
		qclass_ctr.ANY,
		qclass_ctr.UNKNOWN,
		qtype_ctr.UNSPECIFIED,
		qtype_ctr.A,
		qtype_ctr.AAAA,
		qtype_ctr.AFSDB,
		qtype_ctr.APL,
		qtype_ctr.CERT,
		qtype_ctr.CNAME,
		qtype_ctr.DHCID,
		qtype_ctr.DLV,
		qtype_ctr.DNAME,
		qtype_ctr.DNSKEY,
		qtype_ctr.DS,
		qtype_ctr.HIP,
		qtype_ctr.IPSECKEY,
		qtype_ctr.KEY,
		qtype_ctr.KX,
		qtype_ctr.LOC,
		qtype_ctr.MX,
		qtype_ctr.NAPTR,
		qtype_ctr.NS,
		qtype_ctr.NSEC,
		qtype_ctr.NSEC3,
		qtype_ctr.NSEC3PARAM,
		qtype_ctr.PTR,
		qtype_ctr.RRSIG,
		qtype_ctr.RP,
		qtype_ctr.SIG,
		qtype_ctr.SOA,
		qtype_ctr.SPF,
		qtype_ctr.SRV,
		qtype_ctr.SSHFP,
		qtype_ctr.TA,
		qtype_ctr.TKEY,
		qtype_ctr.TSIG,
		qtype_ctr.TXT,
		qtype_ctr.ANY,
		qtype_ctr.AXFR,
		qtype_ctr.IXFR,
		qtype_ctr.OPT,
		qtype_ctr.UNKNOWN,
		iptype_ctr.V4,
		iptype_ctr.V6,
		proto_ctr.TCP,
		proto_ctr.UDP,
		edns0_ctr.EDNS0_NO,
		edns0_ctr.EDNS0_BELOW_512,
		edns0_ctr.EDNS0_512_TO_999,
		edns0_ctr.EDNS0_1000_TO_1499,
		edns0_ctr.EDNS0_1500_TO_1999,
		edns0_ctr.EDNS0_2000_TO_2499,
		edns0_ctr.EDNS0_2500_TO_2999,
		edns0_ctr.EDNS0_3000_TO_3499,
		edns0_ctr.EDNS0_3500_TO_3999,
		edns0_ctr.EDNS0_4000_TO_4499,
		edns0_ctr.EDNS0_ABOVE_4500,
		edns0_ctr.EDNS0_DO_SET,
		edns0_ctr.EDNS0_DO_UNSET,
		EDNS0_TOTAL, 
		EDNS0_PCT_ON, 
		EDNS0_PCT_OFF, 
		EDNS0_PCT_LT_512, 
		EDNS0_PCT_512_999, 
		EDNS0_PCT_1000_1499, 
		EDNS0_PCT_1500_1999, 
		EDNS0_PCT_2000_2499, 
		EDNS0_PCT_2500_2999, 
		EDNS0_PCT_3000_3499, 
		EDNS0_PCT_3500_3999, 
		EDNS0_PCT_4000_4499, 
		EDNS0_PCT_GT_4500, 
		EDNS0_PCT_DO_SET, 
		EDNS0_PCT_DO_UNSET, 
		QUERY_TOTAL);

		fflush(stat_fp);

		/* Reset the statistics if necessary */
		if (stat_reset)
		{
			eemo_dnsstats_stats_reset();
		}
	}

	/* Close the file if necessary */
	if (!stat_append && (stat_fp != NULL))
	{
		fclose(stat_fp);
	}

	/* Set the new alarm if necessary */
	if (signum == SIGALRM)
	{
		alarm(stat_emit_interval);
	}
}

/* Reset statistics */
void eemo_dnsstats_stats_reset(void)
{
	memset(&qclass_ctr, 0, sizeof(qclass_ctr));
	memset(&qtype_ctr, 0, sizeof(qtype_ctr));
	memset(&iptype_ctr, 0, sizeof(iptype_ctr));
	memset(&proto_ctr, 0, sizeof(proto_ctr));
	memset(&edns0_ctr, 0, sizeof(edns0_ctr));

	DEBUG_MSG("DNS statistics reset");
}

/* Initialise the DNS query counter module */
void eemo_dnsstats_stats_init(char** ips, int ip_count, int emit_interval, char* stats_file, int append_file, int reset)
{
	int i = 0;

	stat_ips = ips;
	stat_ipcount = ip_count;

	INFO_MSG("Listening to %d IP addresses", stat_ipcount);

	for (i = 0; i < stat_ipcount; i++)
	{
		INFO_MSG("Listening for queries to IP %s", ips[i]);
	}

	stat_emit_interval = emit_interval;

	INFO_MSG("Emitting statistics every %d seconds", emit_interval);

	stat_file = stats_file;

	INFO_MSG("Writing statistics to the file called %s", stat_file);

	stat_append = append_file;

	INFO_MSG("Will %soverwrite the file when new statistics are available", stat_append ? "not " : "");

	stat_reset = reset;

	INFO_MSG("Will %sreset statistics once they have been written to file", stat_reset ? "" : "not ");

	if (stat_append)
	{
		stat_fp = fopen(stat_file, "w");

		if (stat_fp != NULL)
		{
			INFO_MSG("Opened %s to write statistics to", stat_file);
		}
		else
		{
			ERROR_MSG("Failed to open %s for writing", stat_file);
		}
	}

	eemo_dnsstats_stats_reset();
	
	/* Register signal handler */
	signal(SIGUSR1, signal_handler);
	signal(SIGALRM, signal_handler);

	/* Set the alarm */
	alarm(stat_emit_interval);
}

/* Uninitialise the DNS query counter module */
void eemo_dnsstats_stats_uninit(eemo_conf_free_string_array_fn free_strings)
{
	/* Unregister signal handlers */
	alarm(0);
	signal(SIGUSR1, SIG_DFL);
	signal(SIGALRM, SIG_DFL);

	/* Close the file */
	if (stat_append && (stat_fp != NULL))
	{
		fclose(stat_fp);

		DEBUG_MSG("Closed %s", stat_file);
	}
	else
	{
		INFO_MSG("Statistics file %s was not open", stat_file);
	}

	(free_strings)(stat_ips, stat_ipcount);
	free(stat_file);
}

/* Handle DNS query packets and log the statistics */
eemo_rv eemo_dnsstats_stats_handleq(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* dns_packet)
{
	int i = 0;
	eemo_dns_query* query_it = NULL;
	eemo_dns_rr* rr_it = NULL;
	int edns0 = 0;

	/* We only process queries, not responses */
	if (dns_packet->qr_flag)
	{
		return ERV_SKIPPED;
	}

	/* Either count all messages or check whether this messages matches any of the IPs we're monitoring */
	if (stat_ipcount > 0)
	{
		int ip_match = 0;
	
		/* Check if this query is directed at the server we're supposed to monitor */
		for (i = 0; i < stat_ipcount; i++)
		{
			if (!strcmp(stat_ips[i], ip_info.ip_dst) || !strcmp(stat_ips[i], IP_ANY))
			{
				ip_match = 1;
				break;
			}
		}
	
		if (!ip_match)
		{
			return ERV_SKIPPED;
		}
	}

	LL_FOREACH(dns_packet->questions, query_it)
	{
		/* Log query class */
		switch(query_it->qclass)
		{
		case DNS_QCLASS_UNSPECIFIED:
			qclass_ctr.UNSPECIFIED++;
			break;
		case DNS_QCLASS_IN:
			qclass_ctr.IN++;
			break;
		case DNS_QCLASS_CS:
			qclass_ctr.CS++;
			break;
		case DNS_QCLASS_CH:
			qclass_ctr.CH++;
			break;
		case DNS_QCLASS_HS:
			qclass_ctr.HS++;
			break;
		case DNS_QCLASS_ANY:
			qclass_ctr.ANY++;
			break;
		default:
			qclass_ctr.UNKNOWN++;
		}
	
		/* Log query type */
		switch(query_it->qtype)
		{
		case DNS_QTYPE_UNSPECIFIED:
			qtype_ctr.UNSPECIFIED++;
			break;
		case DNS_QTYPE_A:
			qtype_ctr.A++;
			break;
		case DNS_QTYPE_AAAA:
			qtype_ctr.AAAA++;
			break;
		case DNS_QTYPE_AFSDB:
			qtype_ctr.AFSDB++;
			break;
		case DNS_QTYPE_APL:
			qtype_ctr.APL++;
			break;
		case DNS_QTYPE_CERT:
			qtype_ctr.CERT++;
			break;
		case DNS_QTYPE_CNAME:
			qtype_ctr.CNAME++;
			break;
		case DNS_QTYPE_DHCID:
			qtype_ctr.DHCID++;
			break;
		case DNS_QTYPE_DLV:
			qtype_ctr.DLV++;
			break;
		case DNS_QTYPE_DNAME:
			qtype_ctr.DNAME++;
			break;
		case DNS_QTYPE_DNSKEY:
			qtype_ctr.DNSKEY++;
			break;
		case DNS_QTYPE_DS:
			qtype_ctr.DS++;
			break;
		case DNS_QTYPE_HIP:
			qtype_ctr.HIP++;
			break;
		case DNS_QTYPE_IPSECKEY:
			qtype_ctr.IPSECKEY++;
			break;
		case DNS_QTYPE_KEY:
			qtype_ctr.KEY++;
			break;
		case DNS_QTYPE_KX:
			qtype_ctr.KX++;
			break;
		case DNS_QTYPE_LOC:
			qtype_ctr.LOC++;
			break;
		case DNS_QTYPE_MX:
			qtype_ctr.MX++;
			break;
		case DNS_QTYPE_NAPTR:
			qtype_ctr.NAPTR++;
			break;
		case DNS_QTYPE_NS:
			qtype_ctr.NS++;
			break;
		case DNS_QTYPE_NSEC:
			qtype_ctr.NSEC++;
			break;
		case DNS_QTYPE_NSEC3:
			qtype_ctr.NSEC3++;
			break;
		case DNS_QTYPE_NSEC3PARAM:
			qtype_ctr.NSEC3PARAM++;
			break;
		case DNS_QTYPE_PTR:
			qtype_ctr.PTR++;
			break;
		case DNS_QTYPE_RRSIG:
			qtype_ctr.RRSIG++;
			break;
		case DNS_QTYPE_RP:
			qtype_ctr.RP++;
			break;
		case DNS_QTYPE_SIG:
			qtype_ctr.SIG++;
			break;
		case DNS_QTYPE_SOA:
			qtype_ctr.SOA++;
			break;
		case DNS_QTYPE_SPF:
			qtype_ctr.SPF++;
			break;
		case DNS_QTYPE_SRV:
			qtype_ctr.SRV++;
			break;
		case DNS_QTYPE_SSHFP:
			qtype_ctr.SSHFP++;
			break;
		case DNS_QTYPE_TA:
			qtype_ctr.TA++;
			break;
		case DNS_QTYPE_TKEY:
			qtype_ctr.TKEY++;
			break;
		case DNS_QTYPE_TSIG:
			qtype_ctr.TSIG++;
			break;
		case DNS_QTYPE_TXT:
			qtype_ctr.TXT++;
			break;
		case DNS_QTYPE_ANY:
			qtype_ctr.ANY++;
			break;
		case DNS_QTYPE_AXFR:
			qtype_ctr.AXFR++;
			break;
		case DNS_QTYPE_IXFR:
			qtype_ctr.IXFR++;
			break;
		case DNS_QTYPE_OPT:
			qtype_ctr.OPT++;
			break;
		default:
			qtype_ctr.UNKNOWN++;
		}

	}

	/* Log EDNS0 data */
	LL_FOREACH(dns_packet->additionals, rr_it)
	{
		if (rr_it->type == DNS_QTYPE_OPT)
		{
			/* Found the OPT RR */
			edns0 = 1;

			/* Log DO bit setting */
			if (EDNS0_DO_SET(rr_it))
			{
				edns0_ctr.EDNS0_DO_SET++;
			}
			else
			{
				edns0_ctr.EDNS0_DO_UNSET++;
			}

			/* Log EDNS0 buffer size */
			if (EDNS0_BUFSIZE(rr_it) < 512)
			{
				edns0_ctr.EDNS0_BELOW_512++;
			}
			else if ((EDNS0_BUFSIZE(rr_it) >= 512) && (EDNS0_BUFSIZE(rr_it) < 1000))
			{
				edns0_ctr.EDNS0_512_TO_999++;
			}
			else if ((EDNS0_BUFSIZE(rr_it) >= 1000) && (EDNS0_BUFSIZE(rr_it) < 1500))
			{
				edns0_ctr.EDNS0_1000_TO_1499++;
			}
			else if ((EDNS0_BUFSIZE(rr_it) >= 1500) && (EDNS0_BUFSIZE(rr_it) < 2000))
			{
				edns0_ctr.EDNS0_1500_TO_1999++;
			}
			else if ((EDNS0_BUFSIZE(rr_it) >= 2000) && (EDNS0_BUFSIZE(rr_it) < 2500))
			{
				edns0_ctr.EDNS0_2000_TO_2499++;
			}
			else if ((EDNS0_BUFSIZE(rr_it) >= 2500) && (EDNS0_BUFSIZE(rr_it) < 3000))
			{
				edns0_ctr.EDNS0_2500_TO_2999++;
			}
			else if ((EDNS0_BUFSIZE(rr_it) >= 3000) && (EDNS0_BUFSIZE(rr_it) < 3500))
			{
				edns0_ctr.EDNS0_3000_TO_3499++;
			}
			else if ((EDNS0_BUFSIZE(rr_it) >= 3500) && (EDNS0_BUFSIZE(rr_it) < 4000))
			{
				edns0_ctr.EDNS0_3500_TO_3999++;
			}
			else if ((EDNS0_BUFSIZE(rr_it) >= 4000) && (EDNS0_BUFSIZE(rr_it) < 4500))
			{
				edns0_ctr.EDNS0_4000_TO_4499++;
			}
			else
			{
				edns0_ctr.EDNS0_ABOVE_4500++;
			}

			break;
		}
	}

	if (!edns0)
	{
		edns0_ctr.EDNS0_NO++;
	}

	/* Log IP type */
	switch(ip_info.ip_type)
	{
	case IP_TYPE_V4:
		iptype_ctr.V4++;
		break;
	case IP_TYPE_V6:
		iptype_ctr.V6++;
		break;
	}

	/* Log protocol type */
	if (is_tcp)
	{
		proto_ctr.TCP++;
	}
	else
	{
		proto_ctr.UDP++;
	}

	return ERV_HANDLED;
}

