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
 * DNS sensor forwarding module
 */

#include "config.h"
#include "eemo.h"
#include "eemo_log.h"
#include "eemo_dnssensorfw_ipfw.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <errno.h>

/* Configuration */
char*	sensor_hostname		= NULL;
int	sensor_port		= 0;
int	reconn_maxinterval	= 0;

/* Retry state */
int	reconn_interval	= 1;

/* Sensor connection */
int		sensor_socket		= -1;
pthread_mutex_t	conn_mutex;
int		stop_conn_thread	= 0;
int		sensor_connected	= 0;
pthread_t	conn_thread_handle;

/* Sensor connection thread */
void* sensor_conn_thread(void* thread_args)
{
	/* FIXME: debug message */
	INFO_MSG("Entering sensor connection thread");

	while (!stop_conn_thread)
	{
		struct addrinfo* sensor_addrs = NULL;
		struct addrinfo* addr_it = NULL;
		struct addrinfo hints;
		char port_str[16];
		int reconn_interval_timer = reconn_interval;
		unsigned char dummy_buf[16384];

		/* Wait the reconnect interval and determine the new interval */
		while (!stop_conn_thread && reconn_interval_timer--) sleep(1);

		if (stop_conn_thread) break;

		reconn_interval *= 2;

		if (reconn_interval > reconn_maxinterval)
		{
			reconn_interval = reconn_maxinterval;
		}

		/* Resolve the address of the sensor */
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = 0;
		hints.ai_protocol = 0;

		snprintf(port_str, 16, "%d", sensor_port);

		if (getaddrinfo(sensor_hostname, port_str, &hints, &sensor_addrs) != 0)
		{
			ERROR_MSG("Unable to resolve host %s", sensor_hostname);
			continue;
		}

		/* Attempt to connect to one of the addresses that was found */
		addr_it = sensor_addrs;

		while(addr_it != NULL)
		{
			if ((addr_it->ai_family == AF_INET) || (addr_it->ai_family == AF_INET6))
			{
				INFO_MSG("Attempting to connect to %s:%d over IPv%d", 
					sensor_hostname, sensor_port,
					addr_it->ai_family == AF_INET ? 4 : 6);

				sensor_socket = socket(addr_it->ai_family, SOCK_STREAM, 0);

				if (sensor_socket == -1)
				{
					ERROR_MSG("Failed to open a new socket");
					continue;
				}

				/* Attempt to connect the socket */
				if (connect(sensor_socket, addr_it->ai_addr, addr_it->ai_addrlen) != 0)
				{
					ERROR_MSG("Failed to connect to %s:%d (%s)", sensor_hostname, sensor_port, strerror(errno));
					close(sensor_socket);
					addr_it = addr_it->ai_next;
					continue;
				}

				INFO_MSG("Established a connection to %s:%d", sensor_hostname, sensor_port);

				pthread_mutex_lock(&conn_mutex);

				sensor_connected = 1;
				reconn_interval = 1;
				
				pthread_mutex_unlock(&conn_mutex);
				break;
			}

			addr_it = addr_it->ai_next;
		}

		freeaddrinfo(sensor_addrs);

		while (sensor_connected && !stop_conn_thread)
		{
			/* Consume data received on the socket */
			int result = recv(sensor_socket, dummy_buf, 16384, MSG_DONTWAIT);

			if (result <= 0)
			{
				if ((result == 0) || ((errno != EAGAIN) && (errno != EWOULDBLOCK)))
				{
					/* The connection was closed */
					ERROR_MSG("Connection to %s:%d lost", sensor_hostname, sensor_port);

					pthread_mutex_lock(&conn_mutex);

					sensor_connected = 0;
					close(sensor_socket);

					pthread_mutex_unlock(&conn_mutex);
					break;
				}
			}

			sleep(1);
		}
	}

	if (sensor_socket >= 0)
	{
		pthread_mutex_lock(&conn_mutex);

		close(sensor_socket);
		sensor_connected = 0;

		pthread_mutex_unlock(&conn_mutex);
	}

	/* FIXME: debug message */
	INFO_MSG("Sensor connection thread finished");

	return NULL;
}

/* Initialise the IP/ICMP to DNS sensor forwarder */
void eemo_dnssensorfw_ipfw_init(const char* hostname, const int port, const int maxinterval)
{
	sensor_hostname = (char*) hostname;
	sensor_port = port;
	reconn_maxinterval = maxinterval;

	/* Initialise sensor connection thread */
	pthread_mutex_init(&conn_mutex, NULL);

	if (pthread_create(&conn_thread_handle, NULL, &sensor_conn_thread, NULL) != 0)
	{
		ERROR_MSG("Failed to start the sensor connection thread");
	}
}

/* Uninitialise the IP/ICMP to DNS sensor forwarder */
void eemo_dnssensorfw_ipfw_uninit(eemo_conf_free_string_array_fn free_strings)
{
	/* Stop the sensor connection thread */
	stop_conn_thread = 1;

	pthread_join(conn_thread_handle, NULL);

	pthread_mutex_destroy(&conn_mutex);
}

/* Handle all packets */
eemo_rv eemo_dnssensorfw_ipfw_handle_pkt(eemo_packet_buf* packet, eemo_ether_packet_info pktinfo)
{
#pragma pack(push,1)
	static struct
	{
		unsigned short pkt_len;
		unsigned char buf[65536];
	} send_packet;
#pragma pack(pop)

	memcpy(send_packet.buf, packet->data, packet->len);
	send_packet.pkt_len = packet->len;

	pthread_mutex_lock(&conn_mutex);
	if (sensor_connected)
	{
		send(sensor_socket, &send_packet, packet->len + 2, 0);
	}
	pthread_mutex_unlock(&conn_mutex);

	return ERV_HANDLED;
}

