// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "lwip/api.h"

#include "azure_c_shared_utility/dns_compact.h"

#define MAX_RETRY 20

uint32_t DNS_Compact_GetIPv4(const char* hostName)
{
	int netconn_retry = 0;
	int getHostResult = -1;
	ip_addr_t target_ip;

	do {
		getHostResult = netconn_gethostbyname(hostName, &target_ip);

	} while (getHostResult && netconn_retry++ < MAX_RETRY);

	uint32_t result = 0;

	if (getHostResult == 0)
	{
#if LWIP_IPV4 && LWIP_IPV6
		result = target_ip.u_addr.ip4.addr;
#else // LWIP_IPV4 && LWIP_IPV6
#if LWIP_IPV6
		// IPv6 only is not supported
		IPv6OnlyNotSupported = ; // deliberate bad syntax
#else // LWIP_IPV6
		// This is an IPv4 result
		result = target_ip.addr;
#endif // LWIP_IPV6
#endif // LWIP_IPV4 && LWIP_IPV6
	}

	return result;
}

