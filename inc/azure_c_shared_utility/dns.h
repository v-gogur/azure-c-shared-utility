// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/** @file ssl_socket.h
 *	@brief	 Implements socket creation for TLSIO adapters.
 */

#ifndef AZURE_IOT_DNS_H
#define AZURE_IOT_DNS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "azure_c_shared_utility/macro_utils.h"
#include "azure_c_shared_utility/umock_c_prod.h"

    // This file will eventually be the header for platform-independent 
    // asynchrounous DNS getaddrinfo replacement. For now, however,
    // it only contains the (blocking) convenience function DNS_Get_IPv4

	/**
	* @brief	Perform a DNS lookup on the serverName and return an IPv4 address.
	*
	* @param   serverName	The url of the SSL server to be contacted.
	*
	* @return	@c A uint32_t IPv4 address. 0 indicates failure.
	*/
	MOCKABLE_FUNCTION(, uint32_t, DNS_Get_IPv4, const char*, serverName);


#ifdef __cplusplus
}
#endif

#endif /* AZURE_IOT_DNS_H */
