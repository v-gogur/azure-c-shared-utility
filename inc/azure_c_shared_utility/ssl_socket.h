// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/** @file ssl_socket.h
 *	@brief	 Implements socket creation for TLSIO adapters.
 */

#ifndef AZURE_SSL_SOCKET_H
#define AZURE_SSL_SOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include "azure_c_shared_utility/macro_utils.h"
#include "azure_c_shared_utility/umock_c_prod.h"

#define SSL_SOCKET_NULL_SOCKET -1

	/**
	* @brief	Perform a DNS lookup on the serverName and return an IPv4 address.
	*
	* @param   serverName	The url of the SSL server to be contacted.
	*
	* @return	@c A uint32_t IPv4 address. 0 indicates failure.
	*/
	MOCKABLE_FUNCTION(, uint32_t, SSL_Get_IPv4, const char*, serverName);

	/**
	* @brief	Create a non-blocking socket that is correctly configured for use by a TLSIO adapter.
	*
	* @param   serverIPv4	The IPv4 of the SSL server to be contacted.
	*
	* @param   port	The port of the SSL server to use.
	*
	* @return	@c An integer file descriptor (fd) if the API call
	*          is successful or SSL_SOCKET_NULL_SOCKET in case it fails. Error logging is
	*          performed by the underlying concrete implementation, so no
	*          further error logging is necessary.
	*/
	MOCKABLE_FUNCTION(, int, SSL_Socket_Create, uint32_t, serverIPv4, int, port);

    /**
    * @brief	Close the socket returned by SSL_Socket_Create.
    *
    * @param   serverName	The url of the SSL server to be contacted.
    */
    MOCKABLE_FUNCTION(, void, SSL_Socket_Close, int, sock);


#ifdef __cplusplus
}
#endif

#endif /* AZURE_SSL_SOCKET_H */
