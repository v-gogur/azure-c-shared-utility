// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/** @file dns_compact.h
 *	@brief	 Implements DNS lookup for microcontrollers.
 */

#ifndef AZURE_DNS_COMPACT_H
#define AZURE_DNS_COMPACT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "azure_c_shared_utility/macro_utils.h"
#include "azure_c_shared_utility/umock_c_prod.h"


/**
 * @brief	Retrieve an IPv4 address. Attempts 20 retries before returning failure.
 *
 * @param   serverName	The url of the SSL server to be contacted.
 *
 * @return	@c The uint32_t value of the IPv4 address. Returns 0 on error.
 *          Error logging is performed by the underlying concrete implementation,
 *          so no further logging is required.
 */
MOCKABLE_FUNCTION(, uint32_t, DNS_Compact_GetIPv4, const char*, hostName);


#ifdef __cplusplus
}
#endif

#endif /* AZURE_DNS_COMPACT_H */
