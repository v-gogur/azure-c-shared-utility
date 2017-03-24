// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef OPEN_SSL_H
#define OPEN_SSL_H

#ifdef __cplusplus

extern "C" {
#include <cstdint>
#else
#include <stdint.h>
#endif /* __cplusplus */

#include "azure_c_shared_utility/umock_c_prod.h"

// This header mocks the small subset of the the OpenSSL ssl.h needed for tlsio_openssl_compact testing

//MOCKABLE_FUNCTION(, uint32_t, xTaskGetTickCount);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // OPEN_SSL_H