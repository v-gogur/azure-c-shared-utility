// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.


#include <stdbool.h>
#include <stdint.h>

// This file is OS-specific, and is identified by setting include directories
// in the project
#include "socket_async_os.h"

#include "azure_c_shared_utility/dns.h"
#include "azure_c_shared_utility/xlogging.h"

// EXTRACT_IPV4 pulls the uint32_t IPv4 address out of an addrinfo struct
#ifdef WIN32	
#define EXTRACT_IPV4(ptr) ((struct sockaddr_in *) ptr->ai_addr)->sin_addr.S_un.S_addr
#else
// The default definition handles lwIP. Please add comments for other systems tested.
#define EXTRACT_IPV4(ptr) ((struct sockaddr_in *) ptr->ai_addr)->sin_addr.s_addr
#endif



uint32_t DNS_Get_IPv4(const char* hostname)
{
    struct addrinfo *addrInfo = NULL;
    struct addrinfo *ptr = NULL;
    struct addrinfo hints;

    uint32_t result;

    //--------------------------------
    // Setup the hints address info structure
    // which is passed to the getaddrinfo() function
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    //--------------------------------
    // Call getaddrinfo(). If the call succeeds,
    // the result variable will hold a linked list
    // of addrinfo structures containing response
    // information
    int getAddrResult = getaddrinfo(hostname, NULL, &hints, &addrInfo);
    if (getAddrResult == 0)
    {
        // 
        uint32_t found = 0;
        // If we find the AF_INET address, use it as the return value
        for (ptr = addrInfo; ptr != NULL; ptr = ptr->ai_next)
        {
            switch (ptr->ai_family)
            {
            case AF_INET:
                found = EXTRACT_IPV4(ptr);
                break;
            }
        }
        freeaddrinfo(addrInfo);
        result = found;
    }
    else
    {
        result = 0;
    }

    return result;
}
