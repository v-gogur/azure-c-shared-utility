// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.


#include <stdbool.h>
#include <stdint.h>

// This file is OS-specific, and is identified by setting include directories
// in the project
#include "socket_async_os.h"

#include "azure_c_shared_utility/dns_async.h"
#include "azure_c_shared_utility/xlogging.h"

// EXTRACT_IPV4 pulls the uint32_t IPv4 address out of an addrinfo struct
#ifdef WIN32	
#define EXTRACT_IPV4(ptr) ((struct sockaddr_in *) ptr->ai_addr)->sin_addr.S_un.S_addr
#else
// The default definition handles lwIP. Please add comments for other systems tested.
#define EXTRACT_IPV4(ptr) ((struct sockaddr_in *) ptr->ai_addr)->sin_addr.s_addr
#endif

typedef struct
{
    char* hostname;
    uint32_t ip_v4;
    int is_complete;
} DNS_ASYNC_INSTANCE;

DNS_ASYNC_HANDLE dns_async_create(const char* hostname, DNS_ASYNC_OPTIONS* options)
{
    DNS_ASYNC_INSTANCE* result;
    if (hostname == NULL)
    {
        LogError("NULL hostname");
        result = NULL;
    }
    else
    {
        result = malloc(sizeof(DNS_ASYNC_INSTANCE));
        if (result == NULL)
        {
            LogError("malloc instance failed");
            result = NULL;
        }
        else
        {
            result->is_complete = true; // TODO: will be false for the asynchronous design
            result->ip_v4 = 0;
            result->hostname = (char*)malloc(strlen(hostname) + 1);
        }
        if (result->hostname == NULL)
        {
            free(result);
            result = NULL;
        }
        else
        {
            (void)strcpy(result->hostname, hostname);
        }
    }
    return result;
}

int dns_async_is_lookup_complete(DNS_ASYNC_HANDLE dns_in, bool* is_complete)
{
    DNS_ASYNC_INSTANCE* dns = (DNS_ASYNC_INSTANCE*)dns_in;

    struct addrinfo *addrInfo = NULL;
    struct addrinfo *ptr = NULL;
    struct addrinfo hints;

    int result;

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
    int getAddrResult = getaddrinfo(dns->hostname, NULL, &hints, &addrInfo);
    if (getAddrResult == 0)
    {
        // 
        dns->ip_v4 = 0;
        dns->is_complete = false;
        // If we find the AF_INET address, use it as the return value
        for (ptr = addrInfo; ptr != NULL; ptr = ptr->ai_next)
        {
            switch (ptr->ai_family)
            {
            case AF_INET:
                dns->ip_v4 = EXTRACT_IPV4(ptr);
                dns->is_complete = true;
                break;
            }
        }
        freeaddrinfo(addrInfo);
        result = dns->is_complete != 0 ? 0 : __FAILURE__;
    }
    else
    {
        result = __FAILURE__;
        LogInfo("Failed DNS lookup for %s", dns->hostname);
    }

    return result;
}

void dns_async_destroy(DNS_ASYNC_HANDLE dns_in)
{
    DNS_ASYNC_INSTANCE* dns = (DNS_ASYNC_INSTANCE*)dns_in;
    free(dns->hostname);
    free(dns);
}

uint32_t dns_async_get_ipv4(DNS_ASYNC_HANDLE dns_in)
{
    DNS_ASYNC_INSTANCE* dns = (DNS_ASYNC_INSTANCE*)dns_in;
    uint32_t result;
    if (dns->is_complete)
    {
        result = dns->ip_v4;
    }
    else
    {
        LogError("dns_async_get_ipv4 when not is_complete");
        result = 0;
    }
    return result;
}
