// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef MOCKED_UNit_TESt_SOCKET_H
#define MOCKED_UNit_TESt_SOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

// We want to use some of the definitions from <Ws2tcpip.h>, but
// we want to mock several of its functions. This construct tricks
// the included file into undefining our functions.

// Prepare to ignore the declarations in <Ws2tcpip.h>
#define getsockopt getsockopt_original
#define socket socket_original
#define setsockopt setsockopt_original
#define fcntl fcntl_original
#define bind bind_original
#define connect connect_original
#define select select_original

//#define FD_SET FD_SET_original
#include <Ws2tcpip.h>
#undef FD_ISSET
#undef FD_SET
#define FD_SET my_fd_set
#undef FD_ZERO
#define FD_ZERO(x)


// Ignore the declarations in <Ws2tcpip.h>
#undef getsockopt
#undef socket
#undef setsockopt
#undef fcntl
#undef bind
#undef connect
#undef select

    // Replaces the Linux FD_SET()
    void my_fd_set(int sock, void* dummy);


#include "azure_c_shared_utility/macro_utils.h"
#include "azure_c_shared_utility/umock_c_prod.h"

// None of these defines is functional or tested, so their values aren't important
//#define SOL_SOCKET 0xffff 
//#define SO_ERROR   0x1007  
//#define AF_INET    0x0010
#define TCP_KEEPIDLE 33
#define TCP_KEEPINTVL 44
#define TCP_KEEPCNT 55
#define F_GETFL 66
#define F_SETFL 77
#define O_NONBLOCK 8

    //typedef struct fd_set
    //{
    //    int dummy;
    //} fd_set;

    int fcntl(int socket, int flags, int value);
    //void FD_ZERO(void* dummy);

    MOCKABLE_FUNCTION(, int, socket, int, domain, int, type, int, protocol);

    MOCKABLE_FUNCTION(, int, setsockopt, int, sock, int, level, int, optname, void*, optval, size_t, optlen);

    MOCKABLE_FUNCTION(WSAAPI, int, getsockopt, int, sock, int, level, int, optname, void*, optval, size_t*, optlen);

    MOCKABLE_FUNCTION(, int, bind, int, sock, void*, addr, size_t, addrlen);

    MOCKABLE_FUNCTION(, int, connect, int, sock, void*, addr, size_t, addrlen);

    MOCKABLE_FUNCTION(, int, select, int, sock, void*, rdset, void*, wrset, void*, errset, void*, timeout);

    MOCKABLE_FUNCTION(, int, FD_ISSET, int, sock, void*, testset);

    MOCKABLE_FUNCTION(, int, close, int, sock);


#ifdef __cplusplus
}
#endif

#endif /* MOCKED_UNit_TESt_SOCKET_H */
