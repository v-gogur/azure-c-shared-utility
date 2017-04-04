// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Enable platform-specific socket.h files using preprocessor defines in the makefile
#ifdef USE_LWIP_SOCKET_FOR_AZURE_IOT
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#endif

#ifdef LINUX
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#endif // LINUX

#include <sys.time>


#include "azure_c_shared_utility/ssl_socket.h"
#include "azure_c_shared_utility/xlogging.h"


// EXTRACT_IPV4 pulls the uint32_t IPv4 address out of an addrinfo struct
#ifdef WIN32	
#define EXTRACT_IPV4(ptr) ((struct sockaddr_in *) ptr->ai_addr)->sin_addr.S_un.S_addr
#else
// The default definition handles lwIP. Please add comments for other systems tested.
#define EXTRACT_IPV4(ptr) ((struct sockaddr_in *) ptr->ai_addr)->sin_addr.s_addr
#endif

#ifndef AZURE_SSL_TIMEOUT_SECONDS
#define AZURE_SSL_TIMEOUT_SECONDS   20
#endif // !AZURE_SSL_TIMEOUT_SECONDS


///////////////////////////////////////////////////////////////////////////////
// These socket behavior constants are chosen as good matches for Azure IoT,
// and it should be unnecessary to to change them for most applications. 
// However, if it is necessary, they can be altered without code change by
// redefining the values at compile time.
///////////////////////////////////////////////////////////////////////////////
#ifndef AZURE_SSL_SOCKET_SO_KEEPALIVE
#define AZURE_SSL_SOCKET_SO_KEEPALIVE 1    /* enable keepalive */
#endif

#ifndef AZURE_SSL_SOCKET_TCP_KEEPIDLE
#define AZURE_SSL_SOCKET_TCP_KEEPIDLE 30   // wait for 30s of inactivity before starting keepalive
#endif

#ifndef AZURE_SSL_SOCKET_TCP_KEEPINTVL
#define AZURE_SSL_SOCKET_TCP_KEEPINTVL 30  // send a keepalive packet every 30 seconds
#endif

#ifndef AZURE_SSL_SOCKET_TCP_KEEPCNT
#define AZURE_SSL_SOCKET_TCP_KEEPCNT 3     /* retry count */
#endif



static int get_socket_errno(int fd)
{
    int sock_errno = 0;
    uint32_t optlen = sizeof(sock_errno);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_errno, &optlen);
    return sock_errno;
}

static uint32_t get_ipv4(const char* hostname)
{
    struct addrinfo *addrInfo = NULL;
    struct addrinfo *ptr = NULL;
    struct addrinfo hints;

    uint32_t result = 0;

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
        // If we find the AF_INET address, use it as the return value
        for (ptr = addrInfo; ptr != NULL; ptr = ptr->ai_next)
        {
            switch (ptr->ai_family)
            {
            case AF_INET:
                result = EXTRACT_IPV4(ptr);
                break;
            }
        }
        freeaddrinfo(addrInfo);
    }

    return result;
}

int SSL_Socket_Create(const char* hostname, int port)
{
    int sock;

    struct sockaddr_in sock_addr;

    uint32_t ipV4address = get_ipv4(hostname);

    if (ipV4address != 0)
    {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
            LogError("create socket failed");
            sock = SSL_SOCKET_NULL_SOCKET;
        }
        else
        {
            // sock is now good and has a non-negative value
            int config_result;

            int keepAlive = AZURE_SSL_SOCKET_SO_KEEPALIVE; // enable keepalive
            int keepIdle = AZURE_SSL_SOCKET_TCP_KEEPIDLE; // wait for AZURE_SSL_SOCKET_TCP_KEEPIDLE seconds of inactivity before starting keepalive
            int keepInterval = AZURE_SSL_SOCKET_TCP_KEEPINTVL; // send the keepalive packet every AZURE_SSL_SOCKET_TCP_KEEPINTVL seconds
            int keepCount = AZURE_SSL_SOCKET_TCP_KEEPCNT; // retry AZURE_SSL_SOCKET_TCP_KEEPCNT of times before declaring the connection dead

            config_result = 0;
            config_result = config_result != 0 || setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive));
            config_result = config_result != 0 || setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&keepIdle, sizeof(keepIdle));
            config_result = config_result != 0 || setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&keepInterval, sizeof(keepInterval));
            config_result = config_result != 0 || setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (void *)&keepCount, sizeof(keepCount));

            // NB: On full-sized (multi-process) systems it would be necessary to use the SO_REUSEADDR option to 
            // grab the socket from any earlier (dying) invocations of the process and then deal with any 
            // residual junk in the connection stream. Embedded systems don't have multiple processes, so it doesn't need
            // to be defended against.

            if (config_result != 0)
            {
                LogError("set socket keep-alive config failed, config_result = %d ", config_result);
            }
            else
            {
                // When supplied with either F_GETFL and F_SETFL parameters, the fcntl function
                // does simple bit flips which have no error path, so it is not necessary to
                // check for errors. (Source checked for linux and lwIP).
                int originalFlags = fcntl(sock, F_GETFL, 0);
                (void)fcntl(sock, F_SETFL, originalFlags | O_NONBLOCK);

                memset(&sock_addr, 0, sizeof(sock_addr));
                sock_addr.sin_family = AF_INET;
                sock_addr.sin_addr.s_addr = 0;
                sock_addr.sin_port = 0; // random local port

                config_result = bind(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr));

                if (config_result != 0)
                {
                    LogError("bind socket failed");
                }
                else
                {

                    memset(&sock_addr, 0, sizeof(sock_addr));
                    sock_addr.sin_family = AF_INET;
                    sock_addr.sin_addr.s_addr = ipV4address;
                    sock_addr.sin_port = htons(port);

                    config_result = connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
                    if (config_result == -1)
                    {
                        int sockErr = get_socket_errno(sock);
                        if (sockErr != EINPROGRESS)
                        {
                            LogError("Socket connect failed, not EINPROGRESS: %d", sockErr);
                        }
                        else
                        {
                            // This is the normally expected code path for our non-blocking socket
                            // Wait for the write socket to be ready to perform a write.
                            fd_set writeset;
                            fd_set errset;
                            FD_ZERO(&writeset);
                            FD_ZERO(&errset);
                            FD_SET(sock, &writeset);
                            FD_SET(sock, &errset);

                            struct timeval timeout = { .tv_sec = AZURE_SSL_TIMEOUT_SECONDS, .tv_usec = 0 };

                            config_result = select(sock + 1, NULL, &writeset, &errset, &timeout);
                            if (config_result <= 0)
                            {
                                LogError("Select failed: %d", get_socket_errno(sock));
                            }
                            else
                            {
                                if (FD_ISSET(sock, &errset))
                                {
                                    LogError("Socket select error is set: %d", get_socket_errno(sock));
                                }
                                else if (FD_ISSET(sock, &writeset))
                                {
                                    // Everything worked as expected, so set the result to our good socket
                                    result = sock;
                                }
                                else
                                {
                                    // not possible, so not worth the space for logging
                                }
                            }
                        }
                    }
                    else
                    {
                        // This result would be a big surprise because a non-blocking socket
                        // should always return EINPROGRESS
                        result = sock;
                    }
                }
            }
            // If we're not configured properly, then don't return the socket
            if (sock != SSL_SOCKET_NULL_SOCKET && config_result != 0)
            {
                SSL_Socket_Close(sock);
                sock = SSL_SOCKET_NULL_SOCKET;
            }
        }
    }
    return result;
}

void SSL_Socket_Close(int sock)
{
    close(sock);
}
