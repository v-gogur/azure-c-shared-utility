// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

//#if USE_LWIP_SOCKET
#include "lwip/sockets.h"
#include "lwip/netdb.h"
//#endif

#include "azure_c_shared_utility/ssl_socket.h"
#include "azure_c_shared_utility/xlogging.h"


// EXTRACT_IPV4 pulls the uint32_t IPv4 address out of an addrinfo struct
#ifdef _INC_WINAPIFAMILY	// An example WinSock test; feel free to change to a better one to compile under Windows
#define EXTRACT_IPV4(ptr) ((struct sockaddr_in *) ptr->ai_addr)->sin_addr.S_un.S_addr
#else
// The default definition handles lwIP. Please add comments for other systems tested.
#define EXTRACT_IPV4(ptr) ((struct sockaddr_in *) ptr->ai_addr)->sin_addr.s_addr
#endif




static int get_socket_errno(int fd)
{
	int sock_errno = 0;
	u32_t optlen = sizeof(sock_errno);
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
	int result = -1;
	int ret;
	int sock;

	struct sockaddr_in sock_addr;

	uint32_t ipV4address = get_ipv4(hostname);

	if (ipV4address != 0)
	{
		sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock < 0)
		{
			LogError("create socket failed");
		}
		else
		{
			int keepAlive = 1; //enable keepalive
			int keepIdle = 20; //20s
			int keepInterval = 2; //2s
			int keepCount = 3; //retry # of times

			ret = 0;
			ret = ret || setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive));
			ret = ret || setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&keepIdle, sizeof(keepIdle));
			ret = ret || setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&keepInterval, sizeof(keepInterval));
			ret = ret || setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (void *)&keepCount, sizeof(keepCount));

			// NB: On full-sized (multi-process) systems it would be necessary to use the SO_REUSEADDR option to 
			// grab the socket from any earlier (dying) invocations of the process and then deal with any 
			// residual junk in the connection stream. This doesn't happen with embedded, so it doesn't need
			// to be defended against.

			if (ret != 0)
			{
				LogError("set socket keep-alive failed, ret = %d ", ret);
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

				ret = bind(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr));

				if (ret)
				{
					LogError("bind socket failed");
				}
				else
				{
					memset(&sock_addr, 0, sizeof(sock_addr));
					sock_addr.sin_family = AF_INET;
					sock_addr.sin_addr.s_addr = ipV4address;
					sock_addr.sin_port = htons(port);

					ret = connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
					if (ret == -1)
					{
						ret = get_socket_errno(sock);
						if (ret != EINPROGRESS)
						{
							ret = -1;
							close(sock);
							LogError("socket connect failed, not EINPROGRESS %s", hostname);
						}
					}// TODO: EINPROGRESS requires a loop and wait

				}
			}
		}
	}
	return result;
}

void SSL_Socket_Close(int sock)
{
	close(sock);
}
