// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.


#include "azure_c_shared_utility/ssl_socket.h"


// EXTRACT_IPV4 pulls the uint32_t IPv4 address out of an addrinfo struct
#ifdef _INC_WINAPIFAMILY	// An example WinSock test; feel free to change to a better one to compile under Windows
#define EXTRACT_IPV4(ptr) ((struct sockaddr_in *) ptr->ai_addr)->sin_addr.S_un.S_addr
#else
// The default definition handles lwIP. Please add comments for other systems tested.
#define EXTRACT_IPV4(ptr) ((struct sockaddr_in *) ptr->ai_addr)->sin_addr.s_addr
#endif


int SSL_Socket_Create(const char* serverName)
{
	return 0;
}

void SSL_Socket_Close(int socket)
{

}
