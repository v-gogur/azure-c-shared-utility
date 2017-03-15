// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

//#include "openssl/ssl_compat-1.0.h"
//#include "../../../../openssl/include/internal/ssl_types.h"
//#include "ssl_pm.h"
//#include "ssl_opt.h"
#include "lwip/opt.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/dns.h"
#include "lwip/err.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/ip_addr.h"
#include "lwip/api.h"
#include "lwip/netdb.h"
//#include "openssl_client.h"
#include "openssl/ssl.h"

#include <stdio.h>
#include <stdbool.h>
#include "azure_c_shared_utility/lock.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/tlsio_openssl.h"
#include "azure_c_shared_utility/socketio.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/threadapi.h"

#define OPENSSL_FRAGMENT_SIZE 5120
#define OPENSSL_LOCAL_TCP_PORT 1000
#define MAX_RETRY 20
#define MAX_RETRY_WRITE 500
#define RETRY_DELAY 1000

// The EXTRACT_IPV4 may have to be redefined for different systems to extract the uint32_t AF_INET address
#ifdef _INC_WINAPIFAMILY	// An example WinSock test; feel free to change to a better one to compile under Windows
#define EXTRACT_IPV4(ptr) ((struct sockaddr_in *) ptr->ai_addr)->sin_addr.S_un.S_addr
#else
// The default definition handles lwIP. Please add comments for other systems tested.
#define EXTRACT_IPV4(ptr) ((struct sockaddr_in *) ptr->ai_addr)->sin_addr.s_addr
#endif


typedef enum TLSIO_STATE_TAG
{
    TLSIO_STATE_NOT_OPEN,
    TLSIO_STATE_OPENING,
    TLSIO_STATE_OPEN,
    TLSIO_STATE_CLOSING,
    TLSIO_STATE_ERROR
} TLSIO_STATE;

typedef struct TLS_IO_INSTANCE_TAG
{
    ON_BYTES_RECEIVED on_bytes_received;
    ON_IO_OPEN_COMPLETE on_io_open_complete;
    ON_IO_CLOSE_COMPLETE on_io_close_complete;
    ON_IO_ERROR on_io_error;
    void* on_bytes_received_context;
    void* on_io_open_complete_context;
    void* on_io_close_complete_context;
    void* on_io_error_context;
    SSL* ssl;
    SSL_CTX* ssl_context;
    TLSIO_STATE tlsio_state;
    char* hostname;
    int port;
    char* certificate;
    const char* x509certificate;
    const char* x509privatekey;
    int sock;
} TLS_IO_INSTANCE;



#define SSL_MIN_FRAG_LEN                    2048
#define SSL_MAX_FRAG_LEN                    8192
#define SSL_DEFAULT_FRAG_LEN                2048


int SSL_set_fragment(SSL_CTX *ctx, unsigned int frag)
{
    if (frag < SSL_MIN_FRAG_LEN || frag > SSL_MAX_FRAG_LEN)
    {
    	printf("error! too long fragment.\n");
    	return -1;
    }
    else
    {
        return 0;
    }
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_001: [ The tlsio_openssl_retrieveoptions shall not do anything, and return NULL. ]*/
static OPTIONHANDLER_HANDLE tlsio_openssl_retrieveoptions(CONCRETE_IO_HANDLE handle)
{
    OPTIONHANDLER_HANDLE result = NULL;
    return result;
}

static const IO_INTERFACE_DESCRIPTION tlsio_openssl_interface_description =
{
    tlsio_openssl_retrieveoptions,
    tlsio_openssl_create,
    tlsio_openssl_destroy,
    tlsio_openssl_open,
    tlsio_openssl_close,
    tlsio_openssl_send,
    tlsio_openssl_dowork,
    tlsio_openssl_setoption
};


static void indicate_open_complete(TLS_IO_INSTANCE* tls_io_instance, IO_OPEN_RESULT open_result)
{
    if (tls_io_instance->on_io_open_complete == NULL)
    {
        LogError("NULL on_io_open_complete.");
    }
    else
    {
        tls_io_instance->on_io_open_complete(tls_io_instance->on_io_open_complete_context, open_result);
    }
}


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


static int openssl_thread_LWIP_CONNECTION(TLS_IO_INSTANCE* tls_io_instance)
{
    int result;
    int ret;
    int sock;

    struct sockaddr_in sock_addr;
    fd_set readset;
    fd_set writeset;
    fd_set errset;

    SSL_CTX *ctx;
    SSL *ssl;

    LogInfo("OpenSSL thread start...");

	uint32_t ipV4address = get_ipv4(tls_io_instance->hostname);

	if (ipV4address == 0)
	{
		// TODO: Get rid of this return in the middle (roy)
		return -1;
	}



     LogInfo("create socket ......");
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        result = __LINE__;
        LogError("create socket failed");
    }
    else
    {
        tls_io_instance->sock = sock;

		LogInfo("set socket keep-alive ");
		int keepAlive = 1; //enable keepalive
		int keepIdle = 20; //20s
		int keepInterval = 2; //2s
		int keepCount = 3; //retry # of times

		ret = 0;
		ret = ret || setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive));
		ret = ret || setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&keepIdle, sizeof(keepIdle));
		ret = ret || setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&keepInterval, sizeof(keepInterval));
		ret = ret || setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (void *)&keepCount, sizeof(keepCount));

		if (ret != 0) {
			result = __LINE__;
			LogError("set socket keep-alive failed, ret = %d ", ret);
			return result;
			// TODO: fix this return in the middle
		}
		else
		{
			LogInfo("set socket keep-alive OK");
		}

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
        
        if (ret) {
            result = __LINE__;
            LogError("bind socket failed");
        }
        else
        {
			memset(&sock_addr, 0, sizeof(sock_addr));
			sock_addr.sin_family = AF_INET;
			sock_addr.sin_addr.s_addr = ipV4address;
			sock_addr.sin_port = htons(tls_io_instance->port);

			ret = connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
            if (ret == -1) {
                ret = get_socket_errno(sock);
                if (ret != EINPROGRESS){
                    result = __LINE__;
                    ret = -1;
                    close(sock);
                    LogError("socket connect failed, not EINPROGRESS %s", tls_io_instance->hostname);
                }
            }

            if(ret != -1)
            {
                int retry = 0;

                while (retry < MAX_RETRY){
                    FD_ZERO(&readset);
                    FD_SET(sock, &readset);
                
                    FD_ZERO(&writeset);
                    FD_SET(sock, &writeset);
                
                    FD_ZERO(&errset);
                    FD_SET(sock, &errset);
                
                    ret = lwip_select(sock + 1, &readset, &writeset, &errset, NULL);
                    if (ret > 0){
                        if (FD_ISSET(sock, &writeset)){
                          break;
                        }
                
                        if (FD_ISSET(sock, &readset)){
                            break;
                        }
                    }

                    retry++;
					ThreadAPI_Sleep(RETRY_DELAY);
                }

                ctx = SSL_CTX_new(TLSv1_client_method());
                if (!ctx) {
                    result = __LINE__;
                    LogError("create new SSL CTX failed");
                }
                else
                {
                    ret = SSL_set_fragment(ctx, OPENSSL_FRAGMENT_SIZE);
                    if (ret != 0){
                        result = __LINE__;
                        LogError("SSL_set_fragment failed");
                    }
                    else
                    {
                        ssl = SSL_new(ctx);
                        if (!ssl) {
                            result = __LINE__;
                            LogError("create ssl failed");
                        }
                        else
                        {
                            // returns 1 on success
                            ret = SSL_set_fd(ssl, sock);
                            //(void*)printf("SSL_set_fd ret:%d \n", ret);
                            if (ret != 1){
                                result = __LINE__;
                                LogError("SSL_set_fd failed");
                            }
                            else{
                                // LogInfo("SSL connect... ");
                            	printf("SSL connect... \n");
                                int retry = 0;
                                while (SSL_connect(ssl) != 0 && retry < MAX_RETRY)
                                {  
                                    FD_ZERO(&readset);
                                    FD_SET(sock, &readset);
                                    FD_ZERO(&writeset);
                                    FD_SET(sock, &writeset);
                                    FD_ZERO(&errset);
                                    FD_SET(sock, &errset);

                                    lwip_select(sock + 1, &readset, &writeset, &errset, NULL);

                                    retry++;
									ThreadAPI_Sleep(RETRY_DELAY);
                                }
                                if (retry >= MAX_RETRY)
                                {
                                    result = __LINE__;
                                    LogError("SSL_connect failed \n");
                                    printf("SSL_connect failed \n");
                                }else{
                                    tls_io_instance->ssl = ssl;
                                    tls_io_instance->ssl_context = ctx;
                                    result = 0;
                                    printf("SSL_connect succeed");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return result;
}

static int send_handshake_bytes(TLS_IO_INSTANCE* tls_io_instance)
{
    //system_print_meminfo(); // This is useful for debugging purpose.
    //LogInfo("free heap size %d", system_get_free_heap_size()); // This is useful for debugging purpose.
    int result;
    if (openssl_thread_LWIP_CONNECTION(tls_io_instance) != 0){
        result = __LINE__;
    }else{
        tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
        indicate_open_complete(tls_io_instance, IO_OPEN_OK);    
        result = 0;
    }

    return result;
}


static int decode_ssl_received_bytes(TLS_IO_INSTANCE* tls_io_instance)
{
    int result;
    unsigned char buffer[64];

    int rcv_bytes;
    rcv_bytes = SSL_read(tls_io_instance->ssl, buffer, sizeof(buffer));
    // LogInfo("decode ssl recv bytes: %d", rcv_bytes);
    if (rcv_bytes > 0)
    {
        if (tls_io_instance->on_bytes_received == NULL)
        {
            LogError("NULL on_bytes_received.");
        }
        else
        {
            tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, buffer, rcv_bytes);
        }
    }
    result = 0;
    return result;
}

static void destroy_openssl_instance(TLS_IO_INSTANCE* tls_io_instance)
{
    if (tls_io_instance != NULL)
    {
        if (tls_io_instance->ssl != NULL)
        {
            SSL_free(tls_io_instance->ssl);
            tls_io_instance->ssl = NULL;
        }
        if (tls_io_instance->ssl_context != NULL)
        {
            SSL_CTX_free(tls_io_instance->ssl_context);
            tls_io_instance->ssl_context = NULL;
        }
        close(tls_io_instance->sock);
    }
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_005: [ The tlsio_openssl_create succeed. ]*/
CONCRETE_IO_HANDLE tlsio_openssl_create(void* io_create_parameters)
{
    TLSIO_CONFIG* tls_io_config = (TLSIO_CONFIG*)io_create_parameters;
    TLS_IO_INSTANCE* result;

    /* Codes_SRS_TLSIO_SSL_ESP8266_99_003: [ The tlsio_openssl_create shall return NULL when io_create_parameters is NULL. ]*/
    if (tls_io_config == NULL)
    {
        result = NULL;
        LogError("NULL tls_io_config.");
    }
    else
    {
        /* Codes_SRS_TEMPLATE_99_004: [ The tlsio_openssl_create shall return NULL when malloc fails. ]*/
        result = (TLS_IO_INSTANCE*) malloc(sizeof(TLS_IO_INSTANCE));
        // LogInfo("result is 0x%x", result);

        if (result == NULL)
        {
            LogError("Failed allocating TLSIO instance.");
        }
        else
        {
            memset(result, 0, sizeof(TLS_IO_INSTANCE));
            mallocAndStrcpy_s(&result->hostname, tls_io_config->hostname);
            result->port = tls_io_config->port;
            result->ssl_context = NULL;
            result->ssl = NULL;
            result->certificate = NULL;

            result->on_bytes_received = NULL;
            result->on_bytes_received_context = NULL;

            result->on_io_open_complete = NULL;
            result->on_io_open_complete_context = NULL;

            result->on_io_close_complete = NULL;
            result->on_io_close_complete_context = NULL;

            result->on_io_error = NULL;
            result->on_io_error_context = NULL;

            result->tlsio_state = TLSIO_STATE_NOT_OPEN;

            result->x509certificate = NULL;
            result->x509privatekey = NULL;
        }
    }

    return (CONCRETE_IO_HANDLE)result;
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_010: [ The tlsio_openssl_destroy succeed ]*/
void tlsio_openssl_destroy(CONCRETE_IO_HANDLE tls_io)
{
    /* Codes_SRS_TLSIO_SSL_ESP8266_99_009: [ The tlsio_openssl_destroy NULL parameter. make sure there is no crash ]*/
    if (tls_io == NULL)
    {
        LogError("NULL tls_io.");
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
        if (tls_io_instance->certificate != NULL)
        {
            free(tls_io_instance->certificate);
        }
        if (tls_io_instance->hostname != NULL)
        {
            free(tls_io_instance->hostname);
        }
        if (tls_io_instance->x509certificate != NULL)
        {
            free((void*)tls_io_instance->x509certificate);
        }
        if (tls_io_instance->x509privatekey != NULL)
        {
            free((void*)tls_io_instance->x509privatekey);
        }
        free(tls_io);
    }
}


/* Codes_SRS_TLSIO_SSL_ESP8266_99_008: [ The tlsio_openssl_open shall return 0 when succeed ]*/
int tlsio_openssl_open(CONCRETE_IO_HANDLE tls_io, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
{
    int result;

    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_SSL_ESP8266_99_006: [ The tlsio_openssl_open failed because tls_io is NULL. ]*/
        result = __LINE__;
        LogError("NULL tls_io.");
    }
    else
    {

        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        /* Codes_SRS_TLSIO_SSL_ESP8266_99_007: [ The tlsio_openssl_open invalid state. ]*/
        if (tls_io_instance->tlsio_state != TLSIO_STATE_NOT_OPEN)
        {
            tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
            tls_io_instance->on_io_error = on_io_error;
            tls_io_instance->on_io_error_context = on_io_error_context;

            result = __LINE__;
            LogError("Invalid tlsio_state. Expected state is TLSIO_STATE_NOT_OPEN.");
            if (tls_io_instance->on_io_error != NULL)
            {
                tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
            }
        }
        else
        {
            tls_io_instance->on_io_open_complete = on_io_open_complete;
            tls_io_instance->on_io_open_complete_context = on_io_open_complete_context;

            tls_io_instance->on_bytes_received = on_bytes_received;
            tls_io_instance->on_bytes_received_context = on_bytes_received_context;

            tls_io_instance->on_io_error = on_io_error;
            tls_io_instance->on_io_error_context = on_io_error_context;

            tls_io_instance->tlsio_state = TLSIO_STATE_OPENING;

            if (send_handshake_bytes(tls_io_instance) != 0){
                result = __LINE__;
                tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
                LogError("send_handshake_bytes failed.");
                if (tls_io_instance->on_io_error != NULL)
                {
                    tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
                }
            }else{
                result = 0;
                tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
            }
        }
    }
    return result;
}


/* Codes_SRS_TLSIO_SSL_ESP8266_99_013: [ The tlsio_openssl_close succeed.]*/
int tlsio_openssl_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
    //LogInfo("tlsio_openssl_close");
    int result;

    /* Codes_SRS_TLSIO_SSL_ESP8266_99_011: [ The tlsio_openssl_close NULL parameter.]*/
    if (tls_io == NULL)
    {
        result = __LINE__;
        LogError("NULL tls_io.");
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if ((tls_io_instance->tlsio_state == TLSIO_STATE_NOT_OPEN) ||
            (tls_io_instance->tlsio_state == TLSIO_STATE_CLOSING) ||
            (tls_io_instance->tlsio_state == TLSIO_STATE_OPENING))
        {
            result = __LINE__;
            tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
            LogError("Invalid tlsio_state. Expected state is TLSIO_STATE_OPEN or TLSIO_STATE_ERROR.");
        }
        else
        {
            tls_io_instance->tlsio_state = TLSIO_STATE_CLOSING;
            tls_io_instance->on_io_close_complete = on_io_close_complete;
            tls_io_instance->on_io_close_complete_context = callback_context;

            (void)SSL_shutdown(tls_io_instance->ssl);
            //(void*)printf("SSL_shutdown ret: %d \n", ret);
            destroy_openssl_instance(tls_io_instance);
            tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
            result = 0;
            if (tls_io_instance->on_io_close_complete != NULL)
            {
                tls_io_instance->on_io_close_complete(tls_io_instance->on_io_close_complete_context);
            }
        }
    }
    return result;
}

int tlsio_openssl_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;

    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_SSL_ESP8266_99_014: [ The tlsio_openssl_send NULL instance.]*/
        result = __LINE__;
        LogError("NULL tls_io.");
    }
    else if (buffer == NULL)
    {
        /* Codes_SRS_TLSIO_SSL_ESP8266_99_014: [ The tlsio_openssl_send NULL instance.]*/
        result = __LINE__;
        LogError("NULL buffer.");
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN)
        {
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_015: [ The tlsio_openssl_send wrog state.]*/
            result = __LINE__;
            LogError("Invalid tlsio_state for send. Expected state is TLSIO_STATE_OPEN.");
        }
        else
        {
            int total_write = 0;
            int res = 0;
            int retry = 0;

            while(size > 0 && retry < MAX_RETRY_WRITE){
                /* Codes_SRS_TLSIO_SSL_ESP8266_99_016: [ The tlsio_openssl_send SSL_write success]*/
                /* Codes_SRS_TLSIO_SSL_ESP8266_99_017: [ The tlsio_openssl_send SSL_write failure]*/
                res = SSL_write(tls_io_instance->ssl, ((uint8_t*)buffer)+total_write, size);

                //printf("SSL_write res: %d, size: %d, retry: %d", res, size, retry);
               // printf("SSL_write res:%d size:%d retry:%d\n",res,size,retry);

                if(res > 0){
                    total_write += res;
                    size = size - res;
                }
                else
                {
                    retry++;
                }
                //vTaskDelay(5);
				// TODO: If this sleep is 5 msec then the device goes into an infinite
				// loop of failure. That is very wrong, and probably indicates a need
				// for redesign. Loop timing should be mere optimization. (roy)
				ThreadAPI_Sleep(50);
            }

            if (retry >= MAX_RETRY_WRITE)
            {
                result = __LINE__;
                if (on_send_complete != NULL)
                {
                    on_send_complete(callback_context, IO_SEND_ERROR);
                }
            }
            else
            {
                result = 0;
                if (on_send_complete != NULL)
                {
                    on_send_complete(callback_context, IO_SEND_OK);
                }
            }
        }
    }
    return result;
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_019: [ The tlsio_openssl_dowrok succeed]*/
void tlsio_openssl_dowork(CONCRETE_IO_HANDLE tls_io)
{
    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_SSL_ESP8266_99_018: [ The tlsio_openssl_dowork NULL parameter. No crash when passing NULL]*/
        LogError("NULL tls_io.");
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
        {
            decode_ssl_received_bytes(tls_io_instance);
        } 
        else
        {
            LogError("Invalid tlsio_state for dowork. Expected state is TLSIO_STATE_OPEN.");
        }
    }

}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_002: [ The tlsio_arduino_setoption shall not do anything, and return 0. ]*/
int tlsio_openssl_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
    return 0;
}

const IO_INTERFACE_DESCRIPTION* tlsio_openssl_get_interface_description(void)
{
    return &tlsio_openssl_interface_description;
}
