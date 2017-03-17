// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

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
#include "azure_c_shared_utility/ssl_socket.h"

#ifndef OPENSSL_DEFAULT_READ_BUFFER_SIZE
    #define OPENSSL_DEFAULT_READ_BUFFER_SIZE 5120
#endif // OPENSSL_DEFAULT_READ_BUFFER_SIZE

#define OPENSSL_LOCAL_TCP_PORT 1000
#define MAX_RETRY 20
#define MAX_RETRY_WRITE 500
#define RETRY_DELAY 1000


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

static TLS_IO_INSTANCE tlsio_static_instance;



#define SSL_MIN_FRAG_LEN                    2048
#define SSL_MAX_FRAG_LEN                    8192
#define SSL_DEFAULT_FRAG_LEN                2048


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


static int openssl_thread_LWIP_CONNECTION(TLS_IO_INSTANCE* tls_io_instance)
{
	int result;
	int ret;
	int sock;

	//struct sockaddr_in sock_addr;

	SSL_CTX *ctx;
	SSL *ssl;

	LogInfo("OpenSSL thread start...");


	sock = SSL_Socket_Create(tls_io_instance->hostname, tls_io_instance->port);
	if (sock < 0) {
		result = __LINE__;
	}
	else
	{
		tls_io_instance->sock = sock;

		ctx = SSL_CTX_new(TLSv1_2_client_method());
		if (!ctx)
		{
			result = __LINE__;
			LogError("create new SSL CTX failed");
		}
		else
		{
			ssl = SSL_new(ctx);
			if (!ssl)
			{
				result = __LINE__;
				LogError("create ssl failed");
			}
			else
			{
				SSL_CTX_set_default_read_buffer_len(ctx, OPENSSL_DEFAULT_READ_BUFFER_SIZE);

				// returns 1 on success
				ret = SSL_set_fd(ssl, sock);
				if (ret != 1)
				{
					result = __LINE__;
					LogError("SSL_set_fd failed");
				}
				else {
					LogInfo("SSL connect... ");
					int retry = 0;
					while (SSL_connect(ssl) != 0 && retry < MAX_RETRY)
					{
						// According to the OpenSSL man page, there's nothing to do
						// for a non-blocking socket but wait 
						// ("... nothing is to be done...")

						// "If the underlying BIO is non - blocking, SSL_connect() will also 
						// return when the underlying BIO could not satisfy the needs of 
						// SSL_connect() to continue the handshake, indicating the 
						// problem by the return value - 1. In this case a call to 
						// SSL_get_error() with the return value of SSL_connect() will 
						// yield SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.The calling 
						// process then must repeat the call after taking appropriate 
						// action to satisfy the needs of SSL_connect().The action 
						// depends on the underlying BIO.When using a non - blocking 
						// socket, nothing is to be done, but select() can be used to 
						// check for the required condition."

						retry++;
						ThreadAPI_Sleep(RETRY_DELAY);
					}
					if (retry >= MAX_RETRY)
					{
						result = __LINE__;
						LogError("SSL_connect failed \n");
					}
					else
					{
						tls_io_instance->ssl = ssl;
						tls_io_instance->ssl_context = ctx;
						result = 0;
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
	if (openssl_thread_LWIP_CONNECTION(tls_io_instance) != 0) {
		result = __LINE__;

    
    
    
        // TODO: make sure the following thing happens somewhere appropriate if thread start fails
    
        //if (result != 0) {
        //    tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        //}
        //return result;

    
    
    
    
    
    
    
    }
	else {
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
        if (tls_io_instance->sock < 0)
        {
            SSL_Socket_Close(tls_io_instance->sock);
            tls_io_instance->sock = -1;
        }
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
        result = &tlsio_static_instance;

		memset(result, 0, sizeof(TLS_IO_INSTANCE));
		int ret = mallocAndStrcpy_s(&result->hostname, tls_io_config->hostname);
        if (ret != 0)
        {
            // Errors already logged (and very unlikely) so no further logging here
            result = NULL;
        }
        else
        {
            result->port = tls_io_config->port;

            result->sock = -1;

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
            tls_io_instance->certificate = NULL;
		}
		if (tls_io_instance->hostname != NULL)
		{
			free(tls_io_instance->hostname);
            tls_io_instance->hostname = NULL;
        }
		if (tls_io_instance->x509certificate != NULL)
		{
			free((void*)tls_io_instance->x509certificate);
            tls_io_instance->x509certificate = NULL;
        }
		if (tls_io_instance->x509privatekey != NULL)
		{
			free((void*)tls_io_instance->x509privatekey);
            tls_io_instance->x509privatekey = NULL;
        }
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

			if (send_handshake_bytes(tls_io_instance) != 0) {
				result = __LINE__;
				tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
				LogError("send_handshake_bytes failed.");
				if (tls_io_instance->on_io_error != NULL)
				{
					tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
				}
			}
			else {
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

			while (size > 0 && retry < MAX_RETRY_WRITE) {
				/* Codes_SRS_TLSIO_SSL_ESP8266_99_016: [ The tlsio_openssl_send SSL_write success]*/
				/* Codes_SRS_TLSIO_SSL_ESP8266_99_017: [ The tlsio_openssl_send SSL_write failure]*/
				res = SSL_write(tls_io_instance->ssl, ((uint8_t*)buffer) + total_write, size);

				//LogInfo("SSL_write res: %d, size: %d, retry: %d", res, size, retry);
			   // LogInfo("SSL_write res:%d size:%d retry:%d\n",res,size,retry);

				if (res > 0) {
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
