// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "openssl/ssl.h"

#include <stdio.h>
#include <stdbool.h>
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/ssl_socket.h"

#ifndef OPENSSL_DEFAULT_READ_BUFFER_SIZE
#define OPENSSL_DEFAULT_READ_BUFFER_SIZE 5120
#endif // OPENSSL_DEFAULT_READ_BUFFER_SIZE

#define CONNECT_RETRY_DELAY_MILLISECONDS 1000
#define SEND_RETRY_DELAY_MILLISECONDS 5

#ifndef TLSIO_SSL_OPEN_RETRIES
#define TLSIO_SSL_OPEN_RETRIES 10
#endif


typedef enum TLSIO_STATE_TAG
{
	TLSIO_STATE_NOT_OPEN,
	TLSIO_STATE_OPEN,
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
	uint32_t host_address;
	int port;
	char* certificate;
	const char* x509certificate;
	const char* x509privatekey;
	int sock;
} TLS_IO_INSTANCE;

// This struct is kept as static storage rather than heap storage
// as an optimization for embedded devices. This reduces heap overhead,
// avoids heap fragmentation, and eliminates several tests for NULL
// and their associated error strings.
static TLS_IO_INSTANCE tlsio_static_instance;

static void set_error_state_with_callback()
{
	tlsio_static_instance.tlsio_state = TLSIO_STATE_ERROR;
	if (tlsio_static_instance.on_io_error != NULL)
	{
		tlsio_static_instance.on_io_error(tlsio_static_instance.on_io_error_context);
	}
}


static void destroy_openssl_connection_members()
{
	if (tlsio_static_instance.ssl != NULL)
	{
		SSL_free(tlsio_static_instance.ssl);
		tlsio_static_instance.ssl = NULL;
	}
	if (tlsio_static_instance.ssl_context != NULL)
	{
		SSL_CTX_free(tlsio_static_instance.ssl_context);
		tlsio_static_instance.ssl_context = NULL;
	}
	if (tlsio_static_instance.sock < 0)
	{
		SSL_Socket_Close(tlsio_static_instance.sock);
		tlsio_static_instance.sock = -1;
	}
}

// This method tests for hard errors returned from either SSL_write or SSL_connect.
// Returns 
//     0 for SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
//     The actual error for other errors (real failures)
int is_hard_ssl_error(SSL* ssl, int callReturn)
{
	int result = 0;
	int err = SSL_get_error(ssl, callReturn);
	if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
	{
		result = err;
	}
	return result;
}


static int create_and_connect_ssl()
{
	int result = __FAILURE__;
	int ret;

	LogInfo("OpenSSL thread start...");


	int sock = SSL_Socket_Create(tlsio_static_instance.host_address, tlsio_static_instance.port);
	if (sock < 0) {
		// Error logging already happened
		result = __FAILURE__;
	}
	else
	{
		// At this point the tls_io_instance "owns" the socket, 
		// so destroy_openssl_instance must be called if the socket needs to be closed
		tlsio_static_instance.sock = sock;

		tlsio_static_instance.ssl_context = SSL_CTX_new(TLSv1_2_client_method());
		if (!tlsio_static_instance.ssl_context)
		{
			result = __FAILURE__;
			LogError("create new SSL CTX failed");
		}
		else
		{
			tlsio_static_instance.ssl = SSL_new(tlsio_static_instance.ssl_context);
			if (!tlsio_static_instance.ssl)
			{
				result = __FAILURE__;
				LogError("SSL_new failed");
			}
			else
			{
				SSL_CTX_set_default_read_buffer_len(tlsio_static_instance.ssl_context, OPENSSL_DEFAULT_READ_BUFFER_SIZE);

				// returns 1 on success
				ret = SSL_set_fd(tlsio_static_instance.ssl, sock);
				if (ret != 1)
				{
					result = __FAILURE__;
					LogError("SSL_set_fd failed");
				}
				else
				{
					// https://www.openssl.org/docs/man1.0.2/ssl/SSL_connect.html

					// "If the underlying BIO is non - blocking, SSL_connect() will also 
					// return when the underlying BIO could not satisfy the needs of 
					// SSL_connect() to continue the handshake, indicating the 
					// problem by the return value -1. In this case a call to 
					// SSL_get_error() with the return value of SSL_connect() will 
					// yield SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.The calling 
					// process then must repeat the call after taking appropriate 
					// action to satisfy the needs of SSL_connect().The action 
					// depends on the underlying BIO. When using a non - blocking 
					// socket, nothing is to be done, but select() can be used to 
					// check for the required condition."

					bool done = false;
					while (!done)
					{
						int connect_result = SSL_connect(tlsio_static_instance.ssl);

						// The manual pages seem to be incorrect. They say that 0 is a failure,
						// but by experiment, 0 is the success result, at least when using
						// SSL_set_fd instead of custom BIO.
						// https://www.openssl.org/docs/man1.0.2/ssl/SSL_connect.html
						if (connect_result == 1 || connect_result == 0)
						{
							// Connect succeeded
							done = true;
							result = 0;
						}
						else
						{
							int hard_error = is_hard_ssl_error(tlsio_static_instance.ssl, connect_result);
							if (hard_error != 0)
							{
								// Connect failed, so delete the connection objects
								done = true;
								destroy_openssl_connection_members();
								LogInfo("Error from SSL_connect: %d", hard_error);
							}
						}

						ThreadAPI_Sleep(CONNECT_RETRY_DELAY_MILLISECONDS);
					}
				}
			}
		}
	}

	return result;
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_005: [ The tlsio_openssl_create succeed. ]*/
CONCRETE_IO_HANDLE tlsio_openssl_create(void* io_create_parameters)
{
	TLSIO_CONFIG* tls_io_config = (TLSIO_CONFIG*)io_create_parameters;
	TLS_IO_INSTANCE* result = NULL;

	/* Codes_SRS_TLSIO_SSL_ESP8266_99_003: [ The tlsio_openssl_create shall return NULL when io_create_parameters is NULL. ]*/
	if (tls_io_config == NULL)
	{
		LogError("NULL tls_io_config.");
	}
	else
	{
		uint32_t ipV4 = SSL_Get_IPv4(tls_io_config->hostname);
		if (ipV4 == 0)
		{
			LogInfo("Could not get IPv4 for %s", tls_io_config->hostname);
		}
		else
		{
			result = &tlsio_static_instance;

			memset(result, 0, sizeof(TLS_IO_INSTANCE));
			result->host_address = ipV4;
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
	tls_io;
	destroy_openssl_connection_members();

	if (tlsio_static_instance.certificate != NULL)
	{
		free(tlsio_static_instance.certificate);
		tlsio_static_instance.certificate = NULL;
	}
	if (tlsio_static_instance.x509certificate != NULL)
	{
		free((void*)tlsio_static_instance.x509certificate);
		tlsio_static_instance.x509certificate = NULL;
	}
	if (tlsio_static_instance.x509privatekey != NULL)
	{
		free((void*)tlsio_static_instance.x509privatekey);
		tlsio_static_instance.x509privatekey = NULL;
	}
}


/* Codes_SRS_TLSIO_SSL_ESP8266_99_008: [ The tlsio_openssl_open shall return 0 when succeed ]*/
int tlsio_openssl_open(CONCRETE_IO_HANDLE tls_io,
	ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context,
	ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context,
	ON_IO_ERROR on_io_error, void* on_io_error_context)
{
	tls_io;
	int result = -1;
	TLS_IO_INSTANCE* tls_io_instance = &tlsio_static_instance;

	if (on_bytes_received == NULL)
	{
		LogError("Required non-NULL parameter on_bytes_received is NULL");
		result = __FAILURE__;
	}
	else
	{
		/* Codes_SRS_TLSIO_SSL_ESP8266_99_007: [ The tlsio_openssl_open invalid state. ]*/
		if (tls_io_instance->tlsio_state != TLSIO_STATE_NOT_OPEN)
		{
			result = __FAILURE__;
			LogError("Invalid tlsio_state. Expected state is TLSIO_STATE_NOT_OPEN.");

			// Set up the error values so set_error_state_with_callback can use them
			tls_io_instance->on_io_error = on_io_error;
			tls_io_instance->on_io_error_context = on_io_error_context;

			set_error_state_with_callback();
		}
		else
		{
			tls_io_instance->on_io_open_complete = on_io_open_complete;
			tls_io_instance->on_io_open_complete_context = on_io_open_complete_context;

			tls_io_instance->on_bytes_received = on_bytes_received;
			tls_io_instance->on_bytes_received_context = on_bytes_received_context;

			tls_io_instance->on_io_error = on_io_error;
			tls_io_instance->on_io_error_context = on_io_error_context;

			if (create_and_connect_ssl() != 0)
			{
				LogError("create_and_connect_ssl failed.");
				set_error_state_with_callback();
				result = __FAILURE__;
			}
			else
			{
				tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
				if (tls_io_instance->on_io_open_complete)
				{
					tls_io_instance->on_io_open_complete(tls_io_instance->on_io_open_complete_context, IO_OPEN_OK);
				}
				result = 0;
			}
		}
	}
	return result;
}


/* Codes_SRS_TLSIO_SSL_ESP8266_99_013: [ The tlsio_openssl_close succeed.]*/
int tlsio_openssl_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
	tls_io;
	//LogInfo("tlsio_openssl_close");
	int result;

	TLS_IO_INSTANCE* tls_io_instance = &tlsio_static_instance;


	// TODO: ALWAYS DO THE CLOSE!!!!!
	if (tls_io_instance->tlsio_state == TLSIO_STATE_NOT_OPEN)
	{
		result = __FAILURE__;
		tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
		LogError("Invalid tlsio_state. Expected state is TLSIO_STATE_OPEN or TLSIO_STATE_ERROR.");
	}
	else
	{
		tls_io_instance->on_io_close_complete = on_io_close_complete;
		tls_io_instance->on_io_close_complete_context = callback_context;

		(void)SSL_shutdown(tls_io_instance->ssl);
		destroy_openssl_connection_members();
		tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
		result = 0;
		if (tls_io_instance->on_io_close_complete != NULL)
		{
			tls_io_instance->on_io_close_complete(tls_io_instance->on_io_close_complete_context);
		}
	}
	return result;
}

int tlsio_openssl_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
	tls_io;
	int result = __FAILURE__;
	size_t bytes_to_send = size;

	if (buffer == NULL)
	{
		/* Codes_SRS_TLSIO_SSL_ESP8266_99_014: [ The tlsio_openssl_send NULL instance.]*/
		result = __FAILURE__;
		LogError("NULL buffer.");
	}
	else
	{
		TLS_IO_INSTANCE* tls_io_instance = &tlsio_static_instance;

		if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN)
		{
			/* Codes_SRS_TLSIO_SSL_ESP8266_99_015: [ The tlsio_openssl_send wrog state.]*/
			result = __FAILURE__;
			LogError("Invalid tlsio_state for send. Expected state is TLSIO_STATE_OPEN.");
		}
		else
		{
			unsigned int total_written = 0;
			int res = 0;

			while (size > 0)
			{
				/* Codes_SRS_TLSIO_SSL_ESP8266_99_016: [ The tlsio_openssl_send SSL_write success]*/
				/* Codes_SRS_TLSIO_SSL_ESP8266_99_017: [ The tlsio_openssl_send SSL_write failure]*/
				res = SSL_write(tls_io_instance->ssl, ((uint8_t*)buffer) + total_written, size);
				// https://wiki.openssl.org/index.php/Manual:SSL_write(3)

				if (res > 0)
				{
					total_written += res;
					size = size - res;
				}
				else
				{
					// SSL_write returned non-success. It may just be busy, or it may be broken.
					int hard_error = is_hard_ssl_error(tls_io_instance->ssl, res);
					if (hard_error != 0)
					{
						// This is an unexpected error, and we need to bail out.
						LogInfo("Error from SSL_write: %d", hard_error);
						break;
					}
				}
				// Try again real soon
				ThreadAPI_Sleep(SEND_RETRY_DELAY_MILLISECONDS);
			}

			IO_SEND_RESULT sr = IO_SEND_ERROR;
			if (total_written == bytes_to_send)
			{
				sr = IO_SEND_OK;
				result = 0;
			}
			else
			{
				set_error_state_with_callback();
			}

			if (on_send_complete != NULL)
			{
				on_send_complete(callback_context, sr);
			}
		}
	}
	return result;
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_019: [ The tlsio_openssl_dowork succeed]*/
void tlsio_openssl_dowork(CONCRETE_IO_HANDLE tls_io)
{
	tls_io;
	if (tlsio_static_instance.tlsio_state == TLSIO_STATE_OPEN)
	{
		unsigned char buffer[64];
		int rcv_bytes;

		// SSL_read is not checked for errors because it never reports anything useful
		rcv_bytes = SSL_read(tlsio_static_instance.ssl, buffer, sizeof(buffer));
		if (rcv_bytes > 0)
		{
			// tlsio_static_instance.on_bytes_received was already checked for NULL
			// in the call to tlsio_openssl_open
			tlsio_static_instance.on_bytes_received(tlsio_static_instance.on_bytes_received_context, buffer, rcv_bytes);
		}
	}
	else if (tlsio_static_instance.tlsio_state == TLSIO_STATE_NOT_OPEN)
	{
		LogError("Invalid tlsio_state for dowork. Expected state is TLSIO_STATE_OPEN.");
		tlsio_static_instance.tlsio_state = TLSIO_STATE_ERROR;
		if (tlsio_static_instance.on_io_error)
		{
			tlsio_static_instance.on_io_error(tlsio_static_instance.on_io_error_context);
		}
	}
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_002: [ The tlsio_arduino_setoption shall not do anything, and return 0. ]*/
int tlsio_openssl_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
	tls_io;
	value;
	optionName;
	return 0;
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_001: [ The tlsio_openssl_retrieveoptions shall not do anything, and return NULL. ]*/
static OPTIONHANDLER_HANDLE tlsio_openssl_retrieveoptions(CONCRETE_IO_HANDLE handle)
{
	handle;
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

const IO_INTERFACE_DESCRIPTION* tlsio_openssl_get_interface_description(void)
{
	return &tlsio_openssl_interface_description;
}
