// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "openssl/ssl.h"

#include <stdio.h>
#include <stdbool.h>
#include "azure_c_shared_utility/gballoc.h"
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

// This adapter keeps itself in either TLSIO_STATE_OPEN, which
// or TLSIO_STATE_NOT_OPEN. There are no internally inconsistent
// states that would need to be labeled "error". Failures that
// tell us that the SSL connection can no longer be trusted
// cause the adapter to close the connection and release all
// resources, at which point it is ready for Open to be called
// again.
typedef enum TLSIO_STATE_TAG
{
	TLSIO_STATE_NOT_OPEN,
	TLSIO_STATE_OPEN,
} TLSIO_STATE;

typedef struct TLS_IO_INSTANCE_TAG
{
	ON_BYTES_RECEIVED on_bytes_received;
	ON_IO_ERROR on_io_error;
	void* on_bytes_received_context;
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

static const char* null_tlsio_message = "NULL tlsio";

#define ASSIGN_AND_CHECK_TLSIO_INSTANCE \
	TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io; \
	if (tls_io_instance == NULL)  \
	{		\
		LogError(null_tlsio_message);	\
	}		\
	else	


static void internal_close(TLS_IO_INSTANCE* tls_io_instance)
{
	// The TLSIO_STATE_OPEN is semantically identical to the state where
	// SSL_shutdown needs to be called.
	if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
	{
		(void)SSL_shutdown(tls_io_instance->ssl);
	}

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
	if (tls_io_instance->sock >= 0)
	{
		SSL_Socket_Close(tls_io_instance->sock);
		tls_io_instance->sock = -1;
	}

	tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
}

static void Internal_close_with_stored_error_callback(TLS_IO_INSTANCE* tls_io_instance)
{
	internal_close(tls_io_instance);
	if (tls_io_instance->on_io_error != NULL)
	{
		tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
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


static int create_and_connect_ssl(TLS_IO_INSTANCE* tls_io_instance)
{
	int result = __FAILURE__;
	int ret;

	LogInfo("OpenSSL thread start...");


	int sock = SSL_Socket_Create(tls_io_instance->host_address, tls_io_instance->port);
	if (sock < 0) {
		// This is a communication interruption rather than a program bug
		LogInfo("Could not open the socket");
		result = __FAILURE__;
	}
	else
	{
		// At this point the tls_io_instance "owns" the socket, 
		// so destroy_openssl_instance must be called if the socket needs to be closed
		tls_io_instance->sock = sock;

		tls_io_instance->ssl_context = SSL_CTX_new(TLSv1_2_client_method());
		if (!tls_io_instance->ssl_context)
		{
			result = __FAILURE__;
			LogError("create new SSL CTX failed");
		}
		else
		{
			tls_io_instance->ssl = SSL_new(tls_io_instance->ssl_context);
			if (!tls_io_instance->ssl)
			{
				result = __FAILURE__;
				LogError("SSL_new failed");
			}
			else
			{
				SSL_CTX_set_default_read_buffer_len(tls_io_instance->ssl_context, OPENSSL_DEFAULT_READ_BUFFER_SIZE);

				// returns 1 on success
				ret = SSL_set_fd(tls_io_instance->ssl, sock);
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
						int connect_result = SSL_connect(tls_io_instance->ssl);

						// The following note applies to the Espressif ESP32 implementation
						// of OpenSSL:
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
							int hard_error = is_hard_ssl_error(tls_io_instance->ssl, connect_result);
							if (hard_error != 0)
							{
								// Connect failed, so delete the connection objects
								done = true;
								internal_close(tls_io_instance);
								LogInfo("Hard error from SSL_connect: %d", hard_error);
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

/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_009: [ The tlsio_openssl_compact_create shall allocate, initialize, and return an instance of the tlsio for compact OpenSSL. ]*/
CONCRETE_IO_HANDLE tlsio_openssl_create(void* io_create_parameters)
{
	/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_005: [ The tlsio_openssl_compact shall receive the connection information using the TLSIO_CONFIG structure defined in tlsio.h ]*/
	/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_012: [ The tlsio_openssl_compact_create shall receive the connection configuration (TLSIO_CONFIG). ]*/
	TLSIO_CONFIG* tls_io_config = (TLSIO_CONFIG*)io_create_parameters;
	TLS_IO_INSTANCE* result = NULL;

	/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_013: [ If the io_create_parameters value is NULL, tlsio_openssl_compact_create shall log an error and return NULL. ]*/
	if (io_create_parameters == NULL)
	{
		LogError("NULL tls_io_config.");
	}
	else
	{
		/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_014: [ The tlsio_openssl_compact_create shall convert the provided hostName to an IPv4 address. ]*/
		uint32_t ipV4 = SSL_Get_IPv4(tls_io_config->hostname);
		if (ipV4 == 0)
		{
			/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_015: [ If the IP for the hostName cannot be found, tlsio_openssl_compact_create shall return NULL. ]*/
			LogInfo("Could not get IPv4 for %s", tls_io_config->hostname);
		}
		else
		{
			result = malloc(sizeof(TLS_IO_INSTANCE));
			if (!result)
			{
				/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_010: [ If the allocation fails, tlsio_openssl_compact_create shall return NULL. ]*/
				LogError("Failed to allocate tlsio instance.");
			}
			else
			{
				memset(result, 0, sizeof(TLS_IO_INSTANCE));
				result->host_address = ipV4;
				result->port = tls_io_config->port;

				result->sock = -1;

				result->ssl_context = NULL;
				result->ssl = NULL;
				result->certificate = NULL;

				/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_011: [ The tlsio_openssl_compact_create shall initialize all internal callback pointers as NULL. ]*/
				result->on_bytes_received = NULL;
				result->on_bytes_received_context = NULL;
				result->on_io_error = NULL;
				result->on_io_error_context = NULL;

				result->tlsio_state = TLSIO_STATE_NOT_OPEN;

				result->x509certificate = NULL;
				result->x509privatekey = NULL;
			}
		}
	}

	return (CONCRETE_IO_HANDLE)result;
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_010: [ The tlsio_openssl_destroy succeed ]*/
void tlsio_openssl_destroy(CONCRETE_IO_HANDLE tls_io)
{
	ASSIGN_AND_CHECK_TLSIO_INSTANCE
	{
		internal_close(tls_io_instance);

		if (tls_io_instance->certificate != NULL)
		{
			free(tls_io_instance->certificate);
			tls_io_instance->certificate = NULL;
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

		free(tls_io_instance);
	}
}


/* Codes_SRS_TLSIO_SSL_ESP8266_99_008: [ The tlsio_openssl_open shall return 0 when succeed ]*/
int tlsio_openssl_open(CONCRETE_IO_HANDLE tls_io,
	ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context,
	ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context,
	ON_IO_ERROR on_io_error, void* on_io_error_context)
{
	int result = -1;
	ASSIGN_AND_CHECK_TLSIO_INSTANCE
	{
		tls_io_instance->on_bytes_received = on_bytes_received;
		tls_io_instance->on_bytes_received_context = on_bytes_received_context;

		tls_io_instance->on_io_error = on_io_error;
		tls_io_instance->on_io_error_context = on_io_error_context;

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
			}
			else
			{
				if (create_and_connect_ssl(tls_io_instance) != 0)
				{
					result = __FAILURE__;
				}
				else
				{
					tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
					result = 0;
				}
			}
		}
		if (result != 0)
		{
			Internal_close_with_stored_error_callback(tls_io_instance);
		}
	}

	if (on_io_open_complete)
	{
		/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_002: [ The tlsio_openssl_compact shall report the open operation status using the IO_OPEN_RESULT enumerator defined in the xio.h ]*/
		on_io_open_complete(on_io_open_complete_context, result == 0 ? IO_OPEN_OK : IO_OPEN_ERROR);
	}
	return result;
}


/* Codes_SRS_TLSIO_SSL_ESP8266_99_013: [ The tlsio_openssl_close succeed.]*/
int tlsio_openssl_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
	int result = 0;

	ASSIGN_AND_CHECK_TLSIO_INSTANCE
	{
		if (tls_io_instance->tlsio_state == TLSIO_STATE_NOT_OPEN)
		{
			result = __FAILURE__;
			LogError("tlsio_openssl_close has been called with no prior successful open.");
		}
		internal_close(tls_io_instance);
	}
	if (on_io_close_complete != NULL)
	{
		on_io_close_complete(callback_context);
	}
	return result;
}

int tlsio_openssl_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
	IO_SEND_RESULT sr = IO_SEND_ERROR;
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
		ASSIGN_AND_CHECK_TLSIO_INSTANCE
		{
			if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN)
			{
				/* Codes_SRS_TLSIO_SSL_ESP8266_99_015: [ The tlsio_openssl_send wrog state.]*/
				result = __FAILURE__;
				LogError("Attempted tlsio_openssl_send without a prior successful open call.");
			}
			else
			{
				size_t total_written = 0;
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

				if (total_written == bytes_to_send)
				{
					sr = IO_SEND_OK;
					result = 0;
				}
				else
				{
					Internal_close_with_stored_error_callback(tls_io_instance);
				}
			}
		}
	}

	if (on_send_complete != NULL)
	{
		on_send_complete(callback_context, sr);
	}
	return result;
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_019: [ The tlsio_openssl_dowork succeed]*/
void tlsio_openssl_dowork(CONCRETE_IO_HANDLE tls_io)
{
	ASSIGN_AND_CHECK_TLSIO_INSTANCE
	{
		if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
		{
			unsigned char buffer[64];
			int rcv_bytes;

			// SSL_read is not checked for errors because it never reports anything useful
			rcv_bytes = SSL_read(tls_io_instance->ssl, buffer, sizeof(buffer));
			if (rcv_bytes > 0)
			{
				// tls_io_instance->on_bytes_received was already checked for NULL
				// in the call to tlsio_openssl_open
				tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, buffer, rcv_bytes);
			}
		}
		else if (tls_io_instance->tlsio_state == TLSIO_STATE_NOT_OPEN)
		{
			LogError("tlsio_openssl_dowork has been called with no prior successful open call.");
			if (tls_io_instance->on_io_error)
			{
				tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
			}
		}
	}
}

/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_052 [ The tlsio_openssl_compact_setoption shall do nothing and return 0. ]*/
int tlsio_openssl_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
	tls_io;
	value;
	optionName;
	return 0;
}

/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_053: [ The tlsio_openssl_compact_retrieveoptions shall do nothing and return NULL. ]*/
static OPTIONHANDLER_HANDLE tlsio_openssl_retrieveoptions(CONCRETE_IO_HANDLE handle)
{
	handle;
	OPTIONHANDLER_HANDLE result = NULL;
	return result;
}

/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_008: [ The tlsio_get_interface_description shall return the VTable IO_INTERFACE_DESCRIPTION. ]*/
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

/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_001: [ The tlsio_openssl_compact shall implement and export all the Concrete functions in the VTable IO_INTERFACE_DESCRIPTION defined in the xio.h. ]*/
const IO_INTERFACE_DESCRIPTION* tlsio_get_interface_description(void)
{
	return &tlsio_openssl_interface_description;
}
