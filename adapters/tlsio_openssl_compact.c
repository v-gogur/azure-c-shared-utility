// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>

#include "openssl/ssl.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/ssl_socket.h"
#include "azure_c_shared_utility/agenttime.h"

// It is not anticipated that there should ever be a need to modify the
// SSL_MAX_BLOCK_TIME_SECONDS value, but if there is then it can be
// overridded with a preprocessor #define
#ifndef SSL_MAX_BLOCK_TIME_SECONDS
#define SSL_MAX_BLOCK_TIME_SECONDS 20
#endif // !SSL_MAX_BLOCK_TIME_SECONDS

#define SSL_MESSAGE_PUMP_DELAY_MILLISECONDS 2

// DOWORK_TRANSFER_BUFFER_SIZE is not very important because if the message is bigger
// then the framework just calls dowork repeatedly until it gets everything. So
// a bigger buffer would just use memory without buying anything.
#define DOWORK_TRANSFER_BUFFER_SIZE 64


// This adapter keeps itself in either TLSIO_STATE_OPEN or
// TLSIO_STATE_NOT_OPEN. There are no internally inconsistent
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

// This structure definition is mirrored in the unit tests, so if you change
// this struct, keep it in sync with the one in tlsio_openssl_compact_ut.c
typedef struct TLS_IO_INSTANCE_TAG
{
    uint16_t struct_size;
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

static void internal_close(TLS_IO_INSTANCE* tls_io_instance)
{
    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_017: [ The tlsio_openssl_compact_destroy shall enter the "Not Open" state if necessary and then release tlsio_handle. ]*/
    if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
    {
        // From the OpenSSL manual pages: "According to the TLS standard, it is acceptable 
        // for an application to only send its shutdown alert and then close the 
        // underlying connection without waiting for the peer's response...". It goes
        // on to say that waiting for shutdown only makes sense if the underlying
        // connection is being re-used, which we do not do. So there's no need
        // to wait for shutdown.
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
        // The underlying socke API does not support waiting for close
        // to complete, so it isn't possible to do so.
        SSL_Socket_Close(tls_io_instance->sock);
        tls_io_instance->sock = -1;
    }

    tls_io_instance->on_bytes_received = NULL;
    tls_io_instance->on_io_error = NULL;
    tls_io_instance->on_bytes_received_context = NULL;
    tls_io_instance->on_io_error_context = NULL;
    tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
}

static void internal_close_with_stored_error_callback(TLS_IO_INSTANCE* tls_io_instance)
{
    ON_IO_ERROR callback = tls_io_instance->on_io_error;
    void* context = tls_io_instance->on_io_error_context;
    internal_close(tls_io_instance);
    if (callback != NULL)
    {
        callback(context);
    }
}

// This method tests for hard errors returned from either SSL_write or SSL_connect.
// Returns 
//     0 for SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
//     The actual error for other errors (real failures)
static int is_hard_ssl_error(SSL* ssl, int callReturn)
{
    int result = SSL_get_error(ssl, callReturn);
    if (result == SSL_ERROR_WANT_READ || result == SSL_ERROR_WANT_WRITE)
    {
        result = 0;
    }
    return result;
}


static int create_and_connect_ssl(TLS_IO_INSTANCE* tls_io_instance)
{
    int result;
    int ret;

    LogInfo("OpenSSL thread start...");


    int sock = SSL_Socket_Create(tls_io_instance->host_address, tls_io_instance->port);
    if (sock < 0)
    {
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
        if (tls_io_instance->ssl_context == NULL)
        {
            result = __FAILURE__;
            LogError("create new SSL CTX failed");
        }
        else
        {
            tls_io_instance->ssl = SSL_new(tls_io_instance->ssl_context);
            if (tls_io_instance->ssl == NULL)
            {
                result = __FAILURE__;
                LogError("SSL_new failed");
            }
            else
            {
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
                    // This result setting here is necessary because the compiler does
                    // not recognize that the while loop will always execute, and so it
                    // puts up an uninitialized variable warning.
                    result = __FAILURE__;
                    time_t end_time = get_time(NULL) + SSL_MAX_BLOCK_TIME_SECONDS;
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
                            tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
                        }
                        else
                        {
                            int hard_error = is_hard_ssl_error(tls_io_instance->ssl, connect_result);
                            if (hard_error != 0)
                            {
                                // Connect failed, so delete the connection objects
                                result = __FAILURE__;
                                done = true;
                                LogInfo("Hard error from SSL_connect: %d", hard_error);
                            }
                            else
                            {
                                time_t now = get_time(NULL);
                                if (now > end_time) 
                                {
                                    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_074: [ The tlsio_openssl_compact_send shall spend no longer than the internally defined SSL_MAX_BLOCK_TIME_SECONDS (20 seconds) attempting to perform the SSL_connect operation. ]*/
                                    // This has taken too long, so bail out
                                    result = __FAILURE__;
                                    done = true;
                                    LogInfo("Timeout from SSL_connect");
                                }
                            }
                        }

                        ThreadAPI_Sleep(SSL_MESSAGE_PUMP_DELAY_MILLISECONDS);
                    }
                }
            }
        }
    }

    return result;
}

/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_009: [ The tlsio_openssl_compact_create shall allocate and initialize all necessary resources, enter the "Not Open" state, and return an instance of the tlsio for compact OpenSSL. ]*/
/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_005: [ The tlsio_openssl_compact shall receive the connection information using the TLSIO_CONFIG structure defined in tlsio.h ]*/
CONCRETE_IO_HANDLE tlsio_openssl_create(void* io_create_parameters)
{
    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_005: [ The tlsio_openssl_compact shall receive the connection information using the TLSIO_CONFIG structure defined in tlsio.h ]*/
    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_012: [ The tlsio_openssl_compact_create shall receive the connection configuration (TLSIO_CONFIG). ]*/
    TLSIO_CONFIG* tls_io_config = (TLSIO_CONFIG*)io_create_parameters;
    TLS_IO_INSTANCE* result;

    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_013: [ If the io_create_parameters value is NULL, tlsio_openssl_compact_create shall log an error and return NULL. ]*/
    if (io_create_parameters == NULL)
    {
        LogError("NULL tls_io_config.");
        result = NULL;
    }
    else
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_014: [ The tlsio_openssl_compact_create shall convert the provided hostName to an IPv4 address. ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_021: [ The tlsio_openssl_compact_open shall open the ssl connection with the host provided in the tlsio_openssl_compact_create. ]*/
        uint32_t ipV4 = SSL_Get_IPv4(tls_io_config->hostname);
        if (ipV4 == 0)
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_015: [ If the IP for the hostName cannot be found, tlsio_openssl_compact_create shall return NULL. ]*/
            LogInfo("Could not get IPv4 for %s", tls_io_config->hostname);
            result = NULL;
        }
        else
        {
            result = malloc(sizeof(TLS_IO_INSTANCE));
            if (result == NULL)
            {
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_010: [ If the allocation fails, tlsio_openssl_compact_create shall return NULL. ]*/
                LogError("Failed to allocate tlsio instance.");
            }
            else
            {
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_011: [ The tlsio_openssl_compact_create shall initialize all internal callback pointers as NULL. ]*/
                memset(result, 0, sizeof(TLS_IO_INSTANCE));
                result->struct_size = sizeof(TLS_IO_INSTANCE);
                result->host_address = ipV4;
                result->port = tls_io_config->port;
                result->tlsio_state = TLSIO_STATE_NOT_OPEN;
                result->sock = SSL_SOCKET_NULL_SOCKET;
            }
        }
    }

    return (CONCRETE_IO_HANDLE)result;
}

void tlsio_openssl_destroy(CONCRETE_IO_HANDLE tls_io)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    if (tls_io_instance == NULL)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_016: [ If tlsio_handle is NULL, tlsio_openssl_compact_destroy shall do nothing. ]*/
        LogError(null_tlsio_message);
    }
    else
    {
        if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_018: [ If the adapter is in the "Open" state, concrete_io_destroy shall log an error. ]*/
            LogError("tlsio_openssl_destroy called while TLSIO_STATE_OPEN.");
        }
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_017: [ The tlsio_openssl_compact_destroy shall enter the "Not Open" state if necessary and then release tlsio_handle. ]*/
        internal_close(tls_io_instance);

        // NOTE: certificate and pk handling will not be specified until x509 support is added.
        // There is currently no way for any of these members to become non-NULL.
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


/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_004: [ The tlsio_openssl_compact shall call the callbacks functions defined in the xio.h ]*/
int tlsio_openssl_open(CONCRETE_IO_HANDLE tls_io,
    ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context,
    ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context,
    ON_IO_ERROR on_io_error, void* on_io_error_context)
{
    int result;
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_019: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
        result = __FAILURE__;
        LogError(null_tlsio_message);
    }
    else
    {
        if (tls_io_instance->tlsio_state != TLSIO_STATE_NOT_OPEN)
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_029: [ If the adapter is in the "Open" state, it shall remain in the "Open" state, log an error, and return FAILURE. ]*/
            result = __FAILURE__;
            LogError("Unexpected tlsio_state. Expected state is TLSIO_STATE_NOT_OPEN.");
        }
        else
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_022: [ The tlsio_openssl_compact_open shall store the provided on_bytes_received callback function address. ]*/
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_023: [ The tlsio_openssl_compact_open shall store the provided on_bytes_received_context handle. ]*/
            tls_io_instance->on_bytes_received = on_bytes_received;
            tls_io_instance->on_bytes_received_context = on_bytes_received_context;

            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_024: [ The tlsio_openssl_compact_open shall store the provided on_io_error callback function address. ]*/
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_025: [ The tlsio_openssl_compact_open shall store the provided on_io_error_context handle. ]*/
            tls_io_instance->on_io_error = on_io_error;
            tls_io_instance->on_io_error_context = on_io_error_context;

            if (on_bytes_received == NULL)
            {
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_052: [ If the on_io_error parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
                LogError("Required parameter on_bytes_received is NULL");
                result = __FAILURE__;
            }
            else
            {
                if (on_io_error == NULL)
                {
                    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_020: [ If the on_bytes_received parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
                    LogError("Required parameter on_io_error is NULL");
                    result = __FAILURE__;
                }
                else
                {
                    if (tls_io_instance->tlsio_state != TLSIO_STATE_NOT_OPEN)
                    {
                        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_029: [ If the adapter is in the "Open" state, it shall remain in the "Open" state, log an error, and return FAILURE. ]*/
                        LogError("Invalid tlsio_state. Expected state is TLSIO_STATE_NOT_OPEN.");
                        result = __FAILURE__;
                    }
                    else
                    {
                        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_026: [ If tlsio_openssl_compact_open successfully opens the ssl connection, it shall enter the "Open" state and return 0. ]*/
                        result = create_and_connect_ssl(tls_io_instance);
                    }
                }
            }
            if (result != 0)
            {
                if (tls_io_instance != NULL)
                {
                    /* Codes_SSRS_TLSIO_OPENSSL_COMPACT_30_071: [ Failures which indicate that the SSL connection cannot be trusted shall cause the tlsio_openssl_compact to transition to the "Not Open" state. ]*/
                    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_030: [ If tlsio_openssl_compact_open fails to open the ssl connection with a non-NULL tlsio_handle, it shall enter the "Not Open" state and return FAILURE. ] */
                    internal_close(tls_io_instance);
                }
            }
        }
    }

    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_007: [ If the callback function is set as NULL, the tlsio_openssl_compact shall not call anything. ] */
    if (on_io_open_complete)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_002: [ The tlsio_openssl_compact shall report the open operation status using the IO_OPEN_RESULT enumerator defined in the xio.h ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_006: [ The tlsio_openssl_compact shall return the status of all async operations using the callbacks. ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_027: [ If tlsio_openssl_compact_open successfully opens the ssl connection and on_io_open_complete is non-NULL it shall call on_io_open_complete with IO_OPEN_OK. ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_028: [ If tlsio_openssl_compact_open calls on_io_open_complete, it shall always pass the provided on_io_open_complete_context parameter. ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_031: [ If the tlsio_openssl_compact_open fails to open the tls connection, and the on_io_open_complete callback was provided, it shall call on_io_open_complete with IO_OPEN_ERROR. ]*/
        on_io_open_complete(on_io_open_complete_context, result == 0 ? IO_OPEN_OK : IO_OPEN_ERROR);
    }
    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_030: [ If tlsio_openssl_compact_open fails to open the ssl connection with a non-NULL tlsio_handle, it shall enter the "Not Open" state and return FAILURE. ] */
    return result;
}


/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_004: [ The tlsio_openssl_compact shall call the callbacks functions defined in the xio.h ]*/
int tlsio_openssl_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
    int result;

    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    if (tls_io == NULL)
    {
    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_033: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_close shall log an error and return FAILURE. ]*/
        result = __FAILURE__;
        LogError(null_tlsio_message);
    }
    else
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_035: [ The tlsio_openssl_compact_close return value shall be 0 except as noted in the next requirement. ] */
        result = 0;
        if (tls_io_instance->tlsio_state == TLSIO_STATE_NOT_OPEN)
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_036: [ If the adapter is in the "Not Open" state, then tlsio_openssl_compact_close shall log an error and return FAILURE. ] */
            result = __FAILURE__;
            LogError("tlsio_openssl_close has been called with no prior successful open.");
        }
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_034: [ The tlsio_openssl_compact_close shall enter the "Not Open" state by forcibly closing any existing ssl connection. ] */
        internal_close(tls_io_instance);
    }

    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_007: [ If the callback function is set as NULL, the tlsio_openssl_compact shall not call anything. ] */
    if (on_io_close_complete != NULL)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_002: [ The tlsio_openssl_compact shall report the open operation status using the IO_OPEN_RESULT enumerator defined in the xio.h ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_006: [ The tlsio_openssl_compact shall return the status of all async operations using the callbacks. ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_037: [ If on_io_close_complete is provided, tlsio_openssl_compact_close shall call on_io_close_complete. ] */
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_038: [ If on_io_close_complete is provided, tlsio_openssl_compact_close shall pass the callback_context handle into the on_io_close_complete call. ] */
        on_io_close_complete(callback_context);
    }
    return result;
}

/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_004: [ The tlsio_openssl_compact shall call the callbacks functions defined in the xio.h ]*/
int tlsio_openssl_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    IO_SEND_RESULT send_result_for_send_complete_callback = IO_SEND_ERROR;
    int result;
    size_t bytes_to_send = size;

    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    if (tls_io_instance == NULL)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_039: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_send shall log an error and return FAILURE. ] ]*/
        result = __FAILURE__;
        LogError(null_tlsio_message);
    }
    else
    {
        if (buffer == NULL)
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_046: [ If the buffer is NULL, the tlsio_openssl_compact_send shall log the error and return FAILURE. ]*/
            result = __FAILURE__;
            LogError("NULL buffer.");
        }
        else
        {
            if (tls_io_instance->tlsio_state == TLSIO_STATE_NOT_OPEN)
            {
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_072: [ If the tlsio state is "Not Open", the tlsio_openssl_compact_send shall log an error and return FAILURE. ]*/
                result = __FAILURE__;
                LogError("Attempted tlsio_openssl_send without a prior successful open call.");
            }
            else
            {
                size_t total_written = 0;
                int res = 0;

                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_040: [ The tlsio_openssl_compact_send shall send the first size bytes in buffer to the ssl connection. ]*/
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_043: [ if the ssl was not able to send all data in the buffer, the tlsio_openssl_compact_send shall call the ssl again to send the remaining bytes. ]*/
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_047: [ If the size is 0, the tlsio_openssl_compact_send shall shall call the on_send_complete with IO_SEND_OK and return 0. ]*/
                time_t end_time = get_time(NULL) + SSL_MAX_BLOCK_TIME_SECONDS;
                while (size > 0)
                {
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
                        else
                        {
                            time_t now = get_time(NULL);
                            if (now > end_time)
                            {
                                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_073: [ The tlsio_openssl_compact_send shall spend no longer than the internally defined SSL_MAX_BLOCK_TIME_SECONDS (20 seconds) attempting to perform the SSL_write operation. ]*/
                                // This has taken too long, so bail out
                                LogInfo("Timeout from SSL_connect");
                                break;
                            }
                        }
                    }
                    // Try again real soon
                    ThreadAPI_Sleep(SSL_MESSAGE_PUMP_DELAY_MILLISECONDS);
                }

                if (total_written == bytes_to_send)
                {
                    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_045: [ if the ssl was able to send all the bytes in the buffer, the tlsio_openssl_compact_send shall call the on_send_complete with IO_SEND_OK, and return 0 ]*/
                    send_result_for_send_complete_callback = IO_SEND_OK;
                    result = 0;
                }
                else
                {
                    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_044: [ if the SSL_write call fails unexpectedly, the tlsio_openssl_compact_send shall enter the "Not Open" state, call the on_send_complete with IO_SEND_ERROR, and return FAILURE. ]*/
                    result = __FAILURE__;
                    internal_close_with_stored_error_callback(tls_io_instance);
                }
            }
        }
    }

    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_007: [ If the callback function is set as NULL, the tlsio_openssl_compact shall not call anything. ] */
    if (on_send_complete != NULL)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_002: [ The tlsio_openssl_compact shall report the open operation status using the IO_OPEN_RESULT enumerator defined in the xio.h ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_006: [ The tlsio_openssl_compact shall return the status of all async operations using the callbacks. ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_041: [ The tlsio_openssl_compact_send shall call the provided on_send_complete callback function. ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_042: [ The tlsio_openssl_compact_send shall supply the provided callback_context when it calls on_send_complete. ]*/
        on_send_complete(callback_context, send_result_for_send_complete_callback);
    }
    return result;
}

/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_004: [ The tlsio_openssl_compact shall call the callbacks functions defined in the xio.h ]*/
void tlsio_openssl_dowork(CONCRETE_IO_HANDLE tls_io)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    if (tls_io_instance == NULL)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_048: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_dowork shall do nothing except log an error and return FAILURE. ]*/
        LogError(null_tlsio_message);
    }
    else
    {
        if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_051: [ The tlsio_openssl_compact_dowork shall use a stack-based buffer to store the data received from the ssl client. ]*/
            // TRANSFER_BUFFER_SIZE is not very important because if the message is bigger
            // then the framework just calls dowork repeatedly until it gets everything. So
            // a bigger buffer would just use memory without buying anything.
            unsigned char buffer[DOWORK_TRANSFER_BUFFER_SIZE];
            int rcv_bytes;

            // SSL_read is not checked for errors because it never reports anything useful
            rcv_bytes = SSL_read(tls_io_instance->ssl, buffer, sizeof(buffer));
            if (rcv_bytes > 0)
            {
                // tls_io_instance->on_bytes_received was already checked for NULL
                // in the call to tlsio_openssl_open
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_006: [ The tlsio_openssl_compact shall return the status of all async operations using the callbacks. ]*/
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_049: [ If the ssl client is able to provide received data, the tlsio_openssl_compact_dowork shall read this data and call on_bytes_received with the pointer to the buffer containing the data and the number of bytes received. ]*/
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_050: [ When tlsio_openssl_compact_dowork calls on_bytes_received, it shall pass the on_bytes_received_context handle as a parameter. ]*/
                tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, buffer, rcv_bytes);
            }
        }
    }
}

/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_056 [ The tlsio_openssl_compact_setoption shall do nothing and return 0. ]*/
int tlsio_openssl_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_053: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
    int result;
    if (tls_io_instance == NULL)
    {
        LogError(null_tlsio_message);
        result = __FAILURE__;
    }
    else
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_054: [ If the optionName parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
        if (optionName == NULL)
        {
            LogError("Required optionName parameter is NULL");
            result = __FAILURE__;
        }
        else
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_055: [ If the value parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
            if (value == NULL)
            {
                LogError("Required value parameter is NULL");
                result = __FAILURE__;
            }
            else
            {
                result = 0;
            }
        }
    }
    return result;
}

/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_058: [ The tlsio_openssl_compact_retrieveoptions shall do nothing and return NULL. ]*/
static OPTIONHANDLER_HANDLE tlsio_openssl_retrieveoptions(CONCRETE_IO_HANDLE tls_io)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_057: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_retrieveoptions shall do nothing except log an error and return NULL. ]*/
    OPTIONHANDLER_HANDLE result;
    if (tls_io_instance == NULL)
    {
        LogError(null_tlsio_message);
        result = NULL;
    }
    else
    {
        result = NULL;
    }
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
