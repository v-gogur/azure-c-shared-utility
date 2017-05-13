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
#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/dns_async.h"
#include "azure_c_shared_utility/socket_async.h"
#include "azure_c_shared_utility/singlylinkedlist.h"

typedef struct PENDING_SOCKET_IO_TAG
{
    unsigned char* bytes;
    size_t size;
    size_t unsent_size;
    ON_SEND_COMPLETE on_send_complete;
    void* callback_context;
} PENDING_SOCKET_IO;

// It is not anticipated that there should ever be a need to modify the
// SSL_MAX_BLOCK_TIME_SECONDS value, but if there is then it can be
// overridden with a preprocessor #define
#ifndef TLSIO_OPERATION_TIMEOUT_SECONDS
#define TLSIO_OPERATION_TIMEOUT_SECONDS 40
#endif // !TLSIO_OPERATION_TIMEOUT_SECONDS

#define MAX_VALID_PORT 0xffff

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
    TLSIO_STATE_OPENING_WAITING_DNS,
    TLSIO_STATE_OPENING_WAITING_SOCKET,
    TLSIO_STATE_OPENING_WAITING_SSL,
    TLSIO_STATE_OPEN,
    TLSIO_STATE_ERROR,      // Needs to be destroyed and recreated
} TLSIO_STATE;

// This structure definition is mirrored in the unit tests, so if you change
// this struct, keep it in sync with the one in tlsio_openssl_compact_ut.c
typedef struct TLS_IO_INSTANCE_TAG
{
    uint16_t struct_size;
    ON_BYTES_RECEIVED on_bytes_received;
    ON_IO_ERROR on_io_error;
    ON_IO_OPEN_COMPLETE on_open_complete;
    void* on_bytes_received_context;
    void* on_io_error_context;
    void* on_open_complete_context;
    SSL* ssl;
    SSL_CTX* ssl_context;
    TLSIO_STATE tlsio_state;
    uint32_t host_ipV4_address;
    DNS_ASYNC_HANDLE dns;
    char* hostname;
    uint16_t port;
    time_t operation_timeout_end_time;
    char* certificate;
    const char* x509certificate;
    const char* x509privatekey;
    SOCKET_ASYNC_HANDLE sock;
    SINGLYLINKEDLIST_HANDLE pending_io_list;
} TLS_IO_INSTANCE;

#ifndef NO_LOGGING
static const char* null_tlsio_message = "NULL tlsio";
static const char* allocate_fail_message = "malloc failed";
#endif

// Return true if a message was available to remove
static bool close_and_destroy_head_message(TLS_IO_INSTANCE* tls_io_instance, IO_SEND_RESULT send_result)
{
    bool result;
    tls_io_instance->operation_timeout_end_time = 0;
    if (send_result == IO_SEND_ERROR)
    {
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
    }
    LIST_ITEM_HANDLE head_pending_io = singlylinkedlist_get_head_item(tls_io_instance->pending_io_list);
    if (head_pending_io != NULL)
    {
        PENDING_SOCKET_IO* head_message = (PENDING_SOCKET_IO*)singlylinkedlist_item_get_value(head_pending_io);
        // on_send_complete is checked for NULL during PENDING_SOCKET_IO creation
        head_message->on_send_complete(head_message->callback_context, send_result);

        free(head_message->bytes);
        free(head_message);
        if (singlylinkedlist_remove(tls_io_instance->pending_io_list, head_pending_io) != 0)
        {
            tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
            // on_io_error is checked for NULL during tlsio_openssl_create
            tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
            LogError("Program bug: unable to remove socket from list");
        }
        result = true;
    }
    else
    {
        result = false;
    }
    return result;
}

static void enter_open_error_state(TLS_IO_INSTANCE* tls_io_instance)
{
    tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
    // on_open_complete has already been checked for non-NULL
    tls_io_instance->on_open_complete(tls_io_instance->on_open_complete_context, IO_OPEN_ERROR);
}

static void check_for_open_timeout(TLS_IO_INSTANCE* tls_io_instance)
{
    time_t now = get_time(NULL);
    if (now > tls_io_instance->operation_timeout_end_time)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_074: [ The tlsio_openssl_compact_send shall spend no longer than the internally defined SSL_MAX_BLOCK_TIME_SECONDS (20 seconds) attempting to perform the SSL_connect operation. ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_030: [ If tlsio_openssl_compact_dowork fails to open the ssl connection it shall call on_io_open_complete with IO_OPEN_ERROR. ]*/
        // This has taken too long, so bail out
        LogInfo("Timeout while opening tlsio");
        enter_open_error_state(tls_io_instance);
    }
}

static void internal_close(TLS_IO_INSTANCE* tls_io_instance)
{
    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_017:  [ The tlsio_openssl_compact_destroy shall release all allocated resources and then release tlsio_handle. ]*/
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

    if (tls_io_instance->dns != NULL)
    {
        dns_async_destroy(tls_io_instance->dns);
        tls_io_instance->dns = NULL;
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
        // The underlying socket API does not support waiting for close
        // to complete, so it isn't possible to do so.
        socket_async_destroy(tls_io_instance->sock);
        tls_io_instance->sock = -1;
    }

    /* clear all pending IOs */
    while (close_and_destroy_head_message(tls_io_instance, IO_SEND_CANCELLED));
    // singlylinkedlist_destroy gets called in the main destroy

    tls_io_instance->on_bytes_received = NULL;
    tls_io_instance->on_io_error = NULL;
    tls_io_instance->on_bytes_received_context = NULL;
    tls_io_instance->on_io_error_context = NULL;
    tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
    tls_io_instance->on_open_complete = NULL;
    tls_io_instance->on_open_complete_context = NULL;
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

void tlsio_openssl_destroy(CONCRETE_IO_HANDLE tls_io)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    if (tls_io_instance == NULL)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_020: [ If tlsio_handle is NULL, tlsio_openssl_compact_destroy shall do nothing. ]*/
        LogError(null_tlsio_message);
    }
    else
    {
        if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_022: [ If tlsio_openssl_compact_close has not been called before concrete_io_destroy, concrete_io_destroy shall additionally log an error. ]*/
            LogError("tlsio_openssl_destroy called while TLSIO_STATE_OPEN.");
        }
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_021: [ The tlsio_openssl_compact_destroy shall release all allocated resources and then release tlsio_handle. ]*/
        internal_close(tls_io_instance);

        if (tls_io_instance->hostname != NULL)
        {
            free(tls_io_instance->hostname);
            tls_io_instance->hostname = NULL;
        }

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
        if (tls_io_instance->pending_io_list != NULL)
        {
            /* Pending IOs were cleared in internal_close */

            singlylinkedlist_destroy(tls_io_instance->pending_io_list);
            tls_io_instance->pending_io_list = NULL;
        }

        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_021: [ The tlsio_openssl_compact_destroy shall release all allocated resources and then release tlsio_handle. ]*/
        free(tls_io_instance);
    }
}

/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_010: [ The tlsio_openssl_compact_create shall allocate and initialize all necessary resources and return an instance of the tlsio_openssl_compact. ]*/
CONCRETE_IO_HANDLE tlsio_openssl_create(void* io_create_parameters)
{
    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_012: [ The tlsio_openssl_compact_create shall receive the connection configuration as a TLSIO_CONFIG* in io_create_parameters. ]*/
    TLSIO_CONFIG* tls_io_config = (TLSIO_CONFIG*)io_create_parameters;
    TLS_IO_INSTANCE* result;

    if (io_create_parameters == NULL)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_013: [ If the io_create_parameters value is NULL, tlsio_openssl_compact_create shall log an error and return NULL. ]*/
        LogError("NULL tls_io_config");
        result = NULL;
    }
    else
    {
        if (tls_io_config->hostname == NULL)
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_014: [ If the hostname member of io_create_parameters value is NULL, tlsio_openssl_compact_create shall log an error and return NULL. ]*/
            LogError("NULL tls_io_config->hostname");
            result = NULL;
        }
        else
        {
            if (tls_io_config->port < 0 || tls_io_config->port > MAX_VALID_PORT)
            {
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_015: [ If the port member of io_create_parameters value is less than 0 or greater than 0xffff, tlsio_openssl_compact_create shall log an error and return NULL. ]*/
                LogError("tls_io_config->port out of range");
                result = NULL;
            }
            else
            {
                result = malloc(sizeof(TLS_IO_INSTANCE));
                if (result == NULL)
                {
                    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_011: [ If any resource allocation fails, tlsio_openssl_compact_create shall return NULL. ]*/
                    LogError(allocate_fail_message);
                }
                else
                {
                    memset(result, 0, sizeof(TLS_IO_INSTANCE));
                    result->struct_size = sizeof(TLS_IO_INSTANCE);
                    result->host_ipV4_address = 0;
                    result->port = (uint16_t)tls_io_config->port;
                    result->tlsio_state = TLSIO_STATE_NOT_OPEN;
                    result->sock = SOCKET_ASYNC_INVALID_SOCKET;
                    result->hostname = NULL;
                    result->dns = NULL;
                    result->pending_io_list = NULL;
                    result->operation_timeout_end_time = 0;
                    result->hostname = (char*)malloc(strlen(tls_io_config->hostname) + 1);
                    if (result->hostname == NULL)
                    {
                        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_011: [ If any resource allocation fails, tlsio_openssl_compact_create shall return NULL. ]*/
                        LogError(allocate_fail_message);
                        tlsio_openssl_destroy(result);
                        result = NULL;
                    }
                    else
                    {
                        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_016: [ tlsio_openssl_compact_create shall make a copy of the hostname member of io_create_parameters to allow deletion of hostname immediately after the call. ]*/
                        (void)strcpy(result->hostname, tls_io_config->hostname);
                        // Create the message queue
                        result->pending_io_list = singlylinkedlist_create();
                        if (result->pending_io_list == NULL)
                        {
                            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_011: [ If any resource allocation fails, tlsio_openssl_compact_create shall return NULL. ]*/
                            LogError("Failed singlylinkedlist_create");
                            tlsio_openssl_destroy(result);
                            result = NULL;
                        }
                    }
                }
            }
        }
    }

    return (CONCRETE_IO_HANDLE)result;
}


int tlsio_openssl_open(CONCRETE_IO_HANDLE tls_io,
    ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context,
    ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context,
    ON_IO_ERROR on_io_error, void* on_io_error_context)
{

    int result;
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_030: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
        result = __FAILURE__;
        LogError(null_tlsio_message);
    }
    else
    {
        tls_io_instance->operation_timeout_end_time = get_time(NULL) + TLSIO_OPERATION_TIMEOUT_SECONDS;
        if (on_io_open_complete == NULL)
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_031: [ If the on_io_open_complete parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
            LogError("Required parameter on_io_open_complete is NULL");
            result = __FAILURE__;
        }
        else
        {
            if (on_bytes_received == NULL)
            {
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_032: [ If the on_bytes_received parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
                LogError("Required parameter on_bytes_received is NULL");
                result = __FAILURE__;
            }
            else
            {
                if (on_io_error == NULL)
                {
                    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_033: [ If the on_io_error parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
                    LogError("Required parameter on_io_error is NULL");
                    result = __FAILURE__;
                }
                else
                {
                    if (tls_io_instance->tlsio_state != TLSIO_STATE_NOT_OPEN)
                    {
                        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_037: [ If tlsio_openssl_compact_open has already been called, it shall log an error, and return FAILURE. ]*/
                        LogError("Invalid tlsio_state. Expected state is TLSIO_STATE_NOT_OPEN.");
                        result = __FAILURE__;
                    }
                    else
                    {
                        tls_io_instance->dns = dns_async_create(tls_io_instance->hostname, NULL);
                        if (tls_io_instance->dns == NULL)
                        {
                            /* Codes_RS_TLSIO_OPENSSL_COMPACT_30_038: [ If the tlsio_openssl_compact_open fails to begin opening the OpenSSL connection it shall return FAILURE. ]*/
                            // Error already logged
                            result = __FAILURE__;
                        }
                        else
                        {
                            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_034: [ The tlsio_openssl_compact_open shall store the provided on_bytes_received, on_bytes_received_context, on_io_error, on_io_error_context, on_io_open_complete, and on_io_open_complete_context parameters for later use as specified and tested per other line entries in this document. ]*/
                            tls_io_instance->on_bytes_received = on_bytes_received;
                            tls_io_instance->on_bytes_received_context = on_bytes_received_context;

                            tls_io_instance->on_io_error = on_io_error;
                            tls_io_instance->on_io_error_context = on_io_error_context;

                            tls_io_instance->on_open_complete = on_io_open_complete;
                            tls_io_instance->on_open_complete_context = on_io_open_complete_context;

                            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_035: [ The tlsio_openssl_compact_open shall begin the process of opening the ssl connection with the host provided in the tlsio_openssl_compact_create call. ]*/
                            // All the real work happens in dowork
                            tls_io_instance->tlsio_state = TLSIO_STATE_OPENING_WAITING_DNS;
                            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_036: [ If tlsio_openssl_compact_open successfully begins opening the OpenSSL connection, it shall return 0. ]*/
                            result = 0;
                        }
                    }
                }
            }
        }
    }

    if (result != 0 && on_io_open_complete != NULL)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_039: [ If the tlsio_openssl_compact_open returns FAILURE it shall call on_io_open_complete with the provided on_io_open_complete_context and IO_OPEN_ERROR. ]*/
        on_io_open_complete(on_io_open_complete_context, IO_OPEN_ERROR);
    }

    return result;
}


/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_004: [ The tlsio_openssl_compact shall call the callbacks functions defined in the xio.h ]*/
int tlsio_openssl_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
    int result;

    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_033: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_close shall log an error and return FAILURE. ]*/
        result = __FAILURE__;
        LogError(null_tlsio_message);
    }
    else
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_035: [ The tlsio_openssl_compact_close return value shall be 0 except as noted in the next requirement. ] */
        result = 0;
        if (tls_io_instance->tlsio_state == TLSIO_STATE_NOT_OPEN)
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_036: [ If tlsio_openssl_compact_open has not been called then tlsio_openssl_compact_close shall log an error and return FAILURE. ] */
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_060: [ If tlsio_openssl_compact_open has been called but the process of opening has not been completed, then the on_io_open_complete callback shall be made with IO_SEND_CANCELLED. ] */
            result = __FAILURE__;
            LogError("tlsio_openssl_close has been called with no prior successful open.");
        }
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_034: [ The tlsio_openssl_compact_close shall forcibly close any existing ssl connection. ] */
        internal_close(tls_io_instance);
    }

    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_007: [ If the callback function is set as NULL, the tlsio_openssl_compact shall not call anything. ] */
    if (on_io_close_complete != NULL)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_002: [ The tlsio_openssl_compact shall report the open operation status using the IO_OPEN_RESULT enumerator defined in the xio.h ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_006: [ The tlsio_openssl_compact shall return the status of all async operations using the callbacks. ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_037: [ If on_io_close_complete is provided, tlsio_openssl_compact_close shall call on_io_close_complete. ] */
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_038: [ If on_io_close_complete is provided, tlsio_openssl_compact_close shall pass the callback_context handle into the on_io_close_complete call. ] */
        on_io_close_complete(callback_context);
    }


    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_76: [ If tlsio_openssl_compact_close is called while there are unsent messages in the queue, the tlsio_openssl_compact_close shall call on_send_complete with IO_SEND_ERROR for each message. ]*/



    return result;
}

/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_004: [ The tlsio_openssl_compact shall call the callbacks functions defined in the xio.h ]*/
int tlsio_openssl_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    if (tls_io_instance == NULL)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_039: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_send shall log an error and return FAILURE. ]*/
        result = __FAILURE__;
        LogError(null_tlsio_message);
    }
    else
    {
        if (on_send_complete == NULL)
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_075: [ If the on_send_complete is NULL, tlsio_openssl_compact_send shall log the error and return FAILURE. ]*/
            result = __FAILURE__;
            LogError("NULL on_send_complete");
        }
        else
        {
            if (buffer == NULL)
            {
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_046: [ If the buffer is NULL, the tlsio_openssl_compact_send shall log the error and return FAILURE. ]*/
                result = __FAILURE__;
                LogError("NULL buffer.");
            }
            else
            {
                if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN)
                {
                    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_072: [ If tlsio_openssl_compact_open has not been called or the opening process has not been completed, tlsio_openssl_compact_send shall log an error and return FAILURE. ]*/
                    result = __FAILURE__;
                    LogError("tlsio_openssl_send without a prior successful open.");
                }
                else
                {
                    PENDING_SOCKET_IO* pending_socket_io = (PENDING_SOCKET_IO*)malloc(sizeof(PENDING_SOCKET_IO));
                    if (pending_socket_io == NULL)
                    {
                        result = __FAILURE__;
                        LogError(allocate_fail_message);
                    }
                    else
                    {
                        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_040: [ The tlsio_openssl_compact_send shall enqueue the size bytes in buffer for transmission to the ssl connection. ]*/
                        // Accept messages of length zero, but don't allocate memory for them
                        if (size > 0)
                        {
                            pending_socket_io->bytes = (unsigned char*)malloc(size);
                        }
                        else
                        {
                            pending_socket_io->bytes = NULL;
                        }

                        if (pending_socket_io->bytes == NULL && size > 0)
                        {
                            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_070: [ if the supplied message cannot be enqueued for transmission, tlsio_openssl_compact_send shall call the on_send_complete with IO_SEND_ERROR, and return FAILURE. ]*/
                            LogError(allocate_fail_message);
                            free(pending_socket_io);
                            result = __FAILURE__;
                        }
                        else
                        {
                            pending_socket_io->size = size;
                            pending_socket_io->unsent_size = size;
                            pending_socket_io->on_send_complete = on_send_complete;
                            pending_socket_io->callback_context = callback_context;
                            if (size > 0)
                            {
                                (void)memcpy(pending_socket_io->bytes, buffer, size);
                            }
                            if (singlylinkedlist_add(tls_io_instance->pending_io_list, pending_socket_io) == NULL)
                            {
                                LogError("Unable to add socket to pending list.");
                                free(pending_socket_io->bytes);
                                free(pending_socket_io);
                                result = __FAILURE__;
                            }
                            else
                            {
                                result = 0;
                            }
                        }
                    }
                }
            }
        }
    }
    return result;
}

static void dowork_read(TLS_IO_INSTANCE* tls_io_instance)
{
    // TRANSFER_BUFFER_SIZE is not very important because if the message is bigger
    // then the framework just calls dowork repeatedly until it gets everything. So
    // a bigger buffer would just use memory without buying anything.
    // Putting this buffer in a small function also allows it to exist on the stack
    // rather than adding to heap fragmentation.
    unsigned char buffer[DOWORK_TRANSFER_BUFFER_SIZE];
    int rcv_bytes;

    // SSL_read is not checked for errors because it never reports anything useful
    rcv_bytes = SSL_read(tls_io_instance->ssl, buffer, sizeof(buffer));
    if (rcv_bytes > 0)
    {
        // tls_io_instance->on_bytes_received was already checked for NULL
        // in the call to tlsio_openssl_open
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_006: [ The tlsio_openssl_compact shall return the status of all async operations using the callbacks. ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_049: [ If the ssl client is able to provide received data, the tlsio_openssl_compact_dowork shall read this data and call on_bytes_received with the pointer to the buffer containing the data and the number of bytes received. ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_050: [ When tlsio_openssl_compact_dowork calls on_bytes_received, it shall pass the on_bytes_received_context handle as a parameter. ]*/
        tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, buffer, rcv_bytes);
    }
}


static int create_ssl(TLS_IO_INSTANCE* tls_io_instance)
{
    int result;
    int ret;

    {
        tls_io_instance->ssl_context = SSL_CTX_new(TLSv1_2_client_method());
        if (tls_io_instance->ssl_context == NULL)
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_030: [ If tlsio_openssl_compact_dowork fails to open the ssl connection it shall call on_io_open_complete with IO_OPEN_ERROR. ]*/
            result = __FAILURE__;
            LogError("create new SSL CTX failed");
        }
        else
        {
            tls_io_instance->ssl = SSL_new(tls_io_instance->ssl_context);
            if (tls_io_instance->ssl == NULL)
            {
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_030: [ If tlsio_openssl_compact_dowork fails to open the ssl connection and the on_io_open_complete callback was provided, it shall call on_io_open_complete with IO_OPEN_ERROR. ]*/
                result = __FAILURE__;
                LogError("SSL_new failed");
            }
            else
            {
                // returns 1 on success
                ret = SSL_set_fd(tls_io_instance->ssl, tls_io_instance->sock);
                if (ret != 1)
                {
                    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_030: [ If tlsio_openssl_compact_dowork fails to open the ssl connection it shall call on_io_open_complete with IO_OPEN_ERROR. ]*/
                    result = __FAILURE__;
                    LogError("SSL_set_fd failed");
                }
                else
                {
                    result = 0;
                }
            }
        }
    }

    return result;
}

static void dowork_send(TLS_IO_INSTANCE* tls_io_instance)
{
    LIST_ITEM_HANDLE first_pending_io = singlylinkedlist_get_head_item(tls_io_instance->pending_io_list);
    if (first_pending_io != NULL)
    {
        PENDING_SOCKET_IO* pending_message = (PENDING_SOCKET_IO*)singlylinkedlist_item_get_value(first_pending_io);
        // Initialize the send start time if necessary
        if (tls_io_instance->operation_timeout_end_time == 0)
        {
            tls_io_instance->operation_timeout_end_time = time(NULL) + TLSIO_OPERATION_TIMEOUT_SECONDS;
        }

        time_t now = time(NULL);
        if (now > tls_io_instance->operation_timeout_end_time)
        {
            LogInfo("send timeout");
            close_and_destroy_head_message(tls_io_instance, IO_SEND_ERROR);
        }
        else
        {
            if (pending_message->unsent_size == 0)
            {
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_047: [ If an enqueued message size is 0, the tlsio_openssl_compact_dowork shall just call the on_send_complete with IO_SEND_OK. ]*/
                close_and_destroy_head_message(tls_io_instance, IO_SEND_OK);
            }
            else
            {
                uint8_t* buffer = ((uint8_t*)pending_message->bytes) +
                    pending_message->size - pending_message->unsent_size;
                int write_result = SSL_write(tls_io_instance->ssl, buffer, pending_message->unsent_size);
                // https://wiki.openssl.org/index.php/Manual:SSL_write(3)

                if (write_result > 0)
                {
                    pending_message->unsent_size -= write_result;
                    if (pending_message->unsent_size == 0)
                    {
                        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_045: [ If the ssl was able to send all the bytes in an enqueued message, the tlsio_openssl_compact_dowork shall call the on_send_complete with IO_SEND_OK. ]*/
                        // The whole message has been sent successfully
                        close_and_destroy_head_message(tls_io_instance, IO_SEND_OK);
                    }
                    else
                    {
                        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_043: [ if the ssl send was not able to send an entire enqueued message at once, tlsio_openssl_compact_dowork shall call the ssl again to send the remaining bytes. ]*/
                        // Repeat the send on the next pass with the rest of the message
                    }
                }
                else
                {
                    // SSL_write returned non-success. It may just be busy, or it may be broken.
                    int hard_error = is_hard_ssl_error(tls_io_instance->ssl, write_result);
                    if (hard_error != 0)
                    {
                        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_044: [ If the ssl fails before sending all of the bytes in an enqueued message, the tlsio_openssl_compact_dowork shall call the on_send_complete with IO_SEND_ERROR. ]*/
                        // This is an unexpected error, and we need to bail out. Probably
                        // lost internet connection.
                        LogInfo("Error from SSL_write: %d", hard_error);
                        close_and_destroy_head_message(tls_io_instance, IO_SEND_ERROR);
                    }
                }
            }
        }
    }
}

static void dowork_poll_dns(TLS_IO_INSTANCE* tls_io_instance)
{
    bool dns_is_complete = dns_async_is_lookup_complete(tls_io_instance->dns);

    if (dns_is_complete)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_014: [ The tlsio_openssl_compact_create shall convert the provided hostName to an IPv4 address. ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_021: [ The tlsio_openssl_compact_open shall begin the process of opening the ssl connection with the host provided in the tlsio_openssl_compact_create call. ]*/
        tls_io_instance->host_ipV4_address = dns_async_get_ipv4(tls_io_instance->dns);
        dns_async_destroy(tls_io_instance->dns);
        tls_io_instance->dns = NULL;
        if (tls_io_instance->host_ipV4_address == 0)
        {
            // Transition to TSLIO_STATE_ERROR
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_015:  [ If the IP for the hostName cannot be found, tlsio_openssl_compact_dowork shall call on_io_open_complete with IO_OPEN_ERROR. ]*/
            // The DNS failure has already been logged
            enter_open_error_state(tls_io_instance);
        }
        else
        {
            SOCKET_ASYNC_HANDLE sock = socket_async_create(tls_io_instance->host_ipV4_address, tls_io_instance->port, false, NULL);
            if (sock < 0)
            {
                // This is a communication interruption rather than a program bug
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_030: [ If tlsio_openssl_compact_dowork fails to open the ssl connection it shall call on_io_open_complete with IO_OPEN_ERROR. ]*/
                LogInfo("Could not open the socket");
                enter_open_error_state(tls_io_instance);
            }
            else
            {
                // The socket has been created successfully, so now wait for it to
                // finish the TCP handshake.
                tls_io_instance->sock = sock;
                tls_io_instance->tlsio_state = TLSIO_STATE_OPENING_WAITING_SOCKET;
            }
        }
    }
    else
    {
        check_for_open_timeout(tls_io_instance);
    }
}

static void dowork_poll_socket(TLS_IO_INSTANCE* tls_io_instance)
{
    bool is_complete;
    int result = socket_async_is_create_complete(tls_io_instance->sock, &is_complete);
    if (result != 0)
    {
        // Transition to TSLIO_STATE_ERROR
        LogInfo("socket_async_is_create_complete failure");
        enter_open_error_state(tls_io_instance);
    }
    else
    {
        if (is_complete)
        {
            // Attempt to transition to TLSIO_STATE_OPENING_WAITING_SSL
            int create_ssl_result = create_ssl(tls_io_instance);
            if (create_ssl_result != 0)
            {
                // Transition to TSLIO_STATE_ERROR
                // create_ssl already did error logging
                enter_open_error_state(tls_io_instance);
            }
            else
            {
                tls_io_instance->tlsio_state = TLSIO_STATE_OPENING_WAITING_SSL;
            }
        }
        else
        {
            check_for_open_timeout(tls_io_instance);
        }
    }
}

static void dowork_poll_open_ssl(TLS_IO_INSTANCE* tls_io_instance)
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
        tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
        tls_io_instance->on_open_complete(tls_io_instance->on_open_complete_context, IO_OPEN_OK);
    }
    else
    {
        int hard_error = is_hard_ssl_error(tls_io_instance->ssl, connect_result);
        if (hard_error != 0)
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30XX_030: [ If tlsio_openssl_compact_dowork fails to open the ssl connection it shall call on_io_open_complete with IO_OPEN_ERROR. ]*/
            LogInfo("Hard error from SSL_connect: %d", hard_error);
            enter_open_error_state(tls_io_instance);
        }
        else
        {
            check_for_open_timeout(tls_io_instance);
        }
    }
}

void tlsio_openssl_dowork(CONCRETE_IO_HANDLE tls_io)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    if (tls_io_instance == NULL)
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_070: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_dowork shall do nothing except log an error. ]*/
        LogError(null_tlsio_message);
    }
    else
    {
        // This switch statement handles all of the state transitions during the opening process
        switch (tls_io_instance->tlsio_state)
        {
        case TLSIO_STATE_NOT_OPEN:
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_075: [ If tlsio_openssl_compact_dowork is called before tlsio_openssl_compact_open, tlsio_openssl_compact_dowork shall do nothing. ]*/
            // Waiting to be opened, nothing to do
            break;
        case TLSIO_STATE_OPENING_WAITING_DNS:
            LogInfo("dowork_poll_dns");
            dowork_poll_dns(tls_io_instance);
            break;
        case TLSIO_STATE_OPENING_WAITING_SOCKET:
            LogInfo("dowork_poll_socket");
            dowork_poll_socket(tls_io_instance);
            break;
        case TLSIO_STATE_OPENING_WAITING_SSL:
            LogInfo("dowork_poll_ssl");
            dowork_poll_open_ssl(tls_io_instance);
            break;
        case TLSIO_STATE_OPEN:
            dowork_read(tls_io_instance);
            dowork_send(tls_io_instance);
            break;
        case TLSIO_STATE_ERROR:
            // There's nothing valid to do here but wait to be destroyed
            break;
        default:
            LogError("Unrecoverable program bug: unexpected internal tlsio state");
            break;
        }
    }
}

int tlsio_openssl_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_120: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
    int result;
    if (tls_io_instance == NULL)
    {
        LogError(null_tlsio_message);
        result = __FAILURE__;
    }
    else
    {
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_121: [ If the optionName parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
        if (optionName == NULL)
        {
            LogError("Required optionName parameter is NULL");
            result = __FAILURE__;
        }
        else
        {
            /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_122: [ If the value parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
            if (value == NULL)
            {
                LogError("Required value parameter is NULL");
                result = __FAILURE__;
            }
            else
            {
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_123 [ The tlsio_openssl_compact_setoption shall do nothing and return 0. ]*/
                result = 0;
            }
        }
    }
    return result;
}

/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_161: [ The tlsio_openssl_compact_retrieveoptions shall do nothing and return NULL. ]*/
static OPTIONHANDLER_HANDLE tlsio_openssl_retrieveoptions(CONCRETE_IO_HANDLE tls_io)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_160: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_retrieveoptions shall do nothing except log an error and return FAILURE. ]*/
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
