// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This file is made an integral part of tlsio_openssl_compact.c with a #include. It
// is broken out for readability. 




// The asynchronous nature of SSL_write and SSL_connect means that they must 
// produce several combinations of results within a single test pass.
// This is because some of the "errors" they produce are real errors and the
// system should give up and fail, while other "errors" really mean "I'm not
// done yet and you should call me again immediately". Of course, they can
// also produce success as well. This is all too complicated for the 
// standard umock framework, so this file manages the SSL errors



// This simple pass-thru lets us control the SSL_get_error output with the prior
// SSL_xxx call output thanks to the way that the OpenSSL error handling 
// happens to be designed.
int SSL_get_error(SSL* ssl, int last_error)
{
	ssl;
	return last_error;
}
