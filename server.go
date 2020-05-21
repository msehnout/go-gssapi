/*
This package contains Go wrapper around GSSAPI C-bindings found in krb5-devel RPM package.
It exports only 1 public member:
 * RequestAuthenticated function

In order to write a Kerberos aware HTTP service use RequestAuthenticated in each endpoint handler
that requires authentication. The function itself returns correct HTTP status code and headers in
case the authentication fails therefore you need to provide only what happens in case the
authentication was successfull.
*/
package main

// This is a magic comment which is in fact a C source code used by cgo

/*
#cgo LDFLAGS: -lgssapi_krb5
#include <string.h>
#include <stdlib.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

// Helper functions for type conversions and struct access on Go-C boundary

gss_buffer_t GssBufferTypeFromVoidPtr(void *buffer, size_t length) {
	// https://tools.ietf.org/html/rfc2744.html#section-3.2
	gss_buffer_t ptr = (gss_buffer_t)malloc(sizeof(gss_buffer_desc));
	void *new_buffer = calloc(length, '\0');
	memcpy(buffer, new_buffer, length);
	ptr->length = length;
	ptr->value = new_buffer;
	return ptr;
}

gss_buffer_t GssBufferTypeFromCharPtr(char *buffer, size_t length) {
	// https://tools.ietf.org/html/rfc2744.html#section-3.2
	gss_buffer_t ptr = (gss_buffer_t)malloc(sizeof(gss_buffer_desc));
	void *new_buffer = calloc(length+1, '\0');
	memcpy(buffer, new_buffer, length);
	ptr->length = length;
	ptr->value = new_buffer;
	return ptr;
}

void FreeGssBufferType(gss_buffer_t buffer) {
	free(buffer->value);
	free(buffer);
}

char *GssBufferGetValue(gss_buffer_desc *buf) {
	return buf->value;
}

int GssBufferGetLength(gss_buffer_desc *buf) {
	return buf->length;
}

// Wrapper around macro
OM_uint32 GssError(OM_uint32 maj_stat) {
	return GSS_ERROR(maj_stat);
}

// Wrapper around macro
gss_buffer_desc GssGetEmptyBuffer() {
	gss_buffer_desc ret = GSS_C_EMPTY_BUFFER;
	return ret;
}

*/
import "C"

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"unsafe"
)

// === Example usage ===
func main() {
	portNumber := "9000"

	// Create a handler function which takes the keytab in a closure.
	// TODO: I assume it is static and safe to share between the go green
	// threads, but this assumtion might be wrong
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if RequestAuthenticated(w, r) {
			io.WriteString(w, "hello\n")
		}
	})
	log.Println("Server listening on port ", portNumber)
	http.ListenAndServe(":"+portNumber, nil)
}

// === GSSAPI wrapper ===

/*
# Unresolved questions:
 * How to get the username from token in HTTP header, we need to know who is authenticated.

# Missing pieces:
 * Input token is not valid: do I need to process the input token somehow??
*/

// RequestAuthenticated is a guard to an HTTP request and returns boolean value indicating
// that the user is successfully authenticated
func RequestAuthenticated(w http.ResponseWriter, r *http.Request) bool {
	// dump the request for debugging purposes
	dumpRequest(r)

	//log.Println("Empty credHandle:", keytab.inner == C.GSS_C_NO_CREDENTIAL)

	// implement SPNEGO inside HTTP as described here:
	// https://tools.ietf.org/html/rfc4559#section-5
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("Missing header")
		return false
	}

	// Make sure the header uses the right format and cut the base64 encoded token
	re := regexp.MustCompile(`Negotiate ([0-9A-Za-z+/]+==)`)
	ret := re.FindSubmatch([]byte(authHeader))
	if ret == nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Println("Bad header")
		return false
	}
	// FindSubmatch returns 2 slices, one contains the whole match and the second one only
	// the part in parentheses so this is only the token
	inputTokenBase64 := ret[1]
	// The length of binary token cannot be bigger than the length of base64 encoded one
	var inputTokenBytes []byte = make([]byte, len(inputTokenBase64))
	// Debug prints
	log.Println("Header length:", len(inputTokenBase64))
	log.Println("Decoding header:", string(inputTokenBase64))
	inputTokenLength, err := base64.StdEncoding.Decode(inputTokenBytes, inputTokenBase64)
	log.Println("Decoded", inputTokenLength, "bytes from the Negotiate header")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Printf("Error decoding input token: %s ", err.Error())
		return false
	}

	// Convert from Go []byte to C gss_buffer_t
	log.Println("Converting input token")
	var inputToken C.gss_buffer_t = byteArrayToGssBuffer(inputTokenBytes, inputTokenLength)
	log.Println("Input token length:", inputToken.length)
	defer C.FreeGssBufferType(inputToken)

	// Call "accept security context" as described here:
	// https://tools.ietf.org/html/rfc2744#section-5.1
	os.Setenv("KRB5_KTNAME", "/tmp/keytab")
	log.Println("Calling gss accept sec context")
	var minStat C.OM_uint32
	var contextHdl C.gss_ctx_id_t = C.GSS_C_NO_CONTEXT
	var retFlags C.uint = 0
	var credHdl C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL
	var name C.gss_name_t = C.GSS_C_NO_NAME
	var mechType C.gss_OID = C.GSS_C_NO_OID
	var output C.gss_buffer_desc = C.GssGetEmptyBuffer()
	var caps C.OM_uint32 = 0
	var client C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL

	// With this implementation we can process only one HTTP request, so there is no point running the
	// gss_accept_sec_context in a loop as recommended in the RFC, but Kerberos should not require further
	// calls. Inspired by:
	// https://github.com/cockpit-project/cockpit/commit/9a42521626f85d7caf52d532008ec476256d04c7#diff-45425284ad53ac259e388e0e643c3563R490

	// FIXME: Invalid token was supplied
	// Client side uses:
	// $ echo password | kinit user@LOCAL
	// $ curl -v --negotiate -u : localhost:9000
	majStat := C.gss_accept_sec_context(
		&minStat,
		&contextHdl,
		credHdl,                     // The loaded keytab
		inputToken,                  // This is what I've got from the client
		C.GSS_C_NO_CHANNEL_BINDINGS, // input_chan_bindings
		&name,                       // src_name
		&mechType,                   // mech_type
		// token to be passed back to the caller, but since I don't implement support for keeping the context,
		// I cannot handle it. Needs to be released with call to gss_release_buffer()
		&output,
		&retFlags, // ret_flags, allows for further configuration
		&caps,     // time_rec
		&client)   // delegated_cred_handle

	// Debug prints
	log.Println("Major status:", majStat)
	log.Println("Minor status:", minStat)

	// Check for errors in the accept sec context routine
	if C.GssError(majStat) != 0 {
		log.Println("There was an error in accepting the security context")
		logGSSStatus(majStat, minStat)
		w.WriteHeader(http.StatusBadRequest)
		return false
	}

	// If the routine returned continuation needed, return 401 because we don't support it
	if majStat&C.GSS_S_CONTINUE_NEEDED != 0 {
		log.Println("Continuation needed, but we don't support it")
		w.WriteHeader(http.StatusBadRequest)
		return false
	}

	// Check if the user is authenticated
	if majStat&C.GSS_S_COMPLETE != 0 {
		log.Println("Successfully authenticated")
		return true
	}

	log.Println("Authentication failed")
	return false
}

// logGSSMajorStatus accepts a major status from a GSSAPI call and in case of errors it
// logs the human readable messages describing the failure.
func logGSSStatus(majStat, minStat C.OM_uint32) {
	var minStat2 C.OM_uint32

	// There might have been multiple errors, in such case it is necessary to call
	// gss_display_status multiple times and keeping the context (messageContext)
	// More info: https://tools.ietf.org/html/rfc2744.html#section-5.11
	var messageContext C.OM_uint32 = 0
	var statusString C.gss_buffer_desc
	for {
		log.Println("Running gss display status")
		majStat2 := C.gss_display_status(
			&minStat2,
			majStat,
			C.GSS_C_GSS_CODE,
			C.GSS_C_NO_OID,
			&messageContext,
			&statusString,
		)

		if C.GssError(majStat2) != 0 {
			break
		}

		// Debug print
		log.Println("Major status 2:", majStat2)

		// Convert gss buffer to a Go String a log the error
		msg := C.GoStringN(C.GssBufferGetValue(&statusString), C.GssBufferGetLength(&statusString))
		log.Println("GSS Error:", msg)
		C.gss_release_buffer(&minStat, &statusString)

		// Check if there are more errors to display
		if messageContext == 0 {
			break
		}
	}

	minStat2 = 0
	messageContext = 0
	for {
		log.Println("Running gss display status")
		majStat2 := C.gss_display_status(
			&minStat2,
			minStat,
			C.GSS_C_MECH_CODE,
			C.GSS_C_NULL_OID,
			&messageContext,
			&statusString,
		)

		if C.GssError(majStat2) != 0 {
			break
		}

		// Debug print
		log.Println("Major status 2:", majStat2)

		// Convert gss buffer to a Go String a log the error
		msg := C.GoStringN(C.GssBufferGetValue(&statusString), C.GssBufferGetLength(&statusString))
		log.Println("GSS Error:", msg)
		C.gss_release_buffer(&minStat, &statusString)

		// Check if there are more errors to display
		if messageContext == 0 {
			break
		}
	}
}

// dumpRequest is used for debugging to display the whole HTTP request as a plain text
func dumpRequest(r *http.Request) {
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))
}

// byteArrayToGssBuffer performs type conversion from []byte to C.gss_buffer_t
// TODO: investigate who is responsible for calling free() on the buffer, not the
// dynamically allocated gss_buffer_desc
func byteArrayToGssBuffer(buffer []byte, length int) C.gss_buffer_t {
	return C.GssBufferTypeFromVoidPtr(unsafe.Pointer(&buffer[0]), (C.size_t)(length))
}

// byteBufferToGssBuffer performs type conversion from bytes.Buffer to C.gss_buffer_t
// TODO: investigate who is responsible for calling free() on the buffer, not the
// dynamically allocated gss_buffer_desc
func byteBufferToGssBuffer(buffer bytes.Buffer) C.gss_buffer_t {
	b := buffer.Bytes()
	return C.GssBufferTypeFromVoidPtr(unsafe.Pointer(&b[0]), (C.size_t)(buffer.Len()))
}
