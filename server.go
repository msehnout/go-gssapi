/*
This package contains Go wrapper around GSSAPI C-bindings found in krb5-devel RPM package.
It exports 3 public members:
 * Keytab structure
 * LoadKeytab function
 * RequestAuthenticated function

In order to write a Kerberos aware HTTP service, load the Keytab using the LoadKeytab function
and use RequestAuthenticated in each endpoint handler that requires authentication. The function
itself returns correct HTTP status code and headers in case the authentication fails therefore
you need to provide only what happens in case the authentication was successfull.
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
	void *new_buffer = malloc(length);
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

gss_key_value_set_desc GssKeyValSetDesc() {
	static gss_key_value_element_desc store_elements[] = { { .key = "keytab", .value = "/tmp/keytab" } };
	static gss_key_value_set_desc cockpit_ktab_store = { .count = 1, .elements = store_elements };
	return cockpit_ktab_store;
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
	"regexp"
	"unsafe"
)

// === Example usage ===
func main() {
	portNumber := "9000"

	// Load keytab into memory
	log.Println("Loading credentials")
	var keytab Keytab = LoadKeytab()

	// Create a handler function which takes the keytab in a closure.
	// TODO: I assume it is static and safe to share between the go green
	// threads, but this assumtion might be wrong
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if RequestAuthenticated(w, r, keytab) {
			io.WriteString(w, "hello\n")
		}
	})
	log.Println("Server listening on port ", portNumber)
	http.ListenAndServe(":"+portNumber, nil)
}

// === GSSAPI wrapper ===

/*
# Unresolved questions:
 * How to get the username from token in HTTP header

# Missing pieces:
 * Fix either GssError or reportGSSStatus because one reports failure and the other one does not
 * Input token is not valid: do I need to process the input token somehow??
*/

// Keytab represents loaded Kerberos keytab. Inside it uses GSSAPI generic storage
// for credentials but we don't intend to support any other authentication than krb.
type Keytab struct {
	inner C.gss_cred_id_t
}

// LoadKeytab takes a filename of a keytab and uses GSSAPI extension from krb5 library
// to load it as a Keytab structure which contains gss_cred_id_t structure
func LoadKeytab() Keytab {
	var majStat C.OM_uint32
	var minStat C.OM_uint32
	var credHandle C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL
	var cockpitKtabStore C.gss_key_value_set_desc = C.GssKeyValSetDesc()

	majStat = C.gss_acquire_cred_from(
		&minStat,                 // minor_status
		C.GSS_C_NO_NAME,          // desired_name
		C.GSS_C_INDEFINITE,       // time_req
		C.GSS_C_NO_OID_SET,       // desired_mechs
		C.GSS_C_ACCEPT,           // cred_usage
		&cockpitKtabStore,        // cred_store
		&credHandle,              // output_cred_handle
		(*C.gss_OID_set)(C.NULL), // actual_mechs
		(*C.OM_uint32)(C.NULL),   // time_rec
	)

	// Debug prints
	log.Println("Major status:", majStat)
	log.Println("Minor status:", minStat)

	logGSSMajorStatus(majStat, "There was an error in loading credentials")

	return Keytab{
		inner: credHandle,
	}
}

// RequestAuthenticated is a guard to an HTTP request and returns boolean value indicating
// that the user is successfully authenticated
func RequestAuthenticated(w http.ResponseWriter, r *http.Request, keytab Keytab) bool {
	// dump the request for debugging purposes
	dumpRequest(r)

	// implement SPNEGO inside HTTP as described here:
	// https://tools.ietf.org/html/rfc4559#section-5
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("Missing header")
		return false
	}

	// Make sure the header uses the right format
	re := regexp.MustCompile(`Negotiate ([0-9A-Za-z+/]+==)`)
	ret := re.FindSubmatch([]byte(authHeader))
	if ret == nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Println("Bad header")
		return false
	}
	// FindSubmatch returns 2 slices, one contains the whole match and the second one only
	// the part in parentheses
	inputTokenBase64 := ret[1]
	var inputTokenBytes []byte = make([]byte, len(inputTokenBase64))
	log.Println("Header length:", len(inputTokenBase64))
	log.Println("Decoding header:", string(inputTokenBase64))
	inputTokenLength, err := base64.StdEncoding.Decode(inputTokenBytes, inputTokenBase64)
	log.Println("Decoded", inputTokenLength, "bytes from the Negotiate header")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Printf("Error decoding input token: %s ", err.Error())
		return false
	}

	log.Println("Converting input token")
	var inputToken C.gss_buffer_t = byteArrayToGssBuffer(inputTokenBytes, inputTokenLength)
	log.Println("Input token length:", inputToken.length)
	defer C.FreeGssBufferType(inputToken)

	// Call "accept security context" as described here:
	// https://tools.ietf.org/html/rfc2744#section-5.1
	log.Println("Calling gss accept sec context")
	var minStat C.OM_uint32
	var contextHdl C.gss_ctx_id_t = C.GSS_C_NO_CONTEXT
	//var outputToken C.gss_buffer_t
	var retFlags C.uint = 0
	var credHdl C.gss_cred_id_t = keytab.inner
	var name C.gss_name_t = C.GSS_C_NO_NAME
	var mechType C.gss_OID = C.GSS_C_NO_OID
	var output C.gss_buffer_desc = C.GssGetEmptyBuffer()
	var caps C.OM_uint32 = 0
	var client C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL

	// FIXME: Invalid token was supplied
	majStat := C.gss_accept_sec_context(
		&minStat,
		&contextHdl,                 // If I don't need to keep the context for further calls, this should be fine
		credHdl,                     // the loaded keytab
		inputToken,                  // This is what I've got from the client
		C.GSS_C_NO_CHANNEL_BINDINGS, // input_chan_bindings
		&name,                       // src_name
		&mechType,                   // mech_type
		// token to be passed back to the caller, but since I don't implement support for keeping the context,
		// I cannot handle it. Needs to be released with call to gss_release_buffer()
		//C.GSS_C_NO_BUFFER,
		&output,
		&retFlags, // ret_flags, allows for further configuration
		&caps,     // time_rec
		&client)   // delegated_cred_handle

	// Debug prints
	log.Println("Major status:", majStat)
	log.Println("Minor status:", minStat)

	logGSSMajorStatus(majStat, "There was an error in accepting the security context")

	// Check if the user is authenticated
	// TODO: this does not seem to work properly
	if majStat&C.GSS_S_COMPLETE == 0 {
		log.Println("Successfully authenticated")
		return true
	}
	log.Println("Authentication failed")
	return false
}

// logGSSMajorStatus accepts a major status from a GSSAPI call and in case of errors it
// logs the human readable messages describing the failure.
func logGSSMajorStatus(majStat C.OM_uint32, header string) {
	var minStat C.OM_uint32
	if C.GssError(majStat) != 0 {
		// Log the description of the operation that went wrong
		log.Println(header)

		// There might have been multiple errors, in such case it is necessary to call
		// gss_display_status multiple times and keeping the context (messageContext)
		// More info: https://tools.ietf.org/html/rfc2744.html#section-5.11
		var messageContext C.OM_uint32 = 0
		var statusString C.gss_buffer_desc
		for {
			log.Println("Running gss display status")
			majStat2 := C.gss_display_status(
				&minStat,
				majStat,
				C.GSS_C_GSS_CODE,
				C.GSS_C_NO_OID,
				&messageContext,
				&statusString,
			)

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
