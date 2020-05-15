package main

/*
#cgo LDFLAGS: -lgssapi_krb5
#include <stdlib.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

gss_buffer_t GssBufferTypeFromVoidPtr(void *buffer, size_t length) {
	// https://tools.ietf.org/html/rfc2744.html#section-3.2
	gss_buffer_t ptr = (gss_buffer_t)malloc(sizeof(gss_buffer_desc));
	ptr->length = length;
	ptr->value = buffer;
	return ptr;
}

void FreeGssBufferType(gss_buffer_t buffer) {
	free(buffer);
}

char *GssBufferGetValue(gss_buffer_desc *buf) {
	return buf->value;
}

int GssBufferGetLength(gss_buffer_desc *buf) {
	return buf->length;
}

OM_uint32 GssError(OM_uint32 maj_stat) {
	return GSS_ERROR(maj_stat);
}
*/
import "C"

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"unsafe"
)

func main() {
	portNumber := "9000"

	// Load keytab into memory
	log.Println("Loading credentials")
	var keytab KeyTab = LoadCredentials("/tmp/keytab")

	// Create a handler function which takes the keytab in a closure.
	// TODO: I assume it is static and safe to share between the go green
	// threads, but this assumtion might be wrong
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if RequestAuthenticated(w, r, keytab) {
			io.WriteString(w, "hello\n")
		} else {
			io.WriteString(w, "bye\n")
		}
	})
	log.Println("Server listening on port ", portNumber)
	http.ListenAndServe(":"+portNumber, nil)
}

/*
# TODO:
 * Load the library dynamically? Isn't it possible to let the linker do this for me?
 * Use something better than 10:
 * Fix either GssError or reportGSSStatus because one reports failure and the other one does not
 * Fix authentication as it does not work
*/

// KeyTab represents loaded Kerberos keytab. Inside it uses GSSAPI generic storage
// for credentials but we don't intend to support any other authentication than krb.
type KeyTab struct {
	inner C.gss_cred_id_t
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
func byteArrayToGssBuffer(buffer []byte) C.gss_buffer_t {
	return C.GssBufferTypeFromVoidPtr(unsafe.Pointer(&buffer[0]), (C.size_t)(len(buffer)))
}

// LogGSSMajorStatus accepts a major status from a GSSAPI call and in case of errors it
// logs the human readable messages describing the failure.
func LogGSSMajorStatus(majStat C.OM_uint32, header string) {
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

// LoadCredentials takes a filename of a keytab and uses GSSAPI extension from krb5 library
// to load it as a KeyTab structure which contains gss_cred_id_t structure
func LoadCredentials(filename string) KeyTab {
	// More info here:
	// https://web.mit.edu/kerberos/krb5-devel/doc/appdev/gssapi.html#importing-and-exporting-credentials
	log.Println("Reading keytab")
	// Content is a byte array ([]byte) which contains binary data loaded from the file
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Converting keytab into buffer")
	var inputToken C.gss_buffer_t = byteArrayToGssBuffer(content)
	defer C.FreeGssBufferType(inputToken)

	log.Println("Calling gss import cred")
	var majStat C.OM_uint32
	var minStat C.OM_uint32
	var credHandle C.gss_cred_id_t
	majStat = C.gss_import_cred(&minStat, inputToken, &credHandle)

	// Debug prints
	log.Println("Major status:", majStat)
	log.Println("Minor status:", minStat)

	LogGSSMajorStatus(majStat, "There was an error in loading credentials")

	return KeyTab{
		inner: credHandle,
	}
}

// RequestAuthenticated is a guard to an HTTP request and returns boolean value indicating
// that the user is successfully authenticated
func RequestAuthenticated(w http.ResponseWriter, r *http.Request, keytab KeyTab) bool {
	// dump the request for debugging purposes
	dumpRequest(r)

	// implement SPNEGO inside HTTP as described here:
	// https://tools.ietf.org/html/rfc4559#section-5
	auth := r.Header.Get("Authorization")
	if auth == "" {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	// Decode the base64 input from user
	// 10: because that's the length of 'Negotiate '
	// TODO: use something better then 10:
	inputTokenBase64 := []byte(auth[10:])
	var inputTokenBytes []byte = make([]byte, 4096)
	log.Println("Decoding header")
	_, err := base64.StdEncoding.Decode(inputTokenBytes, inputTokenBase64)
	if err != nil {
		log.Printf("Error decoding input token: %s ", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return false
	}

	log.Println("Converting input token")
	var inputToken C.gss_buffer_t = byteArrayToGssBuffer(inputTokenBytes)
	defer C.FreeGssBufferType(inputToken)

	// Call "accept security context" as described here:
	// https://tools.ietf.org/html/rfc2744#section-5.1
	log.Println("Calling gss accept sec context")
	var minStat C.OM_uint32
	var contextHdl C.gss_ctx_id_t = C.GSS_C_NO_CONTEXT
	var outputToken C.gss_buffer_t
	var retFlags C.uint = 0
	var credHdl C.gss_cred_id_t = keytab.inner

	majStat := C.gss_accept_sec_context(&minStat,
		&contextHdl,                 // If I don't need to keep the context for further calls, this should be fine
		credHdl,                     // I think I need to load keytab here somehow
		inputToken,                  // This is what I've got from the client
		C.GSS_C_NO_CHANNEL_BINDINGS, // input_chan_bindings
		(*C.gss_name_t)(C.NULL),     // src_name
		(*C.gss_OID)(C.NULL),        // mech_type
		// token to be passed back to the caller, but since I don't implement support for keeping the context,
		// I cannot handle it. Needs to be released with call to gss_release_buffer()
		outputToken,
		(*C.uint)(&retFlags),       // ret_flags, allows for further configuration
		(*C.uint)(C.NULL),          // time_rec
		(*C.gss_cred_id_t)(C.NULL)) // delegated_cred_handle

	// Debug prints
	log.Println("Major status:", majStat)
	log.Println("Minor status:", minStat)

	LogGSSMajorStatus(majStat, "There was an error in accepting the security context")

	// Check if the user is authenticated
	// TODO: this does not seem to work properly
	if majStat&C.GSS_S_COMPLETE != 0 {
		log.Println("Successfully authenticated")
		return true
	}
	log.Println("Authentication failed")
	return false
}
