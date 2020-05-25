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
#cgo CFLAGS: -I.
#cgo LDFLAGS: -lgssapi_krb5 krb.o
#include <string.h>
#include <stdlib.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#include "krb.h"

extern void goLog(char *);

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
	"strings"
	"unsafe"
)

//export goLog
func goLog(text *C.char) {
	log.Println("C:", strings.TrimSpace(C.GoString(text)))
}

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

	os.Setenv("KRB5_KTNAME", "/tmp/keytab")

	var buf bytes.Buffer
	buf.Write(inputTokenBytes[:inputTokenLength])
	slice := buf.Bytes()

	log.Println("Buffer length:", buf.Len())

	log.Println("request authentication")
	switch ret := C.requestAuthenticated(unsafe.Pointer(&slice[0]), (C.size_t)(buf.Len())); ret {
	case 200:
		log.Println("Successfully authenticated")
		w.WriteHeader(http.StatusOK)
		return true
	case 400:
		log.Println("Bad request")
		w.WriteHeader(http.StatusBadRequest)
		return false
	case 401:
		log.Println("Unauthorized")
		w.WriteHeader(http.StatusUnauthorized)
		return false
	default:
		panic("nonexpected output")
	}

	log.Println("oops")
	return false
}

// dumpRequest is used for debugging to display the whole HTTP request as a plain text
func dumpRequest(r *http.Request) {
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))
}
