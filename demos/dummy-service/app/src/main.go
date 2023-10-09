package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rconway/goutils/httputils"
)

func main() {
	// Flags
	var authMode bool
	var resourceMode bool
	var port int
	flag.BoolVar(&authMode, "auth", false, "use auth mode")
	flag.BoolVar(&resourceMode, "resource", false, "use resource mode")
	flag.IntVar(&port, "port", 80, "port to listen on")
	flag.Parse()

	router := mux.NewRouter()

	// select handler based upon the indicated mode
	var handler http.HandlerFunc
	if authMode {
		fmt.Println("auth mode enabled")
		handler = authHandler
	} else if resourceMode {
		fmt.Println("resource mode enabled")
		handler = resourceHandler
	} else {
		log.Fatal(fmt.Errorf("must specify one of -auth or -resource"))
	}

	// root
	router.PathPrefix("/").HandlerFunc(handler)

	// Start server
	addr := fmt.Sprintf(":%v", port)
	fmt.Printf("Starting to listen at %v\n", addr)
	log.Fatal(http.ListenAndServe(addr, router))
}

// Handler to provide the 'auth' response
func authHandler(w http.ResponseWriter, r *http.Request) {
	var statusCode int

	// Response - deferred to end of function
	defer func() {
		w.Header().Set("WWW-Authenticate", "use this ticket: 123ABC")
		w.WriteHeader(statusCode)
		fmt.Fprintf(w, "Endpoint = Auth Handler\n")
		httputils.DumpRequest(w, r)
		httputils.DumpRequest(os.Stdout, r)
	}()

	// Get the Authorization header
	authorizationStr := r.Header.Get("Authorization")

	// UNAUTHORIZED - if there is no Authorization header then treat as UNAUTHORIZED
	if len(authorizationStr) == 0 {
		fmt.Println("UNAUTHORIZED: no Authorization header")
		statusCode = http.StatusUnauthorized
		return
	}

	// Get the Bearer token from the Authorization header
	authParts := strings.Split(authorizationStr, " ")

	// UNAUTHORIZED - if there is no Bearer token
	if len(authParts) != 2 || authParts[0] != "Bearer" {
		fmt.Println("UNAUTHORIZED: no Bearer token")
		statusCode = http.StatusUnauthorized
		return
	}

	// Get the value of the token as an int
	requestedCode, err := strconv.Atoi(authParts[1])

	// UNAUTHORIZED - if the Bearer token value is not an int
	if err != nil {
		fmt.Println("UNAUTHORIZED: non-integer Bearer token")
		statusCode = http.StatusUnauthorized
		return
	}

	// All checks pass - use the provided status code
	w.Header().Set("X-Pep-Special-Header", "If needed, extra header(s) set by PEP")
	statusCode = requestedCode
}

// Handler for the 'protected' resource
func resourceHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Endpoint = Resource Server\n")
	httputils.DumpRequest(w, r)
	// Output to stdout - but suppress output for k8s liveness probes
	if !strings.HasPrefix(r.Header.Get("User-Agent"), "kube-probe/") {
		httputils.DumpRequest(os.Stdout, r)
	}
}
