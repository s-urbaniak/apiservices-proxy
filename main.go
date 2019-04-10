package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

var (
	to   = flag.String("to", "", "the upstream proxy target")
	addr = flag.String("addr", "", "the listening address")
)

func main() {
	flag.Parse()

	crt, key, err := NewKeys(3 * 365 * time.Hour)
	if err != nil {
		exit(err)
	}

	toURL, err := url.Parse(*to)
	if err != nil {
		exit(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(toURL)
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,

		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,

		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,

		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	mux := http.NewServeMux()
	mux.Handle("/", proxy)

	cert, err := tls.X509KeyPair(crt, key)
	if err != nil {
		exit(err)
	}

	srv := &http.Server{
		Addr:    *addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	if err := srv.ListenAndServeTLS("", ""); err != nil {
		exit(err)
	}
}

func exit(e error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", e)
	os.Exit(1)
}
