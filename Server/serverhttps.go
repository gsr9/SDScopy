package main

// https://blog.kowalczyk.info/article/Jl3G/https-for-free-in-go.html
// To run:
// go run main.go
// Command-line options:
//   -production : enables HTTPS on port 443
//   -redirect-to-https : redirect HTTP to HTTTPS

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

//Login : Struc para login
type Login struct {
	Name string `json:"name"`
	Pass string `json:"pass"`
}

//Loginbody : Struct para leer login desde el body
type Loginbody struct {
	Name []string `json:"name"`
	Pass []string `json:"pass"`
}

const (
	htmlIndex = `<html><body>Welcome!</body></html>`
	httpPort  = "127.0.0.1:8080"
)

var (
	flgProduction          = false
	flgRedirectHTTPToHTTPS = false
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.Method)
}

func leerLogin() []Login {
	users := make([]Login, 2)
	raw, err := ioutil.ReadFile("./storage/login.json")
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	json.Unmarshal(raw, &users)
	return users
}

func comprobarLogin(user Loginbody) bool {

	users := leerLogin()
	r := false
	for _, u := range users {

		if u.Name == user.Name[0] && u.Pass == user.Pass[0] {
			r = true
		}
	}
	return r
}

func login(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	body := buf.Bytes()

	var userLogin Loginbody
	json.Unmarshal(body, &userLogin)

	fmt.Println(userLogin)
	res := comprobarLogin(userLogin)

	if res {
		fmt.Println("LOG OK")
	} else {
		fmt.Println("LOG BAD")
	}

}

func makeServerFromMux(mux *http.ServeMux) *http.Server {
	// set timeouts so that a slow or malicious client doesn't
	// hold resources forever
	return &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      mux,
	}
}

func makeHTTPServer() *http.Server {
	mux := &http.ServeMux{}
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/login", login)
	return makeServerFromMux(mux)

}

func makeHTTPToHTTPSRedirectServer() *http.Server {
	handleRedirect := func(w http.ResponseWriter, r *http.Request) {
		newURI := "https://" + r.Host + r.URL.String()
		http.Redirect(w, r, newURI, http.StatusFound)
	}
	mux := &http.ServeMux{}
	mux.HandleFunc("/", handleRedirect)
	return makeServerFromMux(mux)
}

func parseFlags() {
	flag.BoolVar(&flgProduction, "production", false, "if true, we start HTTPS server")
	flag.BoolVar(&flgRedirectHTTPToHTTPS, "redirect-to-https", false, "if true, we redirect HTTP to HTTPS")
	flag.Parse()
}

func main() {
	parseFlags()
	var m *autocert.Manager

	var httpsSrv *http.Server
	if flgProduction {
		cert, errCert := tls.LoadX509KeyPair("cert.pem", "key.pem")

		if errCert != nil {
			log.Fatalf("No se encuentran los certificados. %s", errCert)
		}

		// Construct a tls.config
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			// Other options
		}

		httpsSrv = makeHTTPServer()
		httpsSrv.Addr = ":443"
		httpsSrv.TLSConfig = tlsConfig //&tls.Config{GetCertificate: m.GetCertificate}

		go func() {
			fmt.Printf("Starting HTTPS server on %s\n", httpsSrv.Addr)
			err := httpsSrv.ListenAndServeTLS("", "")
			if err != nil {
				log.Fatalf("httpsSrv.ListendAndServeTLS() failed with %s", err)
			}
		}()
	}

	var httpSrv *http.Server
	if flgRedirectHTTPToHTTPS {
		httpSrv = makeHTTPToHTTPSRedirectServer()
	} else {
		httpSrv = makeHTTPServer()
	}
	// allow autocert handle Let's Encrypt callbacks over http
	if m != nil {
		httpSrv.Handler = m.HTTPHandler(httpSrv.Handler)
	}

	httpSrv.Addr = httpPort
	fmt.Printf("Starting HTTP server on %s\n", httpPort)
	err := httpSrv.ListenAndServe()
	if err != nil {
		log.Fatalf("httpSrv.ListenAndServe() failed with %s", err)
	}
}
