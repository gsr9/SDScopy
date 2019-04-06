package main

// https://blog.kowalczyk.info/article/Jl3G/https-for-free-in-go.html
// To run:
// go run main.go
// Command-line options:
//   -production : enables HTTPS on port 443
//   -redirect-to-https : redirect HTTP to HTTTPS

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/scrypt"
)

//resp : Respuesta del servidor
type Resp struct {
	Ok   bool   `json:"ok"`   // true -> correcto, false -> error
	Msg  string `json:"msg"`  // mensaje adicional
	Data []byte `json:"data"` //datos a enviar
	ID   int    `json:"id"`
}

//User: Estructura de usuario para el login
// type User struct {
// 	Name string `json:"name"`
// 	Pass string `json:"pass"`
// }
type UserReq struct {
	Name     string `json:"name"` // nombre de usuario
	Password string `json:"pass"` // hash de la contraseña
	//	Data map[string]string // datos adicionales del usuario
}

type UserStore struct {
	ID   int    `json:"id"`   //id del usuario
	Name string `json:"name"` // nombre de usuario
	Hash []byte `json:"pass"` // hash de la contraseña
	Salt []byte `json:"salt"`
}

type Req struct {
	ID   int    `json:"id"`
	Data []byte `json:"data"`
}

const (
	htmlIndex = `<html><body>Welcome!</body></html>`
	httpPort  = "127.0.0.1:8080"
)

var (
	flgProduction          = false
	flgRedirectHTTPToHTTPS = false
)

func chk(err error) {
	if err != nil {
		panic(err)
	}
}

func createDir(dir string, filename string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			panic(err)
		}
		_, err := os.Create(dir + "/" + filename)
		chk(err)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.Method)
}

func leerLogin() []UserStore {
	users := make([]UserStore, 2)
	raw, err := ioutil.ReadFile("./storage/login.json")
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	json.Unmarshal(raw, &users)
	return users
}

func login(w http.ResponseWriter, r *http.Request) {
	userLogin := parseUserData(r)
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	users := leerLogin()
	res := checkUserExists(userLogin, users)
	var dat []byte
	var err error
	var msg string
	var uid int
	if res {
		msg = "User correcto"
		fmt.Println("LOG OK")
		uid = getUserID(userLogin, users)
		dat, err = ioutil.ReadFile("/" + strconv.Itoa(uid) + "/" + strconv.Itoa(uid) + ".txt")
	} else {
		msg = "User incorrecto"
		fmt.Println("LOG BAD")
	}

	respuesta := Resp{Ok: res, Msg: msg, Data: dat, ID: uid}

	rJSON, err := json.Marshal(&respuesta)
	chk(err)
	w.Write(rJSON)
}

func parseRequest(r *http.Request) Req {
	r.ParseForm()
	var req Req
	req.ID, _ = strconv.Atoi(r.Form.Get("ID"))
	req.Data = decode64(r.Form.Get("data"))
	return req
}

func parseUserData(r *http.Request) UserReq {
	r.ParseForm()
	var user UserReq
	user.Name = r.Form.Get("name")
	user.Password = r.Form.Get("pass")
	return user
}

func getUserID(user UserReq, users []UserStore) int {
	id := -1
	// Comprobar si existe algún usuario con el mismo username
	// Calcular el hash con la sal de ese usuario y comprobar con el hash obteneido con el guardado
	for _, us := range users {
		if us.Name == user.Name {
			auxHash, _ := scrypt.Key(decode64(user.Password), us.Salt, 16384, 8, 1, 32)
			if bytes.Compare(us.Hash, auxHash) == 0 {
				id = us.ID
				break
			}
		}
	}
	return id
}

func checkUserExists(user UserReq, users []UserStore) bool {
	exists := false
	// Comprobar si existe algún usuario con el mismo username
	// Calcular el hash con la sal de ese usuario y comprobar con el hash obteneido con el guardado
	for _, us := range users {
		if us.Name == user.Name {
			auxHash, _ := scrypt.Key(decode64(user.Password), us.Salt, 16384, 8, 1, 32)
			if bytes.Compare(us.Hash, auxHash) == 0 {
				exists = true
				break
			}
		}
	}
	return exists
}

func register(w http.ResponseWriter, r *http.Request) {

	user := parseUserData(r)
	var userToSave UserStore
	userToSave.Name = user.Name
	fmt.Printf("Nombre: %s --- Pass: %s", r.Form.Get("name"), r.Form.Get("pass"))
	ok := false
	msg := ""
	//Escribir
	if userToSave.Name != "" {
		//Comprobar que no exite el usuario
		//password := = user.Pass
		// Array to Slice
		users := leerLogin()
		fmt.Println(users)
		exists := checkUserExists(user, users)
		if exists {
			fmt.Println("El usuario que intenta registrar ya existe")
			msg = "El usuario que intenta registrar ya existe"
		} else {
			// Calcular Salt
			userToSave.Salt = make([]byte, 16)
			rand.Read(userToSave.Salt)
			// Calculamos el hash
			userToSave.Hash, _ = scrypt.Key(decode64(user.Password), userToSave.Salt, 16384, 8, 1, 32)
			//Asignamos una id al usuario
			userToSave.ID = len(users) + 1
			//creamos la carpeta del usuario
			createDir("./storage/"+strconv.Itoa(userToSave.ID), strconv.Itoa(userToSave.ID)+".txt")
			// Añadimos los nuevos datos al listado de usuarios
			users = append(users, userToSave)
			// Parseamos la lista de usuarios a JSON
			usersJson, _ := json.Marshal(users)
			// Escribimos el JSON en el fichero donde centralizamos los usuarios registrados
			ioutil.WriteFile("storage/login.json", usersJson, 0644)
			fmt.Println("El usuario se ha registrado con éxito")
			msg = "El usuario se ha registrado con éxito"
			ok = true
		}
	}
	//Respuesta
	//w.Header().Set("Content-Type", "text/plain") // cabecera estándar
	respuesta := Resp{Ok: ok, Msg: msg}
	fmt.Println(respuesta)
	rJSON, err := json.Marshal(&respuesta)
	chk(err)
	w.Write(rJSON)
}

func updateFile(id int, data []byte) bool {

	path := "./storage/" + strconv.Itoa(id) + "/" + strconv.Itoa(id) + ".txt"
	var err = os.Remove(path)
	chk(err)
	_, err = os.Create(path)
	chk(err)
	file, err := os.OpenFile(path, os.O_RDWR, 0644)
	chk(err)

	_, err = file.Write(data)
	chk(err)
	file.Close()
	return true

}

func newPassword(w http.ResponseWriter, r *http.Request) {
	request := parseRequest(r)
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	var dat []byte
	var err error

	changed := updateFile(request.ID, request.Data)
	respuesta := Resp{Ok: changed, Msg: "Contraseñas guardadas", Data: dat}

	rJSON, err := json.Marshal(&respuesta)
	chk(err)
	w.Write(rJSON)
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
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
	mux.HandleFunc("/register", register)
	mux.HandleFunc("/newPassword", newPassword)
	//mux.HandleFunc("/update", func)

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

func main() {
	var m *autocert.Manager

	var httpsSrv *http.Server
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
	err := httpSrv.ListenAndServe()
	if err != nil {
		log.Fatalf("httpSrv.ListenAndServe() failed with %s", err)
	}
}
