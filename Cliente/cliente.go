package main

import (
	"bytes"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"

	"github.com/zserge/lorca"
)

var ui lorca.UI
var err error

//resp : respuesta del servidor
type Resp struct {
	*sync.Mutex
	Ok   bool   `json:"ok"`  // true -> correcto, false -> error
	Msg  string `json:"msg"` // mensaje adicional
	Data []byte `json:"data"`
}

//Registro
type Registro struct {
	sync.Mutex
	Nick string
	Pass string
}

//Login
type Login struct {
	sync.Mutex
	Nick string
	Pass string
}

type User struct {
	username string
	keyData  []byte
	// token para gestionar sesión
}

func (r *Registro) goToLogin() {
	b, err := ioutil.ReadFile("./www/index.html") // just pass the file name
	if err != nil {
		fmt.Print(err)
	}
	html := string(b) // convert content to a 'string'
	ui.Load("data:text/html," + url.PathEscape(html))
}

func (l *Login) registro() {

	b, err := ioutil.ReadFile("./www/registro.html") // just pass the file name
	if err != nil {
		fmt.Print(err)
	}
	html := string(b) // convert content to a 'string'
	ui.Load("data:text/html," + url.PathEscape(html))

}

func (r *Registro) getRegistro(n string, p string) string {
	r.Lock()
	defer r.Unlock()

	res := register(n, p)

	return res.Msg
}

func (l *Login) getLogin(n string, p string) string {
	l.Lock()
	defer l.Unlock()

	user := &User{}

	r := login(n, p)

	if r.Ok {
		keyClient := sha512.Sum512([]byte(p))
		keyData := keyClient[32:64]
		user.username = n
		user.keyData = keyData
		fmt.Printf("DATA:--" + string(r.Data))
	}
	return r.Msg
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func sendServerPetition(method string, datos io.Reader, route string, contentType string) *http.Response {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, _ := http.NewRequest(method, "http://localhost:8080"+route, datos)
	req.Header.Set("Content-Type", contentType)
	r, _ := client.Do(req)

	return r
}
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	check(err)                                   // comprobamos el error
	return b                                     // devolvemos los datos originales
}

func login(nick string, pass string) Resp {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	keyClient := sha512.Sum512([]byte(pass))
	keyLogin := keyClient[:32] // una mitad para el login (256 bits)
	// keyData := keyClient[32:64]          // la otra para los datos (256 bits)
	data := url.Values{}                 // estructura para contener los valores
	data.Set("name", nick)               // comando (string)
	data.Set("pass", encode64(keyLogin)) // "contraseña" a base64

	r, err := client.PostForm("https://localhost:443/login", data)
	check(err)
	fmt.Println(r.Body)

	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)

	var log Resp
	err1 := json.Unmarshal(buf.Bytes(), &log)
	check(err1)

	return log
}

func register(username string, pass string) Resp {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	keyClient := sha512.Sum512([]byte(pass))
	keyLogin := keyClient[:32] // una mitad para el login (256 bits)
	//keyData := keyClient[32:64]          // la otra para los datos (256 bits)
	data := url.Values{}                 // estructura para contener los valores
	data.Set("name", username)           // comando (string)
	data.Set("pass", encode64(keyLogin)) // "contraseña" a base64

	r, err := client.PostForm("https://localhost:443/register", data)
	check(err)

	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)

	var log Resp
	err1 := json.Unmarshal(buf.Bytes(), &log)
	check(err1)

	return log
}

func main() {

	ui, _ = lorca.New("", "", 1024, 720)

	b, err := ioutil.ReadFile("./www/index.html") // just pass the file name
	if err != nil {
		fmt.Print(err)
	}
	html := string(b) // convert content to a 'string'
	ui.Load("data:text/html," + url.PathEscape(html))

	l := &Login{}
	ui.Bind("hazLogin", l.getLogin)
	ui.Bind("goToRegistro", l.registro)

	r := &Registro{}
	ui.Bind("goToLogin", r.goToLogin)
	ui.Bind("hazRegistro", r.getRegistro)

	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}

}
