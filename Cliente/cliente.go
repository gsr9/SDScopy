package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
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
	data     []byte
	// token para gestionar sesión

}

// Usuario global
var user User

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

	r := login(n, p)

	if r.Ok {
		keyClient := sha512.Sum512([]byte(p))
		keyData := keyClient[32:64]
		user.username = n
		user.keyData = keyData

		fmt.Printf("DATA:--" + string(r.Data))
		// guardar el data en la estructura usuario ( tb el token)
		// para usarla cuando quiera añadir una clave (decodificar??)
		// dirigir al home.html
	}
	return r.Msg
}

func chk(err error) {
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
	chk(err)                                     // comprobamos el error
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
	chk(err)
	fmt.Println(r.Body)

	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)

	var log Resp
	err1 := json.Unmarshal(buf.Bytes(), &log)
	chk(err1)

	return log
}

func register(username string, pass string) Resp {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	keyClient := sha512.Sum512([]byte(pass))
	keyLogin := keyClient[:32]           // una mitad para el login (256 bits)
	user.keyData = keyClient[32:64]      // la otra para los datos (256 bits)
	data := url.Values{}                 // estructura para contener los valores
	data.Set("name", username)           // comando (string)
	data.Set("pass", encode64(keyLogin)) // "contraseña" a base64

	r, err := client.PostForm("https://localhost:443/register", data)
	chk(err)

	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)

	var log Resp
	err1 := json.Unmarshal(buf.Bytes(), &log)
	chk(err1)

	return log
}

func descifrar(pK []byte, url string, url2 string) {

	var rd io.Reader
	var err error
	var S cipher.Stream
	var wr io.WriteCloser
	var fin, fout *os.File

	fin, err = os.Open(url)
	chk(err)
	defer fout.Close()

	fout, err = os.OpenFile(url2, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	chk(err)
	defer fout.Close()

	h := sha256.New()
	h.Reset()
	_, err = h.Write(pK)
	chk(err)
	key := h.Sum(nil)

	h.Reset()
	_, err = h.Write([]byte("<inicializar>"))
	chk(err)
	iv := h.Sum(nil)

	block, err := aes.NewCipher(key)
	chk(err)
	S = cipher.NewCTR(block, iv[:16])
	var dec cipher.StreamReader
	dec.S = S
	dec.R = fin

	wr = fout
	rd, err = zlib.NewReader(dec)
	chk(err)

	_, err = io.Copy(wr, rd)
	chk(err)
	wr.Close()
}

func cifrar(pK []byte, url string, data []byte) {

	var rd io.Reader
	var err error
	var S cipher.Stream
	var wr io.WriteCloser
	var fout *os.File

	fout, err = os.OpenFile(url, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	chk(err)
	defer fout.Close()

	h := sha256.New()
	h.Reset()
	_, err = h.Write(pK)
	chk(err)
	key := h.Sum(nil)

	h.Reset()
	_, err = h.Write([]byte("<inicializar>"))
	chk(err)
	iv := h.Sum(nil)

	block, err := aes.NewCipher(key)
	chk(err)
	S = cipher.NewCTR(block, iv[:16])
	var enc cipher.StreamWriter
	enc.S = S
	enc.W = fout

	rd = bytes.NewReader(data)
	wr = zlib.NewWriter(enc)

	_, err = io.Copy(wr, rd)
	chk(err)
	wr.Close()
}

func addEntry() {
	//leer el user.Data

	//decodificar el fichero o ya lo tenemos decodificado?

	//añadir la nueva entrada al fichero
}

// Una vez añadidas todas las entradas las enviaos al servidor (pulsnado el botón Guardar)
func saveFile() {
	// Enviar el user.data al servidor para guardarlo

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

	//ui.Bind("addEntry")
	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}

}
