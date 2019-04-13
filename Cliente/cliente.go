package main

import (
	"bufio"
	"bytes"
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
	"strconv"
	"strings"
	"sync"

	"github.com/zserge/lorca"
)

var ui lorca.UI
var err error

const VAR_AES = "UniversidadAlicantesdsJonayGuille2019"

//resp : respuesta del servidor
type Resp struct {
	*sync.Mutex
	Ok    bool   `json:"ok"`  // true -> correcto, false -> error
	Msg   string `json:"msg"` // mensaje adicional
	Data  []byte `json:"data"`
	ID    int    `json:"id"`
	Token string `json:"token"`
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

//Add new entries
type Entry struct {
	sync.Mutex
	SiteUrl string
	User    string
	Pass    string
	Msg     string
}

type User struct {
	username string
	keyData  []byte
	data     []byte
	id       int
	token    string // token para gestionar sesión
}

// Usuario global
var user User

func (r *Registro) goToLogin() {
	b, error := ioutil.ReadFile("./www/index.html") // just pass the file name
	chk(error)
	html := string(b) // convert content to a 'string'
	ui.Load("data:text/html," + url.PathEscape(html))
}

func (l *Login) registro() {

	b, error := ioutil.ReadFile("./www/registro.html") // just pass the file name
	chk(error)
	html := string(b) // convert content to a 'string'
	ui.Load("data:text/html," + url.PathEscape(html))
}

func (e *Entry) addEntryToFile(url string, user string, pass string) bool {
	e.Lock()
	defer e.Unlock()

	ok := addEntry(url, user, pass)

	return ok
}

func (e *Entry) synchronize() bool {
	resp := saveFileAndSend()
	if !resp.Ok {
		b, error := ioutil.ReadFile("./www/index.html") // just pass the file name
		chk(error)
		html := string(b) // convert content to a 'string'
		ui.Load("data:text/html," + url.PathEscape(html))
	}
	return resp.Ok
}

func (l *Login) cargar() []string {

	file, error := os.Open("./tmp/dataIn")
	chk(error)

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var txtlines []string

	for scanner.Scan() {
		txtlines = append(txtlines, scanner.Text())
	}

	return txtlines
}

func (r *Registro) getRegistro(n string, p string) string {
	r.Lock()
	defer r.Unlock()

	res := register(n, p)

	return res.Msg
}

func inicializarFicheros() {
	// detect if file exists
	_, err = os.Stat("./tmp/dataIn")

	// create file if not exists
	if os.IsNotExist(err) {
		var file, error = os.Create("./tmp/dataIn")
		chk(error)
		defer file.Close()
	} else {
		var err = os.Remove("./tmp/dataIn")
		chk(err)
		var file, err2 = os.Create("./tmp/dataIn")
		chk(err2)
		defer file.Close()
	}

	var _, err3 = os.Stat("./tmp/dataOut")

	// create file if not exists
	if os.IsNotExist(err3) {
		var file, error = os.Create("./tmp/dataOut")
		chk(error)
		defer file.Close()
	} else {
		var err = os.Remove("./tmp/dataOut")
		chk(err)
		var file, err2 = os.Create("./tmp/dataOut")
		chk(err2)
		defer file.Close()
	}
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
		user.id = r.ID
		tokenByte := r.Token
		user.token = string(decode64(tokenByte))
		// guardar el data en la estructura usuario ( tb el token)
		// para usarla cuando quiera añadir una clave (decodificar??)
		// Y si en lugar de guardar el data lo escribimos en un fichero que borramos al hacer logout ??
		dataOut := "./tmp/dataOut"
		dataIn := "./tmp/dataIn"
		inicializarFicheros()
		if len(r.Data) > 0 {
			err = ioutil.WriteFile(dataOut, r.Data, 0644)
			chk(err)
			descifrar(keyData, dataOut, dataIn)
		}
		goToHome()
	}
	return r.Msg
}

func goToHome() {
	b, err := ioutil.ReadFile("./www/home.html") // just pass the file name
	chk(err)
	html := string(b) // convert content to a 'string'
	ui.Load("data:text/html," + url.PathEscape(html))
}

func (l *Login) goToAddScreen() {
	b, err := ioutil.ReadFile("./www/addEntries.html")
	chk(err)
	html := string(b)
	ui.Load("data:text/html," + url.PathEscape(html))
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

func descifrar(pK []byte, sourceUrl string, destUrl string) {

	var rd io.Reader
	var err error
	var S cipher.Stream
	var wr io.WriteCloser
	var fin, fout *os.File

	fin, err = os.Open(sourceUrl)
	chk(err)
	defer fin.Close()

	fout, err = os.OpenFile(destUrl, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	chk(err)
	defer fout.Close()

	h := sha256.New()
	h.Reset()
	_, err = h.Write(pK)
	chk(err)
	key := h.Sum(nil)

	h.Reset()
	_, err = h.Write([]byte(VAR_AES))
	chk(err)
	iv := h.Sum(nil)

	block, err := aes.NewCipher(key)
	chk(err)
	S = cipher.NewCTR(block, iv[:16])
	var dec cipher.StreamReader
	dec.S = S
	dec.R = fin

	wr = fout
	//rd, err = zlib.NewReader(dec)
	//chk(err)
	rd = dec
	_, err = io.Copy(wr, rd)
	chk(err)
	wr.Close()
}

func cifrar(pK []byte, fileUrl string, data []byte) {

	var rd io.Reader
	var err error
	var S cipher.Stream
	var wr io.WriteCloser
	var fout *os.File

	fout, err = os.OpenFile(fileUrl, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	chk(err)
	defer fout.Close()

	h := sha256.New()
	h.Reset()
	_, err = h.Write(pK)
	chk(err)
	key := h.Sum(nil)

	h.Reset()
	_, err = h.Write([]byte(VAR_AES))
	chk(err)
	iv := h.Sum(nil)

	block, err := aes.NewCipher(key)
	chk(err)
	S = cipher.NewCTR(block, iv[:16])
	var enc cipher.StreamWriter
	enc.S = S
	enc.W = fout

	rd = bytes.NewReader(data)
	//wr = zlib.NewWriter(enc)
	wr = enc

	_, err = io.Copy(wr, rd)
	chk(err)
	wr.Close()
}

func addEntry(site string, username string, pass string) bool {
	// Leemos el fichero
	f, err := os.OpenFile("./tmp/dataIn", os.O_APPEND|os.O_WRONLY, 0600)
	chk(err)
	defer f.Close()
	//añadir la nueva entrada al fichero
	_, err = f.WriteString(fmt.Sprintf("%s %s %s\n", site, username, pass))
	chk(err)
	return true
}

// Una vez añadidas todas las entradas las enviaos al servidor (pulsnado el botón Guardar)
func saveFileAndSend() Resp {
	// Enviar el user.data al servidor para guardarlo
	dataOut := "./tmp/dataOut"
	dataIn := "./tmp/dataIn"
	// Leemos el fichero sin cifrar con todas las contraseñas
	data, err := ioutil.ReadFile(dataIn)
	chk(err)
	// ciframos y lo guardamos en el fichero a enviar
	cifrar(user.keyData, dataOut, data)
	// Leemos el fichero cifrado con las contraseñas antiguas y nuevas
	data, err = ioutil.ReadFile(dataOut)
	chk(err)
	dataToSend := url.Values{}
	dataToSend.Set("data", encode64(data)) // lo codificamos para que pese menos
	//Falta obtener el id del server o calcularlo cada vez en el server
	dataToSend.Set("ID", strconv.Itoa(user.id))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", "https://localhost:443/newPassword", strings.NewReader(dataToSend.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+user.token)
	r, err := client.Do(req)
	// r, err := client.PostForm("https://localhost:443/newPassword", dataToSend)
	chk(err)

	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)

	var log Resp
	err = json.Unmarshal(buf.Bytes(), &log)
	chk(err)
	fmt.Println(log.Msg)
	return log
}

func main() {

	ui, _ = lorca.New("", "", 1024, 720)

	b, err := ioutil.ReadFile("./www/index.html") // just pass the file name
	chk(err)
	html := string(b) // convert content to a 'string'
	ui.Load("data:text/html," + url.PathEscape(html))

	l := &Login{}
	ui.Bind("hazLogin", l.getLogin)
	ui.Bind("goToRegistro", l.registro)
	ui.Bind("cargaDatos", l.cargar)
	ui.Bind("showAddScreen", l.goToAddScreen)

	r := &Registro{}
	ui.Bind("goToLogin", r.goToLogin)
	ui.Bind("hazRegistro", r.getRegistro)

	e := &Entry{}
	ui.Bind("addEntryToFile", e.addEntryToFile)
	ui.Bind("synchronize", e.synchronize)
	ui.Bind("goToHome", goToHome)

	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}

}
