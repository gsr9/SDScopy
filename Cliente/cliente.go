package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
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

var array []Password

type Password struct {
	Url  string `json:"Url"`
	Nick string `json:"Nick"`
	Pass string `json:"Pass"`
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
	//resp := saveFileAndSend()
	resp := sincronizar()
	return resp.Ok
}

func (l *Login) cargar() []Password {

	/*file, err := os.Open("./tmp/dataIn")
	chk(err)

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var txtlines []string

	for scanner.Scan() {
		txtlines = append(txtlines, scanner.Text())
	}
	*/
	return array
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
		user.token = r.Token

		// guardar el data en la estructura usuario ( tb el token)
		// para usarla cuando quiera añadir una clave (decodificar??)
		// Y si en lugar de guardar el data lo escribimos en un fichero que borramos al hacer logout ??

		inicializarFicheros()
		if len(r.Data) > 0 {
			//err = ioutil.WriteFile(dataOut, r.Data, 0644)
			chk(err)
			decrypt(keyData, string(r.Data))
			//	descifrar(keyData, dataOut, dataIn)
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
	return base64.URLEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.URLEncoding.DecodeString(s) // recupera el formato original
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

func decrypt(key []byte, securemess string) {

	fmt.Println(securemess)
	cipherText := decode64(securemess)

	block, err := aes.NewCipher(key)
	chk(err)

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	p := make([]Password, 1)
	//var aux ArrayPasswords
	err = json.Unmarshal(cipherText, &p)
	chk(err)
	array = p
	fmt.Println(p)
}
func encrypt(key []byte, message string) (encmess string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	chk(err)

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//returns to base64 encoded string
	encmess = base64.URLEncoding.EncodeToString(cipherText)
	return
}
func addEntry(site string, username string, pass string) bool {
	var p Password
	p.Nick = username
	p.Url = site
	p.Pass = pass

	array = append(array, p)
	return true
}
func sincronizar() Resp {

	jsonPass, err := json.Marshal(&array)
	chk(err)
	data, _ := encrypt(user.keyData, string(jsonPass))

	dataToSend := url.Values{}
	dataToSend.Set("data", data) // lo codificamos para que pese menos
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
	fmt.Println(log.Msg)
	return log
}

func eliminarPass(id int) {
	var aux []Password
	for index, element := range array {
		if index != id {
			aux = append(aux, element)
		}
	}
	array = aux
	sincronizar()
	goToHome()
}

func editarPass(id int, newURL string, newNick string, newPass string) {

	var aux Password
	aux.Url = newURL
	aux.Nick = newNick
	aux.Pass = newPass

	array[id] = aux

	/*for index, element := range array {
		if index != id {
			element = aux
		}
	}*/
	sincronizar()
	goToHome()
}

type pws struct {
	Passwords []string `json:"pws"`
}

func (e *Entry) generatePassword(passType string) string {
	url := ""
	switch passType {
	case "weak":
		url = "https://makemeapassword.ligos.net/api/v1/passphrase/json?pc=1&whenNum=Anywhere&whenUps=Anywhere&wc=2&sp=n&maxCh=80"
		break
	case "medium":
		url = "https://makemeapassword.ligos.net/api/v1/readablepassphrase/json?pc=1&s=Strong&sp=f&whenUp=RunOfLetters&whenNum=Anywhere"
		break
	default:
		url = "https://makemeapassword.ligos.net/api/v1/readablepassphrase/json?pc=1&s=RandomForever&sp=f&whenUp=RunOfLetters"
	}
	r, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error: %s", err)
		return ""
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	var passwords pws
	err = json.Unmarshal(buf.Bytes(), &passwords)
	return passwords.Passwords[0]
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
	ui.Bind("generatePass", e.generatePassword)
	ui.Bind("eliminarPass", eliminarPass)
	ui.Bind("editarPass", editarPass)

	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}

	// https://makemeapassword.ligos.net/api/v1/readablepassphrase/json?pc=1&s=RandomForever&sp=f&whenUp=RunOfLetters

}
