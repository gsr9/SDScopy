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
	DataC []byte `json:"datac"`
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

//Add new cards
type Card struct {
	sync.Mutex
	Number string
	Date    string
	Pin    string
	Cvv     string
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


type Password struct {
	Url  string `json:"Url"`
	Nick string `json:"Nick"`
	Pass string `json:"Pass"`
}

type pws struct {
	Passwords []string `json:"pws"`
}

// Usuario global
var user User
var array []Password
var tarjetas []Card

/* FUNCION CHK */
func chk(err error) {
	if err != nil {
		panic(err)
	}
}



/******************
	AUTH
******************/
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
		user.id = r.ID
		user.token = r.Token

		if len(r.Data) > 0 {
			chk(err)
			decrypt(keyData, string(r.Data),"pass")
			decrypt(keyData, string(r.DataC),"card")
		}
		goToHome()
	}
	return r.Msg
}

func login(nick string, pass string) Resp {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	keyClient := sha512.Sum512([]byte(pass))
	keyLogin := keyClient[:32] // una mitad para el login (256 bits)
	data := url.Values{}                 // estructura para contener los valores
	data.Set("name", nick)               // comando (string)
	data.Set("pass", encode64(keyLogin)) // "contraseña" a base64
	fmt.Println("KEY: " + encode64(keyLogin))
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

/******************
	PASSWORDS
******************/
func goToHome() {
	b, err := ioutil.ReadFile("./www/home.html") 
	chk(err)
	html := string(b) 
	ui.Load("data:text/html," + url.PathEscape(html))
}
func (l *Login) goToAddScreen() {
	b, err := ioutil.ReadFile("./www/addEntries.html")
	chk(err)
	html := string(b)
	ui.Load("data:text/html," + url.PathEscape(html))
}

func (e *Entry) addEntryToFile(url string, user string, pass string) bool {
	e.Lock()
	defer e.Unlock()

	ok := addEntry(url, user, pass)

	return ok
}

func (e *Entry) synchronize() bool {
	resp := sincronizar()
	return resp.Ok
}
func (l *Login) cargar() []Password {

	return array
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
	dataToSend.Set("data", data) 
	dataToSend.Set("ID", strconv.Itoa(user.id))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", "https://localhost:443/newPassword", strings.NewReader(dataToSend.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+user.token)
	r, err := client.Do(req)
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
	sincronizar()
	goToHome()
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

/******************
	TARJETAS
******************/
func goToCards() {
	b, error := ioutil.ReadFile("./www/cards.html") // just pass the file name
	chk(error)
	html := string(b) // convert content to a 'string'
	ui.Load("data:text/html," + url.PathEscape(html))
}

func (c *Card) addCard() {
	b, error := ioutil.ReadFile("./www/addCards.html") // just pass the file name
	chk(error)
	html := string(b) // convert content to a 'string'
	ui.Load("data:text/html," + url.PathEscape(html))
}
func (c *Card) addCardToFile(number string, date string, pin string, cvv string) bool {
	c.Lock()
	defer c.Unlock()

	ok := addCard(number, date, pin, cvv)

	return ok
}

func (c *Card) cargarTarjetas() []Card {

	return tarjetas
}

func addCard(number string, date string, pin string, cvv string) bool {
	var c Card
	c.Number = number
	c.Date = date
	c.Pin = pin
	c.Cvv = cvv

	tarjetas = append(tarjetas, c)
	return true
}

func sincronizarCards() Resp {

	jsonCard, err := json.Marshal(&tarjetas)
	chk(err)
	data, _ := encrypt(user.keyData, string(jsonCard))

	dataToSend := url.Values{}
	dataToSend.Set("data", data) 
	dataToSend.Set("ID", strconv.Itoa(user.id))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", "https://localhost:443/newCard", strings.NewReader(dataToSend.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+user.token)
	r, err := client.Do(req)
	chk(err)

	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)

	var log Resp
	err = json.Unmarshal(buf.Bytes(), &log)
	fmt.Println(log.Msg)
	return log
}

func eliminarCard(id int) {
	var aux []Card
	for index, element := range tarjetas {
		if index != id {
			aux = append(aux, element)
		}
	}
	tarjetas = aux
	sincronizarCards()
	goToCards()
}

/******************
	SERVER
******************/


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

func decrypt(key []byte, securemess string, tipo string) {

	fmt.Println(securemess)
	cipherText := decode64(securemess)

	block, err := aes.NewCipher(key)
	chk(err)

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	if tipo == "pass"{
		
		p := make([]Password, 1)
		err = json.Unmarshal(cipherText, &p)
		chk(err)
		array = p
		fmt.Println("Descifradas contraseñas")
	}else{
		c := make([]Card, 1)
		err = json.Unmarshal(cipherText, &c)
		chk(err)
		tarjetas = c
		fmt.Println("Descifradas tarjetas")
	}
	
}
func encrypt(key []byte, message string) (encmess string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	chk(err)

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	encmess = base64.URLEncoding.EncodeToString(cipherText)
	return
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

	c := &Card{}
	ui.Bind("goToCards",goToCards)
	ui.Bind("addCard",c.addCard)
	ui.Bind("addCardToFile", c.addCardToFile)
	ui.Bind("sincronizarCards",sincronizarCards)
	ui.Bind("cargarTarjetas",c.cargarTarjetas)
	ui.Bind("eliminarCard",eliminarCard)

	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}


}
