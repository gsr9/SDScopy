package main

import (
	"bytes"
	"crypto/tls"
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
	sync.Mutex
	Ok  bool   `json:"ok"`  // true -> correcto, false -> error
	Msg string `json:"msg"` // mensaje adicional
}

//Login
type Login struct {
	sync.Mutex
	Nick string
	Pass string
}

func (l *Login) registro() {

	b, err := ioutil.ReadFile("./www/registro.html") // just pass the file name
	if err != nil {
		fmt.Print(err)
	}
	html := string(b) // convert content to a 'string'
	ui.Load("data:text/html," + url.PathEscape(html))

}

func (l *Login) getLogin(n string, p string) string {
	l.Lock()
	defer l.Unlock()

	fmt.Println(n + "-----" + p)
	r := login(n, p, "/login")

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

func login(nick string, pass string, resource string) Resp {

	var jsonStr = []byte(
		`{
			"name": "` + nick + `",
			"pass": "` + pass + `"
			}`)

	reader := bytes.NewReader(jsonStr)

	response := sendServerPetition("POST", reader, resource, "application/json")
	defer response.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)

	var log Resp
	err := json.Unmarshal(buf.Bytes(), &log)
	check(err)

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

	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}

}
