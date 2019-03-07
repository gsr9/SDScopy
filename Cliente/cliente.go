package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

//resp : respuesta del servidor
type resp struct {
	Ok  bool   `json:"ok"`  // true -> correcto, false -> error
	Msg string `json:"msg"` // mensaje adicional
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

func login(nick string, pass string, resource string) resp {

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

	var login resp
	err := json.Unmarshal(buf.Bytes(), &login)
	check(err)

	return login
}

func main() {

	var logueado resp
	Nick := "Jonay"
	Pass := "pass1"

	logueado = login(Nick, Pass, "/login")

	fmt.Println(logueado.Msg)

}
