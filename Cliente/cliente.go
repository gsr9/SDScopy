package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

func main() {
	resource := "/login"
	data := url.Values{}
	data.Set("name", "Jonay")
	data.Set("pass", "pass1")

	bytesJSON, err := json.Marshal(data)
	check(err)
	fmt.Println(data)

	reader := bytes.NewReader(bytesJSON)

	response := sendServerPetition("POST", reader, resource, "application/json")
	defer response.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)

	var login resp
	err = json.Unmarshal(buf.Bytes(), &login)
	check(err)

	//buf := new(bytes.Buffer)
	fmt.Println(login.Msg)

}
