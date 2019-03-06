package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
)

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
	/*resource := "/register"
	data := url.Values{}
	data.Set("name", "miscojones")
	data.Set("pass", "hola")

	bytesJSON, _ := json.Marshal(data)
	fmt.Println(data)

	reader := bytes.NewReader(bytesJSON)

	response := sendServerPetition("POST", reader, resource, "application/json")*/
	// comienzo
	url := "http://127.0.0.1:8080/register"
	fmt.Println("URL:>", url)

	var jsonStr = []byte(
		`{
			"name": "Cheese",
			"pass": "123456"
			}`)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	// fin
	/*defer response.Body.Close()
	buf := new(bytes.Buffer)
	fmt.Println(buf)*/

}
