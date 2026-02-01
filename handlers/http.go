package handlers

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net/http"
)

// PeekHttpReq reads the HTTP request to extract the Host name without consuming the stream.
func PeekHttpReq(reader io.Reader) (string, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	req, err := parseHttpReq(io.TeeReader(reader, peekedBytes))
	if err != nil {
		return "", nil, err
	}
	return req.Host, io.MultiReader(peekedBytes, reader), nil
}

func parseHttpReq(reader io.Reader) (*http.Request, error) {
	buf := bufio.NewReader(reader)
	req, err := http.ReadRequest(buf)
	if err != nil {
		if req == nil {
			log.Printf("http parse error: %v", err)
		}
		return nil, err
	}
	return req, nil
}
