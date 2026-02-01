package handlers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// PeekClientHello parses the TLS Client Hello to extract the Server Name (SNI) manually.
func PeekClientHello(reader io.Reader) (string, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	// We use a limited reader to ensure we don't block indefinitely on malformed input
	// Most ClientHellos are well within 2KB.
	helloReader := io.TeeReader(io.LimitReader(reader, 4096), peekedBytes)

	sni, err := parseSNI(helloReader)
	// Even if SNI fails, we must return the MultiReader so the connection can be handled or logged.
	return sni, io.MultiReader(peekedBytes, reader), err
}

func parseSNI(r io.Reader) (string, error) {
	// 1. Read Record Layer Header (5 bytes)
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", err
	}

	if header[0] != 0x16 { // Handshake
		return "", errors.New("not a TLS handshake")
	}

	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLen == 0 {
		return "", errors.New("empty record")
	}

	// 2. Read Handshake Layer
	data := make([]byte, recordLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", err
	}

	if len(data) < 4 || data[0] != 0x01 { // Client Hello
		return "", errors.New("not a client hello")
	}

	// Handshake Length is data[1:4]
	// Skip Handshake header (4) + Version (2) + Random (32)
	offset := 38

	// Session ID
	if offset+1 > len(data) {
		return "", nil
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Cipher Suites
	if offset+2 > len(data) {
		return "", nil
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + cipherSuitesLen

	// Compression Methods
	if offset+1 > len(data) {
		return "", nil
	}
	compressionMethodsLen := int(data[offset])
	offset += 1 + compressionMethodsLen

	// Extensions
	if offset+2 > len(data) {
		return "", nil
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	extensionsEnd := offset + extensionsLen

	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	for offset+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if extType == 0x00 { // Server Name Extension
			if offset+extLen > extensionsEnd {
				return "", nil
			}
			// Server Name List Length (2)
			// Server Name Type (1) - 0 is host_name
			// Server Name Length (2)
			// Server Name (variable)
			if extLen < 5 {
				return "", nil
			}
			// Skip SNI List Length (2)
			sniOffset := offset + 2
			if sniOffset+3 > extensionsEnd {
				return "", nil
			}
			
			if data[sniOffset] == 0x00 { // host_name
				sniLen := int(binary.BigEndian.Uint16(data[sniOffset+1 : sniOffset+3]))
				if sniOffset+3+sniLen > extensionsEnd {
					return "", nil
				}
				return string(data[sniOffset+3 : sniOffset+3+sniLen]), nil
			}
		}
		offset += extLen
	}

	return "", nil
}
