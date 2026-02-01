package handlers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// PeekClientHello parses the TLS Client Hello to extract the Server Name (SNI) manually.
// This is more robust than relying on the tls.Server side effects.
func PeekClientHello(reader io.Reader) (string, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	helloReader := io.TeeReader(reader, peekedBytes)

	sni, err := parseSNI(helloReader)
	// We always return the MultiReader so the connection can continue even if SNI fails
	return sni, io.MultiReader(peekedBytes, reader), err
}

func parseSNI(r io.Reader) (string, error) {
	// 1. Read Record Layer Header (5 bytes)
	// ContentType (1), Version (2), Length (2)
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", err
	}

	if header[0] != 0x16 { // Handshake
		return "", errors.New("not a TLS handshake")
	}

	recordLen := binary.BigEndian.Uint16(header[3:5])
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
	offset := 4 + 2 + 32

	// Session ID
	if offset+1 > len(data) {
		return "", errors.New("malformed client hello")
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Cipher Suites
	if offset+2 > len(data) {
		return "", errors.New("malformed client hello")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + cipherSuitesLen

	// Compression Methods
	if offset+1 > len(data) {
		return "", errors.New("malformed client hello")
	}
	compressionMethodsLen := int(data[offset])
	offset += 1 + compressionMethodsLen

	// Extensions
	if offset+2 > len(data) {
		// No extensions, so no SNI
		return "", nil
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	extensionsEnd := offset + extensionsLen

	if extensionsEnd > len(data) {
		return "", errors.New("malformed extensions")
	}

	for offset+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if extType == 0x00 { // Server Name Extension
			if offset+extLen > extensionsEnd {
				return "", errors.New("malformed SNI extension")
			}
			// Server Name List Length (2)
			// Server Name Type (1) - 0 is host_name
			// Server Name Length (2)
			// Server Name (variable)
			if extLen < 5 {
				return "", nil
			}
			sniListLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			_ = sniListLen
			if data[offset+2] == 0x00 { // host_name
				sniLen := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
				if offset+5+sniLen > extensionsEnd {
					return "", errors.New("malformed host_name")
				}
				return string(data[offset+5 : offset+5+sniLen]), nil
			}
		}
		offset += extLen
	}

	return "", nil
}
