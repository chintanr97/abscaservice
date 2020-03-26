package utils

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"strings"
)

func getUserID(accessToken string) (string, error) {
	claimsEncoded := strings.Split(accessToken, ".")
	if len(claimsEncoded) < 2 {
		return "", errors.New("invalid token received")
	}

	claimsDecoded, err := base64.RawURLEncoding.DecodeString(claimsEncoded[1])
	check(err, "Failed to decode given access token.")

	var claims map[string]interface{}
	err = json.NewDecoder(bytes.NewBuffer(claimsDecoded)).Decode(&claims)
	check(err, "Could not decode claims from given access token.")

	oid := claims["oid"].(string)

	return oid, nil
}

//AADCertUtil : The server calls this function to create certificate for an AAD user
func AADCertUtil(accessToken string) (string, string, string, string) {
	//Start AADCertUtil call
	log.Println("Hello! This is AADCertUtil.")

	//Read root cert
	certin, err := ioutil.ReadFile("rca.crt")
	check(err, "Could not read file (\"rca.crt\"). CA credentials were not found.")
	rootCABlock, _ := pem.Decode(certin)
	if rootCABlock == nil {
		log.Println("failed to decode pem file - Cannot create certificate block from .PEM file.")
	}
	rootCA, err := x509.ParseCertificate(rootCABlock.Bytes)
	check(err, "Could not parse the CA certificate. Please check the format.")

	//Fetch client attributes
	userID, err := getUserID(accessToken)
	userAttributes := fetchUserAttributes(accessToken, userID)
	userAttributes.IsCA = false
	userAttributes.IsNode = false

	//Create client cert
	userAttributes.IsTLS = false
	clientCert, clientKey := createCertificate(userAttributes, *rootCA)
	userAttributes.IsTLS = true
	clientTLSCert, clientTLSKey := createCertificate(userAttributes, *rootCA)

	return clientCert, clientKey, clientTLSCert, clientTLSKey
}
