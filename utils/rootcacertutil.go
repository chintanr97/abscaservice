package utils

import (
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"log"
)

func convertCertificateToBase64String(certPEMBlock *pem.Block) string {
	pemEncodedCert := pem.EncodeToMemory(certPEMBlock)
	if pemEncodedCert == nil {
		log.Println("Failed to encode certificate bytes into PEM format.")
	}
	base64EncodedPEMCert := base64.StdEncoding.EncodeToString([]byte(string(pemEncodedCert)))

	return base64EncodedPEMCert
}

//RootCACertUtil : The server calls this function to create certificate for a node identity
func RootCACertUtil(requestType int) (string, string, string, string) {
	//Start NodeCertUtil call
	log.Println("Hello! This is RootCACertUtil.")

	//Read root cert
	certin, err := ioutil.ReadFile("rca.crt")
	check(err, "Could not read file (\"rca.crt\"). CA certificate was not found.")
	rootCACertBlock, _ := pem.Decode(certin)
	if rootCACertBlock == nil {
		log.Println("failed to decode pem file - Cannot create certificate block from .PEM file.")
	}

	base64EncodedRootCert := convertCertificateToBase64String(rootCACertBlock)
	return base64EncodedRootCert, "", base64EncodedRootCert, ""
}
