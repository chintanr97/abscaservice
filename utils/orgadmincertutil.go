package utils

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"strings"
)

//OrgAdminCertUtil : The server calls this function to create certificate for a node identity
func OrgAdminCertUtil(name string, secret string) (string, string, string, string) {
	//Start NodeCertUtil call
	log.Println("Hello! This is OrgAdminCertUtil.")

	//Read root cert
	certin, err := ioutil.ReadFile("rca.crt")
	check(err, "Could not read file (\"rca.crt\"). CA credentials were not found.")
	rootCABlock, _ := pem.Decode(certin)
	if rootCABlock == nil {
		log.Println("failed to decode pem file - Cannot create certificate block from .PEM file.")
	}
	rootCA, err := x509.ParseCertificate(rootCABlock.Bytes)
	check(err, "Could not parse the CA certificate. Please check the format.")

	//Read root cert private key
	keyin, err := ioutil.ReadFile("rca.key")
	check(err, "Could not read file (\"rca.key\"). CA credentials were not found.")
	rootCAPrivateKeyBlock, _ := pem.Decode(keyin)
	if rootCAPrivateKeyBlock == nil {
		log.Println("failed to decode pem file - Cannot create private key block from .PEM file.")
	}
	rootCAPrivateKey, err := x509.ParseECPrivateKey(rootCAPrivateKeyBlock.Bytes)
	check(err, "Could not parse the CA private key. Please check the format.")

	//Create node attributes
	orgName := strings.Split(name, ".")[1]
	orgAdminProperties := certSubject{
		CN:      name,
		Org:     []string{orgName},
		OU:      []string{"admin"},
		Hosts:   []string{"fabric-tools"},
		IsCA:    false,
		IsNode:  false,
		IsAdmin: true,
	}

	//Create node cert
	orgAdminProperties.IsTLS = false
	adminCert, adminKey := createCertificate(orgAdminProperties, *rootCA, rootCAPrivateKey)

	orgAdminProperties.IsTLS = true
	adminTLSCert, adminTLSKey := createCertificate(orgAdminProperties, *rootCA, rootCAPrivateKey)

	return adminCert, adminKey, adminTLSCert, adminTLSKey
}
