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

	//Create node attributes
	orgName := strings.Split(name, ".")[1]
	nodeProperties := certSubject{
		CN:      name,
		Org:     []string{orgName},
		OU:      []string{"admin"},
		Hosts:   []string{"fabric-tools"},
		IsCA:    false,
		IsNode:  true,
		IsAdmin: true,
	}

	//Create node cert
	nodeProperties.IsTLS = false
	nodeCert, nodeKey := createCertificate(nodeProperties, *rootCA)

	nodeProperties.IsTLS = true
	nodeTLSCert, nodeTLSKey := createCertificate(nodeProperties, *rootCA)

	return nodeCert, nodeKey, nodeTLSCert, nodeTLSKey
}
