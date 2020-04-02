package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"log"
	"math/big"
	"time"
)

type certSubject struct {
	CN       string
	Org      []string
	OU       []string
	Country  []string
	Province []string
	Locality []string
	Hosts    []string
	IsCA     bool
	IsNode   bool
	IsAdmin  bool
	IsTLS    bool
}

func check(err error, msg string) {
	if err != nil {
		log.Print(err)
		log.Println(" - " + msg)
	}
}

func writeCertificateAndKeyToString(certBytes []byte, keyBytes []byte) (string, string) {
	pemEncodedCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if pemEncodedCert == nil {
		log.Println("Failed to encode certificate bytes into PEM format.")
	}
	base64EncodedPEMCert := base64.StdEncoding.EncodeToString(pemEncodedCert)

	pemEncodedKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	if pemEncodedKey == nil {
		log.Println("Failed to encode key bytes into PEM format.")
	}
	base64EncodedPEMKey := base64.StdEncoding.EncodeToString(pemEncodedKey)

	return base64EncodedPEMCert, base64EncodedPEMKey
}

func createCertificate(userProperties certSubject, rootCert x509.Certificate, rootKey *ecdsa.PrivateKey) (string, string) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err, "Failed to generate ECDSA private key.")

	publicKey := privateKey.PublicKey
	publicKeyBytes := elliptic.Marshal(publicKey, publicKey.X, publicKey.Y)
	sha1OfPublicKeyBytes := sha1.Sum(publicKeyBytes)
	subKeyIDValue := sha1OfPublicKeyBytes[:]

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	check(err, "Failed to generate a large random number.")

	certProperties := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         userProperties.CN,
			Organization:       userProperties.Org,
			OrganizationalUnit: userProperties.OU,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Minute * 10),
		BasicConstraintsValid: true,
		SubjectKeyId:          subKeyIDValue,
		IsCA:                  userProperties.IsCA,
	}

	if userProperties.Country != nil {
		certProperties.Subject.Country = userProperties.Country
	}
	if userProperties.Province != nil {
		certProperties.Subject.Province = userProperties.Province
	}
	if userProperties.Locality != nil {
		certProperties.Subject.Locality = userProperties.Locality
	}

	if userProperties.IsCA {
		certProperties.NotAfter = time.Now().AddDate(5, 0, 0)
		certProperties.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		certProperties.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}

		certBytes, err := x509.CreateCertificate(rand.Reader, &certProperties, &certProperties, &publicKey, privateKey)
		check(err, "Failed to create Intermediate CA certificate.")

		keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		check(err, "Could not convert Intermediate CA private key to bytes.")

		rootCACert, rootCAKey := writeCertificateAndKeyToString(certBytes, keyBytes)
		return rootCACert, rootCAKey

	} else if userProperties.IsNode {
		certProperties.NotAfter = time.Now().AddDate(2, 0, 0)
		certProperties.KeyUsage = x509.KeyUsageDigitalSignature
		certProperties.DNSNames = userProperties.Hosts

		if userProperties.IsTLS {
			certProperties.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
			certProperties.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		}

		customAttrs := "{\"attrs\":{\"hf.Affiliation\":\"\",\"hf.EnrollmentID\":\"" + userProperties.CN + "\",\"hf.Type\":\"" + userProperties.OU[0] + "\"}}"

		e1 := pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1},
			Critical: false,
			Value:    []byte(customAttrs),
		}

		certProperties.ExtraExtensions = []pkix.Extension{e1}

		certBytes, err := x509.CreateCertificate(rand.Reader, &certProperties, &rootCert, &publicKey, rootKey)
		check(err, "Failed to create client certificate.")

		keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		check(err, "Could not convert client private key to bytes.")

		nodeCert, nodeKey := writeCertificateAndKeyToString(certBytes, keyBytes)
		return nodeCert, nodeKey

	} else if userProperties.IsAdmin {
		certProperties.NotAfter = time.Now().AddDate(1, 0, 0)
		certProperties.KeyUsage = x509.KeyUsageDigitalSignature
		certProperties.DNSNames = userProperties.Hosts

		customAttrs := ""
		if userProperties.IsTLS {
			certProperties.Subject.CommonName = "admin.tls." + userProperties.Org[0]
			certProperties.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
			certProperties.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}

			customAttrs = "{\"attrs\":{\"abac.init\":\"true\",\"admin\":\"true\",\"hf.Affiliation\":\"\",\"hf.EnrollmentID\":\"" + certProperties.Subject.CommonName + "\",\"hf.Type\":\"admin\"}}"
		} else {
			customAttrs = "{\"attrs\":{\"abac.init\":\"true\",\"admin\":\"true\",\"hf.Affiliation\":\"\",\"hf.EnrollmentID\":\"" + userProperties.CN + "\",\"hf.Type\":\"admin\"}}"
		}

		e1 := pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1},
			Critical: false,
			Value:    []byte(customAttrs),
		}

		certProperties.ExtraExtensions = []pkix.Extension{e1}

		certBytes, err := x509.CreateCertificate(rand.Reader, &certProperties, &rootCert, &publicKey, rootKey)
		check(err, "Failed to create admin certificate.")

		keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		check(err, "Could not convert admin private key to bytes.")

		adminCert, adminKey := writeCertificateAndKeyToString(certBytes, keyBytes)
		return adminCert, adminKey
	}

	certProperties.NotAfter = time.Now().AddDate(0, 1, 0)
	certProperties.KeyUsage = x509.KeyUsageDigitalSignature

	customAttrs := ""
	if userProperties.IsTLS {
		certProperties.Subject.CommonName = userProperties.CN + ".tls"
		customAttrs = "{\"attrs\":{\"hf.Affiliation\":\"\",\"hf.EnrollmentID\":\"" + userProperties.CN + ".tls\",\"hf.Type\":\"client\"}}"
	} else {
		customAttrs = "{\"attrs\":{\"hf.Affiliation\":\"\",\"hf.EnrollmentID\":\"" + userProperties.CN + "\",\"hf.Type\":\"client\"}}"
	}

	e1 := pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1},
		Critical: false,
		Value:    []byte(customAttrs),
	}

	certProperties.ExtraExtensions = []pkix.Extension{e1}

	certBytes, err := x509.CreateCertificate(rand.Reader, &certProperties, &rootCert, &publicKey, rootKey)
	check(err, "Failed to create client certificate.")

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	check(err, "Could not convert client private key to bytes.")

	clientCert, clientKey := writeCertificateAndKeyToString(certBytes, keyBytes)
	return clientCert, clientKey
}
