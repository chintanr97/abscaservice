package main

import (
	"absCAServer/utils"
	"encoding/json"
	"log"
	"net/http"
)

type nodeEnrollRequest struct {
	Name   string
	Secret string
	Type   string
	Host   string
}

type orgAdminUserEnrollRequest struct {
	Name   string
	Secret string
}

type aadUserEnrollRequest struct {
	AccessToken string
}

type httpResponseObject struct {
	IDCert    string
	IDKey     string
	TLSIDCert string
	TLSIDKey  string
}

func main() {
	http.HandleFunc("/", serveHTTP)
	http.ListenAndServeTLS(":6054", "rca.crt", "rca.key", nil)
}

func serveHTTP(w http.ResponseWriter, req *http.Request) {
	var response httpResponseObject

	idCert, idKey, tlsIDCert, tlsIDKey := "", "", "", ""

	var request nodeEnrollRequest
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		var request orgAdminUserEnrollRequest
		err = json.NewDecoder(req.Body).Decode(&request)
		if err != nil {
			var request aadUserEnrollRequest
			err = json.NewDecoder(req.Body).Decode(&request)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			idCert, idKey, tlsIDCert, tlsIDKey = utils.AADCertUtil(request.AccessToken)
		}

		idCert, idKey, tlsIDCert, tlsIDKey = utils.OrgAdminCertUtil(request.Name, request.Secret)
	}

	idCert, idKey, tlsIDCert, tlsIDKey = utils.NodeCertUtil(request.Name, request.Secret, request.Type, request.Host)

	response.IDCert, response.IDKey, response.TLSIDCert, response.TLSIDKey = idCert, idKey, tlsIDCert, tlsIDKey

	responseObject, err := json.Marshal(response)
	if err != nil {
		log.Println(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(responseObject)
	//w.Write([]byte("PONG\n"))
}
