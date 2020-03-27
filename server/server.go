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

type rootCAEnrollRequest struct {
	RequestType int
}

type enrollResponseObject struct {
	IDCert    string
	IDKey     string
	TLSIDCert string
	TLSIDKey  string
}

type fetchRootCAResponseObject struct {
	IDCert    string
	TLSIDCert string
}

func main() {
	http.HandleFunc("/rootca", fetchRootCA)
	http.HandleFunc("/node", enrollNode)
	http.HandleFunc("/orgadmin", enrollOrgAdmin)
	http.HandleFunc("/aaduser", enrollAADUser)
	http.ListenAndServeTLS(":6054", "rca.crt", "rca.key", nil)
}

func fetchRootCA(w http.ResponseWriter, req *http.Request) {
	var response fetchRootCAResponseObject

	var request rootCAEnrollRequest
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response.IDCert, response.TLSIDCert = utils.RootCACertUtil(request.RequestType)

	responseObject, err := json.Marshal(response)
	if err != nil {
		log.Println(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(responseObject)
}

func enrollNode(w http.ResponseWriter, req *http.Request) {
	var response enrollResponseObject

	var request nodeEnrollRequest
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response.IDCert, response.IDKey, response.TLSIDCert, response.TLSIDKey = utils.NodeCertUtil(request.Name, request.Secret, request.Type, request.Host)

	responseObject, err := json.Marshal(response)
	if err != nil {
		log.Println(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(responseObject)
}

func enrollOrgAdmin(w http.ResponseWriter, req *http.Request) {
	var response enrollResponseObject

	var request orgAdminUserEnrollRequest
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response.IDCert, response.IDKey, response.TLSIDCert, response.TLSIDKey = utils.OrgAdminCertUtil(request.Name, request.Secret)
	responseObject, err := json.Marshal(response)
	if err != nil {
		log.Println(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(responseObject)
}

func enrollAADUser(w http.ResponseWriter, req *http.Request) {
	var response enrollResponseObject

	var request aadUserEnrollRequest
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response.IDCert, response.IDKey, response.TLSIDCert, response.TLSIDKey = utils.AADCertUtil(request.AccessToken)
	responseObject, err := json.Marshal(response)
	if err != nil {
		log.Println(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(responseObject)
}
