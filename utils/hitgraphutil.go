package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	//"fmt"
)

func fetchUserAttributes(accessToken string, uid string) certSubject {
	client := &http.Client{}
	bearer := "Bearer " + accessToken

	//Fetch user properties
	params := "?$select=displayName,givenName,city,companyName,country,department,id,jobTitle,mail,officeLocation,state,surname,streetAddress,userType,userPrincipalName"
	url := "https://graph.microsoft.com/v1.0/me/" + params //+ uid + params

	req, err := http.NewRequest("GET", url, nil)
	check(err, "Failed to create a new HTTP GET request object for fetching user attributes.")

	req.Header.Add("Authorization", bearer)

	response, err := client.Do(req)
	check(err, "Could not receive HTTP GET response for user attributes.")

	var infoMap map[string]interface{}
	body, err := ioutil.ReadAll(response.Body)
	check(err, "Failed to read HTTP response body for fetching user attributes.")
	err = json.Unmarshal([]byte(body), &infoMap)
	check(err, "Could not convert response body to user attributes map.")

	//Fetch user groups
	urlForUG := "https://graph.microsoft.com/v1.0/me/memberOf"

	requestBody, err := json.Marshal(map[string]bool{
		"securityEnabledOnly": true,
	})
	req, err = http.NewRequest("GET", urlForUG, bytes.NewBuffer(requestBody))
	check(err, "Failed to create a new HTTP GET request object for fetching user groups.")

	req.Header.Add("Authorization", bearer)
	req.Header.Set("Content-type", "application/json")

	response, err = client.Do(req)
	check(err, "Could not receive HTTP GET response for fetching user groups.")

	var userGroups map[string]interface{}
	body, err = ioutil.ReadAll(response.Body)
	check(err, "Failed to read HTTP response body for user groups.")
	err = json.Unmarshal([]byte(body), &userGroups)
	check(err, "Could not convert response body to user groups map.")

	//Create an array of role OUs
	title := infoMap["jobTitle"].(string)
	if title == "" {
		title = "member"
	}
	roleOUs := []string{title}

	//Append groups as custom role OUs
	listOfGroups := userGroups["value"].([]interface{})
	for _, v := range listOfGroups {
		groupMap := v.(map[string]interface{})
		dataType := groupMap["@odata.type"].(string)
		if dataType == "#microsoft.graph.group" {
			roleOUs = append(roleOUs, groupMap["displayName"].(string))
		}
	}

	//Create and initialize user attributes' object
	userAttributes := certSubject{
		CN: infoMap["givenName"].(string),
		OU: roleOUs,
	}

	if infoMap["department"].(string) == "" {
		err := errors.New("department field for azure ad user should be filled with org name")
		check(err, "Department field for the Azure AD user should be filled with Org Name.")
	} else {
		userAttributes.Org = []string{infoMap["department"].(string)}
	}

	if infoMap["country"].(string) != "" {
		userAttributes.Country = []string{infoMap["country"].(string)}
	}
	if infoMap["state"].(string) != "" {
		userAttributes.Province = []string{infoMap["state"].(string)}
	}
	if infoMap["city"].(string) != "" {
		userAttributes.Locality = []string{infoMap["city"].(string)}
	}

	if title == "admin" {
		userAttributes.IsAdmin = true
		userAttributes.Hosts = []string{"fabric-tools"}
	} else {
		userAttributes.IsAdmin = false
	}

	return userAttributes
}
