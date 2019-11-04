package main

import (
	"io/ioutil"
	"time"

	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"software.sslmate.com/src/go-pkcs12"
)

type OAuth2Token struct {
	TokenType   string `json:"token_type"`
	AccessToken string `json:"access_token"`
}

func GenerateOauth2TokenSP(oauth2URL, resource, clientID, clientSecret string) (string, error) {

	authURL := oauth2URL

	data := url.Values{}
	data.Add("grant_type", "client_credentials")
	data.Add("client_id", clientID)
	data.Add("client_secret", clientSecret)
	data.Add("resource", resource)
	data.Add("scope", "https://management.azure.com/")

	req, _ := http.NewRequest("POST", authURL, strings.NewReader(data.Encode()))
	req.Header.Add("Host", "login.microsoftonline.com")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	var oauth2 OAuth2Token
	err = json.NewDecoder(resp.Body).Decode(&oauth2)
	if err != nil {
		return "", err
	}
	token := []string{oauth2.TokenType, oauth2.AccessToken}

	return strings.Join(token, " "), nil
}

func SignJwt(tenantID, clientID, clientCert, clientCertPassword string) (string, error) {

	pfxData, _ := ioutil.ReadFile(clientCert)
	PrivateKey, Certificate, err := pkcs12.Decode(pfxData, clientCertPassword)
	if err != nil {
		return "", err
	}

	hasher := sha1.New()
	hasher.Write(Certificate.Raw)

	thumbprint := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	jti := make([]byte, 20)
	_, err = rand.Read(jti)
	if err != nil {
		return "", err
	}

	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["x5t"] = thumbprint
	x5c := []string{base64.StdEncoding.EncodeToString(Certificate.Raw)}
	token.Header["x5c"] = x5c
	token.Claims = jwt.MapClaims{
		"aud": "https://login.microsoftonline.com/" + tenantID + "/oauth2/token",
		"iss": clientID,
		"sub": clientID,
		"jti": base64.URLEncoding.EncodeToString(jti),
		"nbf": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	}

	signedString, err := token.SignedString(PrivateKey)
	return signedString, err
}

func GenerateOauth2TokenWithCert(oauth2URL, resource, tenantid, clientID, clientCert, clientCertPassword string) (string, error) {

	authURL := oauth2URL

	jwt, err := SignJwt(tenantid, clientID, clientCert, clientCertPassword)

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_assertion", jwt)
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("resource", resource)
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "https://management.azure.com/")

	body := data.Encode()

	req, _ := http.NewRequest("POST", authURL, strings.NewReader(body))
	req.Header.Set("Host", "login.microsoftonline.com")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+jwt)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	var oauth2 OAuth2Token

	err = json.NewDecoder(resp.Body).Decode(&oauth2)
	if err != nil {
		return "", err
	}
	token := []string{oauth2.TokenType, oauth2.AccessToken}

	return strings.Join(token, " "), nil
}

func APICall(accessToken, contentType, requestURL, query string) (int, error) {

	url := fmt.Sprintf(requestURL)
	req, err := http.NewRequest("POST", url, strings.NewReader(query))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", accessToken)
	req.Header.Set("Content-Type", contentType)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}

	return resp.StatusCode, nil
}

func main() {

	resource := "https://api.loganalytics.io/"
	tenantid := "<your tenant id>"
	clientid := "<your cliend id>"
	certpathname := "<youpathfilename_of_cert.pfx>"
	certpassword := "<your cert.pfx password"
	workspaceid := "<your workspace id>"

	token, _ := GenerateOauth2TokenWithCert("https://login.microsoftonline.com/"+tenantid+"/oauth2/token", resource, tenantid, clientid, certpathname, certpassword)

	fmt.Println("---- Token ----")
	fmt.Println(token)
	fmt.Println("---------------")

	loganalyticsWorkspaceURL := "https://api.loganalytics.io/v1/workspaces/" + workspaceid + "/query/"
	loganalyticsQuery := "{\"query\": \"AzureActivity | summarize count() by Category\"}"
	contentType := "application/json"
	response, _ := APICall(token, contentType, loganalyticsWorkspaceURL, loganalyticsQuery)

	fmt.Println("---- Response ----")
	fmt.Println(response)
	fmt.Println("------------------")

}
