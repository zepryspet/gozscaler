package zcc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

type auth struct {
	ApiKey    string `json:"apiKey"`    //client id obtainted from the mobile portal
	SecretKey string `json:"secretKey"` // client secret obtainted from the mobile  portal
}

type myToken struct {
	Token string `json:"jwtToken"`
}

type Devices struct {
	Udid string `json:"udid"`
	User string `json:"user"`
}

func Authenticate(base_url string, client_id string, secret_key string) (string, error) {
	url := base_url + "/auth/v1/login"
	payload := auth{ApiKey: client_id, SecretKey: secret_key}
	json_data, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(json_data)
	fmt.Println(url)
	client := http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(json_data))

	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode >= 300 {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	if err != nil {
		panic(err.Error())
	}
	var token myToken
	json.Unmarshal(body, &token)
	if err != nil {
		return "", err
	}
	return token.Token, nil
}

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	RetryMax   int
	Token      string
}

func NewClient(BaseURL string, client_id string, client_secret string) (*Client, error) {
	//Validating URL
	_, err := url.Parse(BaseURL)
	if err != nil {
		return &Client{}, errors.New("failed to parse API URL")
	}
	//Getting access token
	access_token, err := Authenticate(BaseURL, client_id, client_secret)
	if err != nil {
		return &Client{}, err
	}
	return &Client{
		BaseURL: BaseURL,
		HTTPClient: &http.Client{
			Timeout: time.Second * 10,
		},
		RetryMax: 10,
		Token:    access_token,
	}, nil

}

func (c *Client) FetchDevices(orgId int) ([]Devices, error) {
	url := c.BaseURL + "/public/v1/getDevices"
	client := http.Client{}
	req , err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal("Error getting response. ", err)
	}
    req.Header.Set("auth-token", c.Token)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Error reading response. ", err)
	}
	defer resp.Body.Close()
    body, err := io.ReadAll(resp.Body)

	if err != nil {
		panic(err.Error())
	}
	res := []Devices{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil


}