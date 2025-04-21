package oneapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// oneApiAuth struct t used to authenticate to oneapi
type oneApiAuth struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
}

type authResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// AuthSecret aiuthenticates to oneapi using client secret
func AuthSecret(vanity, clientId, clientSecret string) (string, error) {
	err := validateVanity(vanity)
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Add("grant_type", "client_credentials")
	form.Add("client_id", clientId)
	form.Add("client_secret", clientSecret)
	form.Add("audience", "https://api.zscaler.com")
	client := http.Client{
		Timeout: time.Second * 100,
	}
	resp, err := client.Post("https://"+vanity+".zslogin.net/oauth2/v1/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("module:gozscaler. error authenticating to oneapi: %v", err)
	}
	defer resp.Body.Close()
	//Check for anything but a http 200 and then parse body
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("module:gozscaler. error authenticating to oneapi: http code %v", resp.StatusCode)
	}
	//Parsing response
	var token authResponse
	err = json.NewDecoder(resp.Body).Decode(&token)
	if err != nil {
		return "", fmt.Errorf("module:gozscaler. error decoding auth token, error:%v", err)
	}
	return token.AccessToken, nil
}
func validateVanity(vanity string) error {
	if strings.HasSuffix(vanity, "-admin") {
		return fmt.Errorf("invalid vanity domain: %s . Please remove -admin", vanity)
	}
	for _, c := range vanity {
		if !unicode.IsDigit(c) && !unicode.IsLetter(c) && c != '-' {
			return fmt.Errorf("invalid vanity character '%c' in domain: %s", c, vanity)
		}
	}
	return nil
}
