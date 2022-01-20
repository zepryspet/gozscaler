package zpa

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"strconv"
	"time"
)

//Client contains the base url, http client and max number of retries per requests
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	RetryMax   int
}

//do Function de send the HTTP request and return the response and error
func (c *Client) do(req *http.Request) ([]byte, error) {
	retryMax := c.RetryMax
	return c.doWithOptions(req, retryMax)
}

//doWithOptions Wrapper that receives options and sends an http request
func (c *Client) doWithOptions(req *http.Request, retryMax int) ([]byte, error) {
	//Extracting body payload
	req, payload := getReqBody(req)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	//Before anything returns defering close body
	defer resp.Body.Close()
	if resp.StatusCode == 429 {
		// Retrying after X seconds only if you have retries left.
		if retryMax > 0 {
			s := time.Duration(retryAfter(retryMax, c.RetryMax)) * time.Second
			time.Sleep(s)
			retryMax -= 1
			// reset Request.Body
			req.Body = ioutil.NopCloser(bytes.NewBuffer(payload))
			return c.doWithOptions(req, retryMax)
		}
	}
	//Retry if the service is unavailable.
	if resp.StatusCode == 503 {
		s := time.Duration(retryAfter(retryMax, c.RetryMax)) * time.Second
		time.Sleep(s)
		retryMax -= 1
		// reset Request.Body
		req.Body = ioutil.NopCloser(bytes.NewBuffer(payload))
		return c.doWithOptions(req, retryMax)
	}
	// Catch all when there's no more retries left
	err = httpStatusCheck(resp)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(resp.Body)
}

//getReqBody Finds http payload and resets it
func getReqBody(req *http.Request) (*http.Request, []byte) {
	if req.Method == "POST" || req.Method == "PUT" {
		//Find payload and reset it
		payload, _ := ioutil.ReadAll(req.Body)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(payload))
		return req, payload
	} else {
		return req, nil
	}
}

//retryAfter will return the number of seconds an API request needs to wait before trying again
func retryAfter(remainingRetries, retries int) int64 {
	//Detecting which number this retry is
	d := retries - remainingRetries
	//Returning exponencial backoff, 2^0, 2^1, 2^2 and so on. so wait for 1, 2,4,etc seconds
	return int64(math.Pow(2, float64(d)))
}

//httpStatusCheck receives an http response and returns an error based on zscaler documentation.
//https://help.zscaler.com/zpa/about-error-codes
func httpStatusCheck(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return nil
	} else if resp.StatusCode == 400 {
		b, _ := io.ReadAll(resp.Body)
		return errors.New("HTTP error: Invalid or bad request. " + string(b))
	} else if resp.StatusCode == 401 {
		return errors.New("HTTP error: Session is not authenticated or timed out")
	} else if resp.StatusCode == 403 {
		return errors.New("HTTP error: The API key was disabled by your service provider, User's role has no access permissions or functional scope or a required SKU subscription is missing")
	} else if resp.StatusCode == 404 {
		return errors.New("Not found")
	} else if resp.StatusCode == 429 {
		return errors.New("HTTP error: Exceeded the rate limit or quota.")
	} else {
		return errors.New("Invalid HTTP response code: " + strconv.Itoa(resp.StatusCode))
	}
}

//NewClient returns a client with the auth header, default http timeouts and max retries per requests
//func NewClient(BaseURL string, client_id string, client_secret string) (*Client, error) {
//	access_token, err := KeyGen(BaseURL, client_id, client_secret)
//	if err != nil {
//		return &Client{}, err
//	}
//	u, err := url.Parse(BaseURL)
//	if err != nil {
//		return &Client{}, errors.New("failed to parse API URL")
//	}
//	CookieJar.SetCookies(u, cookie)
//	return &Client{
//		BaseURL: BaseURL,
//		HTTPClient: &http.Client{
//			Jar:     CookieJar,
//			Timeout: time.Second * 10,
//		},
//		RetryMax: 10,
//	}, nil
//}

//KeyGen function gets the authentication parameter and returns the JSESSIONID which is the cookie that authenticates the requests
func KeyGen(BaseURL string, client_id string, client_secret string) (string, error) {
	postBody, err := json.Marshal(map[string]string{
		"client_id":     client_id,
		"client_secret": client_secret,
	})
	if err != nil {
		return "", err
	}
	data := bytes.NewBuffer(postBody)
	client := http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Post(BaseURL+"/signin", "application/x-www-form-urlencoded", data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	// b, err := ioutil.ReadAll(resp.Body)  Go.1.15 and earlier
	if err != nil {
		return "", err
	}
	fmt.Println(string(b))
	return "", errors.New("can't authenticate please check credentials,base url or apikey")
}
