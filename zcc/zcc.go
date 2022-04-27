package zcc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

//myToken parses the authentication request
type auth struct {
	ApiKey    string `json:"apiKey"`    //client id obtainted from the mobile portal
	SecretKey string `json:"secretKey"` // client secret obtainted from the mobile  portal
}

//myToken parses the authentication response
type myToken struct {
	Token string `json:"jwtToken"`
}

//Devices holds de device information
type Devices struct {
	Udid string `json:"udid"`
	User string `json:"user"`
}

//Client is the struct holding the client parameters for http calls
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	RetryMax   int
	Token      string
}

//Authenticate receives autentication information and returns the authentication token and error if exist
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

//Newclient wraps the authenticate function and return a client that will have all the http calls.
//Base URL changes based on cloud name.
//i.e https://api-mobile.zscalerbeta.net/papi for beta cliud
// or https://api-mobile.zscalertwo.net/papi for cloud two
func NewClient(BaseURL string, clientID string, clientSecret string) (*Client, error) {
	//Validating URL
	_, err := url.Parse(BaseURL)
	if err != nil {
		return &Client{}, errors.New("failed to parse API URL")
	}
	//Getting access token
	access_token, err := Authenticate(BaseURL, clientID, clientSecret)
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

//FetchDevices get all the devices enrolled in ZCC mobile portal
func (c *Client) GetDevices() ([]Devices, error) {
	res := []Devices{}
	res, err := GetPaged[Devices](c, 50, "/public/v1/getDevices")
	if err != nil {
		return res, err
	}
	return res, nil
}

//GetPaged is a generic function that iterates and returns the parsed object
func GetPaged[K any](c *Client, pageSize int, path string) ([]K, error) {
	var ret []K
	//Creating tmp struct to unmarshal to.
	var tmp []K
	//Setting the 1st page number
	page := 1
	//iterating over all pages to get all
	for {
		npath := path + "?page=" + strconv.Itoa(page) + "&pagesize=" + strconv.Itoa(pageSize)
		body, err := c.getRequest(npath)
		if err != nil {
			//not sure about this
			return ret, nil
		}
		// Unmarshal response
		err = json.Unmarshal(body, &tmp)
		if err != nil {
			return ret, err
		}
		//Apending to response
		ret = append(ret, tmp...)
		//If less than pagesize exit
		if len(tmp) < pageSize {
			break
		}
		page += 1
	}
	return ret, nil
}

//getRequest Process and sends HTTP GET requests
func (c *Client) getRequest(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

//do Function de send the HTTP request and return the response and error
func (c *Client) do(req *http.Request) ([]byte, error) {
	retryMax := c.RetryMax
	//Adding auth header
	req.Header.Set("auth-token", c.Token)
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
