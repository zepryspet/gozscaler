package zia

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//Client contains the base url, http client and max number of retries per requests
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	RetryMax   int
}

//UrlRule parses responses for urls policies
type UrlRule struct {
	ID        int      `json:"id"`
	Name      string   `json:"name"`
	Order     int      `json:"order"`
	Protocols []string `json:"protocols"`
	Locations []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"locations,omitempty"`
	Groups []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"groups,omitempty"`
	Departments []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"departments,omitempty"`
	Users []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"users,omitempty"`
	URLCategories []string `json:"urlCategories"`
	State         string   `json:"state"`
	TimeWindows   []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"timeWindows,omitempty"`
	Rank                   int      `json:"rank"`
	RequestMethods         []string `json:"requestMethods"`
	EndUserNotificationURL string   `json:"endUserNotificationUrl"`
	OverrideUsers          []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"overrideUsers,omitempty"`
	OverrideGroups []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"overrideGroups,omitempty"`
	BlockOverride  bool   `json:"blockOverride"`
	TimeQuota      int    `json:"timeQuota"`
	SizeQuota      int    `json:"sizeQuota"`
	Description    string `json:"description"`
	LocationGroups []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"locationGroups,omitempty"`
	Labels []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"labels,omitempty"`
	ValidityStartTime  int    `json:"validityStartTime"`
	ValidityEndTime    int    `json:"validityEndTime"`
	ValidityTimeZoneID string `json:"validityTimeZoneId"`
	LastModifiedTime   int    `json:"lastModifiedTime"`
	LastModifiedBy     struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"lastModifiedBy,omitempty"`
	EnforceTimeValidity bool   `json:"enforceTimeValidity,omitempty"`
	Action              string `json:"action,omitempty"`
	Ciparule            bool   `json:"ciparule,omitempty"`
}

//BlockedUrls parses responses for blocked urls
type BlockedUrls struct {
	Urls []string `json:"blacklistUrls"`
}

//UrlCat parses responses for received url categories
type UrlCat struct {
	URL       string   `json:"url"`
	URLCat    []string `json:"urlClassifications"`
	URLCatSec []string `json:"urlClassificationsWithSecurityAlert"`
}

//retry parses response for an HTTP 429 response to retry after X seconds.
type retry struct {
	Message string `json:"message"`
	Retry   string `json:"Retry-After"`
}

//NewClient returns a client with the auth cookie, default http timeouts and max retries per requests
func NewClient(BaseURL string, admin string, pass string, apiKey string) (*Client, error) {
	cookie, err := KeyGen(BaseURL, admin, pass, apiKey)
	if err != nil {
		return &Client{}, err
	}
	CookieJar, err := cookiejar.New(nil)
	if err != nil {
		return &Client{}, errors.New("failed to set authentication cookie")
	}
	u, err := url.Parse(BaseURL)
	if err != nil {
		return &Client{}, errors.New("failed to parse API URL")
	}
	CookieJar.SetCookies(u, cookie)
	return &Client{
		BaseURL: BaseURL,
		HTTPClient: &http.Client{
			Jar:     CookieJar,
			Timeout: time.Second * 10,
		},
		RetryMax: 3,
	}, nil
}

//UrlLookup return the url categories for requested URLs.
//up to 100 urls per request and 400 requests per hour according to zscaler limits
func (c *Client) UrlLookup(urls []string) ([]UrlCat, error) {
	postBody, _ := json.Marshal(urls)
	body, err := c.postRequest("/urlLookup", postBody)
	if err != nil {
		log.Fatal(err)
	}
	res := []UrlCat{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//GetUrlRules gets a list of URL filtering rules
func (c *Client) GetUrlRules() ([]UrlRule, error) {
	body, err := c.getRequest("/urlFilteringRules")
	if err != nil {
		return nil, err
	}
	res := []UrlRule{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//AddUrlRule adds a URL filtering rules
func (c *Client) AddUrlRule(rule UrlRule) error {
	postBody, _ := json.Marshal(rule)
	_, err := c.postRequest("/urlFilteringRules", postBody)
	return err
}

//GetBlockedUrls gets a list of blocked URLs in Advanced Threat policy
func (c *Client) GetBlockedUrls() (BlockedUrls, error) {
	body, err := c.getRequest("/security/advanced")
	if err != nil {
		return BlockedUrls{}, err
	}
	res := BlockedUrls{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return BlockedUrls{}, err
	}
	return res, nil
}

func (c *Client) AddBlockedUrls(urls BlockedUrls) error {
	postBody, _ := json.Marshal(urls)
	return c.putRequest("/security/advanced", postBody)
}

//Process and sends HTTP POST requests
func (c *Client) postRequest(path string, payload []byte) ([]byte, error) {
	data := bytes.NewBuffer(payload)
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, data)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

//Process and sends HTTP GET requests
func (c *Client) getRequest(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

//Process and sends HTTP PUT requests
func (c *Client) putRequest(path string, payload []byte) error {
	data := bytes.NewBuffer(payload)
	req, err := http.NewRequest(http.MethodPut, c.BaseURL+path, data)
	if err != nil {
		return err
	}
	_, err = c.do(req)
	return err
}

//Function de send the HTTP request and return the response and error
func (c *Client) do(req *http.Request) ([]byte, error) {
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 429 {
		// Retrying after X seconds only if you have retries left.
		if c.RetryMax > 0 {
			t, err := retryAfter(resp)
			if err != nil {
				return nil, err
			}
			s := time.Duration(t) * time.Second
			time.Sleep(s)
			c.RetryMax -= 1
			return c.do(req)
		}
	}
	//Retry if there's an unexpected error or if the service is unavailable.
	if resp.StatusCode == 500 || resp.StatusCode == 503 {
		s := time.Duration(c.RetryMax) * time.Second
		time.Sleep(s)
		c.RetryMax -= 1
		return c.do(req)
	}
	// Catch all when there's no more retries left
	err = httpStatusCheck(resp)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

//retryAfter will return the number of seconds an API request needs to wait before trying again
func retryAfter(resp *http.Response) (int64, error) {
	body, _ := ioutil.ReadAll(resp.Body)
	ret := retry{}
	err := json.Unmarshal(body, &ret)
	if err != nil {
		return 0, err
	}
	seconds := strings.Split(ret.Retry, " ")[0]
	intVar, err := strconv.ParseInt(seconds, 10, 64)
	if err != nil {
		return 0, err
	}
	return intVar, nil
}

//httpStatusCheck receives an http response and returns an error based on zscaler documentation.
//From https://help.zscaler.com/zia/about-error-handling
func httpStatusCheck(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return nil
	} else if resp.StatusCode == 400 {
		return errors.New("HTTP error: Invalid or bad request")
	} else if resp.StatusCode == 401 {
		return errors.New("HTTP error: Session is not authenticated or timed out")
	} else if resp.StatusCode == 403 {
		return errors.New("HTTP error: The API key was disabled by your service provider, User's role has no access permissions or functional scope or a required SKU subscription is missing")
	} else if resp.StatusCode == 409 {
		return errors.New("HTTP error: Request could not be processed because of possible edit conflict occurred. Another admin might be saving a configuration change at the same time. In this scenario, the client is expected to retry after a short time period.")
	} else if resp.StatusCode == 415 {
		return errors.New("HTTP error: Unsupported media type. This error is returned if you don't include application/json as the Content-Type in the request header (for example, Content-Type: application/json).")
	} else if resp.StatusCode == 429 {
		return errors.New("HTTP error: Exceeded the rate limit or quota. The response includes a Retry-After value.")
	} else if resp.StatusCode == 500 {
		return errors.New("HTTP error: Unexpected error")
	} else if resp.StatusCode == 503 {
		return errors.New("HTTP error: Service is temporarily unavailable")
	} else {
		return errors.New("Invalid HTTP response code")
	}
}

//KeyGen function gets the authentication parameter and returns the JSESSIONID which is the cookie that authenticates the requests
func KeyGen(BaseURL string, admin string, pass string, apiKey string) ([]*http.Cookie, error) {
	t := strconv.FormatInt(time.Now().UnixMilli(), 10)
	key := obfuscateApiKey(apiKey, t)
	postBody, _ := json.Marshal(map[string]string{
		"apiKey":    key,
		"username":  admin,
		"password":  pass,
		"timestamp": t,
	})
	data := bytes.NewBuffer(postBody)
	client := http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Post(BaseURL+"/authenticatedSession", "application/json", data)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "JSESSIONID" {
			return resp.Cookies(), nil
		}
	}
	return nil, errors.New("can't authenticate please check credentials,base url or apikey")
}

//obfuscateApiKey ofuscates the API key based on Zscaler documentation
func obfuscateApiKey(api string, t string) string {
	n := t[len(t)-6:]
	intVar, _ := strconv.Atoi(n)
	r := fmt.Sprintf("%06d", intVar>>1)
	key := ""
	for i, _ := range n {
		d, _ := strconv.Atoi((n)[i : i+1])
		key += api[d : d+1]
	}
	for j, _ := range r {
		d, _ := strconv.Atoi((r)[j : j+1])
		key += api[d+2 : d+3]
	}
	return key
}
