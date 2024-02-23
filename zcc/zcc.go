package zcc

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// ZIAError is the error
type ZCCError struct {
	//this is the Error
	Err string
	//Code this is the http status code
	Code int
}

// DeviceFilter filters enrolled devices.
type DeviceFilter struct {
	// The following values represent different OS types:
	//1 - iOS
	//2 - Android
	//3 - Windows
	//4 - macOS
	//5 - Linux
	OsType   int
	Username string
}

func (e *ZCCError) Error() string {
	if e.Code != 0 {
		return e.Err + ", HTTP status code: " + strconv.Itoa(e.Code)
	}
	return e.Err
}

// myToken parses the authentication request
type auth struct {
	ApiKey    string `json:"apiKey"`    //client id obtainted from the mobile portal
	SecretKey string `json:"secretKey"` // client secret obtainted from the mobile  portal
}

// myToken parses the authentication response
type myToken struct {
	Token string `json:"jwtToken"`
}

// Device holds de device information
type Device struct {
	User                    string `json:"user" csv:"User"`
	Udid                    string `json:"udid" csv:"UDID"`
	MacAddress              string `json:"macAddress" csv:"Mac Address"`
	CompanyName             string `json:"companyName" csv:"Company Name"`
	OsVersion               string `json:"osVersion" csv:"OS Version"`
	AgentVersion            string `json:"agentVersion" csv:"Zscaler Client Connector Version"`
	PolicyName              string `json:"policyName" csv:"Policy Name"`
	VpnStateString          string `csv:"VPN State"`
	VpnState                int    `json:"vpnState" `
	RegistrationState       string `json:"registrationState" csv:"Device State|Registration State"`
	Owner                   string `json:"owner" csv:"Owner"`
	MachineHostname         string `json:"machineHostname" csv:"Hostname"`
	Manufacturer            string `json:"manufacturer" csv:"Manufacturer"`
	DownloadCount           int    `json:"download_count" csv:"Config Download Count"`
	RegistrationTime        string `json:"registration_time" csv:"Registration TimeStamp"`
	DeregistrationTimestamp string `json:"deregistrationTimestamp" csv:"Last Deregistration TimeStamp"`
	ConfigDownloadTime      string `json:"config_download_time" csv:"Config Download TimeStamp"`
	KeepAliveTime           string `json:"keepAliveTime" csv:"Keep Alive Timestamp"`
	HardwareFingerprint     string `json:"hardwareFingerprint" csv:"Device Hardware Fingerprint"`
	TunnelVersion           string `json:"tunnelVersion" csv:"Tunnel Version"`
	DeviceType              string `csv:"Device type"`
	DeviceModel             string `csv:"Device model"`
	ExternalDeviceID        string `csv:"External Device ID"`
	LogTS                   string `csv:"Log TS"`
	LogAckTS                string `csv:"Log Ack TS"`
	LogUrl                  string `csv:"Log Url"`
	ZCCRevertStatus         string `csv:"ZCC Revert Status"`
	DeviceTrustLevel        string `csv:"Device Trust Level"`
	ZDXVersion              string `csv:"Zscaler Digital Experience Version"`
	LastConnectedToZIA      string `csv:"Last Seen Connected to ZIA"`
	Detail                  string `json:"detail"`
	LastSeenTime            string `json:"last_seen_time"`
	State                   int    `json:"state"`
	Type                    int    `json:"type"`
	UpmVersion              string `json:"upmVersion"`
	ZappArch                string `json:"zappArch"`
	//Device state
	ZIAEnabled       string `csv:"ZIA Enabled"`
	ZIAHealth        string `csv:"ZIA Health"`
	ZIALastConnected string `csv:"Last Seen Connected to ZIA"`
	ZPAEnabled       string `csv:"ZPA Enabled"`
	ZPAHealth        string `csv:"ZPA Health"`
	ZPALastConnected string `csv:"Last Seen Connected to ZPA"`
	ZDXEnabled       string `csv:"ZDX Enabled"`
	ZDXHealth        string `csv:"ZDX Health"`
	ZDXLastConnected string `csv:"Last Seen Connected to ZDX"`
}

// String prints the struct in json pretty format
func (p Device) String() string {
	return jsonString(p)
}

// JsonString prints the struct in json pretty format
func jsonString(v any) string {
	s, e := json.MarshalIndent(v, "", "    ")
	if e != nil {
		return "Invalid struct"
	}
	return string(s)
}

// Client is the struct holding the client parameters for http calls
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	RetryMax   int
	Token      string
}

// Authenticate receives autentication information and returns the authentication token and error if exist
func Authenticate(base_url string, client_id string, secret_key string) (string, error) {
	url := base_url + "/auth/v1/login"
	payload := auth{ApiKey: client_id, SecretKey: secret_key}
	json_data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	client := http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(json_data))
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 300 {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}
	var token myToken
	json.Unmarshal(body, &token)
	if err != nil {
		return "", err
	}
	return token.Token, nil
}

// Newclient wraps the authenticate function and return a client that will have all the http calls.
// Base URL changes based on cloud name.
// cloudName can be zscalertwo, zscaler, zscloud, zscalerbeta, etc
// clientSecret is generated once in the mobile portal, if you can see it generate a new one
// clientID can be seen in the mobile portal
func NewClient(cloudName string, clientID string, clientSecret string) (*Client, error) {
	BaseURL := "https://api-mobile." + cloudName + ".net/papi"
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
		BaseURL: BaseURL + "/public/v1",
		HTTPClient: &http.Client{
			Timeout: time.Second * 10,
		},
		RetryMax: 10,
		Token:    access_token,
	}, nil

}

// GetDevices get all the devices enrolled in ZCC mobile portal
func (c *Client) GetDevices() ([]Device, error) {
	return getPaged[Device](c, 50, "/getDevices")
}

// GetFilteredDevices get all the devices enrolled in ZCC mobile portal given the filters
func (c *Client) GetFilteredDevices(filter DeviceFilter) ([]Device, error) {
	queries := url.Values{}
	if filter.OsType != 0 {
		queries.Set("osType", strconv.Itoa(filter.OsType))
	}
	if filter.Username != "" {
		queries.Set("username", filter.Username)
	}
	return getPagedQuery[Device](c, 1000, "/getDevices", queries)
}

// GetAllDevices uses the downloadDevices public api which downloads all enrolled devices in a single call
// This call is rate limited to 3 per day per IP so use with caution
func (c *Client) GetAllDevices() ([]Device, error) {
	body, err := c.getRequest("/downloadDevices")
	if err != nil {
		return []Device{}, err
	}
	return ParseDeviceCSV(body)
}

// GetServiceStatus uses the downloadServiceStatus public api which downloads all enrolled devices in a single call
// This call is rate limited to 3 per day per IP so use with caution. It only contains service status
func (c *Client) GetServiceStatus() ([]Device, error) {
	body, err := c.getRequest("/downloadServiceStatus")
	if err != nil {
		return []Device{}, err
	}
	return ParseDeviceCSV(body)
}

func ParseDeviceCSV(in []byte) ([]Device, error) {
	ret := []Device{}
	r := csv.NewReader(strings.NewReader(string(in[:])))
	//header
	header, err := r.Read()
	if err != nil {
		return ret, err
	}
	index := GetCSVIndex(header, Device{})
	for {
		record, err := r.Read()
		// Stop at EOF.
		if err == io.EOF {
			break
		}
		if err != nil {
			return ret, err
		}
		tmp := &Device{}
		err = Unmarshal(record, index, tmp)
		if err != nil {
			return ret, err
		}
		ret = append(ret, *tmp)
	}
	return ret, err
}

func Unmarshal(record []string, index map[string]int, v interface{}) error {
	s := reflect.ValueOf(v).Elem()
	st := reflect.TypeOf(v).Elem()
	for i := 0; i < s.NumField(); i++ {
		//only csv tags
		field := st.Field(i)
		tags := splitTag(field.Tag.Get("csv"))
		for _, tag := range tags {
			if tag != "" {
				//Making sure index for header exist
				value, ok := index[field.Name]
				if ok {
					f := s.Field(i)
					switch f.Type().String() {
					case "string":
						f.SetString(record[value])
					case "int":
						ival, err := strconv.ParseInt(record[value], 10, 0)
						if err != nil {
							return err
						}
						f.SetInt(ival)
					default:
						return fmt.Errorf("unssuported type: %v", f.Type().String())
					}
				}
			}
		}

	}
	return nil
}

func GetCSVIndex(header []string, v interface{}) map[string]int {
	ret := make(map[string]int)
	st := reflect.TypeOf(v)
	for i := 0; i < st.NumField(); i++ {
		field := st.Field(i)
		tags := splitTag(field.Tag.Get("csv"))
		for _, tag := range tags {
			if tag != "" { //only maps non-empty csv tags
				index := findIndex(header, tag)
				//Only add it if it exist
				if index != -1 {
					ret[field.Name] = index
				}

			}
		}

	}
	return ret
}

func splitTag(tag string) []string {
	return strings.Split(tag, "|")
}

// findIndex find index in array, returns -1 if not found
func findIndex(arr []string, val string) int {
	for i, v := range arr {
		if v == val {
			return i
		}
	}
	return -1
}

// GetPaged is a generic function that iterates through multiple pageds and returns the joined parsed object
func getPaged[K any](c *Client, pageSize int, path string) ([]K, error) {
	return getPagedQuery[K](c, pageSize, path, url.Values{})
}

// getPagedQuery is a generic function that iterates through multiple pageds and returns the joined parsed object
// It received query parameters in case we want to add more than pageSize
func getPagedQuery[K any](c *Client, pageSize int, path string, queries url.Values) ([]K, error) {
	var ret []K
	//Setting the 1st page number
	page := 1
	//iterating over all pages to get all
	//Setting pagesize
	queries.Set("pageSize", strconv.Itoa(pageSize))
	for {
		//Creating tmp struct to unmarshal to.
		var tmp []K
		//setting page number
		queries.Set("page", strconv.Itoa(page))
		npath := path + "?" + queries.Encode()
		body, err := c.getRequest(npath)
		if err != nil {
			//check status code and return response if 400
			re, ok := err.(*ZCCError)
			if ok {
				//only return no error when a 404 is received
				if re.Code == 404 {
					return ret, nil
				} else {
					return ret, err
				}
			} else { // hopefuly we won't hit this
				return ret, err
			}
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

// getRequest Process and sends HTTP GET requests
func (c *Client) getRequest(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

// do Function de send the HTTP request and return the response and error
func (c *Client) do(req *http.Request) ([]byte, error) {
	retryMax := c.RetryMax
	//Adding auth header
	req.Header.Set("auth-token", c.Token)
	return c.doWithOptions(req, retryMax)
}

// doWithOptions Wrapper that receives options and sends an http request
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
			req.Body = io.NopCloser(bytes.NewBuffer(payload))
			return c.doWithOptions(req, retryMax)
		}
	}
	//Retry if the service is unavailable.
	if resp.StatusCode == 503 {
		s := time.Duration(retryAfter(retryMax, c.RetryMax)) * time.Second
		time.Sleep(s)
		retryMax -= 1
		// reset Request.Body
		req.Body = io.NopCloser(bytes.NewBuffer(payload))
		return c.doWithOptions(req, retryMax)
	}
	// Catch all when there's no more retries left
	err = httpStatusCheck(resp)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(resp.Body)
}

// getReqBody Finds http payload and resets it
func getReqBody(req *http.Request) (*http.Request, []byte) {
	if req.Method == "POST" || req.Method == "PUT" {
		//Find payload and reset it
		payload, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(payload))
		return req, payload
	} else {
		return req, nil
	}
}

// retryAfter will return the number of seconds an API request needs to wait before trying again
func retryAfter(remainingRetries, retries int) int64 {
	//Detecting which number this retry is
	d := retries - remainingRetries
	//Returning exponencial backoff, 2^0, 2^1, 2^2 and so on. so wait for 1, 2,4,etc seconds
	return int64(math.Pow(2, float64(d)))
}

// httpStatusCheck receives an http response and returns an error based on zscaler documentation.
// From https://help.zscaler.com/zia/about-error-handling
func httpStatusCheck(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return nil
	} else if resp.StatusCode == 400 {
		b, _ := io.ReadAll(resp.Body)
		return &ZCCError{Err: "HTTP error: Invalid or bad request" + string(b), Code: resp.StatusCode}
	} else if resp.StatusCode == 401 {
		return &ZCCError{Err: "HTTP error: Session is not authenticated or timed out", Code: resp.StatusCode}
	} else if resp.StatusCode == 403 {
		return &ZCCError{Err: "HTTP error: The API key was disabled by your service provider, User's role has no access permissions or functional scope or a required SKU subscription is missing", Code: resp.StatusCode}
	} else if resp.StatusCode == 409 {
		return &ZCCError{Err: "HTTP error: Request could not be processed because of possible edit conflict occurred. Another admin might be saving a configuration change at the same time. In this scenario, the client is expected to retry after a short time period.", Code: resp.StatusCode}
	} else if resp.StatusCode == 415 {
		return &ZCCError{Err: "HTTP error: Unsupported media type. This error is returned if you don't include application/json as the Content-Type in the request header (for example, Content-Type: application/json).", Code: resp.StatusCode}
	} else if resp.StatusCode == 429 {
		return &ZCCError{Err: "HTTP error: Exceeded the rate limit or quota. The response includes a Retry-After value.", Code: resp.StatusCode}
	} else if resp.StatusCode == 500 {
		return &ZCCError{Err: "HTTP error: Unexpected error", Code: resp.StatusCode}
	} else if resp.StatusCode == 503 {
		return &ZCCError{Err: "HTTP error: Service is temporarily unavailable", Code: resp.StatusCode}
	} else {
		return &ZCCError{Err: "Invalid HTTP response code", Code: resp.StatusCode}
	}
}
