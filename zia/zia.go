package zia

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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
	ID                     int      `json:"id"`
	Name                   string   `json:"name"`
	Order                  int      `json:"order,omitempty"`
	Protocols              []string `json:"protocols,omitempty"`
	Locations              []NameID `json:"locations,omitempty"`
	Groups                 []NameID `json:"groups,omitempty"`
	Departments            []NameID `json:"departments,omitempty"`
	Users                  []NameID `json:"users,omitempty"`
	URLCategories          []string `json:"urlCategories,omitempty"`
	State                  string   `json:"state,omitempty"` //"ENABLED" or "DISABLED"
	TimeWindows            []NameID `json:"timeWindows,omitempty"`
	Rank                   int      `json:"rank"`
	RequestMethods         []string `json:"requestMethods,omitempty"`
	EndUserNotificationURL string   `json:"endUserNotificationUrl"`
	OverrideUsers          []NameID `json:"overrideUsers,omitempty"`
	OverrideGroups         []NameID `json:"overrideGroups,omitempty"`
	BlockOverride          bool     `json:"blockOverride,omitempty"`
	TimeQuota              int      `json:"timeQuota,omitempty"`
	SizeQuota              int      `json:"sizeQuota,omitempty"`
	Description            string   `json:"description,omitempty"`
	LocationGroups         []NameID `json:"locationGroups,omitempty"`
	Labels                 []NameID `json:"labels,omitempty"`
	ValidityStartTime      int      `json:"validityStartTime"`
	ValidityEndTime        int      `json:"validityEndTime"`
	ValidityTimeZoneID     string   `json:"validityTimeZoneId"`
	LastModifiedTime       int      `json:"lastModifiedTime"`
	LastModifiedBy         *NameID  `json:"lastModifiedBy,omitempty"`
	EnforceTimeValidity    bool     `json:"enforceTimeValidity,omitempty"`
	Action                 string   `json:"action,omitempty"`
	Ciparule               bool     `json:"ciparule,omitempty"`
}

//NameID is a helper for json entries with name and ID
type NameID struct {
	ID   int    `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

//AppGroup parses network application groups
type AppGroup struct {
	ID                  int      `json:"id"`
	Name                string   `json:"name,omitempty"`
	NetworkApplications []string `json:"networkApplications"`
	Description         string   `json:"description,omitempty"`
}

//GetID returns name, id
func (u AppGroup) GetID() (string, int) {
	return u.Name, u.ID
}

//UrlCat parses responses for urls categories
type UrlCat struct {
	ID                              string   `json:"id"`
	ConfiguredName                  string   `json:"configuredName"`
	Keywords                        []string `json:"keywords,omitempty"`
	KeywordsRetainingParentCategory []string `json:"keywordsRetainingParentCategory,omitempty"`
	Urls                            []string `json:"urls,omitempty"`
	DbCategorizedUrls               []string `json:"dbCategorizedUrls,omitempty"`
	CustomCategory                  bool     `json:"customCategory"`
	SuperCategory                   string   `json:"superCategory,omitempty"`
	Scopes                          []struct {
		ScopeGroupMemberEntities []NameID `json:"scopeGroupMemberEntities"`
		Type                     string   `json:"Type"`
		ScopeEntities            []NameID `json:"ScopeEntities"`
	} `json:"scopes,omitempty"`
	Editable         bool   `json:"editable"`
	Description      string `json:"description"`
	Type             string `json:"type"`
	URLKeywordCounts struct {
		TotalURLCount            int `json:"totalUrlCount"`
		RetainParentURLCount     int `json:"retainParentUrlCount"`
		TotalKeywordCount        int `json:"totalKeywordCount"`
		RetainParentKeywordCount int `json:"retainParentKeywordCount"`
	} `json:"urlKeywordCounts,omitempty"`
	Val                              int `json:"val,omitempty"`
	CustomUrlsCount                  int `json:"customUrlsCount,omitempty"`
	UrlsRetainingParentCategoryCount int `json:"urlsRetainingParentCategoryCount,omitempty"`
}

//GetID returns name, id
func (u UrlCat) GetID() (string, int) {
	//If this is a custom category the name is configured name.
	//Predefined categories have the name on ID
	if u.CustomCategory {
		return u.ConfiguredName, u.Val
	} else {
		return u.ID, u.Val
	}
}

//FwRule parses firewall rules
type FwRule struct {
	ID                  int      `json:"id"`
	Name                string   `json:"name"`
	Order               int      `json:"order,omitempty"`
	Rank                int      `json:"rank,omitempty"`
	Locations           []NameID `json:"locations,omitempty"`
	LocationGroups      []NameID `json:"locationGroups,omitempty"`
	Departments         []NameID `json:"departments,omitempty"`
	Groups              []NameID `json:"groups,omitempty"`
	Users               []NameID `json:"users,omitempty"`
	TimeWindows         []NameID `json:"timeWindows,omitempty"`
	Action              string   `json:"action,omitempty"`
	State               string   `json:"state,omitempty"`
	Description         string   `json:"description,omitempty"`
	LastModifiedTime    int      `json:"lastModifiedTime,omitempty"`
	LastModifiedBy      NameID   `json:"lastModifiedBy,omitempty"`
	SrcIps              []string `json:"srcIps,omitempty"`
	SrcIPGroups         []NameID `json:"srcIpGroups,omitempty"`
	DestAddresses       []string `json:"destAddresses,omitempty"`
	DestIPCategories    []string `json:"destIpCategories,omitempty"`
	DestCountries       []string `json:"destCountries,omitempty"`
	DestIPGroups        []NameID `json:"destIpGroups,omitempty"`
	NwServices          []NameID `json:"nwServices,omitempty"`
	NwServiceGroups     []NameID `json:"nwServiceGroups,omitempty"`
	NwApplications      []string `json:"nwApplications,omitempty"`
	NwApplicationGroups []NameID `json:"nwApplicationGroups,omitempty"`
	AppServices         []NameID `json:"appServices,omitempty"`
	AppServiceGroups    []NameID `json:"appServiceGroups,omitempty"`
	Labels              []NameID `json:"labels,omitempty"`
	DefaultRule         bool     `json:"defaultRule,omitempty"`
	Predefined          bool     `json:"predefined,omitempty"`
}

//IPDstGroup parses responses for IP destination groups
type IPDstGroup struct {
	ID           int      `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"` //Available values : DSTN_IP, DSTN_FQDN, DSTN_DOMAIN, DSTN_OTHER
	Addresses    []string `json:"addresses,omitempty"`
	Description  string   `json:"description,omitempty"`
	IPCategories []string `json:"ipCategories,omitempty"`
	Countries    []string `json:"countries,omitempty"`
}

//IPSrcGroup parses responses for IP source groups
type IPSrcGroup struct {
	ID          int      `json:"id"`
	Name        string   `json:"name"`
	IPAddresses []string `json:"ipAddresses"`
	Description string   `json:"description,omitempty"`
}

//StartEnd json helper for ranges
type StartEnd struct {
	Start *int `json:"start"`
	End   *int `json:"end"`
}

//Service parses responses for network services
type Service struct {
	ID            int        `json:"id"`
	Name          string     `json:"name"`
	Tag           string     `json:"tag,omitempty"`
	SrcTCPPorts   []StartEnd `json:"srcTcpPorts,omitempty"`
	DestTCPPorts  []StartEnd `json:"destTcpPorts,omitempty"`
	SrcUDPPorts   []StartEnd `json:"srcUdpPorts,omitempty"`
	DestUDPPorts  []StartEnd `json:"destUdpPorts,omitempty"`
	Type          string     `json:"type,omitempty"` //Types are CUSTOM, STANDARD AND PREDEFINED. The last 2 are default ones, STANDARD seems to be used for non port based services
	Description   string     `json:"description,omitempty"`
	IsNameL10NTag bool       `json:"isNameL10nTag,omitempty"`
}

//GetID return the name a string and the ID as int
func (u Service) GetID() (string, int) {
	return u.Name, u.ID
}

//ServiceGroup parses responses for network servicesgroups
type ServiceGroup struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Services    []Service `json:"services"`
	Description string    `json:"description,omitempty"`
}

//GetID return the name a string and the ID as int
func (u ServiceGroup) GetID() (string, int) {
	return u.Name, u.ID
}

//VpnLocation helper to hold vpn credential on a location

type VpnLocation struct {
	Type         string `json:"type"`
	Fqdn         string `json:"fqdn"`
	PreSharedKey string `json:"preSharedKey"`
	Comments     string `json:"comments"`
}

//Location parses locations
type Location struct {
	ID                                  int           `json:"id,omitempty"`
	Name                                string        `json:"name"`
	ParentID                            int           `json:"parentId,omitempty"`
	UpBandwidth                         int           `json:"upBandwidth,omitempty"`
	DnBandwidth                         int           `json:"dnBandwidth,omitempty"`
	Country                             string        `json:"country,omitempty"`
	Tz                                  string        `json:"tz,omitempty"`
	IPAddresses                         []string      `json:"ipAddresses,omitempty"`
	Ports                               []int         `json:"ports,omitempty"`
	VpnCredentials                      []VpnLocation `json:"vpnCredentials,omitempty"`
	AuthRequired                        bool          `json:"authRequired,omitempty"`
	SslScanEnabled                      bool          `json:"sslScanEnabled,omitempty"`
	ZappSSLScanEnabled                  bool          `json:"zappSSLScanEnabled,omitempty"`
	XffForwardEnabled                   bool          `json:"xffForwardEnabled,omitempty"`
	SurrogateIP                         bool          `json:"surrogateIP,omitempty"`
	IdleTimeInMinutes                   int           `json:"idleTimeInMinutes,omitempty"`
	DisplayTimeUnit                     string        `json:"displayTimeUnit,omitempty"`
	SurrogateIPEnforcedForKnownBrowsers bool          `json:"surrogateIPEnforcedForKnownBrowsers,omitempty"`
	SurrogateRefreshTimeInMinutes       int           `json:"surrogateRefreshTimeInMinutes,omitempty"`
	SurrogateRefreshTimeUnit            string        `json:"surrogateRefreshTimeUnit,omitempty"`
	OfwEnabled                          bool          `json:"ofwEnabled,omitempty"`
	IpsControl                          bool          `json:"ipsControl,omitempty"`
	AupEnabled                          bool          `json:"aupEnabled,omitempty"`
	CautionEnabled                      bool          `json:"cautionEnabled,omitempty"`
	AupBlockInternetUntilAccepted       bool          `json:"aupBlockInternetUntilAccepted,omitempty"`
	AupForceSslInspection               bool          `json:"aupForceSslInspection,omitempty"`
	AupTimeoutInDays                    int           `json:"aupTimeoutInDays,omitempty"`
	Profile                             string        `json:"profile,omitempty"`
	Description                         string        `json:"description,omitempty"`
}

//GetID return the name a string and the ID as int
func (u Location) GetID() (string, int) {
	return u.Name, u.ID
}

//LocationGroup parses location groups
type LocationGroup struct {
	ID                           int    `json:"id"`
	Name                         string `json:"name"`
	Deleted                      bool   `json:"deleted,omitempty"`
	GroupType                    string `json:"groupType"`
	DynamicLocationGroupCriteria struct {
		Name struct {
			MatchString string `json:"matchString"`
			MatchType   string `json:"matchType"`
		} `json:"name"`
		Countries []string `json:"countries"`
		City      struct {
			MatchString string `json:"matchString"`
			MatchType   string `json:"matchType"`
		} `json:"city"`
		ManagedBy              []NameID `json:"managedBy"`
		EnforceAuthentication  bool     `json:"enforceAuthentication"`
		EnforceAup             bool     `json:"enforceAup"`
		EnforceFirewallControl bool     `json:"enforceFirewallControl"`
		EnableXffForwarding    bool     `json:"enableXffForwarding"`
		EnableCaution          bool     `json:"enableCaution"`
		EnableBandwidthControl bool     `json:"enableBandwidthControl"`
		Profiles               []string `json:"profiles"`
	} `json:"dynamicLocationGroupCriteria"`
	Locations   []NameID `json:"locations"`
	Comments    string   `json:"comments"`
	LastModUser NameID   `json:"lastModUser"`
	LastModTime int      `json:"lastModTime"`
	Predefined  bool     `json:"predefined"`
}

//GetID return the name a string and the ID as int
func (u LocationGroup) GetID() (string, int) {
	return u.Name, u.ID
}

//Department parses user departments
type Department struct {
	ID       int    `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	IdpID    int    `json:"idpId,omitempty"`
	Comments string `json:"comments,omitempty"`
	Deleted  bool   `json:"deleted,omitempty"`
}

//GetID return the name a string and the ID as int
func (u Department) GetID() (string, int) {
	return u.Name, u.ID
}

//UserGroup parses UserGroup
type UserGroup struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	IdpID    int    `json:"idpId"`
	Comments string `json:"comments"`
}

//GetID return the name a string and the ID as int
func (u UserGroup) GetID() (string, int) {
	return u.Name, u.ID
}

//Users parses Users
type User struct {
	ID            int         `json:"id"`
	Name          string      `json:"name"`
	Email         string      `json:"email"`
	Groups        []UserGroup `json:"groups,omitempty"`
	Department    Department  `json:"department,omitempty"`
	Comments      string      `json:"comments,omitempty"`
	TempAuthEmail string      `json:"tempAuthEmail,omitempty"`
	Password      string      `json:"password,omitempty"`
	AdminUser     bool        `json:"adminUser,omitempty"`
	Type          string      `json:"type,omitempty"`
}

//GetID return the name a string and the ID as int
func (u User) GetID() (string, int) {
	return u.Name, u.ID
}

//BlockedUrls parses responses for blocked urls
type BlockedUrls struct {
	Urls []string `json:"blacklistUrls"`
}

//AllowedUrls parses responses for Allowed urls
type AllowedUrls struct {
	Urls []string `json:"whitelistUrls"`
}

//UrlLookup parses responses for received url categories
type UrlLookup struct {
	URL       string   `json:"url"`
	URLCat    []string `json:"urlClassifications"`
	URLCatSec []string `json:"urlClassificationsWithSecurityAlert"`
}

//DLPDictionary holds the DLP dictionaries from ZIA
type DLPDictionary struct {
	ID                      int          `json:"id,omitempty"`
	Name                    string       `json:"name,omitempty"`
	Description             string       `json:"description,omitempty"`
	ConfidenceThreshold     string       `json:"confidenceThreshold,omitempty"`
	Phrases                 []Phrase     `json:"phrases,omitempty"`
	CustomPhraseMatchType   string       `json:"customPhraseMatchType,omitempty"`
	Patterns                []Pattern    `json:"patterns,omitempty"`
	DictionaryType          string       `json:"dictionaryType,omitempty"`
	ExactDataMatchDetails   []EDMDetails `json:"exactDataMatchDetails,omitempty"`
	IdmProfileMatchAccuracy []IDMProfile `json:"idmProfileMatchAccuracy,omitempty"`
	Proximity               int          `json:"proximity,omitempty"`
	Custom                  bool         `json:"custom,omitempty"`
	ProximityLengthEnabled  bool         `json:"proximityLengthEnabled,omitempty"`
}

//GetID return the name a string and the ID as int
func (u DLPDictionary) GetID() (string, int) {
	return u.Name, u.ID
}

//Phrases holds DLP dictionary phrases
type Phrase struct {
	Action string `json:"action,omitempty"`
	Phrase string `json:"phrase,omitempty"`
}

//Pattern holds DLP dictionary Patterns
type Pattern struct {
	Action  string `json:"action,omitempty"`
	Pattern string `json:"pattern,omitempty"`
}

//EDMDetails holds EDM details from DLP dictionary
type EDMDetails struct {
	DictionaryEdmMappingID int    `json:"dictionaryEdmMappingId,omitempty"`
	SchemaID               int    `json:"schemaId,omitempty"`
	PrimaryField           int    `json:"primaryField,omitempty"`
	SecondaryFields        []int  `json:"secondaryFields,omitempty"`
	SecondaryFieldMatchOn  string `json:"secondaryFieldMatchOn,omitempty"`
}

//IDMProfile holds IDM details from DLP dictionary
type IDMProfile struct {
	AdpIdmProfile struct {
		ID         int `json:"id,omitempty"`
		Extensions struct {
			AdditionalProp1 string `json:"additionalProp1,omitempty"`
			AdditionalProp2 string `json:"additionalProp2,omitempty"`
			AdditionalProp3 string `json:"additionalProp3,omitempty"`
		} `json:"extensions,omitempty"`
	} `json:"adpIdmProfile,omitempty"`
	MatchAccuracy string `json:"matchAccuracy,omitempty"`
}

//DLPEngine hols dlp engine details
type DLPEngine struct {
	ID                   int    `json:"id,omitempty"`
	Name                 string `json:"name,omitempty"`
	PredefinedEngineName string `json:"predefinedEngineName,omitempty"`
	EngineExpression     string `json:"engineExpression,omitempty"`
	CustomDlpEngine      bool   `json:"customDlpEngine,omitempty"`
	Description          string `json:"description,omitempty"`
}

//GetID return the name a string and the ID as int
func (u DLPEngine) GetID() (string, int) {
	if u.CustomDlpEngine == false {
		return u.PredefinedEngineName, u.ID
	} else {
		return u.Name, u.ID
	}
}

//DLPEngine hols dlp notification template details
type DLPNotificationTemplate struct {
	ID               int    `json:"id,omitempty"`
	Name             string `json:"name,omitempty"`
	Subject          string `json:"subject,omitempty"`
	AttachContent    bool   `json:"attachContent,omitempty"`
	PlainTextMessage string `json:"plainTextMessage,omitempty"`
	HTMLMessage      string `json:"htmlMessage,omitempty"`
}

//GetID return the name a string and the ID as int
func (u DLPNotificationTemplate) GetID() (string, int) {
	return u.Name, u.ID
}

//ICAPServer holds an icap server detail
type ICAPServer struct {
	ID     int    `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	URL    string `json:"url,omitempty"`
	Status string `json:"status,omitempty"`
}

//GetID return the name a string and the ID as int
func (u ICAPServer) GetID() (string, int) {
	return u.Name, u.ID
}

//DLPRule holds a DLP rule information
type DLPRule struct {
	ID                       int      `json:"id,omitempty"`
	Order                    int      `json:"order,omitempty"`
	Protocols                []string `json:"protocols,omitempty"`
	Rank                     int      `json:"rank,omitempty"`
	Description              string   `json:"description,omitempty"`
	Locations                []NameID `json:"locations,omitempty"`
	LocationGroups           []NameID `json:"locationGroups,omitempty"`
	Groups                   []NameID `json:"groups,omitempty"`
	Departments              []NameID `json:"departments,omitempty"`
	Users                    []NameID `json:"users,omitempty"`
	URLCategories            []NameID `json:"urlCategories,omitempty"`
	DlpEngines               []NameID `json:"dlpEngines,omitempty"`
	FileTypes                []string `json:"fileTypes,omitempty"`
	CloudApplications        []string `json:"cloudApplications,omitempty"`
	MinSize                  int      `json:"minSize,omitempty"`
	Action                   string   `json:"action,omitempty"`
	State                    string   `json:"state,omitempty"`
	TimeWindows              []NameID `json:"timeWindows,omitempty"`
	Auditor                  *NameID  `json:"auditor,omitempty"`
	ExternalAuditorEmail     string   `json:"externalAuditorEmail,omitempty"`
	NotificationTemplate     *NameID  `json:"notificationTemplate,omitempty"`
	MatchOnly                bool     `json:"matchOnly,omitempty"`
	LastModifiedTime         int      `json:"lastModifiedTime,omitempty"`
	LastModifiedBy           *NameID  `json:"lastModifiedBy,omitempty"`
	IcapServer               *NameID  `json:"icapServer,omitempty"`
	WithoutContentInspection bool     `json:"withoutContentInspection"`
	Name                     string   `json:"name,omitempty"`
	Labels                   []NameID `json:"labels,omitempty"`
	OcrEnabled               bool     `json:"ocrEnabled,omitempty"`
	ExcludedGroups           []NameID `json:"excludedGroups,omitempty"`
	ExcludedDepartments      []NameID `json:"excludedDepartments,omitempty"`
	ExcludedUsers            []NameID `json:"excludedUsers,omitempty"`
	ZscalerIncidentReciever  bool     `json:"zscalerIncidentReciever,omitempty"`
}

type Label struct {
	ID                  int     `json:"id,omitempty"`
	Name                string  `json:"name,omitempty"`
	Description         string  `json:"description,omitempty"`
	LastModifiedTime    int     `json:"lastModifiedTime,omitempty"`
	LastModifiedBy      *NameID `json:"lastModifiedBy,omitempty"`
	CreatedBy           *NameID `json:"createdBy,omitempty"`
	ReferencedRuleCount int     `json:"referencedRuleCount,omitempty"`
}

//GetID returns the name as string and the ID as int
func (u Label) GetID() (string, int) {
	return u.Name, u.ID
}

//Zurl is an interface that allows you to interact with 3 different types of url objects: allowlist, blocklist and url objects.
type Zurl interface {
	GetUrls(string) []string
	SetUrls(string, []string)
	PushItems(client *Client) error
	GetName() string
}

//Zid is the interface for tyopes that can return ID, so most of them
type Zid interface {
	GetID() (string, int)
}

//func (c BlockedUrls)  returns all the urls in a blocklist
func (c *BlockedUrls) GetUrls(f string) []string {
	return c.Urls
}

//func (c Allowed)  returns all the urls in a allowlist
func (c *AllowedUrls) GetUrls(f string) []string {
	return c.Urls
}

//SetUrls sets all the urls in a allowlist
func (c *UrlCat) GetUrls(f string) []string {
	if f == "urlsRetainingParentCategory" {
		return c.DbCategorizedUrls
	}
	//default is return urls
	return c.Urls
}

//func (c BlockedUrls)  sets all the urls in a blocklist
func (c *BlockedUrls) SetUrls(f string, u []string) {
	c.Urls = u
}

//SetUrls sets all the urls in a allowlist
func (c *AllowedUrls) SetUrls(f string, u []string) {
	c.Urls = u
}

//SetUrls sets all the urls in a allowlist
func (c *UrlCat) SetUrls(f string, u []string) {
	if f == "urls" {
		c.Urls = u
	} else if f == "urlsRetainingParentCategory" {
		c.DbCategorizedUrls = u
	}
}

//func (c BlockedUrls) GetName()   returns all the urls in a blocklist
func (c *BlockedUrls) GetName() string {
	return "Global Block List"
}

//func (c AllowedUrls) GetName()  returns all the urls in a allowlist
func (c *AllowedUrls) GetName() string {
	return "Global Allow List"
}

//func (c UrlCat) GetName()  returns all the urls in a UrlCat
func (c *UrlCat) GetName() string {
	return c.ConfiguredName
}

//PushItems pushes all the urls in a blocklist
func (c BlockedUrls) PushItems(client *Client) error {
	return client.RepBlockedUrls(c)
}

//PushItems pushes all the urls in a allowlist
func (c AllowedUrls) PushItems(client *Client) error {
	return client.RepAllowedUrls(c)
}

//PushItems pushes all the urls in a allowlist
func (c UrlCat) PushItems(client *Client) error {
	return client.UpdateUrlCat(c)
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
		RetryMax: 10,
	}, nil
}

//UrlLookup return the url categories for requested URLs.
//up to 100 urls per request and 400 requests per hour according to zscaler limits
func (c *Client) UrlLookup(urls []string) ([]UrlLookup, error) {
	postBody, _ := json.Marshal(urls)
	body, err := c.postRequest("/urlLookup", postBody)
	if err != nil {
		return nil, err
	}
	res := []UrlLookup{}
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
func (c *Client) AddUrlRule(rule UrlRule) (int, error) {
	//Seting rank to 7 if missing
	if rule.Rank == 0 {
		rule.Rank = 7
	}
	postBody, _ := json.Marshal(rule)
	body, err := c.postRequest("/urlFilteringRules", postBody)
	if err != nil {
		return 0, err
	}
	res := UrlRule{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, nil
}

//GetFwRules gets a list of firewall filtering rules
func (c *Client) GetFwRules() ([]FwRule, error) {
	body, err := c.getRequest("/firewallFilteringRules")
	if err != nil {
		return nil, err
	}
	res := []FwRule{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//AddFwRule adds a firewall filtering rules
func (c *Client) AddFwRule(rule FwRule) (int, error) {
	postBody, _ := json.Marshal(rule)
	body, err := c.postRequest("/firewallFilteringRules", postBody)
	if err != nil {
		return 0, err
	}
	res := FwRule{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, err
}

//GetIPDstGroups gets a list of firewall filtering rules
func (c *Client) GetIPDstGroups() ([]IPDstGroup, error) {
	body, err := c.getRequest("/ipDestinationGroups")
	if err != nil {
		return nil, err
	}
	res := []IPDstGroup{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//AddIPDstGroups adds a firewall filtering rules
func (c *Client) AddIPDstGroup(obj IPDstGroup) (int, error) {
	postBody, _ := json.Marshal(obj)
	body, err := c.postRequest("/ipDestinationGroups", postBody)
	if err != nil {
		return 0, err
	}
	res := IPDstGroup{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, err
}

//GetAppGroups gets a list of network application groups
func (c *Client) GetAppGroups() ([]AppGroup, error) {
	body, err := c.getRequest("/networkApplicationGroups")
	if err != nil {
		return nil, err
	}
	res := []AppGroup{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//GetIPSrcGroups gets a list of firewall filtering rules
func (c *Client) GetIPSrcGroups() ([]IPSrcGroup, error) {
	body, err := c.getRequest("/ipSourceGroups")
	if err != nil {
		return nil, err
	}
	res := []IPSrcGroup{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//AddIPSrcGroup adds a firewall filtering rules
func (c *Client) AddIPSrcGroup(obj IPSrcGroup) (int, error) {
	postBody, _ := json.Marshal(obj)
	body, err := c.postRequest("/ipSourceGroups", postBody)
	if err != nil {
		return 0, err
	}
	res := IPSrcGroup{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, err
}

//GetServiceGroups gets a list of network service groups
func (c *Client) GetServiceGroups() ([]ServiceGroup, error) {
	body, err := c.getRequest("/networkServiceGroups")
	if err != nil {
		return nil, err
	}
	res := []ServiceGroup{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//AddServiceGroup adds a  network service group
func (c *Client) AddServiceGroup(obj ServiceGroup) (int, error) {
	postBody, _ := json.Marshal(obj)
	body, err := c.postRequest("/networkServiceGroups", postBody)
	if err != nil {
		return 0, err
	}
	res := ServiceGroup{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, err
}

//GetService gets a list of network service groups
func (c *Client) GetServices() ([]Service, error) {
	body, err := c.getRequest("/networkServices")
	if err != nil {
		return nil, err
	}
	res := []Service{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//GetService gets a list of network service groups
func (c *Client) GetAuditors() ([]User, error) {
	body, err := c.getRequest("/users/auditors")
	if err != nil {
		return nil, err
	}
	res := []User{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//AddService adds a  network service and returns the new service ID
func (c *Client) AddService(obj Service) (int, error) {
	postBody, _ := json.Marshal(obj)
	body, err := c.postRequest("/networkServices", postBody)
	if err != nil {
		return 0, err
	}
	res := Service{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, err
}

//GetLocations gets all locations
func (c *Client) GetLocations() ([]Location, error) {
	return getPaged[Location](c, 1000, "/locations")
}

//GetLabels gets all labels
func (c *Client) GetLabels() ([]Label, error) {
	return getPaged[Label](c, 1000, "/ruleLabels")
}

//AddLabel adds a  network service and returns the new service ID
func (c *Client) AddLabel(obj Label) (int, error) {
	res := Label{}
	postBody, _ := json.Marshal(obj)
	body, err := c.postRequest("/ruleLabels", postBody)
	if err != nil {
		return 0, err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, err
}

//GetLocationsPaged allows you to request between 100 and 1000 items
func (c *Client) GetLocationsPaged(page int, pageSize int) ([]Location, error) {
	//Validating pagezise
	if pageSize < 100 || pageSize > 1000 {
		return nil, errors.New("Page size must be a number between 100 or 1000")
	}
	path := "/locations" + "?page=" + strconv.Itoa(page) + "&pageSize=" + strconv.Itoa(pageSize)
	body, err := c.getRequest(path)
	if err != nil {
		return nil, err
	}
	res := []Location{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//GetLocationGroups gets all location groups
func (c *Client) GetLocationGroups() ([]LocationGroup, error) {
	return getPaged[LocationGroup](c, 1000, "/locations/groups")
}

//GetLocationsPaged allows you to request between 100 and 1000 items
func (c *Client) GetLocationGroupsPaged(page int, pageSize int) ([]LocationGroup, error) {
	//Validating pagezise
	if pageSize < 100 || pageSize > 1000 {
		return nil, errors.New("Page size must be a number between 100 or 1000")
	}
	path := "/locations/groups" + "?page=" + strconv.Itoa(page) + "&pageSize=" + strconv.Itoa(pageSize)
	body, err := c.getRequest(path)
	if err != nil {
		return nil, err
	}
	res := []LocationGroup{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//GetLocationGroups gets all departments
func (c *Client) GetDeparments() ([]Department, error) {
	return getPaged[Department](c, 1000, "/departments")
}

//GetDepartmentsPaged allows you to request between 100 and 1000 items
func (c *Client) GetDepartmentsPaged(page int, pageSize int) ([]Department, error) {
	//Validating pagezise
	if pageSize < 100 || pageSize > 1000 {
		return nil, errors.New("Page size must be a number between 100 or 1000")
	}
	path := "/departments" + "?page=" + strconv.Itoa(page) + "&pageSize=" + strconv.Itoa(pageSize)
	body, err := c.getRequest(path)
	if err != nil {
		return nil, err
	}
	res := []Department{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//GetGroups gets all user groups
func (c *Client) GetGroups() ([]UserGroup, error) {
	return getPaged[UserGroup](c, 1000, "/groups")
}

//GetGroupsPaged allows you to request between 100 and 1000 items
func (c *Client) GetGroupsPaged(page int, pageSize int) ([]UserGroup, error) {
	//Validating pagezise
	if pageSize < 100 || pageSize > 1000 {
		return nil, errors.New("Page size must be a number between 100 or 1000")
	}
	path := "/groups" + "?page=" + strconv.Itoa(page) + "&pageSize=" + strconv.Itoa(pageSize)
	body, err := c.getRequest(path)
	if err != nil {
		return nil, err
	}
	res := []UserGroup{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//GetUsers return all the ZIA users
func (c *Client) GetUsers() ([]User, error) {
	return getPaged[User](c, 1000, "/users")
}

//GetUsersPaged allows you to request between 100 and 1000 items
func (c *Client) GetUsersPaged(page int, pageSize int) ([]User, error) {
	//Validating pagezise
	if pageSize < 100 || pageSize > 1000 {
		return nil, errors.New("Page size must be a number between 100 or 1000")
	}
	path := "/users" + "?page=" + strconv.Itoa(page) + "&pageSize=" + strconv.Itoa(pageSize)
	body, err := c.getRequest(path)
	if err != nil {
		return nil, err
	}
	res := []User{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//UpdateUser updates the user info using the provided user object
func (c *Client) UpdateUser(user User) error {
	path := "/users/" + strconv.Itoa(user.ID)
	postBody, _ := json.Marshal(user)
	err := c.putRequest(path, postBody)
	return err
}

//GetSublocations gets a list of sublocations from the received location id
func (c *Client) GetSublocations(id int) ([]Location, error) {
	path := "/locations/" + strconv.Itoa(id) + "/sublocations"
	body, err := c.getRequest(path)
	if err != nil {
		return nil, err
	}
	res := []Location{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//AddLocation adds a new location or sublocation and returns the new object ID
func (c *Client) AddLocation(obj Location) (int, error) {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return 0, e
	}
	body, err := c.postRequest("/locations", postBody)
	if err != nil {
		return 0, err
	}
	res := Location{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, err
}

//Edit adds a new location or sublocation and returns the new object ID
func (c *Client) UpdateLocation(obj Location) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/locations/" + strconv.Itoa(obj.ID)
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

//GetUrlCats gets a list of all URL filtering category
func (c *Client) GetUrlCats() ([]UrlCat, error) {
	res := []UrlCat{}
	body, err := c.getRequest("/urlCategories")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return res, err
	}
	return res, nil
}

//GetDLPDictionaries get all the DLP dictionaries
func (c *Client) GetDLPDictionaries() ([]DLPDictionary, error) {
	res := []DLPDictionary{}
	body, err := c.getRequest("/dlpDictionaries")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return res, err
	}
	return res, nil
}

//AddDLPDictionary adds a DLP dictionary and returns the id if created or error
func (c *Client) AddDLPDictionary(obj DLPDictionary) (int, error) {
	res := DLPDictionary{}
	postBody, _ := json.Marshal(obj)
	body, err := c.postRequest("/dlpDictionaries", postBody)
	if err != nil {
		return 0, err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, nil
}

//GetDLPEngines get all the DLP engines
func (c *Client) GetDLPEngines() ([]DLPEngine, error) {
	res := []DLPEngine{}
	body, err := c.getRequest("/dlpEngines")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return res, err
	}
	return res, nil
}

//GetDLPNotificationTemplates get all the DLP notification templates
func (c *Client) GetDLPNotificationTemplates() ([]DLPNotificationTemplate, error) {
	res := []DLPNotificationTemplate{}
	body, err := c.getRequest("/dlpNotificationTemplates")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return res, err
	}
	return res, nil
}

//AddDLPNotificationTemplates add a DLP notification template
func (c *Client) AddDLPNotificationTemplate(entry DLPNotificationTemplate) (int, error) {
	res := DLPNotificationTemplate{}
	postBody, _ := json.Marshal(entry)
	body, err := c.postRequest("/dlpNotificationTemplates", postBody)
	if err != nil {
		return 0, err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, nil
}

//GetDLPEngines get all the DLP engines
func (c *Client) GetICAPServers() ([]ICAPServer, error) {
	res := []ICAPServer{}
	body, err := c.getRequest("/icapServers")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return res, err
	}
	return res, nil
}

//GetDLPEngines get all the DLP engines
func (c *Client) GetDLPRules() ([]DLPRule, error) {
	res := []DLPRule{}
	body, err := c.getRequest("/webDlpRules")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return res, err
	}
	return res, nil
}

//AddUrlRule adds a URL filtering category
func (c *Client) AddDLPRule(item DLPRule) (int, error) {
	res := DLPRule{}
	postBody, _ := json.Marshal(item)
	body, err := c.postRequest("/webDlpRules", postBody)
	if err != nil {
		return 0, err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, nil
}

//AddUrlRule adds a URL filtering category
func (c *Client) AddUrlCat(category UrlCat) (string, error) {
	res := UrlCat{}
	postBody, _ := json.Marshal(category)
	body, err := c.postRequest("/urlCategories", postBody)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return "", err
	}
	return res.ID, nil
}

//UpdateUrlCat updates a URL filtering category
func (c *Client) UpdateUrlCat(category UrlCat) error {
	//Validating at least 1 urls is in the entries
	if category.Urls == nil {
		return errors.New("You can't delete all urls, at least 1 url should be sent on url category:" + category.ConfiguredName)
	}
	path := "/urlCategories/" + category.ID
	postBody, _ := json.Marshal(category)
	err := c.putRequest(path, postBody)
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

//RepBlockedUrls replaces current existing blocked list
func (c *Client) RepBlockedUrls(urls BlockedUrls) error {
	postBody, err := json.Marshal(urls)
	if err != nil {
		return err
	}
	return c.putRequest("/security/advanced", postBody)
}

//GetAllowedUrls gets a list of blocked URLs in Advanced Threat policy
func (c *Client) GetAllowedUrls() (AllowedUrls, error) {
	body, err := c.getRequest("/security")
	if err != nil {
		return AllowedUrls{}, err
	}
	res := AllowedUrls{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return AllowedUrls{}, err
	}
	return res, nil
}

//RepAllowedUrls replaces current existing allowed list
func (c *Client) RepAllowedUrls(urls AllowedUrls) error {
	postBody, err := json.Marshal(urls)
	if err != nil {
		return err
	}
	return c.putRequest("/security", postBody)
}

//GetPaged is a generic function that iterates through multiple pageds and returns the joined parsed object
func getPaged[K any](c *Client, pageSize int, path string) ([]K, error) {
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

//GetIDs is a generic function that receives an arrray object and return a map with the name as key and ID as value
func GetIDs[K Zid](obj []K) map[string]int {
	//Creating map
	m := make(map[string]int)
	//Iterating
	for _, v := range obj {
		name, id := v.GetID()
		m[name] = id
	}
	return m
}

//postRequest Process and sends HTTP POST requests
func (c *Client) postRequest(path string, payload []byte) ([]byte, error) {
	data := bytes.NewBuffer(payload)
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, data)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

//getRequest Process and sends HTTP GET requests
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
			t, err := retryAfter(resp)
			if err != nil {
				return nil, err
			}
			s := time.Duration(t) * time.Second
			time.Sleep(s)
			retryMax -= 1
			// reset Request.Body
			req.Body = ioutil.NopCloser(bytes.NewBuffer(payload))
			return c.doWithOptions(req, retryMax)
		}
	}
	//Retry if the service is unavailable.
	if resp.StatusCode == 503 {
		s := time.Duration(retryMax) * time.Second
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

//httpStatusCheck receives an http response and returns an error based on zscaler documentation.
//From https://help.zscaler.com/zia/about-error-handling
func httpStatusCheck(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return nil
	} else if resp.StatusCode == 400 {
		b, _ := io.ReadAll(resp.Body)
		return errors.New("HTTP error: Invalid or bad request" + string(b))
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
	key, err := obfuscateApiKey(apiKey, t)
	if err != nil {
		return nil, err
	}
	postBody, err := json.Marshal(map[string]string{
		"apiKey":    key,
		"username":  admin,
		"password":  pass,
		"timestamp": t,
	})
	if err != nil {
		return nil, err
	}
	data := bytes.NewBuffer(postBody)
	client := http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Post(BaseURL+"/authenticatedSession", "application/json", data)
	if err != nil {
		return nil, err
	}
	//Checking response
	err = httpStatusCheck(resp)
	if err != nil {
		return nil, err
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
func obfuscateApiKey(api string, t string) (string, error) {
	if len(t) < 6 {
		return "", errors.New("time lenght for ofuscation is less than 6 digits, please check your system's clock")
	}
	n := t[len(t)-6:]
	intVar, err := strconv.Atoi(n)
	if err != nil {
		return "", err
	}
	r := fmt.Sprintf("%06d", intVar>>1)
	key := ""
	for i, _ := range n {
		d, err := strconv.Atoi((n)[i : i+1])
		if err != nil {
			return "", err
		}
		if d+1 > len(api) {
			return "", errors.New("invalid api key size")
		}
		key += api[d : d+1]
	}
	for j, _ := range r {
		d, err := strconv.Atoi((r)[j : j+1])
		if err != nil {
			return "", err
		}
		if d+3 > len(api) {
			return "", errors.New("invalid api key size")
		}
		key += api[d+2 : d+3]
	}
	return key, nil
}

//SetRetryMax adds a URL filtering rules
func (c *Client) SetRetryMax(r int) {
	c.RetryMax = r
}
