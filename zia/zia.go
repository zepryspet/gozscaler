package zia

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ZIAError is the error
type ZIAError struct {
	//this is the Error
	Err string
	//Code this is the http status code
	Code int
}

func (e *ZIAError) Error() string {
	if e.Code != 0 {
		return e.Err + ", HTTP status code: " + strconv.Itoa(e.Code)
	}
	return e.Err
}

// Client contains the base url, http client and max number of retries per requests
type Client struct {
	BaseURL    string
	SanboxUrl  string
	HTTPClient *http.Client
	RetryMax   int
	Log        *slog.Logger
	//oneapi auth
	Bearer string
}

type DnsRule struct {
	Action              string   `json:"action"`
	CapturePCAP         bool     `json:"capturePCAP,omitempty"`
	BlockResponseCode   string   `json:"blockResponseCode,omitempty"`
	AccessControl       string   `json:"accessControl,omitempty"`
	ID                  int      `json:"id,omitempty"`
	Name                string   `json:"name"`
	Order               int      `json:"order,omitempty"`
	Rank                int      `json:"rank,omitempty"`
	Description         string   `json:"description,omitempty"`
	Locations           []NameID `json:"locations,omitempty"`
	LocationGroups      []NameID `json:"locationGroups,omitempty"`
	Groups              []NameID `json:"groups,omitempty"`
	Departments         []NameID `json:"departments,omitempty"`
	Users               []NameID `json:"users,omitempty"`
	Protocols           []string `json:"protocols,omitempty"`
	State               string   `json:"state,omitempty"`
	TimeWindows         []NameID `json:"timeWindows,omitempty"`
	SrcIps              []string `json:"srcIps,omitempty"`
	SrcIPGroups         []NameID `json:"srcIpGroups,omitempty"`
	SrcIpv6Groups       []NameID `json:"srcIpv6Groups,omitempty"`
	DestAddresses       []string `json:"destAddresses,omitempty"`
	DestIPGroups        []NameID `json:"destIpGroups,omitempty"`
	DestIpv6Groups      []NameID `json:"destIpv6Groups,omitempty"`
	DestCountries       []string `json:"destCountries,omitempty"`
	SourceCountries     []string `json:"sourceCountries,omitempty"`
	DestIPCategories    []string `json:"destIpCategories,omitempty"`
	ResCategories       []string `json:"resCategories,omitempty"`
	RedirectIP          string   `json:"redirectIp,omitempty"`
	Applications        []string `json:"applications,omitempty"`
	ApplicationGroups   []NameID `json:"applicationGroups,omitempty"`
	DNSGateway          *NameID  `json:"dnsGateway,omitempty"`
	DNSRuleRequestTypes []string `json:"dnsRuleRequestTypes,omitempty"`
	ZpaIPGroup          *NameID  `json:"zpaIpGroup,omitempty"`
	LastModifiedTime    int      `json:"lastModifiedTime,omitempty"`
	LastModifiedBy      *NameID  `json:"lastModifiedBy,omitempty"`
	Devices             []NameID `json:"devices,omitempty"`
	DeviceGroups        []NameID `json:"deviceGroups,omitempty"`
	Labels              []NameID `json:"labels,omitempty"`
	EdnsEcsObject       *NameID  `json:"ednsEcsObject,omitempty"`
	Predefined          bool     `json:"predefined,omitempty"`
	DefaultRule         bool     `json:"defaultRule"`
}

// String prints the struct in json pretty format
func (p DnsRule) String() string {
	return jsonString(p)
}

// Delete deletes an object
func (u DnsRule) Delete(c *Client) error {
	return c.DeleteDnsRule(u.ID)
}

type SslRule struct {
	ID                     int           `json:"id,omitempty"`
	AccessControl          string        `json:"accessControl,omitempty"`
	Name                   string        `json:"name"`
	Order                  int           `json:"order,omitempty"`
	Rank                   int           `json:"rank,omitempty"`
	Locations              []NameID      `json:"locations,omitempty"`
	LocationGroups         []NameID      `json:"locationGroups,omitempty"`
	Departments            []NameID      `json:"departments,omitempty"`
	Groups                 []NameID      `json:"groups,omitempty"`
	Users                  []NameID      `json:"users,omitempty"`
	Platforms              []string      `json:"platforms,omitempty"`
	RoadWarriorForKerberos bool          `json:"roadWarriorForKerberos,omitempty"`
	URLCategories          []string      `json:"urlCategories,omitempty"`
	CloudApplications      []string      `json:"cloudApplications,omitempty"`
	Action                 DecryptAction `json:"action,omitempty"`
	State                  string        `json:"state,omitempty"`
	Description            string        `json:"description,omitempty"`
	LastModifiedTime       int           `json:"lastModifiedTime,omitempty"`
	LastModifiedBy         string        `json:"lastModifiedBy,omitempty"`
	DestIPGroups           []NameID      `json:"destIpGroups,omitempty"`
	SourceIPGroups         []NameID      `json:"sourceIpGroups,omitempty"`
	ProxyGateways          []NameID      `json:"proxyGateways,omitempty"`
	UserAgentTypes         []string      `json:"userAgentTypes,omitempty"`
	Devices                []NameID      `json:"devices,omitempty"`
	DeviceGroups           []NameID      `json:"deviceGroups,omitempty"`
	DeviceTrustLevels      []string      `json:"deviceTrustLevels,omitempty"`
	Labels                 []NameID      `json:"labels,omitempty"`
	ZpaAppSegments         []NameID      `json:"zpaAppSegments,omitempty"`
	WorkloadGroups         []NameID      `json:"workloadGroups,omitempty"`
	TimeWindows            []NameID      `json:"timeWindows,omitempty"`
	Predefined             bool          `json:"predefined,omitempty"`
	DefaultRule            bool          `json:"defaultRule,omitempty"`
}

type DecryptAction struct {
	Type                       string                  `json:"type,omitempty"`
	DecryptSubActions          *DecryptSubActions      `json:"decryptSubActions,omitempty"`
	DoNotDecryptSubActions     *DoNotDecryptSubActions `json:"doNotDecryptSubActions,omitempty"`
	ShowEUN                    bool                    `json:"showEUN,omitempty"`
	ShowEUNATP                 bool                    `json:"showEUNATP,omitempty"`
	OverrideDefaultCertificate bool                    `json:"overrideDefaultCertificate,omitempty"`
	SslInterceptionCert        *NameID                 `json:"sslInterceptionCert,omitempty"`
}

type DecryptSubActions struct {
	ServerCertificates              string `json:"serverCertificates,omitempty"`
	OcspCheck                       bool   `json:"ocspCheck,omitempty"`
	MinClientTLSVersion             string `json:"minClientTLSVersion,omitempty"`
	MinServerTLSVersion             string `json:"minServerTLSVersion,omitempty"`
	BlockUndecrypt                  bool   `json:"blockUndecrypt,omitempty"`
	HTTP2Enabled                    bool   `json:"http2Enabled,omitempty"`
	BlockSslTrafficWithNoSniEnabled bool   `json:"blockSslTrafficWithNoSniEnabled,omitempty"`
}

type DoNotDecryptSubActions struct {
	BypassOtherPolicies             bool   `json:"bypassOtherPolicies,omitempty"`
	ServerCertificates              string `json:"serverCertificates,omitempty"`
	OcspCheck                       bool   `json:"ocspCheck,omitempty"`
	MinTLSVersion                   string `json:"minTLSVersion,omitempty"`
	BlockSslTrafficWithNoSniEnabled bool   `json:"blockSslTrafficWithNoSniEnabled,omitempty"`
}

// String prints the struct in json pretty format
func (p SslRule) String() string {
	return jsonString(p)
}

// Delete deletes an object
func (u SslRule) Delete(c *Client) error {
	return c.DeleteSslRule(u.ID)
}

// UrlRule parses responses for urls policies
type UrlRule struct {
	ID                     int        `json:"id,omitempty"`
	Name                   string     `json:"name"`
	Order                  int        `json:"order,omitempty"`
	Protocols              []string   `json:"protocols,omitempty"`
	Locations              []NameID   `json:"locations,omitempty"`
	Groups                 []NameID   `json:"groups,omitempty"`
	Departments            []NameID   `json:"departments,omitempty"`
	Users                  []NameID   `json:"users,omitempty"`
	URLCategories          []string   `json:"urlCategories,omitempty"`
	State                  string     `json:"state,omitempty"` //"ENABLED" or "DISABLED"
	TimeWindows            []NameID   `json:"timeWindows,omitempty"`
	SourceIpGroups         []NameID   `json:"sourceIpGroups,omitempty"`
	Rank                   int        `json:"rank"`
	RequestMethods         []string   `json:"requestMethods,omitempty"`
	EndUserNotificationURL string     `json:"endUserNotificationUrl,omitempty"`
	OverrideUsers          []NameID   `json:"overrideUsers,omitempty"`
	OverrideGroups         []NameID   `json:"overrideGroups,omitempty"`
	BlockOverride          bool       `json:"blockOverride,omitempty"`
	TimeQuota              int        `json:"timeQuota,omitempty"`
	SizeQuota              int        `json:"sizeQuota,omitempty"`
	Description            string     `json:"description,omitempty"`
	LocationGroups         []NameID   `json:"locationGroups,omitempty"`
	Labels                 []NameID   `json:"labels,omitempty"`
	ValidityStartTime      int        `json:"validityStartTime,omitempty"`
	ValidityEndTime        int        `json:"validityEndTime,omitempty"`
	ValidityTimeZoneID     string     `json:"validityTimeZoneId,omitempty"`
	LastModifiedTime       int        `json:"lastModifiedTime,omitempty"`
	LastModifiedBy         *NameID    `json:"lastModifiedBy,omitempty"`
	EnforceTimeValidity    bool       `json:"enforceTimeValidity,omitempty"`
	Action                 string     `json:"action,omitempty"`
	Ciparule               bool       `json:"ciparule,omitempty"`
	UserAgentTypes         []string   `json:"userAgentTypes,omitempty"`
	CbiProfile             CbiProfile `json:"cbiProfile,omitempty"`
}

type MalwareInspection struct {
	InspectInbound  bool `json:"inspectInbound"`
	InspectOutbound bool `json:"inspectOutbound"`
}
type Subscriptions struct {
	ID                 string `json:"id"`
	Status             string `json:"status"`
	State              string `json:"state"`
	Licenses           int    `json:"licenses"`
	StartDate          int    `json:"startDate"`
	StrStartDate       string `json:"strStartDate"`
	StrEndDate         string `json:"strEndDate"`
	EndDate            int    `json:"endDate"`
	Sku                string `json:"sku"`
	CellCount          string `json:"cellCount"`
	UpdatedAtTimestamp int    `json:"updatedAtTimestamp"`
	Subscribed         bool   `json:"subscribed"`
}

func (p Subscriptions) String() string {
	return jsonString(p)
}

func (p MalwareInspection) String() string {
	return jsonString(p)
}

type AdvThreatSettings struct {
	RiskTolerance                        int      `json:"riskTolerance"`
	RiskToleranceCapture                 bool     `json:"riskToleranceCapture"`
	CmdCtlServerBlocked                  bool     `json:"cmdCtlServerBlocked"`
	CmdCtlServerCapture                  bool     `json:"cmdCtlServerCapture"`
	CmdCtlTrafficBlocked                 bool     `json:"cmdCtlTrafficBlocked"`
	CmdCtlTrafficCapture                 bool     `json:"cmdCtlTrafficCapture"`
	MalwareSitesBlocked                  bool     `json:"malwareSitesBlocked"`
	MalwareSitesCapture                  bool     `json:"malwareSitesCapture"`
	ActiveXBlocked                       bool     `json:"activeXBlocked"`
	ActiveXCapture                       bool     `json:"activeXCapture"`
	BrowserExploitsBlocked               bool     `json:"browserExploitsBlocked"`
	BrowserExploitsCapture               bool     `json:"browserExploitsCapture"`
	FileFormatVunerabilitesBlocked       bool     `json:"fileFormatVunerabilitesBlocked"`
	FileFormatVunerabilitesCapture       bool     `json:"fileFormatVunerabilitesCapture"`
	KnownPhishingSitesBlocked            bool     `json:"knownPhishingSitesBlocked"`
	KnownPhishingSitesCapture            bool     `json:"knownPhishingSitesCapture"`
	SuspectedPhishingSitesBlocked        bool     `json:"suspectedPhishingSitesBlocked"`
	SuspectedPhishingSitesCapture        bool     `json:"suspectedPhishingSitesCapture"`
	SuspectAdwareSpywareSitesBlocked     bool     `json:"suspectAdwareSpywareSitesBlocked"`
	SuspectAdwareSpywareSitesCapture     bool     `json:"suspectAdwareSpywareSitesCapture"`
	WebspamBlocked                       bool     `json:"webspamBlocked"`
	WebspamCapture                       bool     `json:"webspamCapture"`
	IrcTunnellingBlocked                 bool     `json:"ircTunnellingBlocked"`
	IrcTunnellingCapture                 bool     `json:"ircTunnellingCapture"`
	AnonymizerBlocked                    bool     `json:"anonymizerBlocked"`
	AnonymizerCapture                    bool     `json:"anonymizerCapture"`
	CookieStealingBlocked                bool     `json:"cookieStealingBlocked"`
	CookieStealingPCAPEnabled            bool     `json:"cookieStealingPCAPEnabled"`
	PotentialMaliciousRequestsBlocked    bool     `json:"potentialMaliciousRequestsBlocked"`
	PotentialMaliciousRequestsCapture    bool     `json:"potentialMaliciousRequestsCapture"`
	BlockedCountries                     []string `json:"blockedCountries"`
	BlockCountriesCapture                bool     `json:"blockCountriesCapture"`
	BitTorrentBlocked                    bool     `json:"bitTorrentBlocked"`
	BitTorrentCapture                    bool     `json:"bitTorrentCapture"`
	TorBlocked                           bool     `json:"torBlocked"`
	TorCapture                           bool     `json:"torCapture"`
	GoogleTalkBlocked                    bool     `json:"googleTalkBlocked"`
	GoogleTalkCapture                    bool     `json:"googleTalkCapture"`
	SSHTunnellingBlocked                 bool     `json:"sshTunnellingBlocked"`
	SSHTunnellingCapture                 bool     `json:"sshTunnellingCapture"`
	CryptoMiningBlocked                  bool     `json:"cryptoMiningBlocked"`
	CryptoMiningCapture                  bool     `json:"cryptoMiningCapture"`
	AdSpywareSitesBlocked                bool     `json:"adSpywareSitesBlocked"`
	AdSpywareSitesCapture                bool     `json:"adSpywareSitesCapture"`
	DgaDomainsBlocked                    bool     `json:"dgaDomainsBlocked"`
	AlertForUnknownOrSuspiciousC2Traffic bool     `json:"alertForUnknownOrSuspiciousC2Traffic"`
	DgaDomainsCapture                    bool     `json:"dgaDomainsCapture"`
	MaliciousUrlsCapture                 bool     `json:"maliciousUrlsCapture"`
}

func (p AdvThreatSettings) String() string {
	return jsonString(p)
}

type MalwareProtocols struct {
	InspectHTTP        bool `json:"inspectHttp"`
	InspectFtpOverHTTP bool `json:"inspectFtpOverHttp"`
	InspectFtp         bool `json:"inspectFtp"`
}

func (p MalwareProtocols) String() string {
	return jsonString(p)
}

// UrlAndCloudSettings updates url can dcloud settings
type UrlAndCloudSettings struct {
	EnableDynamicContentCat           bool `json:"enableDynamicContentCat"`
	ConsiderEmbeddedSites             bool `json:"considerEmbeddedSites"`
	EnforceSafeSearch                 bool `json:"enforceSafeSearch"`
	EnableOffice365                   bool `json:"enableOffice365"`
	EnableMsftO365                    bool `json:"enableMsftO365"`
	EnableUcaasZoom                   bool `json:"enableUcaasZoom"`
	EnableUcaasLogMeIn                bool `json:"enableUcaasLogMeIn"`
	EnableUcaasRingCentral            bool `json:"enableUcaasRingCentral"`
	EnableUcaasWebex                  bool `json:"enableUcaasWebex"`
	EnableChatGptPrompt               bool `json:"enableChatGptPrompt,omitempty"`
	EnableMicrosoftCoPilotPrompt      bool `json:"enableMicrosoftCoPilotPrompt,omitempty"`
	EnableGeminiPrompt                bool `json:"enableGeminiPrompt,omitempty"`
	EnablePOEPrompt                   bool `json:"enablePOEPrompt,omitempty"`
	EnableMetaPrompt                  bool `json:"enableMetaPrompt,omitempty"`
	EnablePerPlexityPrompt            bool `json:"enablePerPlexityPrompt,omitempty"`
	BlockSkype                        bool `json:"blockSkype"`
	EnableNewlyRegisteredDomains      bool `json:"enableNewlyRegisteredDomains"`
	EnableBlockOverrideForNonAuthUser bool `json:"enableBlockOverrideForNonAuthUser"`
	EnableCIPACompliance              bool `json:"enableCIPACompliance"`
}

func (p UrlAndCloudSettings) String() string {
	return jsonString(p)
}

type AdvSettings struct {
	AuthBypassURLCategories                                []string   `json:"authBypassUrlCategories,omitempty"`
	DomainFrontingBypassURLCategories                      []string   `json:"domainFrontingBypassUrlCategories,omitempty"`
	AuthBypassUrls                                         []string   `json:"authBypassUrls,omitempty"`
	AuthBypassApps                                         []string   `json:"authBypassApps,omitempty"`
	KerberosBypassURLCategories                            []string   `json:"kerberosBypassUrlCategories,omitempty"`
	KerberosBypassUrls                                     []string   `json:"kerberosBypassUrls,omitempty"`
	KerberosBypassApps                                     []string   `json:"kerberosBypassApps,omitempty"`
	BasicBypassURLCategories                               []string   `json:"basicBypassUrlCategories,omitempty"`
	BasicBypassApps                                        []string   `json:"basicBypassApps,omitempty"`
	HTTPRangeHeaderRemoveURLCategories                     []string   `json:"httpRangeHeaderRemoveUrlCategories,omitempty"`
	DigestAuthBypassURLCategories                          []string   `json:"digestAuthBypassUrlCategories,omitempty"`
	DigestAuthBypassUrls                                   []string   `json:"digestAuthBypassUrls,omitempty"`
	DigestAuthBypassApps                                   []string   `json:"digestAuthBypassApps,omitempty"`
	EnableDNSResolutionOnTransparentProxy                  bool       `json:"enableDnsResolutionOnTransparentProxy"`
	EnableIPv6DNSResolutionOnTransparentProxy              bool       `json:"enableIPv6DnsResolutionOnTransparentProxy"`
	EnableIPv6DNSOptimizationOnAllTransparentProxy         bool       `json:"enableIPv6DnsOptimizationOnAllTransparentProxy"`
	EnableEvaluatePolicyOnGlobalSSLBypass                  bool       `json:"enableEvaluatePolicyOnGlobalSSLBypass"`
	DNSResolutionOnTransparentProxyExemptURLCategories     []string   `json:"dnsResolutionOnTransparentProxyExemptUrlCategories,omitempty"`
	DNSResolutionOnTransparentProxyIPv6ExemptURLCategories []string   `json:"dnsResolutionOnTransparentProxyIPv6ExemptUrlCategories,omitempty"`
	DNSResolutionOnTransparentProxyExemptUrls              []string   `json:"dnsResolutionOnTransparentProxyExemptUrls,omitempty"`
	DNSResolutionOnTransparentProxyExemptApps              []string   `json:"dnsResolutionOnTransparentProxyExemptApps,omitempty"`
	DNSResolutionOnTransparentProxyIPv6ExemptApps          []string   `json:"dnsResolutionOnTransparentProxyIPv6ExemptApps,omitempty"`
	DNSResolutionOnTransparentProxyURLCategories           []string   `json:"dnsResolutionOnTransparentProxyUrlCategories,omitempty"`
	DNSResolutionOnTransparentProxyIPv6URLCategories       []string   `json:"dnsResolutionOnTransparentProxyIPv6UrlCategories,omitempty"`
	DNSResolutionOnTransparentProxyUrls                    []string   `json:"dnsResolutionOnTransparentProxyUrls,omitempty"`
	DNSResolutionOnTransparentProxyApps                    []string   `json:"dnsResolutionOnTransparentProxyApps,omitempty"`
	DNSResolutionOnTransparentProxyIPv6Apps                []string   `json:"dnsResolutionOnTransparentProxyIPv6Apps,omitempty"`
	BlockDomainFrontingApps                                []string   `json:"blockDomainFrontingApps,omitempty"`
	PreferSniOverConnHostApps                              []string   `json:"preferSniOverConnHostApps,omitempty"`
	EnableOffice365                                        bool       `json:"enableOffice365"`
	LogInternalIP                                          bool       `json:"logInternalIp"`
	EnforceSurrogateIPForWindowsApp                        bool       `json:"enforceSurrogateIpForWindowsApp"`
	TrackHTTPTunnelOnHTTPPorts                             bool       `json:"trackHttpTunnelOnHttpPorts"`
	BlockHTTPTunnelOnNonHTTPPorts                          bool       `json:"blockHttpTunnelOnNonHttpPorts"`
	BlockDomainFrontingOnHostHeader                        bool       `json:"blockDomainFrontingOnHostHeader"`
	ZscalerClientConnector1AndPacRoadWarriorInFirewall     bool       `json:"zscalerClientConnector1AndPacRoadWarriorInFirewall"`
	CascadeURLFiltering                                    bool       `json:"cascadeUrlFiltering"`
	EnablePolicyForUnauthenticatedTraffic                  bool       `json:"enablePolicyForUnauthenticatedTraffic"`
	BlockNonCompliantHTTPRequestOnHTTPPorts                bool       `json:"blockNonCompliantHttpRequestOnHttpPorts"`
	EnableAdminRankAccess                                  bool       `json:"enableAdminRankAccess"`
	UISessionTimeout                                       int        `json:"uiSessionTimeout"`
	HTTP2NonbrowserTrafficEnabled                          bool       `json:"http2NonbrowserTrafficEnabled"`
	EcsForAllEnabled                                       bool       `json:"ecsForAllEnabled"`
	EcsObject                                              *EcsObject `json:"ecsObject,omitempty"`
	DynamicUserRiskEnabled                                 bool       `json:"dynamicUserRiskEnabled"`
	BlockConnectHostSniMismatch                            bool       `json:"blockConnectHostSniMismatch"`
	PreferSniOverConnHost                                  bool       `json:"preferSniOverConnHost"`
	SipaXffHeaderEnabled                                   bool       `json:"sipaXffHeaderEnabled"`
	BlockNonHTTPOnHTTPPortEnabled                          bool       `json:"blockNonHttpOnHttpPortEnabled"`
	SniDNSOptimizationBypassURLCategories                  []string   `json:"sniDnsOptimizationBypassUrlCategories,omitempty"`
}

func (p AdvSettings) String() string {
	return jsonString(p)
}

type EcsObject struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	ExternalID string `json:"externalId"`
	Extensions struct {
		AdditionalProp1 string `json:"additionalProp1"`
		AdditionalProp2 string `json:"additionalProp2"`
		AdditionalProp3 string `json:"additionalProp3"`
	} `json:"extensions"`
}

type AdvOptions struct {
	Val                int    `json:"val"`
	Mask               int    `json:"mask"`
	URLSupercategory   string `json:"urlSupercategory"`
	Deprecated         bool   `json:"deprecated"`
	BackendName        string `json:"backendName"`
	Name               string `json:"name"`
	UserConfiguredName string `json:"userConfiguredName"`
	Comments           string `json:"comments"`
}

type AdvAppOptions struct {
	Val                 int    `json:"val"`
	WebApplicationClass string `json:"webApplicationClass"`
	BackendName         string `json:"backendName"`
	OriginalName        string `json:"originalName"`
	Name                string `json:"name"`
	Deprecated          bool   `json:"deprecated"`
	Misc                bool   `json:"misc"`
	AppNotReady         bool   `json:"appNotReady"`
	UnderMigration      bool   `json:"underMigration"`
	AppCatModified      bool   `json:"appCatModified"`
}

type MalwareSettings struct {
	VirusBlocked                bool `json:"virusBlocked"`
	VirusCapture                bool `json:"virusCapture"`
	UnwantedApplicationsBlocked bool `json:"unwantedApplicationsBlocked"`
	UnwantedApplicationsCapture bool `json:"unwantedApplicationsCapture"`
	TrojanBlocked               bool `json:"trojanBlocked"`
	TrojanCapture               bool `json:"trojanCapture"`
	WormBlocked                 bool `json:"wormBlocked"`
	WormCapture                 bool `json:"wormCapture"`
	AdwareBlocked               bool `json:"adwareBlocked"`
	AdwareCapture               bool `json:"adwareCapture"`
	SpywareBlocked              bool `json:"spywareBlocked"`
	SpywareCapture              bool `json:"spywareCapture"`
	RansomwareBlocked           bool `json:"ransomwareBlocked"`
	RansomwareCapture           bool `json:"ransomwareCapture"`
	RemoteAccessToolBlocked     bool `json:"remoteAccessToolBlocked"`
	RemoteAccessToolCapture     bool `json:"remoteAccessToolCapture"`
}

func (p MalwareSettings) String() string {
	return jsonString(p)
}

type MalwarePolicy struct {
	BlockUnscannableFiles              bool `json:"blockUnscannableFiles"`
	BlockPasswordProtectedArchiveFiles bool `json:"blockPasswordProtectedArchiveFiles"`
}

func (p MalwarePolicy) String() string {
	return jsonString(p)
}

type CbiProfile struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// String prints the struct in json pretty format
func (p UrlRule) String() string {
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

// Delete deletes an object
func (u UrlRule) Delete(c *Client) error {
	return c.DeleteUrlRule(u.ID)
}

// NameID is a helper for json entries with name and ID
type NameID struct {
	ID   int    `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Uuid string `json:"uuid,omitempty"`
}

type NameStringID struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// AppGroup parses network application groups
type AppGroup struct {
	ID                  int      `json:"id"`
	Name                string   `json:"name,omitempty"`
	NetworkApplications []string `json:"networkApplications"`
	Description         string   `json:"description,omitempty"`
}

// GetID returns name, id
func (u AppGroup) GetID() (string, int) {
	return u.Name, u.ID
}

// UrlCat parses responses for urls categories
type UrlCat struct {
	ID                              string   `json:"id,omitempty"` // This goes from CUSTOM_00 to CUSTOM_256
	ConfiguredName                  string   `json:"configuredName"`
	Keywords                        []string `json:"keywords,omitempty"`
	KeywordsRetainingParentCategory []string `json:"keywordsRetainingParentCategory,omitempty"`
	Urls                            []string `json:"urls,omitempty"`
	DbCategorizedUrls               []string `json:"dbCategorizedUrls,omitempty"`
	IPRanges                        []string `json:"ipRanges,omitempty"`
	IPRangesRetainingParentCategory []string `json:"ipRangesRetainingParentCategory,omitempty"`
	CustomCategory                  bool     `json:"customCategory,omitempty"` //set to true if custom
	SuperCategory                   string   `json:"superCategory"`            //Use USER_DEFINED for custom category creation
	Scopes                          []struct {
		ScopeGroupMemberEntities []struct {
			ID         int    `json:"id"`
			Name       string `json:"name"`
			Extensions struct {
				AdditionalProp1 string `json:"additionalProp1"`
				AdditionalProp2 string `json:"additionalProp2"`
				AdditionalProp3 string `json:"additionalProp3"`
			} `json:"extensions"`
		} `json:"scopeGroupMemberEntities"`
		Type          string `json:"Type"`
		ScopeEntities []struct {
			ID         int    `json:"id"`
			Name       string `json:"name"`
			Extensions struct {
				AdditionalProp1 string `json:"additionalProp1"`
				AdditionalProp2 string `json:"additionalProp2"`
				AdditionalProp3 string `json:"additionalProp3"`
			} `json:"extensions"`
		} `json:"ScopeEntities"`
	} `json:"scopes,omitempty"`
	Editable         bool   `json:"editable,omitempty"`
	Description      string `json:"description,omitempty"`
	Type             string `json:"type,omitempty"`
	URLKeywordCounts *struct {
		TotalURLCount            int `json:"totalUrlCount"`
		RetainParentURLCount     int `json:"retainParentUrlCount"`
		TotalKeywordCount        int `json:"totalKeywordCount"`
		RetainParentKeywordCount int `json:"retainParentKeywordCount"`
	} `json:"urlKeywordCounts,omitempty"`
	Val                                  int `json:"val,omitempty"`
	CustomUrlsCount                      int `json:"customUrlsCount,omitempty"`
	UrlsRetainingParentCategoryCount     int `json:"urlsRetainingParentCategoryCount,omitempty"`
	CustomIPRangesCount                  int `json:"customIpRangesCount,omitempty"`
	IPRangesRetainingParentCategoryCount int `json:"ipRangesRetainingParentCategoryCount,omitempty"`
}

// String prints the struct in json pretty format
func (p UrlCat) String() string {
	return jsonString(p)
}

// Delete deletes an object
func (u UrlCat) Delete(c *Client) error {
	return c.DeleteUrlCat(u.ID)
}

// GetID returns name, id
func (u UrlCat) GetID() (string, int) {
	//If this is a custom category the name is configured name.
	//Predefined categories have the name on ID
	if u.CustomCategory {
		return u.ConfiguredName, u.Val
	} else {
		return u.ID, u.Val
	}
}

// FwRule parses firewall rules
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

// Delete deletes an object
func (u FwRule) Delete(c *Client) error {
	return c.DeleteFwRule(u.ID)
}

// String prints the struct in json pretty format
func (p FwRule) String() string {
	return jsonString(p)
}

// IPDstGroup parses responses for IP destination groups
type IPDstGroup struct {
	ID           int      `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"` //Available values : DSTN_IP, DSTN_FQDN, DSTN_DOMAIN, DSTN_OTHER
	Addresses    []string `json:"addresses,omitempty"`
	Description  string   `json:"description,omitempty"`
	IPCategories []string `json:"ipCategories,omitempty"`
	Countries    []string `json:"countries,omitempty"`
}

// Delete deletes an object
func (u IPDstGroup) Delete(c *Client) error {
	return c.DeleteIPDstGroups(u.ID)
}

// String prints the struct in json pretty format
func (p IPDstGroup) String() string {
	return jsonString(p)
}

// IPSrcGroup parses responses for IP source groups
type IPSrcGroup struct {
	ID          int      `json:"id"`
	Name        string   `json:"name"`
	IPAddresses []string `json:"ipAddresses"`
	Description string   `json:"description,omitempty"`
}

// Delete deletes an object
func (u IPSrcGroup) Delete(c *Client) error {
	return c.DeleteIPSrcGroups(u.ID)
}

// String prints the struct in json pretty format
func (p IPSrcGroup) String() string {
	return jsonString(p)
}

// StartEnd json helper for ranges
type StartEnd struct {
	Start *int `json:"start"`
	End   *int `json:"end"`
}

// Service parses responses for network services
type Service struct {
	ID            int        `json:"id"`
	Name          string     `json:"name"`
	Tag           string     `json:"tag,omitempty"`
	SrcTCPPorts   []StartEnd `json:"srcTcpPorts,omitempty"`
	DestTCPPorts  []StartEnd `json:"destTcpPorts,omitempty"`
	SrcUDPPorts   []StartEnd `json:"srcUdpPorts,omitempty"`
	DestUDPPorts  []StartEnd `json:"destUdpPorts,omitempty"`
	Type          string     `json:"type,omitempty"` //Types are CUSTOM, STANDARD AND PREDEFINED. The last 2 are default ones, STANDARD seems to be used for non-port based services
	Description   string     `json:"description,omitempty"`
	IsNameL10NTag bool       `json:"isNameL10nTag,omitempty"`
}
type Application struct {
	ID             int    `json:"id"`
	ParentCategory string `json:"parentCategory"`
	Description    string `json:"description,omitempty"`
	Deprecated     bool   `json:"deprecated,omitempty"`
}

// GetID return the name a string and the ID as int
func (u Service) GetID() (string, int) {
	return u.Name, u.ID
}

// Delete deletes an object
func (u Service) Delete(c *Client) error {
	return c.DeleteService(u.ID)
}

// String prints the struct in json pretty format
func (p Service) String() string {
	return jsonString(p)
}

// ServiceGroup parses responses for network servicesgroups
type ServiceGroup struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Services    []Service `json:"services"`
	Description string    `json:"description,omitempty"`
}

// GetID return the name a string and the ID as int
func (u ServiceGroup) GetID() (string, int) {
	return u.Name, u.ID
}

// Delete deletes an object
func (u ServiceGroup) Delete(c *Client) error {
	return c.DeleteServiceGroup(u.ID)
}

// String prints the struct in json pretty format
func (p ServiceGroup) String() string {
	return jsonString(p)
}

//VpnLocation helper to hold vpn credential on a location

type VpnLocation struct {
	Type         string `json:"type"`
	Fqdn         string `json:"fqdn"`
	PreSharedKey string `json:"preSharedKey"`
	Comments     string `json:"comments"`
}

// String prints the struct in json pretty format
func (p VpnLocation) String() string {
	return jsonString(p)
}

// UserFilter filter user searches
// The name search parameter performs a partial match. The dept and group parameters perform a 'starts with' match.
type UserFilter struct {
	Name  string
	Dept  string
	Group string
}

// Location parses locations
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

// GetID return the name a string and the ID as int
func (u Location) GetID() (string, int) {
	return u.Name, u.ID
}

// String prints the struct in json pretty format
func (p Location) String() string {
	return jsonString(p)
}

// LocationGroup parses location groups
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

// GetID return the name a string and the ID as int
func (u LocationGroup) GetID() (string, int) {
	return u.Name, u.ID
}

// String prints the struct in json pretty format
func (p LocationGroup) String() string {
	return jsonString(p)
}

// Department parses user departments
type Department struct {
	ID       int    `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	IdpID    int    `json:"idpId,omitempty"`
	Comments string `json:"comments,omitempty"`
	Deleted  bool   `json:"deleted,omitempty"`
}

// GetID return the name a string and the ID as int
func (u Department) GetID() (string, int) {
	return u.Name, u.ID
}

// String prints the struct in json pretty format
func (p Department) String() string {
	return jsonString(p)
}

// UserGroup parses UserGroup
type UserGroup struct {
	ID       int    `json:"id,omitempty"`
	Name     string `json:"name"`
	IdpID    int    `json:"idpId,omitempty"`
	Comments string `json:"comments,omitempty"`
}

// GetID return the name a string and the ID as int
func (u UserGroup) GetID() (string, int) {
	return u.Name, u.ID
}

// String prints the struct in json pretty format
func (p UserGroup) String() string {
	return jsonString(p)
}

// delUsers struct used to delte users.
type delUsers struct {
	Ids []int `json:"ids"`
}

// Append the element
func (u *delUsers) Append(e []int) {
	u.Ids = append(u.Ids, e...)
}

// Get returns the elements
func (u *delUsers) Get() []int {
	return u.Ids
}

// User parses Users
type User struct {
	ID            int         `json:"id,omitempty"`
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

// GetID return the name a string and the ID as int
func (u User) GetID() (string, int) {
	return u.Name, u.ID
}

// String prints the struct in json pretty format
func (p User) String() string {
	return jsonString(p)
}

// Delete deletes an object
func (u User) Delete(c *Client) error {
	return c.DeleteUser(u.ID)
}

// BlockedUrls parses responses for blocked urls
type BlockedUrls struct {
	Urls []string `json:"blacklistUrls"`
}

// String prints the struct in json pretty format
func (p BlockedUrls) String() string {
	return jsonString(p)
}

// AllowedUrls parses responses for Allowed urls
type AllowedUrls struct {
	Urls []string `json:"whitelistUrls"`
}

// String prints the struct in json pretty format
func (p AllowedUrls) String() string {
	return jsonString(p)
}

// UrlLookup parses responses for received url categories
type UrlLookup struct {
	URL         string   `json:"url"`
	URLCat      []string `json:"urlClassifications"`
	URLCatSec   []string `json:"urlClassificationsWithSecurityAlert"`
	Error       string   `json:"error,omitempty"`
	Application string   `json:"application"`
}

// String prints the struct in json pretty format
func (p UrlLookup) String() string {
	return jsonString(p)
}

// DLPDictionary holds the DLP dictionaries from ZIA
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

// GetID return the name a string and the ID as int
func (u DLPDictionary) GetID() (string, int) {
	return u.Name, u.ID
}

// Delete deletes an object
func (u DLPDictionary) Delete(c *Client) error {
	return c.DeleteDLPDictionary(u.ID)
}

// String prints the struct in json pretty format
func (p DLPDictionary) String() string {
	return jsonString(p)
}

// Phrase holds DLP dictionary phrases
type Phrase struct {
	Action string `json:"action,omitempty"`
	Phrase string `json:"phrase,omitempty"`
}

// Pattern holds DLP dictionary Patterns
type Pattern struct {
	Action  string `json:"action,omitempty"`
	Pattern string `json:"pattern,omitempty"`
}

// EDMDetails holds EDM details from DLP dictionary
type EDMDetails struct {
	DictionaryEdmMappingID int    `json:"dictionaryEdmMappingId,omitempty"`
	SchemaID               int    `json:"schemaId,omitempty"`
	PrimaryField           int    `json:"primaryField,omitempty"`
	SecondaryFields        []int  `json:"secondaryFields,omitempty"`
	SecondaryFieldMatchOn  string `json:"secondaryFieldMatchOn,omitempty"`
}

// IDMProfile holds IDM details from DLP dictionary
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

// DLPEngine hols dlp engine details
type DLPEngine struct {
	ID                   int    `json:"id,omitempty"`
	Name                 string `json:"name,omitempty"`
	PredefinedEngineName string `json:"predefinedEngineName,omitempty"`
	EngineExpression     string `json:"engineExpression,omitempty"`
	CustomDlpEngine      bool   `json:"customDlpEngine,omitempty"`
	Description          string `json:"description,omitempty"`
}

// GetID return the name a string and the ID as int
func (u DLPEngine) GetID() (string, int) {
	if !u.CustomDlpEngine {
		return u.PredefinedEngineName, u.ID
	} else {
		return u.Name, u.ID
	}
}

// Delete deletes an object
func (u DLPEngine) Delete(c *Client) error {
	return c.DeleteDLPEngine(u.ID)
}

// GetDictionaries returns dictionary Uuids used on an engine
func (u DLPEngine) GetDictionaries() []int {
	var m = make(map[int]bool)
	var a = []int{}
	//Getting engine IDS
	re := regexp.MustCompile(`D[0-9]+\.S`)
	entries := re.FindAllString(u.EngineExpression, -1)
	for _, entry := range entries {
		val := entry[1 : len(entry)-2]
		i, _ := strconv.Atoi(val) // Excluding error, this should be mostly safe since ids should always be a number
		_, ok := m[i]
		if !ok { //if value doesn't exist add it
			m[i] = true
			a = append(a, i)
		}
	}
	return a
}

// String prints the struct in json pretty format
func (p DLPEngine) String() string {
	return jsonString(p)
}

// Sandbox response
type Sandbox struct {
	Code              int    `json:"code"`
	Message           string `json:"message"`
	FileType          string `json:"fileType"`
	Md5               string `json:"md5"`
	SandboxSubmission string `json:"sandboxSubmission"`
	VirusName         string `json:"virusName"`
	VirusType         string `json:"virusType"`
}

// String prints the struct in json pretty format
func (p Sandbox) String() string {
	return jsonString(p)
}

type SandboxRule struct {
	ID                 int         `json:"id,omitempty"`
	Name               string      `json:"name"`
	Protocols          []string    `json:"protocols,omitempty"`
	Order              int         `json:"order,omitempty"`
	BaPolicyCategories []string    `json:"baPolicyCategories,omitempty"`
	Description        string      `json:"description,omitempty"`
	Locations          []NameID    `json:"locations,omitempty"`
	LocationGroups     []NameID    `json:"locationGroups,omitempty"`
	Groups             []NameID    `json:"groups,omitempty"`
	Departments        []NameID    `json:"departments,omitempty"`
	Users              []NameID    `json:"users,omitempty"`
	URLCategories      []string    `json:"urlCategories,omitempty"`
	FileTypes          []string    `json:"fileTypes,omitempty"`
	CbiProfile         *CbiProfile `json:"cbiProfile,omitempty"`
	CbiProfileID       *int        `json:"cbiProfileId,omitempty"`
	State              string      `json:"state,omitempty"`
	TimeWindows        []NameID    `json:"timeWindows,omitempty"`
	Rank               int         `json:"rank"`
	LastModifiedTime   *int        `json:"lastModifiedTime,omitempty"`
	LastModifiedBy     *NameID     `json:"lastModifiedBy,omitempty"`
	AccessControl      string      `json:"accessControl,omitempty"`
	BaRuleAction       string      `json:"baRuleAction"`
	FirstTimeEnable    bool        `json:"firstTimeEnable,omitempty"`
	FirstTimeOperation string      `json:"firstTimeOperation"`
	MlActionEnabled    bool        `json:"mlActionEnabled"`
	Labels             []NameID    `json:"labels,omitempty"`
	Devices            []NameID    `json:"devices,omitempty"`
	DeviceGroups       []NameID    `json:"deviceGroups,omitempty"`
	ZpaAppSegments     []NameID    `json:"zpaAppSegments,omitempty"`
	ByThreatScore      int         `json:"byThreatScore,omitempty"`
	DefaultRule        bool        `json:"defaultRule,omitempty"`
}

// String prints the struct in json pretty format
func (p SandboxRule) String() string {
	return jsonString(p)
}

// DLPNotificationTemplate hols dlp notification template details
type DLPNotificationTemplate struct {
	ID               int    `json:"id,omitempty"`
	Name             string `json:"name,omitempty"`
	Subject          string `json:"subject,omitempty"`
	AttachContent    bool   `json:"attachContent,omitempty"`
	PlainTextMessage string `json:"plainTextMessage,omitempty"`
	HTMLMessage      string `json:"htmlMessage,omitempty"`
}

// GetID return the name a string and the ID as int
func (u DLPNotificationTemplate) GetID() (string, int) {
	return u.Name, u.ID
}

// String prints the struct in json pretty format
func (p DLPNotificationTemplate) String() string {
	return jsonString(p)
}

// ICAPServer holds an icap server detail
type ICAPServer struct {
	ID     int    `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	URL    string `json:"url,omitempty"`
	Status string `json:"status,omitempty"`
}

// GetID return the name a string and the ID as int
func (u ICAPServer) GetID() (string, int) {
	return u.Name, u.ID
}

// String prints the struct in json pretty format
func (p ICAPServer) String() string {
	return jsonString(p)
}

// GetID return the name a string and the ID as string
func (u CbiProfile) GetUUIDs() (string, string) {
	return u.Name, u.ID
}

// DLPRule holds a DLP rule information
type DLPRule struct {
	ID                       int       `json:"id,omitempty"`
	Order                    int       `json:"order,omitempty"`
	Protocols                []string  `json:"protocols,omitempty"`
	Rank                     int       `json:"rank,omitempty"`
	Description              string    `json:"description,omitempty"`
	Locations                []NameID  `json:"locations,omitempty"`
	LocationGroups           []NameID  `json:"locationGroups,omitempty"`
	Groups                   []NameID  `json:"groups,omitempty"`
	Departments              []NameID  `json:"departments,omitempty"`
	Users                    []NameID  `json:"users,omitempty"`
	URLCategories            []NameID  `json:"urlCategories,omitempty"`
	DlpEngines               []NameID  `json:"dlpEngines,omitempty"`
	FileTypes                []string  `json:"fileTypes,omitempty"`
	CloudApplications        []string  `json:"cloudApplications,omitempty"`
	MinSize                  int       `json:"minSize,omitempty"`
	Action                   string    `json:"action,omitempty"`
	State                    string    `json:"state,omitempty"`
	TimeWindows              []NameID  `json:"timeWindows,omitempty"`
	Auditor                  *NameID   `json:"auditor,omitempty"`
	ExternalAuditorEmail     string    `json:"externalAuditorEmail,omitempty"`
	NotificationTemplate     *NameID   `json:"notificationTemplate,omitempty"`
	MatchOnly                bool      `json:"matchOnly,omitempty"`
	LastModifiedTime         int       `json:"lastModifiedTime,omitempty"`
	LastModifiedBy           *NameID   `json:"lastModifiedBy,omitempty"`
	IcapServer               *NameID   `json:"icapServer,omitempty"`
	WithoutContentInspection bool      `json:"withoutContentInspection"`
	Name                     string    `json:"name,omitempty"`
	Labels                   []NameID  `json:"labels,omitempty"`
	OcrEnabled               bool      `json:"ocrEnabled,omitempty"`
	ExcludedGroups           []NameID  `json:"excludedGroups,omitempty"`
	ExcludedDepartments      []NameID  `json:"excludedDepartments,omitempty"`
	ExcludedUsers            []NameID  `json:"excludedUsers,omitempty"`
	ZscalerIncidentReciever  bool      `json:"zscalerIncidentReciever,omitempty"`
	Severity                 string    `json:"severity,omitempty"`
	SubRules                 []DLPRule `json:"subRules,omitempty"`
	ParentRule               int       `json:"parentRule,omitempty"`
}

// Delete deletes an object
func (u DLPRule) Delete(c *Client) error {
	return c.DeleteDLPRule(u.ID)
}

// String prints the struct in json pretty format
func (p DLPRule) String() string {
	return jsonString(p)
}

type FileTypeRule struct {
	ID                int      `json:"id,omitempty"`
	Protocols         []string `json:"protocols"`
	Order             int      `json:"order,omitempty"`
	TimeQuota         *int     `json:"timeQuota,omitempty"`
	SizeQuota         *int     `json:"sizeQuota,omitempty"`
	Description       string   `json:"description,omitempty"`
	Locations         []NameID `json:"locations,omitempty"`
	LocationGroups    []NameID `json:"locationGroups,omitempty"`
	Groups            []NameID `json:"groups,omitempty"`
	Departments       []NameID `json:"departments,omitempty"`
	Users             []NameID `json:"users,omitempty"`
	URLCategories     []string `json:"urlCategories,omitempty"`
	FileTypes         []string `json:"fileTypes,omitempty"`
	Devices           []NameID `json:"devices,omitempty"`
	DeviceGroups      []NameID `json:"deviceGroups,omitempty"`
	DeviceTrustLevels []string `json:"deviceTrustLevels,omitempty"`
	MinSize           *int     `json:"minSize,omitempty"`
	MaxSize           *int     `json:"maxSize,omitempty"`
	FilteringAction   string   `json:"filteringAction"`
	CapturePCAP       *bool    `json:"capturePCAP,omitempty"`
	Operation         string   `json:"operation,omitempty"`
	ActiveContent     *bool    `json:"activeContent,omitempty"`
	Unscannable       *bool    `json:"unscannable,omitempty"`
	State             string   `json:"state,omitempty"`
	TimeWindows       []NameID `json:"timeWindows,omitempty"`
	Rank              int      `json:"rank"`
	LastModifiedTime  *int     `json:"lastModifiedTime,omitempty"`
	LastModifiedBy    *NameID  `json:"lastModifiedBy,omitempty"`
	AccessControl     string   `json:"accessControl,omitempty"`
	Name              string   `json:"name,omitempty"`
	Labels            []NameID `json:"labels,omitempty"`
	ZpaAppSegments    []NameID `json:"zpaAppSegments,omitempty"`
	CloudApplications []string `json:"cloudApplications,omitempty"`
}

// String prints the struct in json pretty format
func (p FileTypeRule) String() string {
	return jsonString(p)
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

// GetID returns the name as string and the ID as int
func (u Label) GetID() (string, int) {
	return u.Name, u.ID
}

// Delete deletes an object
func (u Label) Delete(c *Client) error {
	return c.DeleteLabel(u.ID)
}

// String prints the struct in json pretty format
func (p Label) String() string {
	return jsonString(p)
}

// Zurl is an interface that allows you to interact with 3 different types of url objects: allowlist, blocklist and url objects.
type Zurl interface {
	GetUrls(string) []string
	SetUrls(string, []string)
	PushItems(client *Client) error
	GetName() string
}

// Zid is the interface for types that can return ID, so most of them
type Zid interface {
	GetID() (string, int)
}

// ZSid is the interface for types that can return ID as string
type ZSid interface {
	GetID() (string, string)
}

// ZDelete interfaces for objects with delete function
type ZDelete interface {
	Delete(*Client) error
}

// GetUrls  returns all the urls in a blocklist
func (c *BlockedUrls) GetUrls(f string) []string {
	return c.Urls
}

// GetUrls all the urls in an allowlist
func (c *AllowedUrls) GetUrls(f string) []string {
	return c.Urls
}

// GetUrls gets all the urls in an allowlist
func (c *UrlCat) GetUrls(f string) []string {
	if f == "urlsRetainingParentCategory" {
		return c.DbCategorizedUrls
	}
	//default is return urls
	return c.Urls
}

// SetUrls  sets all the urls in a blocklist
func (c *BlockedUrls) SetUrls(f string, u []string) {
	c.Urls = u
}

// SetUrls sets all the urls in a allowlist
func (c *AllowedUrls) SetUrls(f string, u []string) {
	c.Urls = u
}

// SetUrls sets all the urls in a allowlist
func (c *UrlCat) SetUrls(f string, u []string) {
	if f == "urls" {
		c.Urls = u
	} else if f == "urlsRetainingParentCategory" {
		c.DbCategorizedUrls = u
	}
}

// GetName   returns all the urls in a blocklist
func (c *BlockedUrls) GetName() string {
	return "Global Block List"
}

// GetName  returns all the urls in a allowlist
func (c *AllowedUrls) GetName() string {
	return "Global Allow List"
}

// GetName  returns all the urls in a UrlCat
func (c *UrlCat) GetName() string {
	return c.ConfiguredName
}

// PushItems pushes all the urls in a blocklist
func (c BlockedUrls) PushItems(client *Client) error {
	return client.RepBlockedUrls(c)
}

// PushItems pushes all the urls in a allowlist
func (c AllowedUrls) PushItems(client *Client) error {
	return client.RepAllowedUrls(c)
}

// PushItems pushes all the urls in a allowlist
func (c UrlCat) PushItems(client *Client) error {
	return client.UpdateUrlCat(c)
}

// retry parses response for an HTTP 429 response to retry after X seconds.
type retry struct {
	Message string `json:"message"`
	Retry   string `json:"Retry-After"`
}

// NewClient returns a client with the auth cookie, default http timeouts and max retries per requests
// cloud options: zscaler, zscalertwo, zscloud, etc.
// logger is set to info unless an env variable  SLOG is set to DEBUG and st.dout
func NewClient(cloud string, admin string, pass string, apiKey string) (*Client, error) {
	return NewClientLogger(cloud, admin, pass, apiKey, os.Getenv("SLOG"), os.Stdout)
}

// NewClientLogger New client logger creates a new client with a custom slog logger
func NewClientLogger(cloud, admin, pass, apiKey, level string, w io.Writer) (*Client, error) {
	BaseURL := "https://zsapi." + cloud + ".net/api/v1"
	u, err := url.Parse(BaseURL)
	if err != nil {
		return &Client{}, &ZIAError{Err: "failed to parse API URL"}
	}
	cookie, err := KeyGen(BaseURL, admin, pass, apiKey)
	if err != nil {
		return &Client{}, fmt.Errorf("module:gozscaler. error login with username: %v, error:%v", admin, err)
	}
	CookieJar, err := cookiejar.New(nil)
	if err != nil {
		return &Client{}, &ZIAError{Err: "failed to set authentication cookie"}
	}
	SanboxUrl := "https://csbapi." + cloud + ".net/zscsb/"
	CookieJar.SetCookies(u, cookie)
	opts := &slog.HandlerOptions{} //level info by default
	if level == "DEBUG" {
		opts.Level = slog.LevelDebug
	}
	parent := slog.New(slog.NewJSONHandler(w, opts))
	child := parent.With(slog.String("module", "gozscaler"),
		slog.String("client", "zia"))
	return &Client{
		BaseURL:   BaseURL,
		SanboxUrl: SanboxUrl,
		HTTPClient: &http.Client{
			Jar:     CookieJar,
			Timeout: time.Second * 200,
		},
		RetryMax: 10,
		Log:      child,
	}, nil
}

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

// NewOneApiClient creates a new client using oneapi
// vanity domain
// client
func NewOneApiClient(vanity, clientId, clientSecret string) (*Client, error) {
	return NewOneApiClientLogger(vanity, clientId, clientSecret, os.Getenv("SLOG"), os.Stdout)
}

// NewOneApiClientLogger New client logger creates a new client with a custom slog logger
// this uses client id and client secret
func NewOneApiClientLogger(vanity, clientId, clientSecret, level string, w io.Writer) (*Client, error) {
	err := validateVanity(vanity)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("module:gozscaler. error authenticating to oneapi: %v", err)
	}
	defer resp.Body.Close()
	//Check for anything but a http 200 and then parse body
	err = httpStatusCheck(resp)
	if err != nil {
		return nil, fmt.Errorf("module:gozscaler. error authenticating to oneapi: %v", err)
	}
	//Parsing response
	var token authResponse
	err = json.NewDecoder(resp.Body).Decode(&token)
	if err != nil {
		return nil, fmt.Errorf("module:gozscaler. error decoding auth token, error:%v", err)
	}
	opts := &slog.HandlerOptions{} //level info by default
	if level == "DEBUG" {
		opts.Level = slog.LevelDebug
	}
	BaseURL := "https://api.zsapi.net/zia/api/v1"
	parent := slog.New(slog.NewJSONHandler(w, opts))
	child := parent.With(slog.String("module", "gozscaler"),
		slog.String("client", "zia"))
	return &Client{
		BaseURL: BaseURL,
		HTTPClient: &http.Client{
			Timeout: time.Second * 200,
		},
		RetryMax: 10,
		Log:      child,
		Bearer:   token.AccessToken,
	}, nil
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

// UrlLookup return the url categories for requested URLs.
// up to 100 urls per request and 400 requests per hour according to zscaler limits
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

// GetUrlRules gets a list of URL filtering rules
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

// AddUrlRule adds a URL filtering rules
func (c *Client) AddUrlRule(rule UrlRule) (int, error) {
	//Seting rank to 7 if missing
	if rule.Rank == 0 {
		rule.Rank = 7
	}
	rule.ID = 0
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

// AddSandbox adds a file for sandbox analysis
func (c *Client) AddSandbox(file io.Reader, api string, force bool, ContentLength int64) (Sandbox, error) {
	v := url.Values{}
	if force {
		v.Set("force", "1")
	} else {
		v.Set("force", "0")
	}
	v.Add("api_token", api)
	path := "submit?" + v.Encode()
	if file == nil {
		return Sandbox{}, fmt.Errorf("invalid file")
	}
	return c.postRequestSandbox(path, file, ContentLength)
}

// AddSandboxQuick adds a file for sandbox quick analysis
func (c *Client) AddSandboxQuick(file io.Reader, api string, ContentLength int64) (Sandbox, error) {
	v := url.Values{}
	v.Add("api_token", api)
	path := "submit?" + v.Encode()
	if file == nil {
		return Sandbox{}, fmt.Errorf("invalid file")
	}
	return c.postRequestSandbox(path, file, ContentLength)
}

// UpdateUrlRule updates the user info using the provided user object
func (c *Client) UpdateUrlRule(rule UrlRule) error {
	path := "/urlFilteringRules/" + strconv.Itoa(rule.ID)
	postBody, _ := json.Marshal(rule)
	err := c.putRequest(path, postBody)
	return err
}

// DeleteUrlRule deletes url rule
func (c *Client) DeleteUrlRule(id int) error {
	return c.deleteRequest("/urlFilteringRules/" + strconv.Itoa(id))
}

// DeleteSslRule updates the user info using the provided user object
func (c *Client) DeleteSslRule(id int) error {
	return c.deleteRequest("/sslInspectionRules/" + strconv.Itoa(id))
}

// GetSslRules gets a list of ssl rules
func (c *Client) GetSslRules() ([]SslRule, error) {
	body, err := c.getRequest("/sslInspectionRules")
	if err != nil {
		return nil, err
	}
	res := []SslRule{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// GetSandboxRules gets a list of sandbox rules
func (c *Client) GetSandboxRules() ([]SandboxRule, error) {
	body, err := c.getRequest("/sandboxRules")
	if err != nil {
		return nil, err
	}
	res := []SandboxRule{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// AddSandboxRule adds a sandbox  rule
func (c *Client) AddSandboxRule(rule SandboxRule) (int, error) {
	postBody, _ := json.Marshal(rule)
	body, err := c.postRequest("/sandboxRules", postBody)
	if err != nil {
		return 0, err
	}
	res := SandboxRule{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, err
}

// UpdateSandboxRule updates a sandbox  rule
func (c *Client) UpdateSandboxRule(obj SandboxRule) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/sandboxRules/" + strconv.Itoa(obj.ID)
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// DeleteSandboxRule deletes sandbox rule
func (c *Client) DeleteSandboxRule(id int) error {
	return c.deleteRequest("/sandboxRules/" + strconv.Itoa(id))
}

// GetFiletypeRules gets a list of filetype rules
func (c *Client) GetFiletypeRules() ([]FileTypeRule, error) {
	body, err := c.getRequest("/fileTypeRules")
	if err != nil {
		return nil, err
	}
	res := []FileTypeRule{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// AddFileTypeRule adds a file type  rule
func (c *Client) AddFileTypeRule(rule FileTypeRule) (int, error) {
	postBody, _ := json.Marshal(rule)
	body, err := c.postRequest("/fileTypeRules", postBody)
	if err != nil {
		return 0, err
	}
	res := FileTypeRule{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, err
}

// UpdateFiletypeRule updates a file type  rule
func (c *Client) UpdateFiletypeRule(obj FileTypeRule) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/fileTypeRules/" + strconv.Itoa(obj.ID)
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// DeleteFileTypeRule deletes file type rule
func (c *Client) DeleteFileTypeRule(id int) error {
	return c.deleteRequest("/fileTypeRules/" + strconv.Itoa(id))
}

// AddSslRule adds a s filtering rules
func (c *Client) AddSslRule(rule SslRule) (int, error) {
	postBody, _ := json.Marshal(rule)
	body, err := c.postRequest("/sslInspectionRules", postBody)
	if err != nil {
		return 0, err
	}
	res := SslRule{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, err
}

// UpdateSslRule updates a ssl filtering rule
func (c *Client) UpdateSslRule(obj SslRule) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/sslInspectionRules/" + strconv.Itoa(obj.ID)
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// DeleteDnsRule deletes dns rule
func (c *Client) DeleteDnsRule(id int) error {
	return c.deleteRequest("/firewallDnsRules/" + strconv.Itoa(id))
}

// GetDnsRules gets a list of dns filtering rules
func (c *Client) GetDnsRules() ([]DnsRule, error) {
	body, err := c.getRequest("/firewallDnsRules")
	if err != nil {
		return nil, err
	}
	res := []DnsRule{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// AddDnsRule adds a dns filtering rules
func (c *Client) AddDnsRule(rule DnsRule) (int, error) {
	postBody, _ := json.Marshal(rule)
	body, err := c.postRequest("/firewallDnsRules", postBody)
	if err != nil {
		return 0, err
	}
	res := DnsRule{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, err
}

// UpdateDnsRule updates a dns filtering rule
func (c *Client) UpdateDnsRule(obj DnsRule) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/firewallDnsRules/" + strconv.Itoa(obj.ID)
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// GetFwRules gets a list of firewall filtering rules
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

// GetMalwareInspection gets malware inspection setting
func (c *Client) GetMalwareInspection() (MalwareInspection, error) {
	res := MalwareInspection{}
	body, err := c.getRequest("/cyberThreatProtection/atpMalwareInspection")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	return res, err
}

// GetSubscriptions gets tenant subscriptions
func (c *Client) GetSubscriptions() ([]Subscriptions, error) {
	res := []Subscriptions{}
	body, err := c.getRequest("/subscriptions")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	return res, err
}

// UpdateMalwareInspection updates  malware inspection setting
func (c *Client) UpdateMalwareInspection(obj MalwareInspection) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/cyberThreatProtection/atpMalwareInspection"
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// GetAdvThreatProtection gets threat inspection setting
func (c *Client) GetAdvThreatProtection() (AdvThreatSettings, error) {
	res := AdvThreatSettings{}
	body, err := c.getRequest("/cyberThreatProtection/advancedThreatSettings")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	return res, err
}

// UpdateAdvThreatProtection updates  adv setting
func (c *Client) UpdateAdvThreatProtection(obj AdvThreatSettings) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/cyberThreatProtection/advancedThreatSettings"
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// GetMalwareProtocols gets malware protocols
func (c *Client) GetMalwareProtocols() (MalwareProtocols, error) {
	res := MalwareProtocols{}
	body, err := c.getRequest("/cyberThreatProtection/atpMalwareProtocols")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	return res, err
}

// UpdateMalwareProtocols updates  malware protocols
func (c *Client) UpdateMalwareProtocols(obj MalwareProtocols) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/cyberThreatProtection/atpMalwareProtocols"
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// GetUrlAndCloudSettings gets  url settings
func (c *Client) GetUrlAndCloudSettings() (UrlAndCloudSettings, error) {
	res := UrlAndCloudSettings{}
	body, err := c.getRequest("/advancedUrlFilterAndCloudAppSettings")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	return res, err
}

// UpdateUrlAndCloudSettings updates  url settings
func (c *Client) UpdateUrlAndCloudSettings(obj UrlAndCloudSettings) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/advancedUrlFilterAndCloudAppSettings"
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// GetCloudAdvSettings gets  url settings
func (c *Client) GetCloudAdvSettings() (AdvSettings, error) {
	res := AdvSettings{}
	body, err := c.getRequest("/advancedSettings")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	return res, err
}

// UpdateCloudAdvSettings updates  cloud adv settings
func (c *Client) UpdateCloudAdvSettings(obj AdvSettings) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/advancedSettings"
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// GetMalwareSettings gets malware inspection setting
func (c *Client) GetMalwareSettings() (MalwareSettings, error) {
	res := MalwareSettings{}
	body, err := c.getRequest("/cyberThreatProtection/malwareSettings")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	return res, err
}

// UpdateMalwareSettings updates  malware inspection setting
func (c *Client) UpdateMalwareSettings(obj MalwareSettings) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/cyberThreatProtection/malwareSettings"
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// GetMalwarePolicy gets malware policy
func (c *Client) GetMalwarePolicy() (MalwarePolicy, error) {
	res := MalwarePolicy{}
	body, err := c.getRequest("/cyberThreatProtection/malwarePolicy")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	return res, err
}

// UpdateMalwarePolicy updates  malware policy
func (c *Client) UpdateMalwarePolicy(obj MalwarePolicy) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/cyberThreatProtection/malwarePolicy"
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// AddFwRule adds a firewall filtering rules
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

// UpdateFwRule updates a firewall filtering rule
func (c *Client) UpdateFwRule(obj FwRule) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/firewallFilteringRules/" + strconv.Itoa(obj.ID)
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// DeleteFwRule deletes a firewall filtering rule
func (c *Client) DeleteFwRule(id int) error {
	return c.deleteRequest("/firewallFilteringRules/" + strconv.Itoa(id))
}

// GetIPDstGroups gets a list of firewall filtering rules
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

// DeleteIPDstGroups deletes ipDestinationGroups
func (c *Client) DeleteIPDstGroups(id int) error {
	return c.deleteRequest("/ipDestinationGroups/" + strconv.Itoa(id))
}

// AddIPDstGroup adds an ip destination group
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

// GetAppGroups gets a list of network application groups
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

// GetIPSrcGroups gets a list of firewall filtering rules
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

// DeleteIPSrcGroups deletes ipSourceGroups
func (c *Client) DeleteIPSrcGroups(id int) error {
	return c.deleteRequest("/ipSourceGroups/" + strconv.Itoa(id))
}

// AddIPSrcGroup adds a firewall filtering rules
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

// GetServiceGroups gets a list of network service groups
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

// AddServiceGroup adds a  network service group
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

// DeleteServiceGroup deletes networkServiceGroups
func (c *Client) DeleteServiceGroup(id int) error {
	return c.deleteRequest("/networkServiceGroups/" + strconv.Itoa(id))
}

// GetServices gets a list of network service groups
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

func (c *Client) GetApplications() ([]Application, error) {
	body, err := c.getRequest("/networkApplications")
	if err != nil {
		return nil, err
	}
	res := []Application{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// DeleteService deletes networkServices
func (c *Client) DeleteService(id int) error {
	return c.deleteRequest("/networkServices/" + strconv.Itoa(id))
}

// GetAuditors gets a list of auditors
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

// AddService adds a  network service and returns the new service ID
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

// GetLocations gets all locations
func (c *Client) GetLocations() ([]Location, error) {
	return getPaged[Location](c, 1000, "/locations")
}

// GetLabels gets all labels
func (c *Client) GetLabels() ([]Label, error) {
	return getPaged[Label](c, 1000, "/ruleLabels")
}

// AddLabel adds a  network service and returns the new service ID
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

// DeleteLabel deletes ruleLabels
func (c *Client) DeleteLabel(id int) error {
	return c.deleteRequest("/ruleLabels/" + strconv.Itoa(id))
}

// GetLocationGroups gets all location groups
func (c *Client) GetLocationGroups() ([]LocationGroup, error) {
	return getPaged[LocationGroup](c, 1000, "/locations/groups")
}

// GetDeparments gets all departments
func (c *Client) GetDeparments() ([]Department, error) {
	return getPaged[Department](c, 1000, "/departments")
}

// GetGroups gets all user groups
func (c *Client) GetGroups() ([]UserGroup, error) {
	return getPaged[UserGroup](c, 1000, "/groups")
}

// GetUsers return all the ZIA users
func (c *Client) GetUsers() ([]User, error) {
	return getPaged[User](c, 1000, "/users")
}

// GetUsersFilter return all the ZIA users matching the filter
func (c *Client) GetUsersFilter(filter UserFilter) ([]User, error) {
	queries := url.Values{}
	if filter.Dept != "" {
		queries.Set("dept", filter.Dept)
	}
	if filter.Group != "" {
		queries.Set("group", filter.Group)
	}
	if filter.Name != "" {
		queries.Set("name", filter.Name)
	}
	return getPagedQuery[User](c, 1000, "/users", queries)
}

// GetUser return the ZIA user
func (c *Client) GetUser(id int) (User, error) {
	body, err := c.getRequest("/users/" + strconv.Itoa(id))
	res := User{}
	if err != nil {
		return res, err
	}

	err = json.Unmarshal(body, &res)
	if err != nil {
		return res, err
	}
	return res, nil
}

// DeleteUser deletes a user
func (c *Client) DeleteUser(id int) error {
	return c.deleteRequest("/users/" + strconv.Itoa(id))
}

// DeleteUsers deletes users in bulk
// return deleted users as []int, and err for http errors
func (c *Client) DeleteUsers(uIds []int) ([]int, error) {
	res := delUsers{}
	//Transforming into chunks of 500 (max per bulkd delete)
	chunks := chunkBy(uIds, 500)
	for _, chk := range chunks {
		r := delUsers{Ids: chk}
		postBody, _ := json.Marshal(r)
		body, err := c.postRequest("/users/bulkDelete", postBody)
		if err != nil {
			return res.Get(), err
		}
		tmp := delUsers{}
		err = json.Unmarshal(body, &tmp)
		if err != nil {
			return res.Get(), err
		}
		//append
		res.Append(tmp.Ids)
	}
	return res.Get(), nil
}

// GetUsersPaged allows you to request between 100 and 1000 items
func (c *Client) GetUsersPaged(page int, pageSize int) ([]User, error) {
	//Validating pagezise
	if pageSize < 100 || pageSize > 1000 {
		return nil, &ZIAError{Err: "Page size must be a number between 100 or 1000"}
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

// AddUser adds a new user and returns the new object ID
func (c *Client) AddUser(user User) (int, error) {
	res := User{}
	postBody, _ := json.Marshal(user)
	body, err := c.postRequest("/users", postBody)
	if err != nil {
		return 0, err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, nil
}

// UpdateUser updates the user info using the provided user object
func (c *Client) UpdateUser(user User) error {
	path := "/users/" + strconv.Itoa(user.ID)
	postBody, _ := json.Marshal(user)
	err := c.putRequest(path, postBody)
	return err
}

// GetSublocations gets a list of sublocations from the received location id
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

// AddLocation adds a new location or sublocation and returns the new object ID
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

// UpdateLocation Edit updates a new location or sublocation and returns the new object ID
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

// GetUrlCats gets a list of all URL filtering category
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

func (c *Client) GetTldCats() ([]UrlCat, error) {
	res := []UrlCat{}
	body, err := c.getRequest("/urlCategories?type=TLD_CATEGORY")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return res, err
	}
	return res, nil
}

// GetDLPDictionaries get all the DLP dictionaries
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

// AddDLPDictionary adds a DLP dictionary and returns the id if created or error
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

// UpdateDLPDictionary updates a dlp dictionary
func (c *Client) UpdateDLPDictionary(obj DLPDictionary) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/dlpDictionaries/" + strconv.Itoa(obj.ID)
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// DeleteDLPDictionary deletes a DLP dictionary
func (c *Client) DeleteDLPDictionary(id int) error {
	return c.deleteRequest("/dlpDictionaries/" + strconv.Itoa(id))
}

// Activate activates all changes
func (c *Client) Activate() error {
	_, err := c.postRequest("/status/activate", nil)
	if err != nil {
		return err
	}
	return nil
}

// GetDLPEngines get all the DLP engines
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

// AddDLPEngine adds a DLP engine and returns the id if created or error
// An additional provisioning ticket needs to be requested for this to work
func (c *Client) AddDLPEngine(obj DLPEngine) (int, error) {
	res := DLPEngine{}
	postBody, _ := json.Marshal(obj)
	body, err := c.postRequest("/dlpEngines", postBody)
	if err != nil {
		return 0, err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return 0, err
	}
	return res.ID, nil
}

// UpdateDLPEngine updates a dlp engine
// An additional provisioning ticket needs to be requested for this to work
func (c *Client) UpdateDLPEngine(obj DLPEngine) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/dlpEngines/" + strconv.Itoa(obj.ID)
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// DeleteDLPEngine deletes dlpEngines
func (c *Client) DeleteDLPEngine(id int) error {
	return c.deleteRequest("/dlpEngines/" + strconv.Itoa(id))
}

// GetDLPNotificationTemplates get all the DLP notification templates
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

// AddDLPNotificationTemplate adds a DLP notification template
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

// DeleteDLPNotificationTemplate deletes dlpNotificationTemplates
func (c *Client) DeleteDLPNotificationTemplate(id int) error {
	return c.deleteRequest("/dlpNotificationTemplates/" + strconv.Itoa(id))
}

// GetICAPServers get all the icap servers
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

// GetDLPRules get all the DLP rules
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

// AddDLPRule adds a URL filtering category
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

// UpdateDLPRule  updates a dlp rule
func (c *Client) UpdateDLPRule(obj DLPRule) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/webDlpRules/" + strconv.Itoa(obj.ID)
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// DeleteDLPRule deleteds the dlp rules
func (c *Client) DeleteDLPRule(id int) error {
	return c.deleteRequest("/webDlpRules/" + strconv.Itoa(id))
}

// AddUrlCat adds a URL filtering category
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

// UpdateUrlCat updates a URL filtering category
func (c *Client) UpdateUrlCat(category UrlCat) error {
	//Validating at least 1 urls is in the entries
	if category.Urls == nil {
		return &ZIAError{Err: "You can't delete all urls, at least 1 url should be sent on url category:" + category.ConfiguredName}
	}
	if category.CustomCategory || strings.HasPrefix(category.ID, "CUSTOM_") {
		category.SuperCategory = "USER_DEFINED"
	}
	path := "/urlCategories/" + category.ID
	postBody, _ := json.Marshal(category)
	err := c.putRequest(path, postBody)
	return err
}

// DeleteUrlCat deleteds the UrlCat
func (c *Client) DeleteUrlCat(id string) error {
	return c.deleteRequest("/urlCategories/" + id)
}

// GetBlockedUrls gets a list of blocked URLs in Advanced Threat policy
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

// RepBlockedUrls replaces current existing blocked list
func (c *Client) RepBlockedUrls(urls BlockedUrls) error {
	postBody, err := json.Marshal(urls)
	if err != nil {
		return err
	}
	return c.putRequest("/security/advanced", postBody)
}

// GetAllowedUrls gets a list of blocked URLs in Advanced Threat policy
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

// RepAllowedUrls replaces current existing allowed list
func (c *Client) RepAllowedUrls(urls AllowedUrls) error {
	postBody, err := json.Marshal(urls)
	if err != nil {
		return err
	}
	return c.putRequest("/security", postBody)
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
			re, ok := err.(*ZIAError)
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

// GetIDs is a generic function that receives an arrray object and return a map with the name as key and ID as value
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

// GetSIDs is a generic function that receives an arrray object and return a map with the name as key and ID as value
func GetSIDs[K ZSid](obj []K) map[string]string {
	//Creating map
	m := make(map[string]string)
	//Iterating
	for _, v := range obj {
		name, id := v.GetID()
		m[name] = id
	}
	return m
}

// postRequest Process and sends HTTP POST requests
func (c *Client) postRequest(path string, payload []byte) ([]byte, error) {
	data := bytes.NewBuffer(payload)
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, data)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

// postRequestSandbox Process and sends HTTP POST requests
func (c *Client) postRequestSandbox(path string, data io.Reader, ContentLength int64) (Sandbox, error) {
	if c.SanboxUrl == "" {
		return Sandbox{}, fmt.Errorf("sandbox url is empty, please make sure you use legacy api")
	}
	buf := make([]byte, 512) // Read first 512 bytes
	_, err := io.ReadAtLeast(data, buf, 512)
	if err != nil {
		return Sandbox{}, fmt.Errorf("couldn't file detect content type: %v", err)
	}
	contentType := http.DetectContentType(buf)
	//buf := bufio.NewReader(data)
	//sniff, _ := buf.Peek(512)
	//contentType := http.DetectContentType(sniff)
	r, err := http.NewRequest("POST", c.SanboxUrl+path, io.MultiReader(bytes.NewReader(buf), data))
	//r, err := http.NewRequest("POST", c.SanboxUrl+path, data)
	if err != nil {
		return Sandbox{}, err
	}
	r.Header.Add("Content-Type", contentType) //"application/pdf"
	r.ContentLength = ContentLength
	//r.Header.Add("Content-Length", "16047202")
	resp, err := c.HTTPClient.Do(r)
	if err != nil {
		return Sandbox{}, err
	}
	defer resp.Body.Close()
	// Catch all when there's no more retries left
	err = httpStatusCheck(resp)
	if err != nil {
		return Sandbox{}, err
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return Sandbox{}, err
	}
	res := Sandbox{}
	err = json.Unmarshal(b, &res)
	if err != nil {
		return Sandbox{}, err
	}
	return res, nil
}

// getRequest Process and sends HTTP GET requests
func (c *Client) getRequest(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

// Process and sends HTTP PUT requests
func (c *Client) putRequest(path string, payload []byte) error {
	data := bytes.NewBuffer(payload)
	req, err := http.NewRequest(http.MethodPut, c.BaseURL+path, data)
	if err != nil {
		return err
	}
	_, err = c.do(req)
	return err
}

// do Function de send the HTTP request and return the response and error
func (c *Client) do(req *http.Request) ([]byte, error) {
	retryMax := c.RetryMax
	//Adding auth header for onelogin
	if c.Bearer != "" {
		req.Header.Add("Authorization", "Bearer "+c.Bearer)
	}
	r, err := c.doWithOptions(req, retryMax)
	if err != nil {
		c.Log.Info("HTTP failed with error ",
			slog.String("url", req.URL.String()),
			slog.String("error", fmt.Sprint(err)),
			slog.String("method", req.Method))
	}
	c.Log.Info("HTTP request completed",
		slog.String("url", req.URL.String()),
		slog.String("method", req.Method))
	c.Log.Debug("HTTP request completed",
		slog.String("url", req.URL.String()),
		slog.String("response body", string(r)),
		slog.String("method", req.Method))
	return r, err
}

// doWithOptions Wrapper that receives options and sends an http request
func (c *Client) doWithOptions(req *http.Request, retryMax int) ([]byte, error) {
	//Extracting body payload
	req, payload := getReqBody(req)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	c.Log.Info("sending HTTP request",
		slog.String("url", req.URL.String()),
		slog.String("method", req.Method))
	c.Log.Debug("sending HTTP request",
		slog.String("url", req.URL.String()),
		slog.String("body", string(payload)), // logging payload and cookies
		slog.String("method", req.Method))
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
			c.Log.Info(fmt.Sprintf("received HTTP 429 waiting for %v seconds", t),
				slog.String("url", req.URL.String()),
				slog.String("method", req.Method),
				slog.String("retries left", fmt.Sprint(retryMax)),
			)
			//Wait for x seconds minus TLs setup time -average 150ms-
			s := (time.Duration(t) * time.Second) - (150 * time.Millisecond)
			time.Sleep(s)
			retryMax -= 1
			// reset Request.Body
			req.Body = io.NopCloser(bytes.NewBuffer(payload))
			return c.doWithOptions(req, retryMax)
		}
	}
	//Retry if the service is unavailable.
	if resp.StatusCode == 503 {
		s := time.Duration(retryMax) * time.Second
		c.Log.Info(fmt.Sprintf("received HTTP 503 retrying in %s ", s),
			slog.String("url", req.URL.String()),
			slog.String("method", req.Method),
		)
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

// retryAfter will return the number of seconds an API request needs to wait before trying again
func retryAfter(resp *http.Response) (int64, error) {
	body, _ := io.ReadAll(resp.Body)
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
		payload, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(payload))
		return req, payload
	} else {
		return req, nil
	}
}

// httpStatusCheck receives an http response and returns an error based on zscaler documentation.
// From https://help.zscaler.com/zia/about-error-handling
func httpStatusCheck(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return nil
	} else if resp.StatusCode == 400 {
		b, _ := io.ReadAll(resp.Body)
		return &ZIAError{Err: "HTTP error: Invalid or bad request" + string(b), Code: resp.StatusCode}
	} else if resp.StatusCode == 401 {
		return &ZIAError{Err: "HTTP error: Session is not authenticated or timed out", Code: resp.StatusCode}
	} else if resp.StatusCode == 403 {
		return &ZIAError{Err: "HTTP error: The API key was disabled by your service provider, User's role has no access permissions or functional scope or a required SKU subscription is missing", Code: resp.StatusCode}
	} else if resp.StatusCode == 409 {
		return &ZIAError{Err: "HTTP error: Request could not be processed because of possible edit conflict occurred. Another admin might be saving a configuration change at the same time. In this scenario, the client is expected to retry after a short time period.", Code: resp.StatusCode}
	} else if resp.StatusCode == 415 {
		return &ZIAError{Err: "HTTP error: Unsupported media type. This error is returned if you don't include application/json as the Content-Type in the request header (for example, Content-Type: application/json).", Code: resp.StatusCode}
	} else if resp.StatusCode == 429 {
		return &ZIAError{Err: "HTTP error: Exceeded the rate limit or quota. The response includes a Retry-After value.", Code: resp.StatusCode}
	} else if resp.StatusCode == 500 {
		return &ZIAError{Err: "HTTP error: Unexpected error", Code: resp.StatusCode}
	} else if resp.StatusCode == 503 {
		return &ZIAError{Err: "HTTP error: Service is temporarily unavailable", Code: resp.StatusCode}
	} else {
		return &ZIAError{Err: "Invalid HTTP response code", Code: resp.StatusCode}
	}
}

// KeyGen function gets the authentication parameter and returns the JSESSIONID which is the cookie that authenticates the requests
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
		Timeout: time.Second * 100,
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
	return nil, &ZIAError{Err: "can't authenticate please check credentials,base url or apikey"}
}

// obfuscateApiKey obfuscates the API key based on Zscaler documentation
func obfuscateApiKey(api string, t string) (string, error) {
	if len(t) < 6 {
		return "", &ZIAError{Err: "time lenght for ofuscation is less than 6 digits, please check your system's clock"}
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
			return "", &ZIAError{Err: "invalid api key size"}
		}
		key += api[d : d+1]
	}
	for j, _ := range r {
		d, err := strconv.Atoi((r)[j : j+1])
		if err != nil {
			return "", err
		}
		if d+3 > len(api) {
			return "", &ZIAError{Err: "invalid api key size"}
		}
		key += api[d+2 : d+3]
	}
	return key, nil
}

// SetRetryMax adds a URL filtering rules
func (c *Client) SetRetryMax(r int) {
	c.RetryMax = r
}

// Process and sends HTTP Delete requests
func (c *Client) deleteRequest(path string) error {
	req, err := http.NewRequest(http.MethodDelete, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	_, err = c.do(req)
	return err
}

// chunkBy split slices in chunks
func chunkBy[T any](items []T, chunkSize int) (chunks [][]T) {
	for chunkSize < len(items) {
		items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
	}
	return append(chunks, items)
}
