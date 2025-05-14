package zcc

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zepryspet/gozscaler/oneapi"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
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
	//http body
	Body []byte
}

func (e *ZCCError) Error() string {
	if e.Code != 0 {
		ret := e.Err + ", HTTP status code: " + strconv.Itoa(e.Code)
		if len(e.Body) > 0 {
			ret += ", body: " + string(e.Body)
		}
		return ret
	}
	return e.Err
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

// DeviceType
// The following values represent different OS types:
// 1 - iOS
// 2 - Android
// 3 - Windows
// 4 - macOS
// 5 - Linux
type DeviceType int

func (d DeviceType) Value() string {
	return strconv.Itoa(int(d))
}

const (
	DeviceIos     DeviceType = 1
	DeviceAndroid DeviceType = 2
	DeviceWindows DeviceType = 3
	DeviceMacOS   DeviceType = 4
	DeviceLinux   DeviceType = 5
)

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

type ForwardingProfile struct {
	Active                   string `json:"active,omitempty"`
	ConditionType            int    `json:"conditionType,omitempty"`
	DNSSearchDomains         string `json:"dnsSearchDomains,omitempty"`
	DNSServers               string `json:"dnsServers,omitempty"`
	EnableLWFDriver          string `json:"enableLWFDriver,omitempty"`
	EnableSplitVpnTN         int    `json:"enableSplitVpnTN,omitempty"`
	EvaluateTrustedNetwork   int    `json:"evaluateTrustedNetwork,omitempty"`
	ForwardingProfileActions []struct {
		DTLSTimeout                    int    `json:"DTLSTimeout,omitempty"`
		TLSTimeout                     int    `json:"TLSTimeout,omitempty"`
		UDPTimeout                     int    `json:"UDPTimeout,omitempty"`
		ActionType                     int    `json:"actionType,omitempty"`
		AllowTLSFallback               int    `json:"allowTLSFallback,omitempty"`
		BlockUnreachableDomainsTraffic int    `json:"blockUnreachableDomainsTraffic,omitempty"`
		CustomPac                      string `json:"customPac,omitempty"`
		DropIpv6IncludeTrafficInT2     int    `json:"dropIpv6IncludeTrafficInT2,omitempty"`
		DropIpv6Traffic                int    `json:"dropIpv6Traffic,omitempty"`
		DropIpv6TrafficInIpv6Network   int    `json:"dropIpv6TrafficInIpv6Network,omitempty"`
		EnablePacketTunnel             int    `json:"enablePacketTunnel,omitempty"`
		LatencyBasedZenEnablement      int    `json:"latencyBasedZenEnablement,omitempty"`
		MtuForZadapter                 int    `json:"mtuForZadapter,omitempty"`
		NetworkType                    int    `json:"networkType,omitempty"`
		PathMtuDiscovery               int    `json:"pathMtuDiscovery,omitempty"`
		PrimaryTransport               int    `json:"primaryTransport,omitempty"`
		RedirectWebTraffic             int    `json:"redirectWebTraffic,omitempty"`
		SystemProxy                    int    `json:"systemProxy,omitempty"`
		SystemProxyData                struct {
			BypassProxyForPrivateIP int    `json:"bypassProxyForPrivateIP,omitempty"`
			EnableAutoDetect        int    `json:"enableAutoDetect,omitempty"`
			EnablePAC               int    `json:"enablePAC,omitempty"`
			EnableProxyServer       int    `json:"enableProxyServer,omitempty"`
			PacDataPath             string `json:"pacDataPath,omitempty"`
			PacURL                  string `json:"pacURL,omitempty"`
			PerformGPUpdate         int    `json:"performGPUpdate,omitempty"`
			ProxyAction             int    `json:"proxyAction,omitempty"`
			ProxyServerAddress      string `json:"proxyServerAddress,omitempty"`
			ProxyServerPort         string `json:"proxyServerPort,omitempty"`
		} `json:"systemProxyData,omitempty"`
		Tunnel2FallbackType            int `json:"tunnel2FallbackType,omitempty"`
		UseTunnel2ForProxiedWebTraffic int `json:"useTunnel2ForProxiedWebTraffic,omitempty"`
		ZenProbeInterval               int `json:"zenProbeInterval,omitempty"`
		ZenProbeSampleSize             int `json:"zenProbeSampleSize,omitempty"`
		ZenThresholdLimit              int `json:"zenThresholdLimit,omitempty"`
	} `json:"forwardingProfileActions,omitempty"`
	ForwardingProfileZpaActions []struct {
		DTLSTimeout                     int `json:"DTLSTimeout,omitempty"`
		TLSTimeout                      int `json:"TLSTimeout,omitempty"`
		ActionType                      int `json:"actionType,omitempty"`
		LatencyBasedServerMTEnablement  int `json:"latencyBasedServerMTEnablement,omitempty"`
		LatencyBasedZpaServerEnablement int `json:"latencyBasedZpaServerEnablement,omitempty"`
		LbsZpaProbeInterval             int `json:"lbsZpaProbeInterval,omitempty"`
		LbsZpaProbeSampleSize           int `json:"lbsZpaProbeSampleSize,omitempty"`
		LbsZpaThresholdLimit            int `json:"lbsZpaThresholdLimit,omitempty"`
		MtuForZadapter                  int `json:"mtuForZadapter,omitempty"`
		NetworkType                     int `json:"networkType,omitempty"`
		PartnerInfo                     struct {
			AllowTLSFallback int `json:"allowTlsFallback,omitempty"`
			MtuForZadapter   int `json:"mtuForZadapter,omitempty"`
			PrimaryTransport int `json:"primaryTransport,omitempty"`
		} `json:"partnerInfo,omitempty"`
		PrimaryTransport              int `json:"primaryTransport,omitempty"`
		SendTrustedNetworkResultToZpa int `json:"sendTrustedNetworkResultToZpa,omitempty"`
	} `json:"forwardingProfileZpaActions,omitempty"`
	Hostname                  string   `json:"hostname,omitempty"`
	ID                        string   `json:"id,omitempty"`
	Name                      string   `json:"name,omitempty"`
	PredefinedTnAll           bool     `json:"predefinedTnAll,omitempty"`
	PredefinedTrustedNetworks bool     `json:"predefinedTrustedNetworks,omitempty"`
	ResolvedIpsForHostname    string   `json:"resolvedIpsForHostname,omitempty"`
	SkipTrustedCriteriaMatch  int      `json:"skipTrustedCriteriaMatch,omitempty"`
	TrustedDhcpServers        string   `json:"trustedDhcpServers,omitempty"`
	TrustedEgressIps          string   `json:"trustedEgressIps,omitempty"`
	TrustedGateways           string   `json:"trustedGateways,omitempty"`
	TrustedNetworkIds         []int    `json:"trustedNetworkIds,omitempty"`
	TrustedNetworks           []string `json:"trustedNetworks,omitempty"`
	TrustedSubnets            string   `json:"trustedSubnets,omitempty"`
}

func (p ForwardingProfile) String() string {
	return jsonString(p)
}

// tries as hard as it can to set a number
type CustomInt int

func (u *CustomInt) UnmarshalJSON(data []byte) error {
	var tmp int
	err := json.Unmarshal(data, &tmp) //tries with int first
	if err != nil {
		//unmarshall as float
		var f float64
		err1 := json.Unmarshal(data, &f)
		if err1 != nil {
			//try as a string
			var s string
			err2 := json.Unmarshal(data, &s)
			if err2 != nil {
				return err2
			}
			n, err3 := strconv.Atoi(s)
			if err3 != nil {
				return err3
			}
			*u = CustomInt(n)
		}
		*u = CustomInt(f)
		return nil
	}
	*u = CustomInt(tmp)
	return nil
}

type CustomString string

func (u *CustomString) UnmarshalJSON(data []byte) error {
	var tmp string
	err := json.Unmarshal(data, &tmp) //tries with int first
	if err != nil {
		//unmarshall as float
		var f float64
		err1 := json.Unmarshal(data, &f)
		if err1 != nil {
			//try as a string
			var s string
			err2 := json.Unmarshal(data, &s)
			if err2 != nil {
				return err2
			}
			n, err3 := strconv.Atoi(s)
			if err3 != nil {
				return err3
			}
			*u = CustomString(strconv.Itoa(n))
		}
		*u = CustomString(strconv.Itoa(int(f)))
		return nil
	}
	*u = CustomString(tmp)
	return nil
}

type AppProfile struct {
	Active                       CustomInt         `json:"active"`
	AllowUnreachablePac          bool              `json:"allowUnreachablePac"`
	AndroidPolicy                *AndroidPolicy    `json:"androidPolicy"`
	AppIdentityNames             []string          `json:"appIdentityNames"`
	AppServiceIds                []int             `json:"appServiceIds"`
	AppServiceNames              []string          `json:"appServiceNames"`
	BypassAppIds                 []int             `json:"bypassAppIds"`
	BypassCustomAppIds           []int             `json:"bypassCustomAppIds"`
	Description                  string            `json:"description"`
	DeviceGroupIds               []int             `json:"deviceGroupIds"`
	DeviceGroupNames             []string          `json:"deviceGroupNames"`
	DeviceType                   int               `json:"device_type"`
	DisasterRecovery             *DisasterRecovery `json:"disasterRecovery"`
	EnableDeviceGroups           CustomInt         `json:"enableDeviceGroups"`
	ForwardingProfileID          int               `json:"forwardingProfileId"`
	GroupAll                     CustomInt         `json:"groupAll"`
	GroupIds                     []int             `json:"groupIds"`
	GroupNames                   []string          `json:"groupNames"`
	HighlightActiveControl       CustomInt         `json:"highlightActiveControl"`
	ID                           CustomInt         `json:"id"`
	IosPolicy                    *IosPolicy        `json:"iosPolicy"`
	LinuxPolicy                  *LinuxPolicy      `json:"linuxPolicy"`
	LogFileSize                  CustomInt         `json:"logFileSize"`
	LogLevel                     CustomInt         `json:"logLevel"`
	LogMode                      CustomInt         `json:"logMode"`
	MacPolicy                    *MacPolicy        `json:"macPolicy,omitempty"`
	Name                         string            `json:"name"`
	PacURL                       string            `json:"pac_url"`
	PolicyExtension              *PolicyExtension  `json:"policyExtension,omitempty"`
	ReactivateWebSecurityMinutes string            `json:"reactivateWebSecurityMinutes"`
	ReauthPeriod                 string            `json:"reauth_period"`
	RuleOrder                    CustomInt         `json:"ruleOrder"`
	SendDisableServiceReason     CustomInt         `json:"sendDisableServiceReason"`
	TunnelZappTraffic            CustomInt         `json:"tunnelZappTraffic"`
	UserIds                      []int             `json:"userIds"`
	UserNames                    []string          `json:"userNames"`
	WindowsPolicy                *WindowsPolicy    `json:"windowsPolicy,omitempty"`
	ZiaPostureConfigID           int               `json:"ziaPostureConfigId"`
	PolicyToken                  string            `json:"policyToken"`
	//fwd profile
	OnNetPolicy *OnNetPolicy `json:"onNetPolicy,omitempty"`
	//missing fields from docs
	LogoutPassword                    string    `json:"logout_password"`
	UninstallPassword                 string    `json:"uninstall_password"`
	DisablePassword                   string    `json:"disable_password"`
	InstallSslCerts                   CustomInt `json:"install_ssl_certs"`
	DisableLoopBackRestriction        CustomInt `json:"disableLoopBackRestriction"`
	RemoveExemptedContainers          CustomInt `json:"removeExemptedContainers"`
	OverrideWPAD                      CustomInt `json:"overrideWPAD"`
	RestartWinHTTPSvc                 CustomInt `json:"restartWinHttpSvc"`
	CacheSystemProxy                  CustomInt `json:"cacheSystemProxy"`
	PrioritizeIPv4                    CustomInt `json:"prioritizeIPv4"`
	PacType                           CustomInt `json:"pacType"`
	PacDataPath                       string    `json:"pacDataPath"`
	DisableParallelIpv4AndIPv6        CustomInt `json:"disableParallelIpv4AndIPv6"`
	WfpDriver                         CustomInt `json:"wfpDriver"`
	FlowLoggerConfig                  string    `json:"flowLoggerConfig"`
	TriggerDomainProfleDetection      CustomInt `json:"triggerDomainProfleDetection"`
	AllInboundTrafficConfig           string    `json:"allInboundTrafficConfig"`
	InstallWindowsFirewallInboundRule CustomInt `json:"installWindowsFirewallInboundRule"`
	CaptivePortalConfig               string    `json:"captivePortalConfig"`
	ForceLocationRefreshSccm          CustomInt `json:"forceLocationRefreshSccm"`
	Groups                            []any     `json:"groups"`
	DeviceGroups                      []any     `json:"deviceGroups"`
	Users                             []any     `json:"users"`
	SccmConfig                        string    `json:"sccmConfig"`
}

func (p AppProfile) String() string {
	return jsonString(p)
}

type OnNetPolicy struct {
	ID                        string    `json:"id"`
	Name                      string    `json:"name"`
	ConditionType             CustomInt `json:"conditionType"`
	PredefinedTrustedNetworks bool      `json:"predefinedTrustedNetworks"`
	PredefinedTnAll           bool      `json:"predefinedTnAll"`
}

type AndroidPolicy struct {
	AllowedApps       string `json:"allowedApps"`
	BillingDay        string `json:"billingDay"`
	BypassAndroidApps string `json:"bypassAndroidApps"`
	BypassMmsApps     string `json:"bypassMmsApps"`
	CustomText        string `json:"customText"`
	DisablePassword   string `json:"disablePassword"`
	EnableVerboseLog  string `json:"enableVerboseLog"`
	Enforced          string `json:"enforced"`
	InstallCerts      string `json:"installCerts"`
	Limit             string `json:"limit"`
	LogoutPassword    string `json:"logoutPassword"`
	QuotaRoaming      string `json:"quotaRoaming"`
	UninstallPassword string `json:"uninstallPassword"`
	Wifissid          string `json:"wifissid"`
}

type DisasterRecovery struct {
	AllowZiaTest        bool   `json:"allowZiaTest,omitempty"`
	AllowZpaTest        bool   `json:"allowZpaTest,omitempty"`
	EnableZiaDR         bool   `json:"enableZiaDR,omitempty"`
	EnableZpaDR         bool   `json:"enableZpaDR,omitempty"`
	PolicyID            string `json:"policyId,omitempty"`
	UseZiaGlobalDb      bool   `json:"useZiaGlobalDb,omitempty"`
	ZiaDRRecoveryMethod int    `json:"ziaDRRecoveryMethod,omitempty"`
	ZiaDomainName       string `json:"ziaDomainName,omitempty"`
	ZiaGlobalDbURL      string `json:"ziaGlobalDbUrl,omitempty"`
	ZiaGlobalDbUrlv2    string `json:"ziaGlobalDbUrlv2,omitempty"`
	ZiaPacURL           string `json:"ziaPacUrl,omitempty"`
	ZiaSecretKeyData    string `json:"ziaSecretKeyData,omitempty"`
	ZiaSecretKeyName    string `json:"ziaSecretKeyName,omitempty"`
	ZpaDomainName       string `json:"zpaDomainName,omitempty"`
	ZpaSecretKeyData    string `json:"zpaSecretKeyData,omitempty"`
	ZpaSecretKeyName    string `json:"zpaSecretKeyName,omitempty"`
}
type IosPolicy struct {
	DisablePassword        string `json:"disablePassword"`
	Ipv6Mode               string `json:"ipv6Mode"`
	LogoutPassword         string `json:"logoutPassword"`
	Passcode               string `json:"passcode"`
	ShowVPNTunNotification string `json:"showVPNTunNotification"`
	UninstallPassword      string `json:"uninstallPassword"`
}

type LinuxPolicy struct {
	DisablePassword   string `json:"disablePassword"`
	InstallCerts      string `json:"installCerts"`
	LogoutPassword    string `json:"logoutPassword"`
	UninstallPassword string `json:"uninstallPassword"`
}

type MacPolicy struct {
	AddIfscopeRoute                          string `json:"addIfscopeRoute"`
	CacheSystemProxy                         string `json:"cacheSystemProxy"`
	ClearArpCache                            string `json:"clearArpCache"`
	DisablePassword                          string `json:"disablePassword"`
	DNSPriorityOrdering                      string `json:"dnsPriorityOrdering"`
	DNSPriorityOrderingForTrustedDNSCriteria string `json:"dnsPriorityOrderingForTrustedDnsCriteria"`
	EnableApplicationBasedBypass             string `json:"enableApplicationBasedBypass"`
	EnableZscalerFirewall                    string `json:"enableZscalerFirewall"`
	InstallCerts                             string `json:"installCerts"`
	LogoutPassword                           string `json:"logoutPassword"`
	PersistentZscalerFirewall                string `json:"persistentZscalerFirewall"`
	UninstallPassword                        string `json:"uninstallPassword"`
}

type WindowsPolicy struct {
	CacheSystemProxy                  int    `json:"cacheSystemProxy"`
	CaptivePortalConfig               string `json:"captivePortalConfig"`
	DisableLoopBackRestriction        int    `json:"disableLoopBackRestriction"`
	DisableParallelIpv4AndIpv6        string `json:"disableParallelIpv4andIpv6"`
	DisablePassword                   string `json:"disablePassword"`
	FlowLoggerConfig                  string `json:"flowLoggerConfig"`
	ForceLocationRefreshSccm          int    `json:"forceLocationRefreshSccm"`
	InstallCerts                      string `json:"installCerts"`
	InstallWindowsFirewallInboundRule int    `json:"installWindowsFirewallInboundRule"`
	LogoutPassword                    string `json:"logoutPassword"`
	OverrideWPAD                      int    `json:"overrideWPAD"`
	PacDataPath                       string `json:"pacDataPath"`
	PacType                           int    `json:"pacType"`
	PrioritizeIPv4                    int    `json:"prioritizeIPv4"`
	RemoveExemptedContainers          int    `json:"removeExemptedContainers"`
	RestartWinHTTPSvc                 int    `json:"restartWinHttpSvc"`
	TriggerDomainProfleDetection      int    `json:"triggerDomainProfleDetection"`
	UninstallPassword                 string `json:"uninstallPassword"`
	WfpDriver                         int    `json:"wfpDriver"`
}

type PolicyExtension struct {
	AdvanceZpaReauth                                bool              `json:"advanceZpaReauth,omitempty"`
	AdvanceZpaReauthTime                            CustomInt         `json:"advanceZpaReauthTime,omitempty"`
	AllowClientCertCachingForWebView2               string            `json:"allowClientCertCachingForWebView2,omitempty""`
	CustomDNS                                       string            `json:"customDNS,omitempty"`
	DdilConfig                                      string            `json:"ddilConfig,omitempty"`
	DeleteDHCPOption121Routes                       string            `json:"deleteDHCPOption121Routes,omitempty"`
	DisableDNSRouteExclusion                        CustomInt         `json:"disableDNSRouteExclusion,omitempty"`
	DropQuicTraffic                                 CustomInt         `json:"dropQuicTraffic,omitempty"`
	EnableAntiTampering                             string            `json:"enableAntiTampering,omitempty"`
	EnableFlowBasedTunnel                           CustomInt         `json:"enableFlowBasedTunnel,omitempty"`
	EnableSetProxyOnVPNAdapters                     CustomInt         `json:"enableSetProxyOnVPNAdapters,omitempty"`
	EnableZCCRevert                                 string            `json:"enableZCCRevert,omitempty"`
	EnableZdpService                                string            `json:"enableZdpService,omitempty"`
	EnforceSplitDNS                                 CustomInt         `json:"enforceSplitDNS,omitempty"`
	ExitPassword                                    string            `json:"exitPassword,omitempty"`
	FallbackToGatewayDomain                         string            `json:"fallbackToGatewayDomain,omitempty"`
	FollowGlobalForPartnerLogin                     string            `json:"followGlobalForPartnerLogin,omitempty"`
	FollowRoutingTable                              string            `json:"followRoutingTable,omitempty"`
	GenerateCliPasswordContract                     *PasswordContract `json:"generateCliPasswordContract,omitempty"`
	InterceptZIATrafficAllAdapters                  string            `json:"interceptZIATrafficAllAdapters,omitempty"`
	MachineIdpAuth                                  bool              `json:"machineIdpAuth,omitempty"`
	Nonce                                           string            `json:"nonce,omitempty"`
	OverrideATCmdByPolicy                           string            `json:"overrideATCmdByPolicy,omitempty"`
	PacketTunnelDNSExcludeList                      string            `json:"packetTunnelDnsExcludeList,omitempty"`
	PacketTunnelDNSIncludeList                      string            `json:"packetTunnelDnsIncludeList,omitempty"`
	PacketTunnelExcludeList                         string            `json:"packetTunnelExcludeList,omitempty"`
	PacketTunnelExcludeListForIPv6                  string            `json:"packetTunnelExcludeListForIPv6,omitempty"`
	PacketTunnelIncludeList                         string            `json:"packetTunnelIncludeList,omitempty"`
	PacketTunnelIncludeListForIPv6                  string            `json:"packetTunnelIncludeListForIPv6,omitempty"`
	PartnerDomains                                  string            `json:"partnerDomains,omitempty"`
	PrioritizeDNSExclusions                         CustomInt         `json:"prioritizeDnsExclusions,omitempty"`
	PurgeKerberosPreferredDCCache                   string            `json:"purgeKerberosPreferredDCCache,omitempty"`
	ReactivateAntiTamperingTime                     CustomInt         `json:"reactivateAntiTamperingTime,omitempty"`
	SourcePortBasedBypasses                         string            `json:"sourcePortBasedBypasses,omitempty"`
	SwitchFocusToNotification                       string            `json:"switchFocusToNotification"`
	TruncateLargeUDPDNSResponse                     CustomInt         `json:"truncateLargeUDPDNSResponse,omitempty"`
	UpdateDNSSearchOrder                            CustomInt         `json:"updateDnsSearchOrder,omitempty"`
	UseDefaultAdapterForDNS                         string            `json:"useDefaultAdapterForDNS,omitempty"`
	UseProxyPortForT1                               string            `json:"useProxyPortForT1,omitempty"`
	UseProxyPortForT2                               string            `json:"useProxyPortForT2,omitempty"`
	UseV8JsEngine                                   string            `json:"useV8JsEngine,omitempty"`
	UseWsaPollForZpa                                string            `json:"useWsaPollForZpa,omitempty"`
	UseZscalerNotificationFramework                 string            `json:"useZscalerNotificationFramework,omitempty"`
	UserAllowedToAddPartner                         string            `json:"userAllowedToAddPartner,omitempty"`
	VpnGateways                                     string            `json:"vpnGateways,omitempty"`
	ZccAppFailOpenPolicy                            CustomInt         `json:"zccAppFailOpenPolicy,omitempty"`
	ZccFailCloseSettingsAppByPassIds                []int             `json:"zccFailCloseSettingsAppByPassIds,omitempty"`
	ZccFailCloseSettingsAppByPassNames              []string          `json:"zccFailCloseSettingsAppByPassNames,omitempty"`
	ZccFailCloseSettingsExitUninstallPassword       string            `json:"zccFailCloseSettingsExitUninstallPassword,omitempty"`
	ZccFailCloseSettingsIPBypasses                  string            `json:"zccFailCloseSettingsIpBypasses,omitempty"`
	ZccFailCloseSettingsLockdownOnTunnelProcessExit CustomInt         `json:"zccFailCloseSettingsLockdownOnTunnelProcessExit,omitempty"`
	ZccFailCloseSettingsThumbPrint                  string            `json:"zccFailCloseSettingsThumbPrint,omitempty"`
	ZccRevertPassword                               string            `json:"zccRevertPassword,omitempty"`
	ZccTunnelFailPolicy                             CustomInt         `json:"zccTunnelFailPolicy,omitempty"`
	ZdDisablePassword                               string            `json:"zdDisablePassword,omitempty"`
	ZdpDisablePassword                              string            `json:"zdpDisablePassword,omitempty"`
	ZdxDisablePassword                              string            `json:"zdxDisablePassword,omitempty"`
	ZdxLiteConfigObj                                string            `json:"zdxLiteConfigObj,omitempty"`
	ZpaAuthExpOnNetIPChange                         CustomInt         `json:"zpaAuthExpOnNetIpChange,omitempty"`
	ZpaAuthExpOnSleep                               CustomInt         `json:"zpaAuthExpOnSleep,omitempty"`
	ZpaAuthExpOnSysRestart                          CustomInt         `json:"zpaAuthExpOnSysRestart,omitempty"`
	ZpaAuthExpOnWinLogonSession                     CustomInt         `json:"zpaAuthExpOnWinLogonSession,omitempty"`
	ZpaAuthExpOnWinSessionLock                      CustomInt         `json:"zpaAuthExpOnWinSessionLock,omitempty"`
	ZpaAuthExpSessionLockStateMinTimeInSecond       CustomInt         `json:"zpaAuthExpSessionLockStateMinTimeInSecond,omitempty"`
	ZpaDisablePassword                              string            `json:"zpaDisablePassword,omitempty"`
}

type PasswordContract struct {
	AllowZpaDisableWithoutPassword bool `json:"allowZpaDisableWithoutPassword,omitempty"`
	EnableCli                      bool `json:"enableCli,omitempty"`
	PolicyID                       int  `json:"policyId,omitempty"`
}

// DeviceCleanup info for device cleanup
type DeviceCleanup struct {
	Active                string `json:"active,omitempty"`
	AutoPurgeDays         string `json:"autoPurgeDays"`
	AutoRemovalDays       string `json:"autoRemovalDays"`
	CompanyID             string `json:"companyId,omitempty"`
	CreatedBy             string `json:"createdBy,omitempty"`
	DeviceExceedLimit     string `json:"deviceExceedLimit"`
	EditedBy              string `json:"editedBy,omitempty"`
	ForceRemoveType       string `json:"forceRemoveType,omitempty"`
	ForceRemoveTypeString string `json:"forceRemoveTypeString,omitempty"`
	ID                    string `json:"id,omitempty"`
}

// WebPrivacyInfo info for privacy settings
type WebPrivacyInfo struct {
	Active                        string `json:"active"`
	CollectMachineHostname        string `json:"collectMachineHostname"`
	CollectUserInfo               string `json:"collectUserInfo"`
	CollectZdxLocation            string `json:"collectZdxLocation"`
	DisableCrashlytics            string `json:"disableCrashlytics"`
	EnablePacketCapture           string `json:"enablePacketCapture"`
	ExportLogsForNonAdmin         string `json:"exportLogsForNonAdmin"`
	GrantAccessToZscalerLogFolder string `json:"grantAccessToZscalerLogFolder"`
	ID                            string `json:"id,omitempty"`
	OverrideT2ProtocolSetting     string `json:"overrideT2ProtocolSetting"`
	RestrictRemotePacketCapture   string `json:"restrictRemotePacketCapture"`
}

// WebFailOpen updates fail open settings in portal
type WebFailOpen struct {
	Active                              string `json:"active"`
	CaptivePortalWebSecDisableMinutes   int    `json:"captivePortalWebSecDisableMinutes"`
	CompanyID                           string `json:"companyId"`
	CreatedBy                           string `json:"createdBy"`
	EditedBy                            string `json:"editedBy"`
	EnableCaptivePortalDetection        int    `json:"enableCaptivePortalDetection"`
	EnableFailOpen                      int    `json:"enableFailOpen"`
	EnableStrictEnforcementPrompt       int    `json:"enableStrictEnforcementPrompt"`
	EnableWebSecOnProxyUnreachable      string `json:"enableWebSecOnProxyUnreachable"`
	EnableWebSecOnTunnelFailure         string `json:"enableWebSecOnTunnelFailure"`
	ID                                  string `json:"id"`
	StrictEnforcementPromptDelayMinutes int    `json:"strictEnforcementPromptDelayMinutes"`
	StrictEnforcementPromptMessage      string `json:"strictEnforcementPromptMessage"`
	TunnelFailureRetryCount             int    `json:"tunnelFailureRetryCount"`
}

// String prints the struct in json pretty format
func (p WebPrivacyInfo) String() string {
	return jsonString(p)
}

// String prints the struct in json pretty format
func (p WebFailOpen) String() string {
	return jsonString(p)
}

// String prints the struct in json pretty format
func (p DeviceCleanup) String() string {
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
	Log        *slog.Logger
	Bearer     string
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
		Timeout: time.Second * 100,
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
	return NewClientLogger(cloudName, clientID, clientSecret, os.Getenv("SLOG"), os.Stdout)
}

func NewClientLogger(cloudName, clientID, clientSecret, level string, w io.Writer) (*Client, error) {
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
	opts := &slog.HandlerOptions{} //level info by default
	if level == "DEBUG" {
		opts.Level = slog.LevelDebug
	}
	parent := slog.New(slog.NewJSONHandler(w, opts))
	child := parent.With(slog.String("module", "gozscaler"),
		slog.String("client", "zia"))
	return &Client{
		BaseURL: BaseURL + "/public/v1",
		HTTPClient: &http.Client{
			Timeout: time.Second * 10,
		},
		RetryMax: 10,
		Token:    access_token,
		Log:      child,
	}, nil

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
	token, err := oneapi.AuthSecret(vanity, clientId, clientSecret)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{} //level info by default
	if level == "DEBUG" {
		opts.Level = slog.LevelDebug
	}
	BaseURL := "https://api.zsapi.net/zcc/papi/public/v1"
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
		Bearer:   token,
	}, nil
}

// GetDevices get all the devices enrolled in ZCC mobile portal
func (c *Client) GetDevices() ([]Device, error) {
	return getPaged[Device](c, 50, "/getDevices")
}

// GetForwardingProfiles gets all configured forwarding profiles
func (c *Client) GetForwardingProfiles() ([]ForwardingProfile, error) {
	return getPaged[ForwardingProfile](c, 50, "/webForwardingProfile/listByCompany")
}

// GetAppProfiles gets all configured app profiles
func (c *Client) GetAppProfiles(d DeviceType) ([]AppProfile, error) {
	q := url.Values{}
	q.Set("deviceType", d.Value())
	profiles, err := getPagedQuery[AppProfile](c, 50, "/web/policy/listByCompany", q)
	if err != nil {
		return nil, err
	}
	for i, _ := range profiles {
		if profiles[i].OnNetPolicy != nil {
			id := profiles[i].OnNetPolicy.ID
			iid, errint := strconv.Atoi(id)
			if errint == nil {
				profiles[i].ForwardingProfileID = iid
			}
		}
		profiles[i].DeviceType = int(d)
		if d == DeviceWindows {
			profiles[i].WindowsPolicy = toPolicy(&WindowsPolicy{}, profiles[i])
		} else if d == DeviceMacOS {
			profiles[i].MacPolicy = toPolicy(&MacPolicy{}, profiles[i])
		} else if d == DeviceLinux {
			profiles[i].LinuxPolicy = toPolicy(&LinuxPolicy{}, profiles[i])
		} else if d == DeviceAndroid {
			profiles[i].AndroidPolicy = toPolicy(&AndroidPolicy{}, profiles[i])
		} else if d == DeviceIos {
			profiles[i].IosPolicy = toPolicy(&IosPolicy{}, profiles[i])
		}
	}
	return profiles, nil
}

// toPolicy hack to unmarchal to policy type
func toPolicy[K any](in *K, profile AppProfile) *K {
	bytes, err := json.Marshal(profile)
	if err != nil {
		return in
	}
	json.Unmarshal(bytes, &in)
	return in
}

// GetDeviceCleanup obtains device cleanup configuration
func (c *Client) GetDeviceCleanup() (res DeviceCleanup, err error) {
	body, err := c.getRequest("/getDeviceCleanupInfo")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return res, err
	}
	return res, nil
}

// UpdateDeviceCleanup updates device cleanup configuration
func (c *Client) UpdateDeviceCleanup(obj DeviceCleanup) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/setDeviceCleanupInfo"
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// GetWebFailOpen obtains web fail openconfiguration
func (c *Client) GetWebFailOpen() (WebFailOpen, error) {
	body, err := c.getRequest("/webFailOpenPolicy/listByCompany")
	if err != nil {
		return WebFailOpen{}, err
	}
	res := []WebFailOpen{} //workaround to bug
	err = json.Unmarshal(body, &res)
	if err != nil || len(res) == 0 {
		return WebFailOpen{}, err
	}
	return res[0], nil
}

// UpdateWebFailOpen updates web fail open configuration
func (c *Client) UpdateWebFailOpen(obj WebFailOpen) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/webFailOpenPolicy/edit"
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
}

// GetWebPrivacyInfo obtains web privacy info configuration
func (c *Client) GetWebPrivacyInfo() (res WebPrivacyInfo, err error) {
	body, err := c.getRequest("/getWebPrivacyInfo")
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return res, err
	}
	return res, nil
}

// UpdateWebPrivacyInfo updates web privacy info configuration
func (c *Client) UpdateWebPrivacyInfo(obj WebPrivacyInfo) error {
	postBody, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	path := "/setWebPrivacyInfo"
	err := c.putRequest(path, postBody)
	if err != nil {
		return err
	}
	return nil
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

// AddForwardingProfile adds a forwarding filtering rules
func (c *Client) AddForwardingProfile(profile ForwardingProfile) (string, error) {
	postBody, _ := json.Marshal(profile)
	body, err := c.postRequest("/webForwardingProfile/edit", postBody)
	if err != nil {
		return "", err
	}
	res := ForwardingProfile{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return "", err
	}
	return res.ID, err
}

// AddAppProfile adds or updates an app profile
func (c *Client) AddAppProfile(profile AppProfile) error {
	postBody, _ := json.Marshal(profile)
	return c.putRequest("/web/policy/edit", postBody)
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
	//Adding auth header for onelogin
	if c.Bearer != "" {
		req.Header.Add("Authorization", "Bearer "+c.Bearer)
	} else { //legacy api
		req.Header.Set("auth-token", c.Token)
	}
	r, err := c.doWithOptions(req, retryMax)
	if err != nil {
		c.Log.Info("HTTP failed with error ",
			slog.String("url", req.URL.String()),
			slog.String("error", fmt.Sprint(err)),
			slog.String("method", req.Method))
		return r, err
	}
	return r, err
}

// doWithOptions Wrapper that receives options and sends a http request
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
			s := time.Duration(retryAfter(retryMax, c.RetryMax)) * time.Second
			c.Log.Info(fmt.Sprintf("received HTTP 429 waiting for %v seconds", s),
				slog.String("url", req.URL.String()),
				slog.String("method", req.Method),
				slog.String("retries left", fmt.Sprint(retryMax)),
			)
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
	body, err := io.ReadAll(resp.Body)
	if err == nil {
		slog.Debug("http response",
			slog.String("url", req.URL.String()),
			slog.String("body", string(body)), // logging payload and cookies
			slog.String("method", req.Method),
		)
	}
	c.Log.Info("HTTP request completed",
		slog.String("url", req.URL.String()),
		slog.String("method", req.Method))
	c.Log.Debug("HTTP request completed",
		slog.String("url", req.URL.String()),
		slog.String("response code", strconv.Itoa(resp.StatusCode)),
		slog.String("response body", string(body)),
		slog.String("method", req.Method))
	return body, err
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
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 400 {
		return &ZCCError{Err: "HTTP error: Invalid or bad request", Code: resp.StatusCode, Body: b}
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
		return &ZCCError{Err: "HTTP error: Unexpected error", Code: resp.StatusCode, Body: b}
	} else if resp.StatusCode == 503 {
		return &ZCCError{Err: "HTTP error: Service is temporarily unavailable", Code: resp.StatusCode, Body: b}
	} else {
		return &ZCCError{Err: "Invalid HTTP response code", Code: resp.StatusCode, Body: b}
	}
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
