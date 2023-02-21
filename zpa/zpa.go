package zpa

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//Client contains the base url, http client and max number of retries per request.
//It also includes ZPA info like customerID
//And policy IDs for
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	RetryMax   int
	Token      string
	CustomerId string
	AccessID   string //ID for ZPA access policy
	ReauthID   string //ID for ZPA reauth policy
	SiemID     string //ID for ZPA SIEM policy
	BypassID   string //ID for Bypass ID policy
	Policy     string //Options are : access,reauth,siem,bypass
	//Policy type so we can detect which kind of policy you want to interact with.
}

//myToken parses the auth response
type myToken struct {
	TType   string `json:"token_type"`
	Expires string `json:"expires_in"`
	Token   string `json:"access_token"`
}

/////////////////
//API structs////
/////////////////

//PortRange helps build port ranges on an app segment
type PortRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

//ClientLessApps helps build app segment
type ClientLessApps struct {
	AllowOptions        bool   `json:"allowOptions"`
	AppID               string `json:"appId"`
	ApplicationPort     string `json:"applicationPort"`
	ApplicationProtocol string `json:"applicationProtocol"`
	CertificateID       string `json:"certificateId"`
	CertificateName     string `json:"certificateName"`
	Cname               string `json:"cname"`
	Description         string `json:"description"`
	Domain              string `json:"domain"`
	Enabled             bool   `json:"enabled"`
	Hidden              bool   `json:"hidden"`
	ID                  string `json:"id"`
	LocalDomain         string `json:"localDomain"`
	Name                string `json:"name"`
	Path                string `json:"path"`
	Portal              bool   `json:"portal"`
	TrustUntrustedCert  bool   `json:"trustUntrustedCert"`
}

//InspectionApps helps build app segment
type InspectionApps struct {
	AppID               string `json:"appId"`
	ApplicationPort     string `json:"applicationPort"`
	ApplicationProtocol string `json:"applicationProtocol"`
	CertificateID       string `json:"certificateId"`
	CertificateName     string `json:"certificateName"`
	Description         string `json:"description"`
	Domain              string `json:"domain"`
	Enabled             bool   `json:"enabled"`
	ID                  string `json:"id"`
	Name                string `json:"name"`
}

//AppsConfig helps build app segment
type AppsConfig struct {
	AllowOptions        bool     `json:"allowOptions"`
	AppID               string   `json:"appId"`
	AppTypes            []string `json:"appTypes"`
	ApplicationPort     string   `json:"applicationPort"`
	ApplicationProtocol string   `json:"applicationProtocol"`
	BaAppID             string   `json:"baAppId"`
	CertificateID       string   `json:"certificateId"`
	CertificateName     string   `json:"certificateName"`
	Cname               string   `json:"cname"`
	Description         string   `json:"description"`
	Domain              string   `json:"domain"`
	Enabled             bool     `json:"enabled"`
	Hidden              bool     `json:"hidden"`
	InspectAppID        string   `json:"inspectAppId"`
	LocalDomain         string   `json:"localDomain"`
	Name                string   `json:"name"`
	Path                string   `json:"path"`
	Portal              bool     `json:"portal"`
	TrustUntrustedCert  bool     `json:"trustUntrustedCert"`
}

//CommonAppsDto helps build app segment
type CommonAppsDto struct {
	AppsConfig         []AppsConfig `json:"appsConfig"`
	DeletedBaApps      []string     `json:"deletedBaApps"`
	DeletedInspectApps []string     `json:"deletedInspectApps"`
}

//AppSegment holds the app segment
type AppSegment struct {
	SegmentGroupID     string           `json:"segmentGroupId,omitempty"`
	SegmentGroupName   string           `json:"segmentGroupName,omitempty"`
	BypassType         string           `json:"bypassType"`
	ClientlessApps     []ClientLessApps `json:"clientlessApps,omitempty"`
	CommonAppsDto      []CommonAppsDto  `json:"commonAppsDto,omitempty"`
	ConfigSpace        string           `json:"configSpace,omitempty"`
	CreationTime       string           `json:"creationTime,omitempty"`
	DefaultIdleTimeout string           `json:"defaultIdleTimeout,omitempty"`
	DefaultMaxAge      string           `json:"defaultMaxAge,omitempty"`
	Description        string           `json:"description"`
	DomainNames        []string         `json:"domainNames,omitempty"`
	DoubleEncrypt      bool             `json:"doubleEncrypt"`
	Enabled            bool             `json:"enabled"`
	HealthCheckType    string           `json:"healthCheckType,omitempty"`
	HealthReporting    string           `json:"healthReporting,omitempty"`
	//Values are "PING" or "NONE"
	IcmpAccessType       string           `json:"icmpAccessType,omitempty"`
	ID                   string           `json:"id,omitempty"`
	InspectionApps       []InspectionApps `json:"inspectionApps,omitempty"`
	IPAnchored           bool             `json:"ipAnchored"`
	IsCnameEnabled       bool             `json:"isCnameEnabled"`
	ModifiedBy           string           `json:"modifiedBy,omitempty"`
	ModifiedTime         string           `json:"modifiedTime,omitempty"`
	Name                 string           `json:"name,omitempty"`
	PassiveHealthEnabled bool             `json:"passiveHealthEnabled,omitempty"`
	ServerGroups         []ServerGroup    `json:"serverGroups,omitempty"`
	TCPPortRange         []PortRange      `json:"tcpPortRange,omitempty"`
	TCPPortRanges        []string         `json:"tcpPortRanges,omitempty"`
	UDPPortRange         []PortRange      `json:"udpPortRange,omitempty"`
	UDPPortRanges        []string         `json:"udpPortRanges,omitempty"`
}

//GetID returns: name , objectID
func (obj AppSegment) GetID() (string, string) {
	return obj.Name, obj.ID
}

//Create creates the object on the ZPA tenant registered with the client
func (obj AppSegment) Create(c *Client) (string, error) {
	return c.AddAppSegment(obj)
}

//ResetID Only add objects if references to them exist on the map map[OldID]newID
func (obj *AppSegment) ResetID(m map[string]string) bool {
	notFound := false
	//Reset own ID
	id, ok := m[obj.ID]
	if ok {
		obj.ID = id
	}
	//Setting Segement group ID
	id, ok = m[obj.SegmentGroupID]
	if ok {
		obj.SegmentGroupID = id
	}
	//Setting server groups
	var SrvGrp []ServerGroup
	//Checking app connector
	for _, v := range obj.ServerGroups {
		v.ResetID(m)
		SrvGrp = append(SrvGrp, v)
	}
	obj.ServerGroups = SrvGrp
	//Creating empty objects. Only appending existing references
	//Removing Clientless apps since it's not supported by API
	if len(obj.ClientlessApps) > 0 {
		//Adding removed items into description
		tmp := ""
		for _, v := range obj.ClientlessApps {
			tmp += v.Name
		}
		obj.Description += "Removed Browser access apps: " + tmp
		//Removing it
		var clapps []ClientLessApps
		obj.ClientlessApps = clapps
	}
	//Checking Commonappsto and inspection apps will be reset until we can find what they do
	var capps []CommonAppsDto
	var iapps []InspectionApps
	obj.CommonAppsDto = capps
	obj.InspectionApps = iapps
	return notFound
}

//SegmentGroup parses segment groups
type SegmentGroup struct {
	Applications        []AppSegment `json:"applications,omitempty"`
	ConfigSpace         string       `json:"configSpace,omitempty"`
	CreationTime        string       `json:"creationTime,omitempty"`
	Description         string       `json:"description,omitempty"`
	Enabled             bool         `json:"enabled,omitempty"`
	ID                  string       `json:"id,omitempty"`
	ModifiedBy          string       `json:"modifiedBy,omitempty"`
	ModifiedTime        string       `json:"modifiedTime,omitempty"`
	Name                string       `json:"name,omitempty"`
	PolicyMigrated      bool         `json:"policyMigrated,omitempty"`
	TCPKeepAliveEnabled string       `json:"tcpKeepAliveEnabled,omitempty"`
}

//GetID return the object name, ID
func (obj SegmentGroup) GetID() (string, string) {
	return obj.Name, obj.ID
}

//Create creates the object on the ZPA tenant registered with the client
func (obj SegmentGroup) Create(c *Client) (string, error) {
	return c.AddSegmentGroup(obj)
}

//ResetID Only add objects if references to them exist on the map map[OldID]newID
func (obj *SegmentGroup) ResetID(m map[string]string) bool {
	notFound := false
	//Reset own ID
	id, ok := m[obj.ID]
	if ok {
		obj.ID = id
	}
	//start with empty objects, only add object if ID exist. Reset ID
	var Segment []AppSegment
	//Checking app connector
	for _, v := range obj.Applications {
		_, ok := m[v.ID]
		if ok {
			v.ResetID(m)
			Segment = append(Segment, v)
		}
	}
	obj.Applications = Segment
	return notFound
}

//Servers parses zpa servers
type Server struct {
	Address           string   `json:"address"`
	AppServerGroupIds []string `json:"appServerGroupIds"`
	ConfigSpace       string   `json:"configSpace"`
	CreationTime      string   `json:"creationTime"`
	Description       string   `json:"description"`
	Enabled           bool     `json:"enabled"`
	ID                string   `json:"id"`
	ModifiedBy        string   `json:"modifiedBy"`
	ModifiedTime      string   `json:"modifiedTime"`
	Name              string   `json:"name"`
}

//GetID return the object name, ID
func (obj Server) GetID() (string, string) {
	return obj.Name, obj.ID
}

//Create creates the object on the ZPA tenant registered with the client
func (obj Server) Create(c *Client) (string, error) {
	return c.AddServer(obj)
}

//ResetID Only add objects if references to them exist on the map map[OldID]newID
func (obj *Server) ResetID(m map[string]string) bool {
	notFound := false
	//Reset own ID
	id, ok := m[obj.ID]
	if ok {
		obj.ID = id
	}
	//start with empty objects, only add object if ID exist. Reset ID
	var SrvGrp []string
	//Checking app connector
	for _, v := range obj.AppServerGroupIds {
		id, ok := m[v]
		if ok {
			SrvGrp = append(SrvGrp, id)
		}
	}
	obj.AppServerGroupIds = SrvGrp
	return notFound
}

//ServerGroup parses zpa servers
type ServerGroup struct {
	Applications       []NameID            `json:"applications,omitempty"`
	AppConnectorGroups []AppConnectorGroup `json:"appConnectorGroups,omitempty"`
	ConfigSpace        string              `json:"configSpace,omitempty"`
	CreationTime       string              `json:"creationTime,omitempty"`
	Description        string              `json:"description,omitempty"`
	Enabled            bool                `json:"enabled,omitempty"`
	ID                 string              `json:"id,omitempty,omitempty"`
	IPAnchored         bool                `json:"ipAnchored,omitempty"`
	DynamicDiscovery   bool                `json:"dynamicDiscovery,omitempty"`
	ModifiedBy         string              `json:"modifiedBy,omitempty"`
	ModifiedTime       string              `json:"modifiedTime,omitempty"`
	Name               string              `json:"name,omitempty"`
	Servers            []Server            `json:"servers,omitempty"`
}

//GetID return the object name,ID
func (obj ServerGroup) GetID() (string, string) {
	return obj.Name, obj.ID
}

//Create creates the object on the ZPA tenant registered with the client
func (obj ServerGroup) Create(c *Client) (string, error) {
	return c.AddServerGroup(obj)
}

//ResetID Only add objects if references to them exist on the map map[OldID]newID
func (obj *ServerGroup) ResetID(m map[string]string) bool {
	notFound := false
	//Reset own ID
	id, ok := m[obj.ID]
	if ok {
		obj.ID = id
	} else {
		notFound = true
	}
	//start with empty objects, only add object if ID exist. Reset ID
	var apps []NameID
	var connGrp []AppConnectorGroup
	var server []Server
	//Checking app segments
	for _, v := range obj.Applications {
		id, ok := m[v.ID]
		if ok {
			v.ID = id
			apps = append(apps, v)
		}
	}
	obj.Applications = apps
	//checking app connector groups
	for _, v := range obj.AppConnectorGroups {
		v.ResetID(m)
		connGrp = append(connGrp, v)
	}
	obj.AppConnectorGroups = connGrp
	//Checking Servers
	for _, v := range obj.Servers {
		//Adding only IDs
		v.ResetID(m)
		server = append(server, v)
	}
	obj.Servers = server
	return notFound
}

//AppConnector parses app connectors
type AppConnector struct {
	ApplicationStartTime             string   `json:"applicationStartTime"`
	AppConnectorGroupID              string   `json:"appConnectorGroupId"`
	AppConnectorGroupName            string   `json:"appConnectorGroupName"`
	ControlChannelStatus             string   `json:"controlChannelStatus"`
	CreationTime                     string   `json:"creationTime"`
	CtrlBrokerName                   string   `json:"ctrlBrokerName"`
	CurrentVersion                   string   `json:"currentVersion"`
	Description                      string   `json:"description"`
	Enabled                          bool     `json:"enabled"`
	ExpectedUpgradeTime              string   `json:"expectedUpgradeTime"`
	ExpectedVersion                  string   `json:"expectedVersion"`
	Fingerprint                      string   `json:"fingerprint"`
	ID                               string   `json:"id"`
	IPACL                            []string `json:"ipAcl"`
	IssuedCertID                     string   `json:"issuedCertId"`
	LastBrokerConnectTime            string   `json:"lastBrokerConnectTime"`
	LastBrokerConnectTimeDuration    string   `json:"lastBrokerConnectTimeDuration"`
	LastBrokerDisconnectTime         string   `json:"lastBrokerDisconnectTime"`
	LastBrokerDisconnectTimeDuration string   `json:"lastBrokerDisconnectTimeDuration"`
	LastUpgradeTime                  string   `json:"lastUpgradeTime"`
	Latitude                         string   `json:"latitude"`
	Location                         string   `json:"location"`
	Longitude                        string   `json:"longitude"`
	ModifiedBy                       string   `json:"modifiedBy"`
	ModifiedTime                     string   `json:"modifiedTime"`
	Name                             string   `json:"name"`
	ProvisioningKeyID                string   `json:"provisioningKeyId"`
	ProvisioningKeyName              string   `json:"provisioningKeyName"`
	Platform                         string   `json:"platform"`
	PreviousVersion                  string   `json:"previousVersion"`
	PrivateIP                        string   `json:"privateIp"`
	PublicIP                         string   `json:"publicIp"`
	SargeVersion                     string   `json:"sargeVersion"`
	EnrollmentCert                   struct {
		AdditionalProp1 string `json:"additionalProp1"`
		AdditionalProp2 string `json:"additionalProp2"`
		AdditionalProp3 string `json:"additionalProp3"`
	} `json:"enrollmentCert"`
	UpgradeAttempt string `json:"upgradeAttempt"`
	UpgradeStatus  string `json:"upgradeStatus"`
}

//GetID return the object name, ID
func (obj AppConnector) GetID() (string, string) {
	return obj.Name, obj.ID
}

//AppConnectorGroup hold app connector groups from zpa
type AppConnectorGroup struct {
	Connectors                    []AppConnector `json:"connectors,omitempty"`
	CityCountry                   string         `json:"cityCountry,omitempty"`
	CountryCode                   string         `json:"countryCode,omitempty"`
	CreationTime                  string         `json:"creationTime,omitempty"`
	Description                   string         `json:"description,omitempty"`
	DNSQueryType                  string         `json:"dnsQueryType,omitempty"`
	Enabled                       bool           `json:"enabled,omitempty"`
	GeoLocationID                 string         `json:"geoLocationId,omitempty"`
	ID                            string         `json:"id"`
	Latitude                      string         `json:"latitude,omitempty"`
	Location                      string         `json:"location,omitempty"`
	Longitude                     string         `json:"longitude,omitempty"`
	ModifiedBy                    string         `json:"modifiedBy,omitempty"`
	ModifiedTime                  string         `json:"modifiedTime,omitempty"`
	Name                          string         `json:"name,omitempty"`
	OverrideVersionProfile        bool           `json:"overrideVersionProfile"`
	ServerGroups                  []ServerGroup  `json:"serverGroups,omitempty"`
	LssAppConnectorGroup          bool           `json:"lssAppConnectorGroup,omitempty"`
	UpgradeDay                    string         `json:"upgradeDay,omitempty"`
	UpgradeTimeInSecs             string         `json:"upgradeTimeInSecs,omitempty"`
	VersionProfileID              string         `json:"versionProfileId,omitempty"`
	VersionProfileName            string         `json:"versionProfileName,omitempty"`
	VersionProfileVisibilityScope string         `json:"versionProfileVisibilityScope,omitempty"`
}

//GetID return the object name,ID
func (obj AppConnectorGroup) GetID() (string, string) {
	return obj.Name, obj.ID
}

//Create creates the object on the ZPA tenant registered with the client
func (obj AppConnectorGroup) Create(c *Client) (string, error) {
	return c.AddAppConnectorGroup(obj)
}

//ResetID Only add objects if references to them exist on the map map[OldID]newID
func (obj *AppConnectorGroup) ResetID(m map[string]string) bool {
	notFound := false
	//Reset own ID
	id, ok := m[obj.ID]
	if ok {
		obj.ID = id
	} else {
		notFound = true
	}
	//start with empty objects, only add object if ID exist. Reset ID
	var conn []AppConnector
	var SrvGrp []ServerGroup
	//Checking app connector
	tmp := ""
	for _, v := range obj.Connectors {
		id, ok := m[v.ID]
		if ok {
			v.ID = id
			conn = append(conn, v)
		} else {
			tmp += v.Name
		}
	}
	//Adding removed app connectors to descriptions
	if tmp != "" {
		obj.Description += "\n ---->Deleted non-configured app connectors:" + tmp
		notFound = true
	}
	obj.Connectors = conn
	//Checking Server groups
	for _, v := range obj.ServerGroups {
		id, ok := m[v.ID]
		if ok {
			v.ID = id
			SrvGrp = append(SrvGrp, v)
		}
	}
	obj.ServerGroups = SrvGrp
	return notFound
}

//PolicyConditions holds conditions for zpa policies
//check https://help.zscaler.com/zpa/access-policy-use-cases for valid options
type PolicyConditions struct {
	CreationTime string           `json:"creationTime,omitempty"`
	ID           string           `json:"id,omitempty"`
	ModifiedBy   string           `json:"modifiedBy,omitempty"`
	ModifiedTime string           `json:"modifiedTime,omitempty"`
	Negated      bool             `json:"negated,omitempty"`
	Operands     []PolicyOperands `json:"operands"`
	Operator     string           `json:"operator"` //Options: OR, AND
}

//PolicyConditions holds PolicyOperands for PolicyConditions used in zpa policies
//check https://help.zscaler.com/zpa/access-policy-use-cases for valid options
type PolicyOperands struct {
	CreationTime string `json:"creationTime,omitempty"`
	ID           string `json:"id,omitempty"`
	IdpID        string `json:"idpId,omitempty"`
	LHS          string `json:"lhs,omitempty"`
	ModifiedBy   string `json:"modifiedBy,omitempty"`
	ModifiedTime string `json:"modifiedTime,omitempty"`
	Name         string `json:"name,omitempty"`
	ObjectType   string `json:"objectType,omitempty"`
	RHS          string `json:"rhs,omitempty"`
}

//Policy parses policies from ZPA
type Policy struct {
	Action                   string              `json:"action"` //Supported values: ALLOW (default value) or DENY
	ActionID                 string              `json:"actionId,omitempty"`
	AppServerGroups          []ServerGroup       `json:"appServerGroups,omitempty"`
	AppConnectorGroups       []AppConnectorGroup `json:"appConnectorGroups,omitempty"`
	BypassDefaultRule        bool                `json:"bypassDefaultRule,omitempty"`
	Conditions               []PolicyConditions  `json:"conditions,omitempty"` //Array of operands with conditions to match the rule on
	CreationTime             string              `json:"creationTime,omitempty"`
	CustomMsg                string              `json:"customMsg,omitempty"`
	DefaultRule              bool                `json:"defaultRule,omitempty"`
	Description              string              `json:"description,omitempty"`
	ID                       string              `json:"id,omitempty"`
	IsolationDefaultRule     bool                `json:"isolationDefaultRule,omitempty"`
	ModifiedBy               string              `json:"modifiedBy,omitempty"`
	ModifiedTime             string              `json:"modifiedTime,omitempty"`
	Name                     string              `json:"name"`
	Operator                 string              `json:"operator,omitempty"`
	PolicySetID              string              `json:"policySetId,omitempty"`
	PolicyType               string              `json:"policyType,omitempty"`
	Priority                 string              `json:"priority,omitempty"`
	ReauthDefaultRule        bool                `json:"reauthDefaultRule,omitempty"`
	ReauthIdleTimeout        string              `json:"reauthIdleTimeout,omitempty"`
	ReauthTimeout            string              `json:"reauthTimeout,omitempty"`
	RuleOrder                string              `json:"ruleOrder,omitempty"`
	LssDefaultRule           bool                `json:"lssDefaultRule,omitempty"`
	ZpnCbiProfileID          string              `json:"zpnCbiProfileId,omitempty"`
	ZpnInspectionProfileID   string              `json:"zpnInspectionProfileId,omitempty"`
	ZpnInspectionProfileName string              `json:"zpnInspectionProfileName,omitempty"`
}

//Create creates the object on the ZPA tenant registered with the client
func (obj Policy) Create(c *Client) (string, error) {
	return c.AddPolicy(obj)
}

//ResetID Only add objects if references to them exist on the map map[OldID]newID
func (obj *Policy) ResetID(m map[string]string) bool {
	notFound := false
	//Reset own ID
	id, ok := m[obj.ID]
	if ok {
		obj.ID = id
	}
	//start with empty objects, only add object if ID exist. Reset ID
	var connGrp []AppConnectorGroup
	var SrvGrp []ServerGroup
	var conditions []PolicyConditions
	//Checking app connector groups
	appc := ""
	for _, v := range obj.AppConnectorGroups {
		found := v.ResetID(m)
		if found {
			connGrp = append(connGrp, v)
		} else {
			//Adding not found names to description and setting the nonFound flag.
			n, _ := v.GetID()
			appc += n + ","
			notFound = true
		}
	}
	if appc != "" {
		obj.Description += "\n---->Deleted not found app connector groups: " + appc
	}
	obj.AppConnectorGroups = connGrp
	//Checking Server groups
	srv := ""
	for _, v := range obj.AppServerGroups {
		found := v.ResetID(m)
		if found {
			SrvGrp = append(SrvGrp, v)
		} else {
			//Adding not ID names to description and setting the nonFound flag.
			n, _ := v.GetID()
			srv += n + ","
			notFound = true
		}
	}
	obj.AppServerGroups = SrvGrp
	if srv != "" {
		obj.Description += "\n---->Deleted not found server groups: " + srv
	}
	//conditions
	//Using https://help.zscaler.com/zpa/access-policy-use-cases#Viewanexampleresponse11 as reference
	for _, v := range obj.Conditions {
		condi := v
		var operands []PolicyOperands
		//it seems that only RHS IDs need to be changed. other IDs don't seem to fall under global IDs
		for _, v := range v.Operands {
			//RHS is the ID for the following types.
			//https://help.zscaler.com/zpa/access-policy-use-cases
			if v.ObjectType == "APP" || v.ObjectType == "APP_GROUP" || v.ObjectType == "CLOUD_CONNECTOR_GROUP" || v.ObjectType == "IDP" || v.ObjectType == "MACHINE_GRP" {
				id, ok := m[v.RHS]
				if ok {
					v.RHS = id                     //Adding new ID
					operands = append(operands, v) //appending it
				} else {
					obj.Description += "\n---->Deleted not found object type:\"" + v.ObjectType + "\" Name:\"" + v.Name + "\"."
					notFound = true
				}
				//LHS
			} else if v.ObjectType == "POSTURE" || v.ObjectType == "SAML" || v.ObjectType == "SCIM" || v.ObjectType == "SCIM_GROUP" || v.ObjectType == "TRUSTED_NETWORK" {
				id, ok := m[v.LHS]
				if ok {
					v.LHS = id                     //Adding new ID
					operands = append(operands, v) //appending it
				} else {
					obj.Description += "\n---->Deleted not found object type:\"" + v.ObjectType + "\" Name:\"" + v.Name + "\" Value:\"" + v.RHS + "\"."
					notFound = true
				}
				//Do nothing with CLIENT_TYPE
			} else if v.ObjectType == "CLIENT_TYPE" {
				operands = append(operands, v)
				//catch all
			} else {
				obj.Description += "\n---->Deleted not found criteria:\"" + v.ObjectType + "\" Name:\"" + v.Name + "\"."
				notFound = true
			}
		}
		//Saving changes if there's more than 1 operand
		if len(operands) > 0 {
			condi.Operands = operands
			conditions = append(conditions, condi)
		}
	} //
	obj.Conditions = conditions
	return notFound
}

//GetID return the object name, ID
func (obj Policy) GetID() (string, string) {
	return obj.Name, obj.ID
}

//PagedResponse parses http response from a paged GET request. List will be parsed later to the right object
type PagedResponse struct {
	Pages string          `json:"totalPages"`
	List  json.RawMessage `json:"list"`
}

//Creating object interface for ZPA objects that can be created with a Post request
type ObjectCreate interface {
	GetID() (string, string)
	Create(*Client) (string, error)
}

//Resettable Pointer allows to modify object and delete invalid references to non existing object IDs
type Resettable[B any] interface {
	*B                              // non-interface type constraint element
	ResetID(map[string]string) bool // Resets IDs inside element bases on old, new map ID and returns true if it's own ID was modified
}

//IDP holds the idp information
type IDP struct {
	AdminMetadata struct {
		CertificateURL string `json:"certificateUrl,omitempty"`
		SpBaseURL      string `json:"spBaseUrl,omitempty"`
		SpEntityID     string `json:"spEntityId,omitempty"`
		SpMetadataURL  string `json:"spMetadataUrl,omitempty"`
		SpPostURL      string `json:"spPostUrl,omitempty"`
	} `json:"adminMetadata,omitempty"`
	AdminSpSigningCertID int `json:"adminSpSigningCertId,omitempty"`
	AutoProvision        int `json:"autoProvision,omitempty"`
	Certificates         []struct {
		CName          string `json:"cName,omitempty"`
		Certificate    string `json:"certificate,omitempty"`
		SerialNo       string `json:"serialNo,omitempty"`
		ValidFromInSec int    `json:"validFromInSec,omitempty"`
		ValidToInSec   int    `json:"validToInSec,omitempty"`
	} `json:"certificates,omitempty"`
	CreationTime                int      `json:"creationTime,omitempty"`
	Description                 string   `json:"description,omitempty"`
	DisableSamlBasedPolicy      bool     `json:"disableSamlBasedPolicy,omitempty"`
	DomainList                  []string `json:"domainList,omitempty"`
	EnableScimBasedPolicy       bool     `json:"enableScimBasedPolicy,omitempty"`
	Enabled                     bool     `json:"enabled,omitempty"`
	ID                          int      `json:"id,omitempty"`
	IdpEntityID                 string   `json:"idpEntityId,omitempty"`
	LoginNameAttribute          string   `json:"loginNameAttribute,omitempty"`
	LoginURL                    string   `json:"loginUrl,omitempty"`
	ModifiedBy                  int      `json:"modifiedBy,omitempty"`
	ModifiedTime                int      `json:"modifiedTime,omitempty"`
	Name                        string   `json:"name,omitempty"`
	ReauthOnUserUpdate          bool     `json:"reauthOnUserUpdate,omitempty"`
	RedirectBinding             bool     `json:"redirectBinding,omitempty"`
	ScimEnabled                 bool     `json:"scimEnabled,omitempty"`
	ScimServiceProviderEndpoint string   `json:"scimServiceProviderEndpoint,omitempty"`
	ScimSharedSecretExists      bool     `json:"scimSharedSecretExists,omitempty"`
	SignSamlRequest             int      `json:"signSamlRequest,omitempty"`
	SsoType                     []string `json:"ssoType,omitempty"`
	UseCustomSPMetadata         bool     `json:"useCustomSPMetadata,omitempty"`
	UserMetadata                struct {
		CertificateURL string `json:"certificateUrl,omitempty"`
		SpBaseURL      string `json:"spBaseUrl,omitempty"`
		SpEntityID     string `json:"spEntityId,omitempty"`
		SpMetadataURL  string `json:"spMetadataUrl,omitempty"`
		SpPostURL      string `json:"spPostUrl,omitempty"`
	} `json:"userMetadata,omitempty"`
	UserSpSigningCertID int `json:"userSpSigningCertId,omitempty"`
}

//SCIMAttr holds the IDP scim attributes
type SCIMAttr struct {
	CanonicalValues []string `json:"canonicalValues"`
	CaseSensitive   bool     `json:"caseSensitive,omitempty"`
	CreationTime    int      `json:"creationTime,omitempty"`
	DataType        string   `json:"dataType,omitempty"`
	Description     string   `json:"description,omitempty"`
	ID              int      `json:"id,omitempty"`
	IdpID           int      `json:"idpId,omitempty"`
	ModifiedBy      int      `json:"modifiedBy,omitempty"`
	ModifiedTime    int      `json:"modifiedTime,omitempty"`
	Multivalued     bool     `json:"multivalued,omitempty"`
	Mutability      string   `json:"mutability,omitempty"`
	Name            string   `json:"name"`
	Required        bool     `json:"required,omitempty"`
	Returned        string   `json:"returned,omitempty"`
	SchemaURI       string   `json:"schemaURI,omitempty"`
	Uniqueness      bool     `json:"uniqueness,omitempty"`
}

//SCIMGroup holds the IDP scim groups
type SCIMGroup struct {
	CreationTime int    `json:"creationTime,omitempty"`
	ID           int    `json:"id,omitempty,omitempty"`
	IdpGroupID   string `json:"idpGroupId,omitempty"`
	IdpID        int    `json:"idpId,omitempty"`
	ModifiedTime int    `json:"modifiedTime,omitempty"`
	Name         string `json:"name,omitempty"`
}

//PostureProfile holds the configured posture profiles
type PostureProfile struct {
	CreationTime      int    `json:"creationTime,omitempty"`
	Domain            string `json:"domain,omitempty"`
	ID                int    `json:"id,omitempty"`
	MasterCustomerID  string `json:"masterCustomerId,omitempty"`
	ModifiedBy        int    `json:"modifiedBy,omitempty"`
	ModifiedTime      int    `json:"modifiedTime,omitempty"`
	Name              string `json:"name,omitempty"`
	PostureUdid       string `json:"postureUdid,omitempty"`
	ZscalerCloud      string `json:"zscalerCloud,omitempty"`
	ZscalerCustomerID int    `json:"zscalerCustomerId,omitempty"`
}

//Struct helpers

//NamedID helps json structs with name and id
type NameID struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

////////////////////////
//Section for API calls
////////////////////////

//GetAppSegments gets a list of app segments
func (c *Client) GetAppSegments() ([]AppSegment, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/application"
	return GetPaged(c, 500, path, []AppSegment{})
}

//AddAppSegment adds an app segments
func (c *Client) AddAppSegment(obj AppSegment) (string, error) {
	obj.ID = ""
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/application"
	tmp, err := PostObj(c, path, obj)
	return tmp.ID, err
}

//EditAppSegment edits the provided app segment
func (c *Client) EditAppSegment(obj AppSegment) error {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/application"
	return PutObj(c, path, obj, obj.ID)
}

//DeleteAppSegment edits the provided app segment
func (c *Client) DeleteAppSegment(id string) error {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/application"
	return DelObj(c, path, id)
}

//GetSegmentGroups gets a list of segment groups
func (c *Client) GetSegmentGroups() ([]SegmentGroup, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/segmentGroup"
	return GetPaged(c, 500, path, []SegmentGroup{})
}

//AddSegmentGroup adds an app segments
func (c *Client) AddSegmentGroup(obj SegmentGroup) (string, error) {
	obj.ID = ""
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/segmentGroup"
	tmp, err := PostObj(c, path, obj)
	return tmp.ID, err
}

//EditSegmentGroup edits the provided app segment
func (c *Client) EditSegmentGroup(obj SegmentGroup) error {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/segmentGroup"
	return PutObj(c, path, obj, obj.ID)
}

//DeleteSegmentGroup edits the provided app segment
func (c *Client) DeleteSegmentGroup(id string) error {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/segmentGroup"
	return DelObj(c, path, id)
}

//GetServers gets a list of servers
func (c *Client) GetServers() ([]Server, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/server"
	return GetPaged(c, 500, path, []Server{})
}

//AddServer adds a server
func (c *Client) AddServer(obj Server) (string, error) {
	obj.ID = ""
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/server"
	tmp, err := PostObj(c, path, obj)
	return tmp.ID, err
}

//EditServer edits the provided server
func (c *Client) EditServer(obj Server) error {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/server"
	return PutObj(c, path, obj, obj.ID)
}

//DeleteServer edits the provided server
func (c *Client) DeleteServer(id string) error {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/server"
	return DelObj(c, path, id)
}

//GetServers gets a list of servers
func (c *Client) GetServerGroups() ([]ServerGroup, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/serverGroup"
	return GetPaged(c, 500, path, []ServerGroup{})
}

//AddServer adds a server
func (c *Client) AddServerGroup(obj ServerGroup) (string, error) {
	obj.ID = ""
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/serverGroup"
	tmp, err := PostObj(c, path, obj)
	return tmp.ID, err
}

//EditServer edits the provided server
func (c *Client) EditServerGroup(obj ServerGroup) error {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/serverGroup"
	return PutObj(c, path, obj, obj.ID)
}

//DeleteServer edits the provided server
func (c *Client) DeleteServerGroup(id string) error {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/serverGroup"
	return DelObj(c, path, id)
}

//GetAppConnectors gets a list of all app connectors
func (c *Client) GetAppConnectors() ([]AppConnector, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/connector"
	return GetPaged(c, 500, path, []AppConnector{})
}

//EditAppConnector edits the provided AppConnector
func (c *Client) EditAppConnector(obj AppConnector) error {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/connector"
	return PutObj(c, path, obj, obj.ID)
}

//DeleteAppConnector edits the provided AppConnector
func (c *Client) DeleteAppConnector(id string) error {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/connector"
	return DelObj(c, path, id)
}

//GetAppConnectorGroups gets a list of all app connectors
func (c *Client) GetAppConnectorGroups() ([]AppConnectorGroup, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/appConnectorGroup"
	return GetPaged(c, 500, path, []AppConnectorGroup{})
}

//AddAppConnectorGroup adds a AppConnectorGroup
func (c *Client) AddAppConnectorGroup(obj AppConnectorGroup) (string, error) {
	obj.ID = ""
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/appConnectorGroup"
	tmp, err := PostObj(c, path, obj)
	return tmp.ID, err
}

//EditAppConnectorGroup edits the provided AppConnectorGroup
func (c *Client) EditAppConnectorGroup(obj AppConnectorGroup) error {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/appConnectorGroup"
	return PutObj(c, path, obj, obj.ID)
}

//DeleteAppConnectorGroup edits the provided AppConnectorGroup
func (c *Client) DeleteAppConnectorGroup(id string) error {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/appConnectorGroup"
	return DelObj(c, path, id)
}

//GetAccessPolicyID gets the global ID for your access policies
func (c *Client) GetAccessPolicyID() (string, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/policyType/ACCESS_POLICY"
	obj, err := GetObj(c, path, Policy{})
	return obj.ID, err
}

//GetReAuthPolicyID gets the global ID for your re-authentication policies
func (c *Client) GetReAuthPolicyID() (string, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/policyType/REAUTH_POLICY"
	obj, err := GetObj(c, path, Policy{})
	return obj.ID, err
}

//GetSIEMPolicyID gets the global ID for your SIEM policies
func (c *Client) GetSIEMPolicyID() (string, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/policyType/SIEM_POLICY"
	obj, err := GetObj(c, path, Policy{})
	return obj.ID, err
}

//GetBypassPolicyID gets the global ID for your bypass policies
func (c *Client) GetBypassPolicyID() (string, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/policyType/BYPASS_POLICY"
	obj, err := GetObj(c, path, Policy{})
	return obj.ID, err
}

//GetAccessPolicies gets a list your access policies
func (c *Client) GetAccessPolicies() ([]Policy, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/rules/policyType/ACCESS_POLICY"
	return GetPaged(c, 500, path, []Policy{})
}

//GetAccessPolicies gets a list of your reauth policies
func (c *Client) GetReAuthPolicies() ([]Policy, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/rules/policyType/REAUTH_POLICY"
	return GetPaged(c, 500, path, []Policy{})
}

//GetAccessPolicies gets a list of your SIEM policies
func (c *Client) GetSIEMPolicies() ([]Policy, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/rules/policyType/SIEM_POLICY"
	return GetPaged(c, 500, path, []Policy{})
}

//GetAccessPolicies gets a list of your bypass policies
func (c *Client) GetBypassPolicies() ([]Policy, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/rules/policyType/BYPASS_POLICY"
	return GetPaged(c, 500, path, []Policy{})
}

//GetIDPs gets a list of your idps
func (c *Client) GetIDPs() ([]IDP, error) {
	path := "/mgmtconfig/v2/admin/customers/" + c.CustomerId + "/idp"
	return GetPaged(c, 500, path, []IDP{})
}

//GetSCIMAttributes gets a list of the scim attributes for a given idp
func (c *Client) GetSCIMAttributes(idpID string) ([]SCIMAttr, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/idp/" + idpID + "/scimattribute"
	return GetPaged(c, 500, path, []SCIMAttr{})
}

//GetSCIMAttrValues gets a list of the scim attributes values for a given attribute
func (c *Client) GetSCIMAttrValues(idpID string, attributeID string) ([]string, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/idp/" + idpID + "/attributeID/" + attributeID
	return GetPaged(c, 500, path, []string{})
}

//GetSCIMGroups gets a list of the scim attributes values for a given attribute
func (c *Client) GetSCIMGroups(idpID string) ([]SCIMGroup, error) {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/scimgroup/idp/" + idpID
	return GetPaged(c, 500, path, []SCIMGroup{})
}

//GetSCIMGroups gets a list of the scim attributes values for a given attribute
func (c *Client) GetPostureProfiles() ([]PostureProfile, error) {
	path := "/mgmtconfig/v2/admin/customers/" + c.CustomerId + "/posture"
	return GetPaged(c, 500, path, []PostureProfile{})
}

//AddPolicy adds a policy to the specified policy set
//Accepted policy type options are "access", "reauth", "siem", "bypass"
//Function NewClient() returns a client with the policyIDs, if you're not using this function make sure the client has those variables.
//You can use functions GetXXXXPolicyID() to get the needed policy ID
func (c *Client) AddPolicy(obj Policy) (string, error) {
	obj.ID = ""
	path := ""
	if c.Policy == "access" {
		path = "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/" + c.AccessID + "/rule"
	} else if c.Policy == "reauth" {
		path = "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/" + c.ReauthID + "/rule"
	} else if c.Policy == "siem" {
		path = "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/" + c.SiemID + "/rule"
	} else if c.Policy == "bypass" {
		path = "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/" + c.BypassID + "/rule"
	} else {
		return "", errors.New("Please request the right policy type.")
	}
	postBody, _ := json.Marshal(obj)
	body, err := c.postRequest(path, postBody)
	if err != nil {
		return obj.ID, err
	}
	err = json.Unmarshal(body, &obj)
	if err != nil {
		return obj.ID, err
	}
	return obj.ID, nil
}

//EditPolicy edits the policy to the specified policy set and the ID on the passed Policy object.
//you can get the policysetID with GetAccessPolicyID(), GetReAuthPolicyID(),GetSIEMPolicyID(), GetBypassPolicyID() depending on the policy type
func (c *Client) EditPolicy(obj Policy, policySetID string) error {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/" + policySetID + "/rule/" + obj.ID
	postBody, _ := json.Marshal(obj)
	return c.putRequest(path, postBody)
}

//DeletePolicy edits the policy to the specified policy set and the ID on the passed Policy object.
//Accepted c policy type options are "access", "reauth", "siem", "bypass", default is access policy
//you can get the policysetID with GetAccessPolicyID(), GetReAuthPolicyID(),GetSIEMPolicyID(), GetBypassPolicyID() depending on the policy type
func (c *Client) DeletePolicy(policyID string) error {
	path := ""
	if c.Policy == "reauth" {
		path = "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/" + c.ReauthID + "/rule/" + policyID
	} else if c.Policy == "siem" {
		path = "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/" + c.SiemID + "/rule/" + policyID
	} else if c.Policy == "bypass" {
		path = "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/" + c.BypassID + "/rule/" + policyID
	} else {
		path = "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/" + c.AccessID + "/rule/" + policyID
	}
	return c.deleteRequest(path)
}

//Reorder edits the policy to the specified policy set based on the passed new order
//you can get the policysetID with GetAccessPolicyID(), GetReAuthPolicyID(),GetSIEMPolicyID(), GetBypassPolicyID() depending on the policy type
func (c *Client) ReorderPolicy(ruleID string, policySetID string, newOrder int) error {
	path := "/mgmtconfig/v1/admin/customers/" + c.CustomerId + "/policySet/" + policySetID + "/rule/" + ruleID + "/reorder/" + strconv.Itoa(newOrder)
	return c.putRequest(path, nil)
}

//////////////////
//Helper functions
//////////////////
//Generic functions to iterate over all paged results, requieres a client, pagesize usually default is 50 and max 500, and the object the response will be unmarshalled to.
func GetPaged[K any](c *Client, pageSize int, path string, obj []K) ([]K, error) {
	//Init struct to parse response
	var res PagedResponse
	//Setting the 1st page number
	page := 1
	//Creating tmp struct to unmarshal to.
	tmp := obj
	//iterating over all pages to get all
	for {
		npath := path + "?page=" + strconv.Itoa(page) + "&pagesize=" + strconv.Itoa(pageSize)
		body, err := c.getRequest(npath)
		if err != nil {
			return obj, err
		}
		// Unmarshal response
		err = json.Unmarshal(body, &res)
		if err != nil {
			return obj, err
		}
		//Return if pages == 0, meaning there are no objects return empty list and no erro
		if res.Pages == "0" {
			return obj, nil
		}
		//Unmarshall List into object
		err = json.Unmarshal(res.List, &tmp)
		if err != nil {
			return obj, err
		}
		obj = append(obj, tmp...)
		//Getting total pages and checking which page we're iterating with
		tpage, err := strconv.Atoi(res.Pages)
		if err != nil {
			return obj, err
		}
		if tpage <= page {
			break
		} else {
			page += 1
		}
	}
	return obj, nil
}

//PostObj : Generic function to marshal an object and send it as HTTP post
func PostObj[K any](c *Client, path string, obj K) (K, error) {
	postBody, _ := json.Marshal(obj)
	body, err := c.postRequest(path, postBody)
	if err != nil {
		return obj, err
	}
	err = json.Unmarshal(body, &obj)
	if err != nil {
		return obj, err
	}
	return obj, nil
}

//Get : Generic function to marshal a GET request
func GetObj[K any](c *Client, path string, tmp K) (K, error) {
	body, err := c.getRequest(path)
	if err != nil {
		return tmp, err
	}
	err = json.Unmarshal(body, &tmp)
	if err != nil {
		return tmp, err
	}
	return tmp, nil
}

//PutObj : Generic function to marshal an object and send it as HTTP put
func PutObj[K any](c *Client, path string, obj K, id string) error {
	path += "/" + id
	postBody, _ := json.Marshal(obj)
	return c.putRequest(path, postBody)
}

//DelObj : Generic function to delete an object based on its id
func DelObj(c *Client, path string, id string) error {
	path += "/" + id
	return c.deleteRequest(path)
}

//do Function de send the HTTP request and return the response and error
func (c *Client) do(req *http.Request) ([]byte, error) {
	retryMax := c.RetryMax
	//Adding auth header
	req.Header.Add("Authorization", "Bearer "+c.Token)
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

//NewClientBase returns a client with the auth header, default http timeouts and max retries per requests
func NewClientBase(BaseURL string, client_id string, client_secret string, CustomerId string) (*Client, error) {
	//Validating URL
	_, err := url.Parse(BaseURL)
	if err != nil {
		return &Client{}, errors.New("failed to parse API URL")
	}
	//Getting access token
	access_token, err := KeyGen(BaseURL, client_id, client_secret)
	if err != nil {
		return &Client{}, err
	}
	//Returning client
	return &Client{
		BaseURL: BaseURL,
		HTTPClient: &http.Client{
			Timeout: time.Second * 10,
		},
		RetryMax:   10,
		Token:      access_token,
		CustomerId: CustomerId,
	}, nil
}

//NewClientBase returns a client with the auth header, default http timeouts and max retries per requests
//In addition it adds the policy IDs for ZPA
func NewClient(BaseURL string, client_id string, client_secret string, CustomerId string) (*Client, error) {
	//Getting a base client
	c, err := NewClientBase(BaseURL, client_id, client_secret, CustomerId)
	if err != nil {
		return c, err
	}
	//Getting policy ID
	c.AccessID, err = c.GetAccessPolicyID()
	if err != nil {
		return c, err
	}
	//Getting reauth policy ID
	c.ReauthID, err = c.GetReAuthPolicyID()
	if err != nil {
		return c, err
	}
	//Getting SIEM policy ID
	c.SiemID, err = c.GetSIEMPolicyID()
	if err != nil {
		return c, err
	}
	//Getting reauth policy ID
	c.BypassID, err = c.GetBypassPolicyID()
	if err != nil {
		return c, err
	}
	return c, err
}

//KeyGen function gets the authentication parameter and returns the bearer token which is the header that authenticates the requests
func KeyGen(BaseURL string, client_id string, client_secret string) (string, error) {
	form := url.Values{}
	form.Add("client_id", client_id)
	form.Add("client_secret", client_secret)
	client := http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Post(BaseURL+"/signin", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	//Check for anything but an http 200 and then parse body
	err = httpStatusCheck(resp)
	if err != nil {
		return "", err
	}
	//Parsing response
	var token myToken
	err = json.NewDecoder(resp.Body).Decode(&token)
	if err != nil {
		return "", err
	}
	return token.Token, nil
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

//Process and sends HTTP Delete requests
func (c *Client) deleteRequest(path string) error {
	req, err := http.NewRequest(http.MethodDelete, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	_, err = c.do(req)
	return err
}
