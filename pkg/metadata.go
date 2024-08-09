package pkg

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
)

type Metadata struct {
	OpenIDProvider           *OpenIDProviderMetadata           `json:"openid_provider,omitempty"`
	RelyingParty             *OpenIDRelyingPartyMetadata       `json:"openid_relying_party,omitempty"`
	OAuthAuthorizationServer *OAuthAuthorizationServerMetadata `json:"oauth_authorization_server,omitempty"`
	OAuthClient              *OAuthClientMetadata              `json:"oauth_client,omitempty"`
	OAuthProtectedResource   *OAuthProtectedResourceMetadata   `json:"oauth_resource,omitempty"`
	FederationEntity         *FederationEntityMetadata         `json:"federation_entity,omitempty"`
}

type policyApplicable interface {
	ApplyPolicy(policy MetadataPolicy) (any, error)
}

func (m Metadata) ApplyPolicy(p *MetadataPolicies) (*Metadata, error) {
	if p == nil {
		return &m, nil
	}
	t := reflect.TypeOf(m)
	v := reflect.ValueOf(m)
	out := &Metadata{}
	for i := 0; i < t.NumField(); i++ {
		policy, policyOk := reflect.ValueOf(*p).Field(i).Interface().(MetadataPolicy)
		if !policyOk || policy == nil {
			reflect.Indirect(reflect.ValueOf(out)).Field(i).Set(v.Field(i))
			continue
		}
		var metadata policyApplicable
		f := v.Field(i)
		if f.IsNil() {
			continue
		}
		var ok bool
		metadata, ok = v.Field(i).Interface().(policyApplicable)
		if !ok {
			continue
		}
		applied, err := metadata.ApplyPolicy(policy)
		if err != nil {
			return nil, err
		}
		reflect.Indirect(reflect.ValueOf(out)).Field(i).Set(reflect.ValueOf(applied))
	}
	return out, nil
}

type metadatas interface {
	*OpenIDProviderMetadata | *OpenIDRelyingPartyMetadata | *OAuthAuthorizationServerMetadata | *OAuthClientMetadata | *OAuthProtectedResourceMetadata | *FederationEntityMetadata
}

func applyPolicy[M metadatas](metadata M, policy MetadataPolicy, ownTag string) (any, error) {
	if policy == nil {
		return metadata, nil
	}
	v := reflect.ValueOf(metadata)
	t := v.Elem().Type()
	for i := 0; i < t.NumField(); i++ {
		j, ok := t.Field(i).Tag.Lookup("json")
		if !ok {
			continue
		}
		j = strings.TrimSuffix(j, ",omitempty")
		p, ok := policy[j]
		if !ok {
			continue
		}
		f := reflect.Indirect(v).Field(i)
		value, err := p.ApplyTo(f.Interface(), fmt.Sprintf("%s.%s", ownTag, j))
		if err != nil {
			return nil, err
		}
		rV := reflect.ValueOf(value)
		if rV.IsValid() {
			f.Set(rV)
		}
	}

	return metadata, nil
}

type OpenIDRelyingPartyMetadata struct {
	Scope                                 string   `json:"scope,omitempty"`
	RedirectURIS                          []string `json:"redirect_uris,omitempty"`
	ResponseTypes                         []string `json:"response_types,omitempty"`
	GrantTypes                            []string `json:"grant_types,omitempty"`
	ApplicationType                       string   `json:"application_type,omitempty"`
	Contacts                              []string `json:"contacts,omitempty"`
	ClientName                            string   `json:"client_name,omitempty"`
	LogoURI                               string   `json:"logo_uri,omitempty"`
	ClientURI                             string   `json:"client_uri,omitempty"`
	PolicyURI                             string   `json:"policy_uri,omitempty"`
	TOSURI                                string   `json:"tos_uri,omitempty"`
	SectorIdentifierURI                   string   `json:"sector_identifier_uri,omitempty"`
	SubjectType                           string   `json:"subject_type,omitempty"`
	IDTokenSignedResponseAlg              string   `json:"id_token_signed_response_alg,omitempty"`
	IDTokenEncryptedResponseAlg           string   `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc           string   `json:"id_token_encrypted_response_enc,omitempty"`
	UserinfoSignedResponseAlg             string   `json:"userinfo_signed_response_alg,omitempty"`
	UserinfoEncryptedResponseAlg          string   `json:"userinfo_encrypted_response_alg,omitempty"`
	UserinfoEncryptedResponseEnc          string   `json:"userinfo_encrypted_response_enc,omitempty"`
	RequestSignedResponseAlg              string   `json:"request_signed_response_alg,omitempty"`
	RequestEncryptedResponseAlg           string   `json:"request_encrypted_response_alg,omitempty"`
	RequestEncryptedResponseEnc           string   `json:"request_encrypted_response_enc,omitempty"`
	TokenEndpointAuthMethod               string   `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg           string   `json:"token_endpoint_auth_signing_alg,omitempty"`
	DefaultMaxAge                         int64    `json:"default_max_age,omitempty"`
	RequireAuthTime                       bool     `json:"require_auth_time,omitempty"`
	DefaultACRValues                      []string `json:"default_acr_values,omitempty"`
	InitiateLoginURI                      string   `json:"initiate_login_uri,omitempty"`
	RequestURIs                           []string `json:"request_uris,omitempty"`
	SoftwareID                            string   `json:"software_id,omitempty"`
	SoftwareVersion                       string   `json:"software_version,omitempty"`
	ClientID                              string   `json:"client_id,omitempty"`
	ClientSecret                          string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt                      int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt                 int64    `json:"client_secret_expires_at,omitempty"`
	RegistrationAccessToken               string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI                 string   `json:"registration_client_uri,omitempty"`
	ClaimsRedirectURIs                    []string `json:"claims_redirect_uris,omitempty"`
	NFVTokenSignedResponseAlg             string   `json:"nfv_token_signed_response_alg,omitempty"`
	NFVTokenEncryptedResponseAlg          string   `json:"nfv_token_encrypted_response_alg,omitempty"`
	NFVTokenEncryptedResponseEnc          string   `json:"nfv_token_encrypted_response_enc,omitempty"`
	TLSClientCertificateBoundAccessTokens bool     `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	TLSClientAuthSubjectDN                string   `json:"tls_client_auth_subject_dn,omitempty"`
	TLSClientAuthSANDNS                   string   `json:"tls_client_auth_san_dns,omitempty"`
	TLSClientAuthSANURI                   string   `json:"tls_client_auth_san_uri,omitempty"`
	TLSClientAuthSANIP                    string   `json:"tls_client_auth_san_ip,omitempty"`
	TLSClientAuthSANEMAIL                 string   `json:"tls_client_auth_san_email,omitempty"`
	RequireSignedRequestObject            bool     `json:"require_signed_request_object,omitempty"`
	RequirePushedAuthorizationRequests    bool     `json:"require_pushed_authorization_requests,omitempty"`
	IntrospectionSignedResponseAlg        string   `json:"introspection_signed_response_alg,omitempty"`
	IntrospectionEncryptedResponseAlg     string   `json:"introspection_encrypted_response_alg,omitempty"`
	IntrospectionEncryptedResponseEnc     string   `json:"introspection_encrypted_response_enc,omitempty"`
	FrontchannelLogoutURI                 string   `json:"frontchannel_logout_uri,omitempty"`
	FrontchannelLogoutSessionRequired     bool     `json:"frontchannel_logout_session_required,omitempty"`
	BackchannelLogoutURI                  string   `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired      bool     `json:"backchannel_logout_session_required,omitempty"`
	PostLogoutRedirectURIs                []string `json:"post_logout_redirect_uris,omitempty"`
	AuthorizationDetailsTypes             []string `json:"authorization_details_types,omitempty"`
	ClientRegistrationTypes               []string `json:"client_registration_types"`

	CommonMetadata

	Extra map[string]interface{} `json:"-"`
}

func (m OpenIDRelyingPartyMetadata) MarshalJSON() ([]byte, error) {
	type openIDRelyingPartyMetadata OpenIDRelyingPartyMetadata
	explicitFields, err := json.Marshal(openIDRelyingPartyMetadata(m))
	if err != nil {
		return nil, err
	}
	return extraMarshalHelper(explicitFields, m.Extra)
}

func (m *OpenIDRelyingPartyMetadata) UnmarshalJSON(data []byte) error {
	type openIDRelyingPartyMetadata OpenIDRelyingPartyMetadata
	mm := openIDRelyingPartyMetadata(*m)
	if mm.JWKS == nil {
		mm.JWKS = jwk.NewSet()
	}
	extra, err := unmarshalWithExtra(data, &mm)
	if err != nil {
		return err
	}
	mm.Extra = extra
	if mm.JWKS.Len() == 0 {
		mm.JWKS = nil
	}
	*m = OpenIDRelyingPartyMetadata(mm)
	return nil
}

func (m OpenIDRelyingPartyMetadata) ApplyPolicy(policy MetadataPolicy) (any, error) {
	return applyPolicy(&m, policy, "openid_relying_party")
}

type OpenIDProviderMetadata struct {
	Issuer                                                    string            `json:"issuer"`
	AuthorizationEndpoint                                     string            `json:"authorization_endpoint"`
	TokenEndpoint                                             string            `json:"token_endpoint"`
	UserinfoEndpoint                                          string            `json:"userinfo_endpoint,omitempty"`
	RegistrationEndpoint                                      string            `json:"registration_endpoint,omitempty"`
	ScopesSupported                                           []string          `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                                    []string          `json:"response_types_supported"`
	ResponseModesSupported                                    []string          `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                       []string          `json:"grant_types_supported,omitempty"`
	ACRValuesSupported                                        []string          `json:"acr_values_supported,omitempty"`
	SubjectTypesSupported                                     []string          `json:"subject_types_supported"`
	IDTokenSignedResponseAlgValuesSupported                   []string          `json:"id_token_signed_response_alg_values_supported,omitempty"`
	IDTokenEncryptedResponseAlgValuesSupported                []string          `json:"id_token_encrypted_response_alg_values_supported,omitempty"`
	IDTokenEncryptedResponseEncValuesSupported                []string          `json:"id_token_encrypted_response_enc_values_supported,omitempty"`
	UserinfoSignedResponseAlgValuesSupported                  []string          `json:"userinfo_signed_response_alg_values_supported,omitempty"`
	UserinfoEncryptedResponseAlgValuesSupported               []string          `json:"userinfo_encrypted_response_alg_values_supported,omitempty"`
	UserinfoEncryptedResponseEncValuesSupported               []string          `json:"userinfo_encrypted_response_enc_values_supported,omitempty"`
	RequestSignedResponseAlgValuesSupported                   []string          `json:"request_signed_response_alg_values_supported,omitempty"`
	RequestEncryptedResponseAlgValuesSupported                []string          `json:"request_encrypted_response_alg_values_supported,omitempty"`
	RequestEncryptedResponseEncValuesSupported                []string          `json:"request_encrypted_response_enc_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                         []string          `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported                []string          `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	DisplayValuesSupported                                    []string          `json:"display_values_supported,omitempty"`
	ClaimsSupported                                           []string          `json:"claims_supported,omitempty"`
	ServiceDocumentation                                      string            `json:"service_documentation,omitempty"`
	ClaimsLocalesSupported                                    []string          `json:"claims_locales_supported,omitempty"`
	UILocalesSupported                                        []string          `json:"ui_locales_supported,omitempty"`
	ClaimsParameterSupported                                  bool              `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported                                 bool              `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported                              bool              `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration                             bool              `json:"require_request_uri_registration,omitempty"`
	OPPolicyURI                                               string            `json:"op_policy_uri,omitempty"`
	OPTOSURI                                                  string            `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                                        string            `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported                    []string          `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported           []string          `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                                     string            `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported                 []string          `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported        []string          `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionSigningAlgValuesSupported                    []string          `json:"introspection_signing_alg_values_supported,omitempty"`
	IntrospectionEncryptionAlgValuesSupported                 []string          `json:"introspection_encryption_alg_values_supported,omitempty"`
	IntrospectionEncryptionEncValuesSupported                 []string          `json:"introspection_encryption_enc_values_supported,omitempty"`
	CodeChallengeMethodsSupported                             []string          `json:"code_challenge_methods_supported,omitempty"`
	SignedMetadata                                            string            `json:"signed_metadata,omitempty"`
	DeviceAuthorizationEndpoint                               string            `json:"device_authorization_endpoint,omitempty"`
	TLSClientCertificateBoundAccessTokens                     bool              `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	MTLSEndpointAliases                                       map[string]string `json:"mtls_endpoint_aliases,omitempty"`
	NFVTokenSigningAlgValuesSupported                         []string          `json:"nfv_token_signing_alg_values_supported,omitempty"`
	NFVTokenEncryptionAlgValuesSupported                      []string          `json:"nfv_token_encryption_alg_values_supported,omitempty"`
	NFVTokenEncryptionEncValuesSupported                      []string          `json:"nfv_token_encryption_enc_values_supported,omitempty"`
	RequireSignedRequestObject                                bool              `json:"require_signed_request_object,omitempty"`
	PushedAuthorizationRequestEndpoint                        string            `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthorizationRequests                        bool              `json:"require_pushed_authorization_requests,omitempty"`
	AuthorizationResponseIssParameterSupported                bool              `json:"authorization_response_iss_parameter_supported,omitempty"`
	CheckSessionIFrame                                        string            `json:"check_session_iframe,omitempty"`
	FrontchannelLogoutSupported                               bool              `json:"frontchannel_logout_supported,omitempty"`
	BackchannelLogoutSupported                                bool              `json:"backchannel_logout_supported,omitempty"`
	BackchannelLogoutSessionSupported                         bool              `json:"backchannel_logout_session_supported,omitempty"`
	EndSessionEndpoint                                        string            `json:"end_session_endpoint,omitempty"`
	BackchannelTokenDeliveryModesSupported                    []string          `json:"backchannel_token_delivery_modes_supported,omitempty"`
	BackchannelAuthenticationEndpoint                         string            `json:"backchannel_authentication_endpoint,omitempty"`
	BackchannelAuthenticationRequestSigningAlgValuesSupported []string          `json:"backchannel_authentication_request_signing_alg_values_supported,omitempty"`
	BackchannelUserCodeParameterSupported                     bool              `json:"backchannel_user_code_parameter_supported,omitempty"`
	AuthorizationDetailsTypesSupported                        []string          `json:"authorization_details_types_supported,omitempty"`

	ClientRegistrationTypesSupported               []string            `json:"client_registration_types_supported"`
	FederationRegistrationEndpoint                 string              `json:"federation_registration_endpoint,omitempty"`
	RequestAuthenticationMethodsSupported          map[string][]string `json:"request_authentication_methods_supported,omitempty"`
	RequestAuthenticationSigningAlgValuesSupported []string            `json:"request_authentication_signing_alg_values_supported,omitempty"`

	CommonMetadata

	Extra map[string]interface{} `json:"-"`
}

func (m OpenIDProviderMetadata) MarshalJSON() ([]byte, error) {
	type openIDProviderMetadata OpenIDProviderMetadata
	explicitFields, err := json.Marshal(openIDProviderMetadata(m))
	if err != nil {
		return nil, err
	}
	return extraMarshalHelper(explicitFields, m.Extra)
}

func (m *OpenIDProviderMetadata) UnmarshalJSON(data []byte) error {
	type openIDProviderMetadata OpenIDProviderMetadata
	mm := openIDProviderMetadata(*m)
	if mm.JWKS == nil {
		mm.JWKS = jwk.NewSet()
	}
	extra, err := unmarshalWithExtra(data, &mm)
	if err != nil {
		return err
	}
	mm.Extra = extra
	if mm.JWKS.Len() == 0 {
		mm.JWKS = nil
	}
	*m = OpenIDProviderMetadata(mm)
	return nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface for usage with caching
func (m OpenIDProviderMetadata) MarshalBinary() ([]byte, error) {
	return json.Marshal(m)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface for usage with caching
func (m *OpenIDProviderMetadata) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, &m)
}

// ApplyPolicy apples a MetadataPolicy the the OpenIDProviderMetadata
func (m OpenIDProviderMetadata) ApplyPolicy(policy MetadataPolicy) (any, error) {
	return applyPolicy(&m, policy, "openid_provider")
}

type OAuthClientMetadata OpenIDRelyingPartyMetadata
type OAuthAuthorizationServerMetadata OpenIDProviderMetadata

// MarshalJSON implements the json.Marshaler interface
func (m OAuthAuthorizationServerMetadata) MarshalJSON() ([]byte, error) {
	return json.Marshal(OpenIDProviderMetadata(m))
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (m *OAuthAuthorizationServerMetadata) UnmarshalJSON(data []byte) error {
	op := OpenIDProviderMetadata(*m)
	if err := json.Unmarshal(data, &op); err != nil {
		return err
	}
	*m = OAuthAuthorizationServerMetadata(op)
	return nil
}
func (m OAuthAuthorizationServerMetadata) ApplyPolicy(policy MetadataPolicy) (any, error) {
	return applyPolicy(&m, policy, "oauth_authorization_server")
}

func (m OAuthClientMetadata) MarshalJSON() ([]byte, error) {
	return json.Marshal(OpenIDRelyingPartyMetadata(m))
}
func (m *OAuthClientMetadata) UnmarshalJSON(data []byte) error {
	rp := OpenIDRelyingPartyMetadata(*m)
	if err := json.Unmarshal(data, &rp); err != nil {
		return err
	}
	*m = OAuthClientMetadata(rp)
	return nil
}
func (m OAuthClientMetadata) ApplyPolicy(policy MetadataPolicy) (any, error) {
	return applyPolicy(&m, policy, "oauth_client")
}

type OAuthProtectedResourceMetadata struct {
	Resource                             string   `json:"resource,omitempty"`
	AuthorizationServers                 []string `json:"authorization_servers,omitempty"`
	ScopesSupported                      []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported               []string `json:"bearer_methods_supported,omitempty"`
	ResourceSigningAlgValuesSupported    []string `json:"resource_signing_alg_values_supported,omitempty"`
	ResourceEncryptionAlgValuesSupported []string `json:"resource_encryption_alg_values_supported"`
	ResourceEncryptionEncValuesSupported []string `json:"resource_encryption_enc_values_supported"`
	ResourceDocumentation                string   `json:"resource_documentation,omitempty"`
	ResourcePolicyURI                    string   `json:"resource_policy_uri,omitempty"`
	ResourceTOSURI                       string   `json:"resource_tos_uri,omitempty"`

	CommonMetadata

	Extra map[string]interface{} `json:"-"`
}

func (m OAuthProtectedResourceMetadata) MarshalJSON() ([]byte, error) {
	type oauthProtectedResourceMetadata OAuthProtectedResourceMetadata
	explicitFields, err := json.Marshal(oauthProtectedResourceMetadata(m))
	if err != nil {
		return nil, err
	}
	return extraMarshalHelper(explicitFields, m.Extra)
}

func (m *OAuthProtectedResourceMetadata) UnmarshalJSON(data []byte) error {
	type oauthProtectedResourceMetadata OAuthProtectedResourceMetadata
	mm := oauthProtectedResourceMetadata(*m)
	if mm.JWKS == nil {
		mm.JWKS = jwk.NewSet()
	}
	extra, err := unmarshalWithExtra(data, &mm)
	if err != nil {
		return err
	}
	mm.Extra = extra
	if mm.JWKS.Len() == 0 {
		mm.JWKS = nil
	}
	*m = OAuthProtectedResourceMetadata(mm)
	return nil
}

func (m OAuthProtectedResourceMetadata) ApplyPolicy(policy MetadataPolicy) (any, error) {
	return applyPolicy(&m, policy, "oauth_resource")
}

type CommonMetadata struct {
	SignedJWKSURI string  `json:"signed_jwks_uri,omitempty"`
	JWKSURI       string  `json:"jwks_uri,omitempty"`
	JWKS          jwk.Set `json:"jwks,omitempty"`

	OrganizationName string   `json:"organization_name,omitempty"`
	Contacts         []string `json:"contacts,omitempty"`
	LogoURI          string   `json:"logo_uri,omitempty"`
	PolicyURI        string   `json:"policy_uri,omitempty"`
	HomepageURI      string   `json:"homepage_uri,omitempty"`
}

type FederationEntityMetadata struct {
	FederationFetchEndpoint           string `json:"federation_fetch_endpoint,omitempty"`
	FederationListEndpoint            string `json:"federation_list_endpoint,omitempty"`
	FederationResolveEndpoint         string `json:"federation_resolve_endpoint,omitempty"`
	FederationTrustMarkStatusEndpoint string `json:"federation_trust_mark_status_endpoint,omitempty"`
	FederationTrustMarkListEndpoint   string `json:"federation_trust_mark_list_endpoint,omitempty"`
	FederationTrustMarkEndpoint       string `json:"federation_trust_mark_endpoint,omitempty"`
	FederationHistoricalLKeysEndpoint string `json:"federation_historical_keys_endpoint,omitempty"`

	CommonMetadata

	Extra map[string]interface{} `json:"-"`
}

func (m FederationEntityMetadata) MarshalJSON() ([]byte, error) {
	type federationEntityMetadata FederationEntityMetadata
	explicitFields, err := json.Marshal(federationEntityMetadata(m))
	if err != nil {
		return nil, err
	}
	return extraMarshalHelper(explicitFields, m.Extra)
}

func (m *FederationEntityMetadata) UnmarshalJSON(data []byte) error {
	type federationEntityMetadata FederationEntityMetadata
	mm := federationEntityMetadata(*m)
	extra, err := unmarshalWithExtra(data, &mm)
	if err != nil {
		return err
	}
	mm.Extra = extra
	*m = FederationEntityMetadata(mm)
	return nil
}
func (m FederationEntityMetadata) ApplyPolicy(policy MetadataPolicy) (any, error) {
	return applyPolicy(&m, policy, "federation_entity")
}
