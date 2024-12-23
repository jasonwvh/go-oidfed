package config

import (
	"github.com/stretchr/testify/assert/yaml"
	"log"
	"os"

	"github.com/zachmann/go-oidfed/pkg"
)

type OIDCProviderConfig struct {
	Issuer                string `yaml:"issuer"`
	AuthorizationEndpoint string `yaml:"authorization_endpoint"`
	TokenEndpoint         string `yaml:"token_endpoint"`
	UserinfoEndpoint      string `yaml:"userinfo_endpoint"`
	JWKSURI               string `yaml:"jwks_uri"`
}

type config struct {
	EntityID           string                                    `yaml:"entity_id" json:"entity_id,omitempty"`
	TrustAnchors       pkg.TrustAnchors                          `yaml:"trust_anchors" json:"trust_anchors,omitempty"`
	AuthorityHints     []string                                  `yaml:"authority_hints" json:"authority_hints,omitempty"`
	OrganisationName   string                                    `yaml:"organisation_name" json:"organisation_name,omitempty"`
	ServerAddr         string                                    `yaml:"server_addr" json:"server_addr,omitempty"`
	KeyStorage         string                                    `yaml:"key_storage" json:"key_storage,omitempty"`
	OnlyAutomaticOPs   bool                                      `yaml:"filter_to_automatic_ops" json:"only_automatic_o_ps,omitempty"`
	EnableDebugLog     bool                                      `yaml:"enable_debug_log" json:"enable_debug_log,omitempty"`
	TrustMarks         []*pkg.EntityConfigurationTrustMarkConfig `yaml:"trust_marks" json:"trust_marks,omitempty"`
	UseResolveEndpoint bool                                      `yaml:"use_resolve_endpoint" json:"use_resolve_endpoint,omitempty"`
	OidcProviderConfig OIDCProviderConfig                        `yaml:"oidc_provider_config" json:"oidc_provider_config"`
}

var Conf *config

func MustLoadConfig() {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatal(err)
	}
	Conf = &config{}
	if err = yaml.Unmarshal(data, Conf); err != nil {
		log.Fatal(err)
	}
	if Conf.KeyStorage == "" {
		log.Fatal("key_storage must be given")
	}
	d, err := os.Stat(Conf.KeyStorage)
	if err != nil {
		log.Fatal(err)
	}
	if !d.IsDir() {
		log.Fatalf("key_storage '%s' must be a directory", Conf.KeyStorage)
	}
	if Conf.EnableDebugLog {
		pkg.EnableDebugLogging()
	}
	for _, c := range Conf.TrustMarks {
		if err = c.Verify(Conf.EntityID, ""); err != nil {
			log.Fatal(err)
		}
	}
}
