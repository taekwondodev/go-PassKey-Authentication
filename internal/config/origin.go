package config

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type OriginConfig struct {
	URL     string
	IsHTTPS bool
	Domain  string
	IsLocal bool
	RPID    string
}

func LoadOriginConfig() (*OriginConfig, error) {
	origin := os.Getenv("ORIGIN")
	if origin == "" {
		return nil, fmt.Errorf("ORIGIN is not defined")
	}

	config := &OriginConfig{
		URL:     origin,
		IsHTTPS: strings.HasPrefix(origin, "https://"),
		IsLocal: strings.Contains(origin, "localhost"),
	}

	if parsedURL, err := url.Parse(origin); err == nil {
		config.RPID = parsedURL.Hostname()

		if config.IsHTTPS {
			config.Domain = parsedURL.Hostname()
		} else {
			config.Domain = ""
		}
	}

	return config, nil
}

func (oc *OriginConfig) GetCookieSameSite() http.SameSite {
	if oc.IsHTTPS {
		return http.SameSiteStrictMode
	} else if oc.IsLocal {
		return http.SameSiteLaxMode
	}
	return http.SameSiteNoneMode
}
