package config

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type OriginConfig struct {
	FrontendURL   string
	BackendDomain string
	IsHTTPS       bool
	IsLocal       bool
}

func LoadOriginConfig() (*OriginConfig, error) {
	frontendOrigin := os.Getenv("ORIGIN_FRONTEND")
	if frontendOrigin == "" {
		return nil, fmt.Errorf("ORIGIN_FRONTEND is not defined")
	}

	backendURL := os.Getenv("URL_BACKEND")
	if backendURL == "" {
		return nil, fmt.Errorf("URL_BACKEND is not defined")
	}

	backendDomain := ""
	if parsedURL, err := url.Parse(backendURL); err == nil {
		backendDomain = parsedURL.Hostname()
	} else {
		return nil, fmt.Errorf("invalid URL_BACKEND: %v", err)
	}

	config := &OriginConfig{
		FrontendURL:   frontendOrigin,
		BackendDomain: backendDomain,
		IsHTTPS:       strings.HasPrefix(frontendOrigin, "https://"),
		IsLocal:       strings.Contains(backendURL, "localhost"),
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

func (oc *OriginConfig) GetCookieDomain() string {
	if oc.IsLocal {
		return ""
	}

	frontendDomain := ""
	if parsedURL, err := url.Parse(oc.FrontendURL); err == nil {
		frontendDomain = parsedURL.Hostname()
	}

	if oc.areSubdomainsOfSame(frontendDomain, oc.BackendDomain) {
		baseDomain := oc.getBaseDomain(frontendDomain, oc.BackendDomain)
		if baseDomain != "" {
			return "." + baseDomain
		}
	}

	return ""
}

func (oc *OriginConfig) areSubdomainsOfSame(domain1, domain2 string) bool {
	domain1 = strings.TrimPrefix(domain1, "www.")
	domain2 = strings.TrimPrefix(domain2, "www.")

	// If they are the same, not subdomains
	if domain1 == domain2 {
		return false
	}

	parts1 := strings.Split(domain1, ".")
	parts2 := strings.Split(domain2, ".")

	if len(parts1) < 2 || len(parts2) < 2 {
		return false
	}

	base1 := parts1[len(parts1)-2] + "." + parts1[len(parts1)-1]
	base2 := parts2[len(parts2)-2] + "." + parts2[len(parts2)-1]

	return base1 == base2
}

func (oc *OriginConfig) getBaseDomain(domain1, domain2 string) string {
	domain1 = strings.TrimPrefix(domain1, "www.")
	domain2 = strings.TrimPrefix(domain2, "www.")

	parts1 := strings.Split(domain1, ".")
	parts2 := strings.Split(domain2, ".")

	if len(parts1) >= 2 && len(parts2) >= 2 {
		base1 := parts1[len(parts1)-2] + "." + parts1[len(parts1)-1]
		base2 := parts2[len(parts2)-2] + "." + parts2[len(parts2)-1]

		if base1 == base2 {
			return base1
		}
	}

	return ""
}
