// Package traefik_plugin_ldap http basic authentication from ldap.
package traefik_plugin_ldap

import (
	"github.com/go-ldap/ldap/v3"
	"context"
	"fmt"
	"net/http"
	"encoding/base64"
	"strings"
)

// Config the plugin configuration.
type Config struct {
	LdapUrl string `json:"url,omitempty"`
	LdapUserBaseDN string `json:"userBaseDN,omitempty"`
	LdapUserAttribute string `json:"userAttribute,omitempty"`
	LdapGroupBaseDN string `json:"groupBaseDN,omitempty"`
	LdapGroupFilter  string `json:"groupFilter,omitempty"` // %s = username
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		LdapUrl: "ldap://ldap:389",
		LdapUserBaseDN: "ou=People,dc=example,dc=org",
		LdapUserAttribute: "uid",
	}
}

// LdapAuth a LDAP plugin.
type LdapAuth struct {
	name              string
	next              http.Handler
	ldapurl           string
	ldapuserbasedn    string
	ldapuserattribute string
	ldapgroupbasedn   string
	ldapgroupfilter   string
}

// New create a new LDAP plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.LdapUrl) == 0 {
		return nil, fmt.Errorf("LDAP url cannot be empty")
	}
	if len(config.LdapUserBaseDN) == 0 {
		return nil, fmt.Errorf("LDAP useBaseDN cannot be empty")
	}
	if len(config.LdapUserAttribute) == 0 {
		return nil, fmt.Errorf("LDAP userAttribute cannot be empty")
	}
	if len(config.LdapGroupFilter) != 0 {
		// validate filter by compiling it
		_, err := ldap.CompileFilter(fmt.Sprintf(config.LdapGroupFilter,"testuser"))
		if err != nil {
			return nil, err
		}
	}

	return &LdapAuth{
		name:     name,
		next:     next,
		ldapurl:  config.LdapUrl,
		ldapuserbasedn: config.LdapUserBaseDN,
		ldapuserattribute: config.LdapUserAttribute,
		ldapgroupbasedn: config.LdapGroupBaseDN,
		ldapgroupfilter: config.LdapGroupFilter,
	}, nil
}

func (a *LdapAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	authHeader := req.Header.Get("Authorization")
	if len(authHeader) == 0 {
		rw.Header().Set("WWW-Authenticate", `Basic realm="LDAP Login"`)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	authParts := strings.Fields(authHeader)
	if len(authParts) != 2 {
		http.Error(rw, "Error parsing Authorization header", http.StatusBadRequest)
		return
	}

	authType := authParts[0]
	if authType != "Basic" {
		http.Error(rw, "Unknown Authorization type", http.StatusBadRequest)
		return
	}

	authUsername, authPassword, err := decodeCredentials(authParts[1])
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	auth_ok, err := doAuth(
		authUsername,
		authPassword,
		a.ldapurl,
		a.ldapuserbasedn,
		a.ldapuserattribute,
		a.ldapgroupbasedn,
		a.ldapgroupfilter,
	)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if ! auth_ok {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}
	a.next.ServeHTTP(rw, req)
}

// extract username and password from base64-encoded string
func decodeCredentials(str string) (string, string, error) {
	byte, decodeErr := base64.StdEncoding.DecodeString(str)
	if decodeErr != nil {
		return "", "", fmt.Errorf("Error decoding base64")
	}
	parts := strings.SplitN(string(byte), ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("Unable to extract username and password")
	}
	return parts[0], parts[1], nil
}

// authenticate against LDAP server
func doAuth(
	username string,
	password string,
	ldapURL string,
	userBaseDN string,
	userAttribute string,
	groupBaseDN string,
	groupFilter string,
) (bool, error) {
	var err error

	// Connect to LDAP server
	l, err := ldap.DialURL(ldapURL)
	// l, err := ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		return false, err
	}
	defer l.Close()

	// // Now reconnect with TLS
	// err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// Authenticate user
	err = l.Bind(fmt.Sprintf("%s=%s,%s", userAttribute, username, userBaseDN), password)
	if err != nil {
		return false, err
	}

	// Match group filter
	if groupFilter != "" && groupBaseDN != "" {
		sr := ldap.NewSearchRequest(
			groupBaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			fmt.Sprintf(groupFilter,username),
			nil,
			nil,
		)
		ret, err := l.Search(sr)
		if err != nil {
			return false, err
		}
		for range ret.Entries {
			return true, nil
		}
		return false, nil
	}
	return true, nil
}
