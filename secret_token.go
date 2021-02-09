package sectoken

import (
	"crypto/subtle"
	"fmt"
	"net/url"
	"regexp"
	"unicode/utf8"
)

type SecretToken struct {
	token string
}

const (
	URIScheme  string = "secret-token"
	URIPattern        = `^secret-token:[a-zA-Z0-9\-._~%]+$`
	URIFormat         = "secret-token:%s"
)

var (
	compiledPattern = regexp.MustCompile(URIPattern)
)

// NewFromString creates a new SecretToken from a string, returning a pointer
// to a SecretToken instance or an error if invalid UTF-8 characters are
// present.
func NewFromString(token string) (*SecretToken, error) {
	return NewFromBytes([]byte(token))
}

// NewFromBytes creates a new SecretToken from a slice of bytes, returning a
// pointer to a SecretToken instance or an error if invalid UTF-8 characters are
// present.
func NewFromBytes(token []byte) (*SecretToken, error) {
	if len(token) < 1 {
		return nil, fmt.Errorf("secret tokens cannot be empty")
	}
	if !utf8.Valid(token) {
		return nil, fmt.Errorf("invalid UTF-8 token")
	}
	return &SecretToken{token: url.QueryEscape(string(token))}, nil
}

// NewFromURI creates a new SecretToken from a URI string, returning a pointer
// to a SecretToken instance or an error if the URI is invalid or invalid UTF-8
// characters are present.
func NewFromURI(uri string) (*SecretToken, error) {
	match := compiledPattern.MatchString(uri)
	if !match {
		return nil, fmt.Errorf("not a valid secret token URI")
	}

	// TODO: normalize the URI

	return &SecretToken{token: crack(uri)}, nil
}

// String can be used to generate a string representation of a SecretToken URI.
// Use Equals()
func (s *SecretToken) String() string {
	return fmt.Sprintf(URIFormat, s.token)
}

// Equals can be used to check if two SecretTokens match, using a constant-time
// comparison.
func (s *SecretToken) Equals(s2 SecretToken) bool {
	return subtle.ConstantTimeCompare([]byte(s.token), []byte(s2.token)) == 1
}

// crack can only be used on URIs that have been validated.
func crack(uri string) string {
	return uri[len(URIScheme)+2 : len(uri)+1]
}
