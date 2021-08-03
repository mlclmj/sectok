package sectok

import (
	"crypto/subtle"
	"fmt"
	"net/url"
	"regexp"
	"unicode/utf8"
)

type SecretToken struct {
	token []byte
}

const (
	URIScheme         = "secret-token"
	URIPattern        = `^secret-token:[a-zA-Z0-9\-._~%]+$`
	URIFormat  string = "secret-token:%s"
)

var (
	compiledPattern = regexp.MustCompile(URIPattern)
)

// FromString creates a new SecretToken from a string, returning a new
// SecretToken instance or an error if invalid UTF-8 characters are
// present.
func New(token string) (SecretToken, error) {
	return NewFromBytes([]byte(token))
}

// FromBytes creates a new SecretToken from a slice of bytes, returning a
// pointer to a SecretToken instance or an error if invalid UTF-8 characters are
// present.
func NewFromBytes(token []byte) (SecretToken, error) {
	if len(token) == 0 {
		return SecretToken{}, fmt.Errorf("secret tokens cannot be empty")
	}

	if !utf8.Valid(token) {
		return SecretToken{}, fmt.Errorf("invalid UTF-8 character in secret token")
	}

	return SecretToken{token: token}, nil
}

func Parse(uri string) (SecretToken, error) {
	return ParseBytes([]byte(uri))
}

func ParseBytes(uri []byte) (SecretToken, error) {
	// token is already in URI format
	if match := compiledPattern.Match(uri); !match {
		return SecretToken{}, fmt.Errorf("could not parse secret token from URI")
	}
	t, err := decode(uri)
	return SecretToken{token: t}, err
}

// String can be used to generate a string representation of a SecretToken URI.
// Use Equals() to compare two SecretTokens
func (s SecretToken) String() string {
	return fmt.Sprintf(URIFormat, url.QueryEscape(string(s.token)))
}

// Equals can be used to check if two SecretTokens match, using a constant-time
// comparison.
func (s SecretToken) Equals(s2 SecretToken) bool {
	return subtle.ConstantTimeCompare([]byte(s.token), []byte(s2.token)) == 1
}

// primitive to decode a token from a URI
func decode(uri []byte) ([]byte, error) {
	token := uri[len(URIScheme)+1:]
	unesc, err := url.QueryUnescape(string(token))
	if err != nil {
		return []byte{}, fmt.Errorf("error unescaping token")
	}
	return []byte(unesc), nil
}
