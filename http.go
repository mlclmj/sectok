package sectoken

import (
	"fmt"
	"net/http"
	"regexp"
)

const (
	HeaderKey string = "Authorization"

	HeaderValuePattern = `^Bearer: .+$`
	HeaderValueFormat  = "Bearer: %s"
)

var (
	compiledHeaderValuePattern = regexp.MustCompile(HeaderValuePattern)
)

// FromRequest parses the provided request's headers to create a SecretToken
func FromRequest(req *http.Request) (*SecretToken, error) {
	if req == nil {
		return nil, fmt.Errorf("request was nil")
	}
	raw := req.Header.Get(HeaderKey)
	if compiledHeaderValuePattern.MatchString(raw) {
		return nil, fmt.Errorf("no token in request")
	}
	return NewFromURI(raw)
}

// AddToRequest adds the SecretToken specified to the headers of the request
func AddToRequest(req *http.Request, s *SecretToken) error {
	if req == nil || s == nil {
		// not allowable
		return fmt.Errorf("nah")
	}
	req.Header.Set(HeaderKey, fmt.Sprintf(HeaderValueFormat, s))
	return nil
}
