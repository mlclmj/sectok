package sectok

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {

	tests := []struct {
		name      string
		input     string
		rawToken  []byte
		expectErr bool
	}{
		{"simple token", "token", []byte("token"), false},
		{"complex utf-8", "🐶", []byte("🐶"), false},
		{"url decodable chars", "%F0%9F%90%B6", []byte("%F0%9F%90%B6"), false},
		{"edge case", "secret-token:", []byte("secret-token:"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := New(tc.input)
			assert.Equal(t, tc.rawToken, tok.token)
			assert.True(t, (tc.expectErr && err == nil) || (!tc.expectErr && err == nil))
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		rawToken  []byte
		expectErr bool
	}{
		{"simple token", "secret-token:token", []byte("token"), false},
		{"complex utf-8", "secret-token:%F0%9F%90%B6", []byte("🐶"), false},
		{"edge case", "secret-token:", []byte(nil), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := Parse(tc.input)
			assert.Equal(t, tc.rawToken, tok.token)
			if tc.expectErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestSecretToken_String(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		output string
	}{
		{"simple token", "token", "secret-token:token"},
		{"complex utf-8", "🐶", "secret-token:%F0%9F%90%B6"},
		{"url decodable chars", "%F0%9F%90%B6", "secret-token:%25F0%259F%2590%25B6"},
		{"edge case", "secret-token:", "secret-token:secret-token%3A"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := New(tc.input)
			assert.Nil(t, err)
			assert.Equal(t, tc.output, tok.String())
		})
	}
}

func TestSecretToken_Equals(t *testing.T) {
	a := SecretToken{token: []byte("test-token")}
	b := SecretToken{token: []byte("test-token")}
	c := SecretToken{token: []byte("test-token-different")}

	assert.True(t, a.Equals(b))
	assert.False(t, a.Equals(c))
}
