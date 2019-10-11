// Package auth provide user Account authentification and authorization service
package auth

import (
	"strings"
	"time"

	"github.com/gofrs/uuid"
)

// CookieSessionName of the token
const CookieSessionName = "session_token"

// Account represent an user account
type Account struct {
	//swagger:strfmt uuid
	ID uuid.UUID `json:"id,omitempty"`
	//swagger:strfmt email
	Email     string    `json:"email,omitempty"`
	Validated bool      `json:"validated,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

// AppToken represent an app token.
//
// It is associated to an Account and provide access to different API via roles.
// An AppToken must be validate, it can be named. To revoke simply delete it
// or set the ExpiredAt to past or current time.
//
// swagger:response appToken
type AppToken struct {
	//example: qNNDZeWVFAOYZw_gCX7M2csgR_8W5HpnSWV2i8MZC68
	Token string `json:"app_token,omitempty"`
	//example: NESGQUHmUFdLaVjBH39
	ValidToken string `json:"validation_token,omitempty"`
	Name       string `json:"name,omitempty"`
	//example: sensor
	Type  string `json:"type,omitempty"`
	Roles Roles  `json:"roles,omitempty"`

	//swagger:strfmt uuid
	AID     uuid.UUID `json:"account_id,omitempty"`
	Account *Account  `json:"account,omitempty"`

	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	ExpiredAt time.Time `json:"expired_at,omitempty"`
}

// Roles is a list of name with their authorization (r: read, w: write)
type Roles map[string]string

// IsMatching a set of roles with a wanted subset of roles
func (roles Roles) IsMatching(wanted Roles) (bool, string) {
	for name, rw := range wanted {
		name = strings.ToLower(name)
		rw = strings.ToLower(rw)

		grw, ok := roles[name]
		grw = strings.ToLower(grw)
		if !ok || !strings.Contains(grw, rw) {
			return false, name + "=" + rw
		}
	}
	return true, ""
}
