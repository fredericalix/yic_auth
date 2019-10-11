package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/labstack/echo"
)

// Middleware handle the authentifiaction and authorization of the request.
// It accept http header or cookie.
// If the session is valid an auth.Account is put in the echo.Context in the key "account".
func Middleware(valid ValidSession, wanted Roles) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {

			// try to extract session token from HTTP header
			tokenstr := strings.TrimPrefix(c.Request().Header.Get("Authorization"), "Bearer ")
			if len(tokenstr) == 0 {
				// try to extract session token from HTTP cookie
				cookie, err := c.Cookie("session_token")
				if err != nil {
					return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Missing authentification header or cookie."})
				}
				tokenstr = cookie.Value
			}

			// validate token
			a, roles, err := valid.Valid(c.Request().Context(), tokenstr)
			if err != nil {
				c.Logger().Errorf("Auth %v", err)
				return c.JSON(http.StatusUnauthorized, map[string]string{"message": err.Error()})
			}

			if match, missing := roles.IsMatching(wanted); !match {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"message": fmt.Sprintf("Missing authorization: %s.", missing),
				})
			}
			// Pass every authorization

			c.Set("account", a)
			c.Set("roles", roles)

			return next(c)
		}
	}
}

// NewValidHTTP autheticate a token by checking to a remote HTTP auth service
func NewValidHTTP(url string) ValidSession {
	return &validHTTP{url: strings.TrimRight(url, "/")}
}

type validHTTP struct{ url string }

func (v validHTTP) Valid(ctx context.Context, token string) (Account, Roles, error) {
	nurl := v.url + "/" + url.PathEscape(token)

	client := &http.Client{
		Timeout: 10 * time.Second,
		// Transport: &http.Transport{
		// 	IdleConnTimeout: 10 * time.Second,
		// },
	}
	req, err := http.NewRequest(http.MethodGet, nurl, nil)
	if err != nil {
		return Account{}, Roles{}, err
	}
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return Account{}, Roles{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Account{}, Roles{}, fmt.Errorf("invalid token")
	}
	defer resp.Body.Close()
	var at AppToken
	err = json.NewDecoder(resp.Body).Decode(&at)
	if err != nil {
		return Account{}, Roles{}, err
	}
	return *at.Account, at.Roles, nil
}

// ValidSession is an interface to abstract the way a session token is authentificated
type ValidSession interface {
	Valid(ctx context.Context, token string) (Account, Roles, error)
}
