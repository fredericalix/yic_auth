// Authentification service
//
//     Schemes: http, https
//     Host: localhost:2020
//     Version: 0.0.1
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//
// swagger:meta
package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/goware/emailx"
	"github.com/spf13/viper"

	auth "github.com/fredericalix/yic_auth"

	_ "net/http/pprof"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

type handler struct {
	store  *PostgreSQL
	rabbit *rabbitMQService

	url     string
	isHTTPS bool

	expValidation time.Duration
	expAppToken   time.Duration

	tokenTmpl  *template.Template
	signupTmpl *template.Template
	loginTmpl  *template.Template
	emailSrv   *emailService
}

func main() {
	viper.AutomaticEnv()
	viper.SetDefault("PORT", 1234)
	viper.SetDefault("EXPIRATION_VALIDATION", 24*time.Hour)
	viper.SetDefault("EXPIRATION_APP_TOKEN", 360*24*time.Hour)
	viper.SetDefault("ADMIN_USERNAME", "admin")
	viper.SetDefault("ADMIN_PASSWORD", "admin")

	configFile := flag.String("config", "./config.toml", "path of the config file")
	flag.Parse()
	viper.SetConfigFile(*configFile)
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		log.Printf("cannot read config file: %v\nUse env instead\n", err)
	}

	h := &handler{
		store:   NewPostgreSQL(viper.GetString("POSTGRESQL_URI")),
		url:     strings.TrimRight(viper.GetString("EXTERNAL_URL"), "/"),
		isHTTPS: strings.HasPrefix(viper.GetString("EXTERNAL_URL"), "https"),

		expValidation: viper.GetDuration("EXPIRATION_VALIDATION"),
		expAppToken:   viper.GetDuration("EXPIRATION_APP_TOKEN"),
		emailSrv:      newEmailService(viper.GetString("RABBITMQ_URI")),
		tokenTmpl:     template.Must(template.ParseFiles("./static/token_validation.html")),
		loginTmpl:     template.Must(template.ParseFiles("./static/login_email.html")),
		signupTmpl:    template.Must(template.ParseFiles("./static/signup_email.html")),
	}
	h.rabbit, err = newTokenNotificationService(h.emailSrv.conn, h.store)
	if err != nil {
		panic(err)
	}

	// Set endpoint handlers
	e := echo.New()
	e.Use(middleware.Logger())

	a := e.Group("/auth")
	a.GET("/debug/pprof/*", echo.WrapHandler(http.DefaultServeMux), middleware.Rewrite(map[string]string{"/auth/*": "/$1"}))

	a.POST("/signup", h.Signup)             // /auth/signup
	a.POST("/login", h.Login)               // /auth/login
	a.GET("/email/:token", h.ValidateEmail) // /auth/email/:token
	a.GET("/roles", roles)
	a.GET("/check/:token", h.CheckToken)

	// authMiddleware, err := auth.MiddlewareLocalCacheFromAMQP(viper.GetString("rabbitmq"), auth.Roles{"account": "rw"})
	// if err != nil {
	// 	panic(err)
	// }
	account := e.Group("/account", h.directAuth(auth.Roles{"account": "rw"}))
	account.GET("/token", h.findTokens)
	account.POST("/token", h.createToken)
	account.DELETE("/token/:token", h.revokeToken)

	// admin part please set a long and strong password
	admin := e.Group("/account/admin", middleware.BasicAuth(func(username, password string, c echo.Context) (bool, error) {
		if username == viper.GetString("ADMIN_USERNAME") && password == viper.GetString("ADMIN_PASSWORD") {
			return true, nil
		}
		return false, nil
	}))
	admin.GET("", h.listAccount)
	admin.POST("", h.createAccount)
	admin.DELETE("/:aid", h.deleteAccount)

	// start the server
	host := fmt.Sprintf(":%d", viper.GetInt("PORT"))
	tlscert := viper.GetString("TLS_CERT")
	tlskey := viper.GetString("TLS_KEY")
	if tlscert == "" || tlskey == "" {
		e.Logger.Error("No cert or key provided. Start server using HTTP instead of HTTPS !")
		e.Logger.Fatal(e.Start(host))
	}
	e.Logger.Fatal(e.StartTLS(host, tlscert, tlskey))
}

var rolesType = map[string]auth.Roles{
	"web": auth.Roles{
		"account": "rw",
		"sensor":  "r",
		"ui":      "rw",
	},
	"sensor": auth.Roles{
		"sensor": "w",
	},
	"ui": auth.Roles{
		"sensor": "r",
		"ui":     "rw",
	},
	"editor": auth.Roles{
		"sensor": "r",
		"ui":     "rw",
	},
	"view": auth.Roles{
		"sensor": "r",
		"ui":     "r",
	},
	"god": auth.Roles{
		"account": "rw",
		"sensor":  "rw",
		"ui":      "rw",
	},
}

func authorizationFromType(typ string) (auth.Roles, error) {
	role, found := rolesType[typ]
	if !found {
		return nil, fmt.Errorf("unknown roles type")
	}
	return role, nil
}

// Possible roles
// swagger:response rolesResponse
type rolesResponse struct {
	//in:body
	Body map[string]auth.Roles
}

// swagger:route GET /auth/roles roles
//
// Roles
//
// Specify all possible roles that a token can take with the definition of there authorizations.
//
//     Consumes:
//     - application/json
//     Produces:
//     - application/json
//     Schemes: http, https
//     Responses:
//     	200: rolesResponse
func roles(c echo.Context) error {
	return c.JSON(http.StatusOK, rolesType)
}

// Error
// swagger:response genericError
type apiError struct {
	// in: body
	Body struct {
		Message string `json:"message"`
	}
}

// Successfull
// swagger:response loginResponse
type loginResponse struct {
	// in: body
	// required: true
	Body struct {
		// example: qNNDZeWVFAOYZw_gCX7M2csgR_8W5HpnSWV2i8MZC68
		AppToken string `json:"app_token"`
	}
}

// swagger:parameters loginParam Signup Login
type loginParam struct {
	//
	// in: body
	// required: true
	Body struct {
		// required: true
		// example: your@email.com
		//
		Email string `json:"email"`
		// required: true
		// description: the role type of the created token
		// example: sensor
		Type string `json:"type"`
		// example: Application name
		Name string `json:"name,omitempty"`
	}
}

// Signup to yourITcity services
//
// swagger:route POST /auth/signup Signup
//
// Signup
//
// Signup to yourITcity services. To be validated you must follow the link sent you by email.
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: loginResponse
//       400:
//       500:
func (h *handler) Signup(c echo.Context) (err error) {
	corrID := randID()

	// swagger:parameters loginParam Signup Login
	var l struct {
		Email string `json:"email"`
		Name  string `json:"name,omitempty"`
		Type  string `json:"type"`
	}
	if err := c.Bind(&l); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": err.Error()})
	}
	if err := emailx.ValidateFast(l.Email); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid email"})
	}

	_, err = authorizationFromType(l.Type)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": fmt.Sprintf("Unknown app type: %s", l.Type)})
	}

	now := time.Now()

	// Find existing account
	a, err := h.store.GetAccountByEmail(l.Email)
	if err != nil {
		c.Logger().Errorf("Signup GetAccountByEmail: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	// Account not found
	if a == nil {
		// Add the new account
		a = &auth.Account{
			Email:     l.Email,
			CreatedAt: now,
		}
		err := h.store.NewAccount(a)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Email already registered"})
		}
	}
	token, err := h.newAppToken(c, l.Type, l.Name, a, corrID, true)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": err.Error()})
	}

	// Session Token
	exp := time.Now().Add(h.expAppToken)
	c.SetCookie(&http.Cookie{
		Name:     auth.CookieSessionName,
		Value:    token.Token,
		Expires:  exp,
		Secure:   h.isHTTPS,
		HttpOnly: true,
		Path:     "/",
	})

	return c.JSON(http.StatusOK, map[string]string{"app_token": token.Token})
}

// Login to yourITcity services
//
// swagger:route POST /auth/login Login
//
// Login
//
// Login to yourITcity services. To be validated you must follow the link sent you by email.
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: loginResponse
//       400:
//       500:
func (h *handler) Login(c echo.Context) (err error) {
	corrID := randID()

	var l struct {
		Email string `json:"email"`
		Name  string `json:"name,omitempty"`
		Type  string `json:"type"`
	}
	if err := c.Bind(&l); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": err.Error()})
	}
	_, err = authorizationFromType(l.Type)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": fmt.Sprintf("Unknown app type: %s", l.Type)})
	}

	a, err := h.store.GetAccountByEmail(l.Email)
	if err != nil {
		c.Logger().Errorf("%v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	if a == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Email not found"})
	}

	token, err := h.newAppToken(c, l.Type, l.Name, a, corrID, true)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": err.Error()})
	}

	// Session Token
	exp := time.Now().Add(h.expAppToken)
	c.SetCookie(&http.Cookie{
		Name:     auth.CookieSessionName,
		Value:    token.Token,
		Expires:  exp,
		Secure:   h.isHTTPS,
		HttpOnly: true,
		Path:     "/",
	})

	return c.JSON(http.StatusOK, map[string]string{"app_token": token.Token})
}

//swagger:parameters tokenParam  ValidateEmail CheckToken revokeToken
type tokenParam struct {
	//in:path
	//example: NESGQUHmUFdLaVjBH39
	Token string
}

// ValidateEmail handle the email verification link
//
// swagger:route GET /auth/email/{Token} ValidateEmail
//
// Token Validation
//
// This validate a signup or login token usualy come from a link sent by email.
//
// Produces:
// - application/html
// Schemes: http, https
// Responses:
// 	200:
// 	404:
// 	500:
func (h *handler) ValidateEmail(c echo.Context) error {
	vtoken := c.Param("token")
	if vtoken == "" {
		return c.HTML(http.StatusNotFound, "Not found")
	}
	at, err := h.store.Validate(vtoken, time.Now().Add(h.expAppToken))
	if err != nil {
		c.Logger().Errorf("ValidateEmail: %v", err)
		return c.HTML(http.StatusInternalServerError, "Internal server error")
	}
	found := at != nil

	code := http.StatusNotFound
	if found {
		code = http.StatusOK
	}

	var buf bytes.Buffer
	if err := h.tokenTmpl.Execute(&buf, map[string]interface{}{
		"Found": found,
		"Name":  c.QueryParam("name"),
		"Type":  c.QueryParam("type"),
	}); err != nil {
		c.Logger().Errorf("ValidateEmail: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	h.rabbit.notify(at, NotifyAdd)

	return c.HTMLBlob(code, buf.Bytes())
}

// Successful
//swagger:response checkTokenResponce
type checkTokenResponce struct {
	// in: body
	Body auth.AppToken
}

// CheckToken to for the authentification & authorization of request to yourITcity services
//
// swagger:route GET /auth/check/{Token} CheckToken
//
// Check Token authentification/authorization
//
// Verify and retrive authorization info from a specified Token.
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: checkTokenResponce
//       400:
//       500:
func (h *handler) CheckToken(c echo.Context) error {
	token := c.Param("token")
	at, err := h.store.GetAppToken(token)
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": err.Error()})
	}
	if at == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"message": "token not found"})
	}
	at.ValidToken = ""
	return c.JSON(http.StatusOK, at)
}

func randID() string {
	var b [32]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

/////
//  Account
/////

// swagger:parameters authAPIKey findToken revokeToken createToken
type authAPIKey struct {
	// Your yourITcity API Key (Bearer : your-token)
	//in: header
	//required: true
	Authorization string
}

type tokenResponse struct {
	Token     string     `json:"app_token,omitempty"`
	ValidLink string     `json:"validation_link,omitempty"`
	Name      string     `json:"name,omitempty"`
	Type      string     `json:"type,omitempty"`
	Roles     auth.Roles `json:"roles,omitempty"`

	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	ExpiredAt time.Time `json:"expired_at,omitempty"`
}

// swagger:route GET /account/token findToken
//
// Find Tokens
//
// Get every tokens and there states of your account.
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Security:
//       - Bearer: []
//
//
//     Responses:
//       200: findTokenResponse
//       401:
//       500:
func (h *handler) findTokens(c echo.Context) error {
	coorID := randID()

	// Auth
	a := c.Get("account").(auth.Account)

	// swagger:response findTokenResponse
	type findTokenResponse struct {
		//in:body
		Body []tokenResponse
	}

	tokens, err := h.store.FindAppTokensFromAID(a.ID)
	if err != nil {
		c.Logger().Errorf("findTokens FindAppTokensFromAID: %v CORRID=%v", err, coorID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal Server Error"})
	}
	var resp = make([]tokenResponse, len(tokens))

	for i, t := range tokens {
		resp[i].Token = t.Token
		if t.ValidToken != "" {
			resp[i].ValidLink = h.url + "/auth/email/" + t.ValidToken
		}
		resp[i].Name = t.Name
		resp[i].Type = t.Type
		resp[i].Roles = t.Roles
		resp[i].CreatedAt = t.CreatedAt
		resp[i].UpdatedAt = t.UpdatedAt
		resp[i].ExpiredAt = t.ExpiredAt
	}

	return c.JSON(http.StatusOK, resp)
}

// swagger:route DELETE /account/token/{Token} revokeToken
//
// Revoke a Token
//
// Revoke a token. Request to any API endpoint will return 401 Unauthorized with a revoked token.
// A revoked token can not be reactived.
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Security:
//       - Bearer: []
//
//     Responses:
//       200:
//       401:
//       500:
func (h *handler) revokeToken(c echo.Context) error {
	coorID := randID()

	// Auth
	a := c.Get("account").(auth.Account)
	t := c.Param("token")

	err := h.store.DeleteAppToken(a.ID, t)
	if err == sql.ErrNoRows {
		return c.JSON(http.StatusNotFound, map[string]string{"message": "Token not found"})
	}
	if err != nil {
		c.Logger().Errorf("revokeToken DeleteAppToken: %v CORRID=%v", err, coorID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal Server Error"})
	}

	h.rabbit.notify(&auth.AppToken{Token: t}, NotifyRevoke)

	return c.NoContent(http.StatusOK)
}

// swagger:route POST /account/token createToken
//
// Create Token
//
// Generate a new token with a specify roles to define the authorization.
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Security:
//       - Bearer: []
//
//
//     Responses:
//       200: createTokenResponse
//       401:
//       500:
func (h *handler) createToken(c echo.Context) error {
	coorID := randID()

	// Auth
	a := c.Get("account").(auth.Account)

	// swagger:parameters createTokenRequest createToken
	type createTokenRequest struct {
		//in: body
		Body struct {
			Name string `json:"name,omitempty"`
			Type string `json:"type"`
		}
	}
	// swagger:response createTokenResponse
	type createTokenResponse struct {
		//in:body
		Body tokenResponse
	}

	var l createTokenRequest
	if err := c.Bind(&l.Body); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": err.Error()})
	}

	_, err := authorizationFromType(l.Body.Type)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": fmt.Sprintf("Unknown app type: %s", l.Body.Type)})
	}

	token, err := h.newAppToken(c, l.Body.Type, l.Body.Name, &a, coorID, false)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": err.Error()})
	}
	at, err := h.store.Validate(token.ValidToken, time.Now().Add(h.expAppToken))
	if err != nil {
		c.Logger().Errorf("ValidateEmail: %v", err)
		return c.HTML(http.StatusInternalServerError, "Internal server error")
	}

	h.rabbit.notify(at, NotifyAdd)

	resp := tokenResponse{
		Token:     token.Token,
		Name:      token.Name,
		Type:      token.Type,
		Roles:     token.Roles,
		CreatedAt: token.CreatedAt,
		UpdatedAt: token.UpdatedAt,
		ExpiredAt: token.ExpiredAt,
	}
	if token.ValidToken != "" {
		resp.ValidLink = h.url + "/auth/email/" + token.ValidToken
	}

	return c.JSON(http.StatusOK, resp)
}

func (h *handler) newAppToken(c echo.Context, atype, name string, a *auth.Account, corrID string, sendEmail bool) (*auth.AppToken, error) {
	roles, err := authorizationFromType(atype)
	if err != nil {
		return nil, fmt.Errorf("Unknown app type %s", atype)
	}

	now := time.Now()

	// make new app token
	at := &auth.AppToken{
		Token:      randID(),
		ValidToken: randID(),
		Type:       atype,
		Name:       name,
		Roles:      roles,
		AID:        a.ID,
		Account:    a,
		CreatedAt:  now,
		UpdatedAt:  now,
		ExpiredAt:  now.Add(h.expValidation),
	}

	if err = h.store.NewAppToken(at); err != nil {
		c.Logger().Errorf("Imposible to insert AppToken into db: %+v, %v CORRID=%s", at, err, corrID)
		return nil, fmt.Errorf("Internal")
	}

	if sendEmail {
		// Send email validation (through RabbitMQ)
		go func() {
			typ := url.PathEscape(at.Type)
			name := url.PathEscape(at.Name)
			url := h.url + "/auth/email/" + at.ValidToken + "?name=" + name + "&type=" + typ
			var buf bytes.Buffer
			err := h.signupTmpl.Execute(&buf, map[string]interface{}{
				"ValidationUrl": url,
			})
			if err != nil {
				c.Logger().Errorf("Error parsing signup template: %v CORRID=%s", err, corrID)
				return
			}
			err = h.emailSrv.SendEmail(a.Email, "YourITCity account verification", buf.Bytes(), corrID)
			if err != nil {
				c.Logger().Errorf("Error sending email: %v CORRID=%s", err, corrID)
			}
		}()
	}

	return at, nil
}

func (h *handler) directAuth(wanted auth.Roles) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// extract the token from the request
			header := c.Response().Header().Get("Authorization")
			token := strings.TrimPrefix(header, "Bearer ")
			if len(token) == 0 {
				// check for cookie
				cookie, err := c.Cookie(auth.CookieSessionName)
				if err != nil {
					return c.JSON(http.StatusUnauthorized, map[string]string{"message": "missing credential"})
				}
				token = cookie.Value
			}
			at, err := h.store.GetAppToken(token)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]string{"message": err.Error()})
			}
			if at == nil || at.ValidToken != "" || at.ExpiredAt.Before(time.Now()) {
				return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid token"})
			}
			if match, missing := at.Roles.IsMatching(wanted); !match {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"message": fmt.Sprintf("Missing authorization: %s.", missing),
				})
			}
			c.Set("apptoken", *at)
			c.Set("account", *at.Account)

			// the token is in the local cache, accept the request
			return next(c)
		}
	}
}

func (h *handler) createAccount(c echo.Context) error {
	corrID := randID()
	var l struct {
		Email string `json:"email"`
		Name  string `json:"name,omitempty"`
		Type  string `json:"type"`
	}
	if err := c.Bind(&l); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": err.Error()})
	}
	if err := emailx.ValidateFast(l.Email); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid email"})
	}

	_, err := authorizationFromType(l.Type)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": fmt.Sprintf("Unknown app type: %s", l.Type)})
	}

	now := time.Now()

	// Find existing account
	a, err := h.store.GetAccountByEmail(l.Email)
	if err != nil {
		c.Logger().Errorf("Signup GetAccountByEmail: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	// Account not found
	if a == nil {
		// Add the new account
		a = &auth.Account{
			Email:     l.Email,
			CreatedAt: now,
		}
		err := h.store.NewAccount(a)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Email already registered"})
		}
	}
	token, err := h.newAppToken(c, l.Type, l.Name, a, corrID, false)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": err.Error()})
	}
	token, err = h.store.Validate(token.ValidToken, time.Now().Add(h.expAppToken))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": err.Error()})
	}
	h.rabbit.notify(token, NotifyAdd)

	// Session Token
	exp := time.Now().Add(h.expAppToken)
	c.SetCookie(&http.Cookie{
		Name:     auth.CookieSessionName,
		Value:    token.Token,
		Expires:  exp,
		Secure:   h.isHTTPS,
		HttpOnly: true,
		Path:     "/",
	})

	return c.JSON(http.StatusOK, map[string]string{"app_token": token.Token, "account_id": a.ID.String()})
}
func (h *handler) listAccount(c echo.Context) error {
	a, err := h.store.ListAccount()
	if err != nil {
		c.Logger().Errorf("cannot listaccount: %v", err)
		return c.JSON(http.StatusInternalServerError, nil)
	}
	return c.JSON(http.StatusOK, a)
}

func (h *handler) deleteAccount(c echo.Context) error {
	aid, err := uuid.FromString(c.Param("aid"))
	if err != nil {
		return c.NoContent(http.StatusNotFound)
	}

	at, err := h.store.FindAppTokensFromAID(aid)
	if err != nil {
		c.Logger().Errorf("cannot find apptoken to delete account %v: %v", aid, err)
		return c.NoContent(http.StatusInternalServerError)
	}

	for _, a := range at {
		h.rabbit.notify(&a, NotifyRevoke)
	}
	h.rabbit.notifyAccountDeleted(aid)

	err = h.store.DeleteAccount(aid)
	if err != nil {
		c.Logger().Errorf("cannot delete account %v: %v", aid, err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}
