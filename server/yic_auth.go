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
	"encoding/json"
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

	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/goware/emailx"
	"github.com/spf13/viper"
	"github.com/streadway/amqp"

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
	e.Use(middleware.Recover())
	// Echo ping status
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Ping Ok\n")
	})
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete},
	}))
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

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

type emailService struct {
	conn *amqp.Connection
	ch   *amqp.Channel
	q    amqp.Queue
}

func newEmailService(rabbitmqHost string) *emailService {
	var err error
	es := &emailService{}
	es.conn, err = amqp.Dial(rabbitmqHost)
	failOnError(err, "Failed to connect to RabbitMQ")

	go func() {
		log.Fatalf("closing: %s", <-es.conn.NotifyClose(make(chan *amqp.Error)))
	}()

	es.ch, err = es.conn.Channel()
	failOnError(err, "Failed to open a channel")

	es.q, err = es.ch.QueueDeclare(
		"email", // name
		true,    // durable
		false,   // delete when unused
		false,   // exclusive
		false,   // no-wait
		nil,     // arguments
	)
	failOnError(err, "Failed to declare a queue")

	return es
}

func (es *emailService) SendEmail(emailTo, subject string, content []byte, corrID string) error {
	err := es.ch.Publish(
		"",        // exchange
		es.q.Name, // routing key
		false,     // mandatory
		false,
		amqp.Publishing{
			DeliveryMode:  amqp.Persistent,
			ContentType:   "text/html",
			Headers:       amqp.Table{"To": emailTo, "Subject": subject},
			Body:          content,
			AppId:         "auth_service",
			CorrelationId: corrID,
		})
	return err
}

func (es *emailService) Close() {
	if es.conn != nil {
		es.conn.Close()
	}
	if es.ch != nil {
		es.ch.Close()
	}
}

// PostgreSQL handle the storage of auth service
type PostgreSQL struct {
	db *sql.DB
}

// NewPostgreSQL create a new PostgreSQL
func NewPostgreSQL(uri string) *PostgreSQL {
	db, err := sql.Open("postgres", uri)
	if err != nil {
		return nil
	}
	// test the connection
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	pg := &PostgreSQL{db: db}
	if err := pg.createSchema(); err != nil {
		panic(err)
	}
	return pg
}

func (pg *PostgreSQL) createSchema() (err error) {
	query := `CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
	CREATE TABLE IF NOT EXISTS account (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		email TEXT UNIQUE NOT NULL,
		validated BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE UNIQUE INDEX IF NOT EXISTS account_email_idx ON account ((lower(email)));`
	_, err = pg.db.Query(query)
	if err != nil {
		return
	}

	query = `CREATE TABLE IF NOT EXISTS app_token (
		token TEXT PRIMARY KEY,
		validation_token TEXT,
		aid UUID REFERENCES account(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		roles JSONB NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		expired_at TIMESTAMPTZ NOT NULL
	);
	CREATE INDEX IF NOT EXISTS app_token_valid_idx ON app_token (validation_token);
	ALTER TABLE app_token DROP CONSTRAINT app_token_aid_fkey;
	ALTER TABLE app_token ADD CONSTRAINT app_token_aid_fkey FOREIGN KEY (aid) REFERENCES account(id) ON DELETE CASCADE;`
	_, err = pg.db.Query(query)
	if err != nil {
		return
	}

	return
}

// NewAccount insert a new user Account in the DB
func (pg *PostgreSQL) NewAccount(a *auth.Account) error {
	query := `INSERT INTO account(email, validated, created_at)
	VALUES($1,$2,$3)
	returning id;`
	err := pg.db.QueryRow(query, a.Email, a.Validated, a.CreatedAt).Scan(&a.ID)
	if err != nil {
		return err
	}
	return err
}

// DeleteAccount remove account and each associate app_token
func (pg *PostgreSQL) DeleteAccount(aid uuid.UUID) error {
	query := `DELETE FROM account WHERE id = $1;`
	_, err := pg.db.Exec(query, aid)
	return err
}

// ListAccount find every account
func (pg *PostgreSQL) ListAccount() ([]auth.Account, error) {
	query := "SELECT id, email, validated, created_at FROM account;"
	rows, err := pg.db.Query(query)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var as []auth.Account
	for rows.Next() {
		var a auth.Account
		err := rows.Scan(&a.ID, &a.Email, &a.Validated, &a.CreatedAt)
		if err != nil {
			continue
		}
		as = append(as, a)
	}
	return as, nil
}

// GetAccountByEmail find an user Account from its Email
func (pg *PostgreSQL) GetAccountByEmail(email string) (*auth.Account, error) {
	var a auth.Account
	query := `SELECT id, email, validated, created_at
	FROM account
	WHERE email = $1;`
	err := pg.db.QueryRow(query, email).Scan(&a.ID, &a.Email, &a.Validated, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// NewAppToken insert a new application token for a user
func (pg *PostgreSQL) NewAppToken(a *auth.AppToken) error {
	roles, err := json.Marshal(a.Roles)
	if err != nil {
		return err
	}
	query := `INSERT INTO app_token(token, aid, name, type, roles, 
		validation_token, created_at, updated_at, expired_at) 
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9);`
	_, err = pg.db.Exec(query, a.Token, a.AID, a.Name, a.Type, roles, a.ValidToken,
		a.CreatedAt, a.UpdatedAt, a.ExpiredAt)
	return err
}

// GetAccountFromToken find an user Account from an app token
func (pg *PostgreSQL) GetAccountFromToken(token string) (*auth.Account, error) {
	query := `SELECT a.id, a.email, a.validated, a.created_at
	FROM account AS a
	LEFT JOIN app_token AS t ON t.aid = a.id
	WHERE t.token = ($1);`
	var a auth.Account
	err := pg.db.QueryRow(query, token).Scan(&a.ID, &a.Email, &a.Validated, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// AllAppToken get every AppToken
func (pg *PostgreSQL) AllAppToken() ([]auth.AppToken, error) {
	query := `SELECT
	a.id,
	a.email,
	a.validated,
	a.created_at,
	t.token,
	t.aid,
	t.name,
	t.type,
	t.roles,
	t.created_at,
	t.updated_at,
	t.expired_at
	FROM account AS a LEFT JOIN app_token AS t ON a.id = t.aid
	WHERE t.validation_token IS NULL AND t.expired_at > now();`
	var res []auth.AppToken
	rows, err := pg.db.Query(query)
	if err == sql.ErrNoRows {
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var roles []byte
		var at auth.AppToken
		at.Account = new(auth.Account)
		err = rows.Scan(
			&at.Account.ID,
			&at.Account.Email,
			&at.Account.Validated,
			&at.Account.CreatedAt,
			&at.Token,
			&at.AID,
			&at.Name,
			&at.Type,
			&roles,
			&at.CreatedAt,
			&at.UpdatedAt,
			&at.ExpiredAt,
		)
		if err != nil {
			continue
		}
		err = json.Unmarshal(roles, &at.Roles)
		if err != nil {
			continue
		}
		res = append(res, at)
	}

	return res, nil
}

// GetAppToken find an AppToken and its associte Account from the token
func (pg *PostgreSQL) GetAppToken(token string) (*auth.AppToken, error) {
	var roles []byte
	query := `SELECT
	a.id,
	a.email,
	a.validated,
	a.created_at,
	t.token,
	t.aid,
	t.name,
	t.type,
	t.roles,
	t.created_at,
	t.updated_at,
	t.expired_at
	FROM account AS a LEFT JOIN app_token AS t ON a.id = t.aid
	WHERE t.token = $1 AND t.validation_token IS NULL;`
	at := new(auth.AppToken)
	at.Account = new(auth.Account)
	err := pg.db.QueryRow(query, token).Scan(
		&at.Account.ID,
		&at.Account.Email,
		&at.Account.Validated,
		&at.Account.CreatedAt,
		&at.Token,
		&at.AID,
		&at.Name,
		&at.Type,
		&roles,
		&at.CreatedAt,
		&at.UpdatedAt,
		&at.ExpiredAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(roles, &at.Roles)
	if err != nil {
		return nil, err
	}
	return at, nil
}

// UpdateAppToken update the date of last renew
func (pg *PostgreSQL) UpdateAppToken(token string) error {
	query := `UPDATE app_token
	SET updated_at = $2
	WHERE token = $1;`
	_, err := pg.db.Exec(query, token, time.Now())
	return err
}

// Validate an AppToken
func (pg *PostgreSQL) Validate(vtoken string, vtime time.Time) (at *auth.AppToken, err error) {
	tx, err := pg.db.Begin()
	if err != nil {
		return nil, err
	}
	query := `UPDATE app_token
	SET validation_token = NULL, expired_at = $2
	WHERE validation_token = $1
	RETURNING token, aid;`
	var token string
	var aid uuid.UUID
	err = tx.QueryRow(query, vtoken, vtime).Scan(&token, &aid)
	if err == sql.ErrNoRows {
		tx.Rollback()
		return nil, nil
	}
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	query = `UPDATE account
	SET validated = TRUE
	WHERE id = $1;`
	_, err = tx.Exec(query, aid)
	if err != nil {
		return nil, tx.Rollback()
	}
	tx.Commit()

	return pg.GetAppToken(token)
}

// FindAppTokensFromAID find every AppToken from a given Account ID
func (pg *PostgreSQL) FindAppTokensFromAID(aid uuid.UUID) ([]auth.AppToken, error) {
	var as []auth.AppToken
	query := `SELECT 
	token,
	aid,
	name,
	type,
	roles,
	validation_token,
	created_at,
	updated_at,
	expired_at
	FROM app_token
	WHERE aid = $1
	ORDER BY updated_at`
	rows, err := pg.db.Query(query, aid)
	if err == sql.ErrNoRows {
		return as, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var roles []byte
		var vtoken sql.NullString
		var at auth.AppToken
		err = rows.Scan(
			&at.Token,
			&at.AID,
			&at.Name,
			&at.Type,
			&roles,
			&vtoken,
			&at.CreatedAt,
			&at.UpdatedAt,
			&at.ExpiredAt,
		)
		if err != nil {
			return nil, err
		}
		if vtoken.Valid {
			at.ValidToken = vtoken.String
		}
		err = json.Unmarshal(roles, &at.Roles)
		if err != nil {
			return nil, err
		}
		as = append(as, at)
	}
	return as, nil
}

// DeleteAppToken remove an app token. Return an error (sql.ErrNoRows) if it does not exist.
func (pg *PostgreSQL) DeleteAppToken(aid uuid.UUID, token string) error {
	query := `DELETE FROM app_token WHERE aid = $1 and token = $2`
	res, err := pg.db.Exec(query, aid, token)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

const (
	// NotifyAdd for the token update action
	NotifyAdd = "add"
	// NotifyRevoke for the token update action
	NotifyRevoke = "revoke"
)

// newTokenNotificationService to notify and serve RPC request for endpoint service to validate
// authentification and authorization
func newTokenNotificationService(conn *amqp.Connection, store *PostgreSQL) (*rabbitMQService, error) {
	var err error
	s := &rabbitMQService{}
	s.ch, err = conn.Channel()
	if err != nil {
		return nil, err
	}
	err = s.ch.ExchangeDeclare(
		"token_update", // name
		"fanout",       // type
		true,           // durable
		false,          // auto-deleted
		false,          // internal
		false,          // no-wait
		nil,            // arguments
	)
	if err != nil {
		return nil, err
	}
	err = s.ch.ExchangeDeclare(
		"account", // name
		"fanout",  // type
		true,      // durable
		false,     // auto-deleted
		false,     // internal
		false,     // no-wait
		nil,       // arguments
	)
	if err != nil {
		return nil, err
	}

	// RPC
	rpcch, err := conn.Channel()
	if err != nil {
		return nil, err
	}
	q, err := rpcch.QueueDeclare(
		"rpc_session_auth", // name
		false,              // durable
		false,              // delete when usused
		false,              // exclusive
		false,              // no-wait
		nil,                // arguments
	)
	if err != nil {
		return nil, err
	}
	err = rpcch.Qos(
		1,     // prefetch count
		0,     // prefetch size
		false, // global
	)
	if err != nil {
		return nil, err
	}
	msgs, err := rpcch.Consume(
		q.Name, // queue
		"auth", // consumer
		false,  // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)
	if err != nil {
		return nil, err
	}

	go func() {
		for msg := range msgs {
			var res struct {
				Roles auth.Roles `json:"roles"`
			}
			err := json.Unmarshal(msg.Body, &res)
			if err != nil {
				log.Println("RPC session auth:", err)
				continue
			}

			var responce json.RawMessage
			at, err := store.AllAppToken()
			if err == nil && at != nil {

				// remove not wanted roles
				for i := 0; i < len(at); i++ {
					if match, _ := at[i].Roles.IsMatching(res.Roles); !match {
						at[i] = at[len(at)-1]
						at = at[:len(at)-1]
						i--
					}
				}

				responce, err = json.Marshal(at)
				if err != nil {
					log.Println("RPC session auth:", err)
					continue
				}
			}
			log.Println("RPC session auth", len(at), "tokens for", res.Roles)

			err = rpcch.Publish(
				"",          // exchange
				msg.ReplyTo, // routing key
				false,       // mandatory
				false,       // immediate
				amqp.Publishing{
					ContentType:   "text/plain",
					CorrelationId: msg.CorrelationId,
					Body:          []byte(responce),
				})
			if err != nil {
				log.Println("RPC session auth publish response:", err)
			}

			msg.Ack(false)
		}
	}()

	return s, nil
}

type rabbitMQService struct {
	ch *amqp.Channel
}

// notify the change of a token with 'add' or 'revoke' action
func (s *rabbitMQService) notify(at *auth.AppToken, action string) error {
	content, err := json.Marshal(map[string]interface{}{
		"app_token": at,
		"action":    action,
	})
	if err != nil {
		return err
	}
	err = s.ch.Publish(
		"token_update", // exchange
		"",             // routing key
		false,          // mandatory
		false,          // immediate
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			ContentType:  "text/json",
			Body:         content,
			AppId:        "auth_service",
		})
	// fmt.Println("**** RabbitMQ ****", at.Token, action)
	return err
}

func (s *rabbitMQService) notifyAccountDeleted(aid uuid.UUID) error {
	err := s.ch.Publish(
		"account",                     // exchange
		fmt.Sprintf("%s.delete", aid), // routing key
		false,                         // mandatory
		false,                         // immediate
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			AppId:        "auth_service",
		})
	// fmt.Println("**** RabbitMQ **** delete account", aid)
	return err
}
