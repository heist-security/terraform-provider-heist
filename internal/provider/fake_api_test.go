package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/heist-security/heist-go/heist"
)

const (
	testToken        = "test-token"
	testClientID     = "test-client-id"
	testClientSecret = "test-client-secret"
)

// fakeAPI is an in-memory Heist API covering the operations the provider
// uses. Tests seed and inspect its fields directly; lock mu while the
// provider may be running.
type fakeAPI struct {
	mu    sync.Mutex
	url   string
	apps  map[string]*heist.Application
	rules map[string]*heist.ScopeRule
	creds map[string]*fakeCredential
	// optionsCalls counts requests for a generated email or phone.
	optionsCalls int
	// passwordCalls and customCalls count in-place credential updates.
	passwordCalls int
	customCalls   int
	// scopeCalls counts scope updates, which start Heist workflows.
	scopeCalls int
	// failScope makes scope updates return a server error.
	failScope bool
	// issued holds unused access tokens from the token endpoint. Each is
	// accepted once, standing in for a token that expires, so a provider that
	// does not refresh tokens fails on its second request.
	issued map[string]bool
	// exchanges counts client credentials exchanges at the token endpoint.
	exchanges int
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	clearCredentialEnv(t)
	f := &fakeAPI{
		apps:   map[string]*heist.Application{},
		rules:  map[string]*heist.ScopeRule{},
		creds:  map[string]*fakeCredential{},
		issued: map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /applications", f.createApplication)
	mux.HandleFunc("GET /applications/{id}", f.getApplication)
	mux.HandleFunc("POST /applications/{id}/scope", f.updateApplicationScope)
	mux.HandleFunc("POST /scope/rules", f.createScopeRule)
	mux.HandleFunc("GET /scope/rules/{id}", f.getScopeRule)
	mux.HandleFunc("DELETE /scope/rules/{id}", f.deleteScopeRule)
	mux.HandleFunc("GET /credentials", f.listCredentials)
	mux.HandleFunc("POST /credentials", f.createCredential)
	mux.HandleFunc("GET /credentials/options", f.credentialOptions)
	mux.HandleFunc("GET /credentials/{id}", f.getCredential)
	mux.HandleFunc("DELETE /credentials/{id}", f.deleteCredential)
	mux.HandleFunc("POST /credentials/{id}/custom", f.updateCustomCredential)
	mux.HandleFunc("POST /credentials/{id}/password", f.setCredentialPassword)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method == http.MethodPost && r.URL.Path == "/oauth2/token" {
			f.token(w, r)
			return
		}
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != testToken && !f.issued[token] {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		delete(f.issued, token)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

// providerConfig returns HCL configuring the provider against the fake.
func (f *fakeAPI) providerConfig() string {
	return fmt.Sprintf(`
provider "heist" {
  server_url   = %q
  access_token = %q
}
`, f.url, testToken)
}

// clientCredentialsConfig returns HCL configuring the provider against the
// fake with client credentials and the fake's token endpoint.
func (f *fakeAPI) clientCredentialsConfig() string {
	return fmt.Sprintf(`
provider "heist" {
  server_url    = %q
  token_url     = %q
  client_id     = %q
  client_secret = %q
}
`, f.url, f.url+"/oauth2/token", testClientID, testClientSecret)
}

// clearCredentialEnv stops credentials in the developer's environment from
// affecting provider configuration in tests.
func clearCredentialEnv(t *testing.T) {
	t.Helper()
	for _, env := range []string{"HEIST_ACCESS_TOKEN", "HEIST_CLIENT_ID", "HEIST_CLIENT_SECRET", "HEIST_TOKEN_URL", "HEIST_SERVER_URL"} {
		t.Setenv(env, "")
	}
}

func testProviderFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"heist": providerserver.NewProtocol6WithError(New("test")()),
	}
}

func (f *fakeAPI) createApplication(w http.ResponseWriter, r *http.Request) {
	var body heist.CreateApplicationJSONBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Like the API, normalize a bare origin to include a trailing slash.
	appURL := body.Url
	if strings.Count(appURL, "/") == 2 {
		appURL += "/"
	}
	app := &heist.Application{
		Id:                   uuid.NewString(),
		Url:                  appURL,
		InScope:              true,
		MainTarget:           true,
		CreatedAt:            "2026-11-23T00:00:00Z",
		ParentApplicationIds: []string{},
	}
	f.apps[app.Id] = app
	writeJSON(w, http.StatusCreated, map[string]any{"application": app, "documentation": nil, "documentationWorkflowId": nil})
}

func (f *fakeAPI) getApplication(w http.ResponseWriter, r *http.Request) {
	app, ok := f.apps[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	writeJSON(w, http.StatusOK, heist.ApplicationDetail{
		Id: app.Id, Url: app.Url, InScope: app.InScope, MainTarget: app.MainTarget, CreatedAt: app.CreatedAt,
	})
}

func (f *fakeAPI) updateApplicationScope(w http.ResponseWriter, r *http.Request) {
	app, ok := f.apps[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if f.failScope {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	var body heist.UpdateApplicationScopeJSONBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	f.scopeCalls++
	app.InScope = body.InScope
	writeJSON(w, http.StatusOK, heist.ApplicationScopeResult{Application: *app})
}

func (f *fakeAPI) createScopeRule(w http.ResponseWriter, r *http.Request) {
	var body heist.CreateScopeRuleJSONBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rule := &heist.ScopeRule{
		Id:        uuid.NewString(),
		Pattern:   body.Pattern,
		Action:    heist.ScopeRuleAction(body.Action),
		CreatedAt: "2026-11-23T00:00:00Z",
		UpdatedAt: "2026-11-23T00:00:00Z",
	}
	f.rules[rule.Id] = rule
	writeJSON(w, http.StatusCreated, rule)
}

func (f *fakeAPI) getScopeRule(w http.ResponseWriter, r *http.Request) {
	rule, ok := f.rules[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (f *fakeAPI) deleteScopeRule(w http.ResponseWriter, r *http.Request) {
	if _, ok := f.rules[r.PathValue("id")]; !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	delete(f.rules, r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// fakeCredential is a stored credential with the secrets the API never
// returns, so tests can check what the provider sent.
type fakeCredential struct {
	heist.Credential
	secrets map[string]string
}

func (f *fakeAPI) listCredentials(w http.ResponseWriter, _ *http.Request) {
	creds := []heist.Credential{}
	for _, c := range f.creds {
		creds = append(creds, c.Credential)
	}
	writeJSON(w, http.StatusOK, creds)
}

func (f *fakeAPI) createCredential(w http.ResponseWriter, r *http.Request) {
	var body heist.CreateCredentialJSONBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Without applicationIds the API links every in-scope root; the
	// provider must always send an empty list.
	if body.ApplicationIds == nil || len(*body.ApplicationIds) != 0 {
		writeError(w, http.StatusBadRequest, "applicationIds must be []")
		return
	}
	c := &fakeCredential{
		Credential: heist.Credential{
			Id:           uuid.NewString(),
			Type:         heist.CredentialType(body.Type),
			LoginUrl:     body.LoginUrl,
			Instructions: body.Instructions,
			Applications: []struct {
				EntityId  *string  `json:"entityId"`
				Id        string   `json:"id"`
				IsPrimary bool     `json:"isPrimary"`
				RoleLevel *float32 `json:"roleLevel"`
				Url       string   `json:"url"`
			}{},
		},
		secrets: map[string]string{},
	}
	h := &c.Hint
	if body.CustomHeaders != nil {
		for _, hdr := range *body.CustomHeaders {
			c.secrets["header:"+hdr.Name] = hdr.Value
		}
	}
	switch body.Type {
	case "BASIC", "HTTP_BASIC":
		h.Username = &body.Basic.Username
		c.setPassword(body.Basic.Password)
	case "EMAIL":
		h.Email = &body.Email.Email
	case "SMS":
		h.Phone = &body.Sms.Phone
		prefix := "+1"
		if body.Sms.PhonePrefix != nil {
			prefix = *body.Sms.PhonePrefix
		}
		h.PhonePrefix = &prefix
	case "API_KEY":
		masked := "****" + body.ApiKey.ApiKey[len(body.ApiKey.ApiKey)-2:]
		h.MaskedKey, h.HeaderName = &masked, &body.ApiKey.HeaderName
		c.secrets["apiKey"] = body.ApiKey.ApiKey
	case "CUSTOM":
		h.Email, h.Phone = &body.Custom.Email, body.Custom.Phone
		names := []string{}
		for _, s := range body.Custom.Secrets {
			names = append(names, s.Name)
			c.secrets[s.Name] = s.Value
		}
		h.SecretNames = &names
	case "GOOGLE":
	default:
		writeError(w, http.StatusBadRequest, "type not supported by the fake")
		return
	}
	f.creds[c.Id] = c
	writeJSON(w, http.StatusCreated, c.Credential)
}

func (c *fakeCredential) setPassword(password string) {
	n := float32(len(password))
	c.Hint.PasswordLength = &n
	c.secrets["password"] = password
}

func (f *fakeAPI) credentialOptions(w http.ResponseWriter, _ *http.Request) {
	f.optionsCalls++
	email := fmt.Sprintf("tester-%d@tester.heisthq.com", f.optionsCalls)
	writeJSON(w, http.StatusOK, map[string]any{"email": email, "phoneNumbers": []string{"+15550000001"}})
}

func (f *fakeAPI) getCredential(w http.ResponseWriter, r *http.Request) {
	c, ok := f.creds[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	writeJSON(w, http.StatusOK, c.Credential)
}

func (f *fakeAPI) deleteCredential(w http.ResponseWriter, r *http.Request) {
	if _, ok := f.creds[r.PathValue("id")]; !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	delete(f.creds, r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (f *fakeAPI) updateCustomCredential(w http.ResponseWriter, r *http.Request) {
	c, ok := f.creds[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	var body heist.UpdateCustomCredentialJSONBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || c.Type != heist.CredentialTypeCUSTOM {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	f.customCalls++
	secrets := map[string]string{}
	names := []string{}
	for _, s := range body.Secrets {
		names = append(names, s.Name)
		switch {
		case s.Value != nil:
			secrets[s.Name] = *s.Value
		case c.secrets[s.Name] != "":
			secrets[s.Name] = c.secrets[s.Name]
		default:
			writeError(w, http.StatusBadRequest, "new secret "+s.Name+" needs a value")
			return
		}
	}
	c.secrets = secrets
	c.Hint.SecretNames = &names
	// Like the API, keep the email and phone of an existing CUSTOM
	// credential.
	c.Instructions = body.Instructions
	writeJSON(w, http.StatusOK, c.Credential)
}

func (f *fakeAPI) setCredentialPassword(w http.ResponseWriter, r *http.Request) {
	c, ok := f.creds[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	var body heist.SetCredentialPasswordJSONBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	f.passwordCalls++
	c.setPassword(body.Password)
	writeJSON(w, http.StatusOK, c.Credential)
}

// token implements the OAuth 2.0 client_credentials grant with HTTP Basic
// client authentication, as the Heist token endpoint does.
func (f *fakeAPI) token(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	if !ok || id != testClientID || secret != testClientSecret || r.PostFormValue("grant_type") != "client_credentials" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	f.exchanges++
	token := fmt.Sprintf("issued-token-%d", f.exchanges)
	f.issued[token] = true
	writeJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 1})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": http.StatusText(status)}})
}
