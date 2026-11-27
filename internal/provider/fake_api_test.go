package provider

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
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
	// linkCalls counts credential link, unlink and reorder requests.
	linkCalls int
	// failScope makes scope updates return a server error.
	failScope bool
	// issued holds unused access tokens from the token endpoint. Each is
	// accepted once, standing in for a token that expires, so a provider that
	// does not refresh tokens fails on its second request.
	issued map[string]bool
	// exchanges counts client credentials exchanges at the token endpoint.
	exchanges int
	// discoverWhilePaging adds an application that sorts first before each
	// request for page 2 of the application list, standing in for Heist
	// discovering one while a client pages through the list.
	discoverWhilePaging bool
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
	mux.HandleFunc("GET /applications", f.listApplications)
	mux.HandleFunc("GET /applications/{id}", f.getApplication)
	mux.HandleFunc("POST /applications/{id}/scope", f.updateApplicationScope)
	mux.HandleFunc("POST /applications/{id}/credential-order", f.reorderCredentials)
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
	mux.HandleFunc("POST /credentials/{id}/link", f.linkCredential)
	mux.HandleFunc("POST /credentials/{id}/unlink", f.unlinkCredential)

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
	// ApplicationDetail extends Application with fields the provider ignores.
	writeJSON(w, http.StatusOK, app)
}

// listApplications filters applications like the API and returns one page,
// ordered by URL. Like the API, parentApplicationId also matches the parent
// itself.
func (f *fakeAPI) listApplications(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	parent := q.Get("parentApplicationId")
	page, size := 1, 25
	if v := q.Get("page"); v != "" {
		page, _ = strconv.Atoi(v)
	}
	if v := q.Get("size"); v != "" {
		size, _ = strconv.Atoi(v)
	}
	if page < 1 || size < 1 || size > 100 {
		writeError(w, http.StatusBadRequest, "invalid_page")
		return
	}
	if page == 2 && f.discoverWhilePaging {
		id := uuid.NewString()
		f.apps[id] = &heist.Application{
			Id: id, Url: "https://a-" + id + ".example.com/", CreatedAt: "2026-11-23T00:00:00Z",
			Domain: "example.com", ParentApplicationIds: []string{},
		}
	}
	matches := []heist.Application{}
	for _, app := range f.apps {
		if v := q.Get("inScope"); v != "" && v != strconv.FormatBool(app.InScope) ||
			q.Get("rootOnly") == "true" && len(app.ParentApplicationIds) > 0 ||
			q.Get("requiresReview") != "" && q.Get("requiresReview") != strconv.FormatBool(app.RequiresReview) ||
			parent != "" && app.Id != parent && !slices.Contains(app.ParentApplicationIds, parent) ||
			!strings.Contains(strings.ToLower(app.Url), strings.ToLower(q.Get("search"))) {
			continue
		}
		matches = append(matches, *app)
	}
	slices.SortFunc(matches, func(a, b heist.Application) int { return strings.Compare(a.Url, b.Url) })
	start := min((page-1)*size, len(matches))
	end := min(start+size, len(matches))
	writeJSON(w, http.StatusOK, map[string]any{"items": matches[start:end], "page": page, "size": size, "total": len(matches)})
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
			Applications: []credentialLink{},
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
		// Like the API, assign an available Heist phone when none is set.
		phone := "+15550000001"
		if body.Custom.Phone != nil {
			phone = *body.Custom.Phone
		}
		h.Email, h.Phone = &body.Custom.Email, &phone
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
	// Like the API, return the first email no credential uses yet. It is
	// reserved only when a credential is saved with it.
	used := map[string]bool{}
	for _, c := range f.creds {
		if c.Hint.Email != nil {
			used[*c.Hint.Email] = true
		}
	}
	var email string
	for n := 1; email == "" || used[email]; n++ {
		email = fmt.Sprintf("tester-%d@tester.heisthq.com", n)
	}
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

// deleteCredential unlinks the credential from every application, choosing
// successor primaries like unlinkCredential, then deletes it.
func (f *fakeAPI) deleteCredential(w http.ResponseWriter, r *http.Request) {
	c, ok := f.creds[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	delete(f.creds, c.Id)
	for _, l := range c.Applications {
		if l.IsPrimary {
			f.promoteSuccessor(l.Id, *l.EntityId)
		}
	}
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

// credentialLink is a credential's direct link to an application.
type credentialLink = struct {
	EntityId  *string  `json:"entityId"`
	Id        string   `json:"id"`
	IsPrimary bool     `json:"isPrimary"`
	RoleLevel *float32 `json:"roleLevel"`
	Url       string   `json:"url"`
}

// appLinks returns every direct link to the application, sorted by
// credential ID so that choices between equal links are deterministic.
func (f *fakeAPI) appLinks(appID string) []*credentialLink {
	ids := slices.Sorted(maps.Keys(f.creds))
	var links []*credentialLink
	for _, id := range ids {
		c := f.creds[id]
		for i := range c.Applications {
			if c.Applications[i].Id == appID {
				links = append(links, &c.Applications[i])
			}
		}
	}
	return links
}

// level is a link's privilege level, with null as the lowest.
func level(l *credentialLink) float32 {
	if l.RoleLevel == nil {
		return float32(math.Inf(-1))
	}
	return *l.RoleLevel
}

// linkCredential follows the service's lane rules: entityId joins that lane,
// isCrossWorkspace starts a new one, and neither joins the main lane, or
// starts it as primary when the application has no links. The link goes to
// the bottom of its lane. Linking an already-linked credential returns it
// unchanged.
func (f *fakeAPI) linkCredential(w http.ResponseWriter, r *http.Request) {
	c, ok := f.creds[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	var body heist.LinkCredentialJSONBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	appID := body.ApplicationId.String()
	app, ok := f.apps[appID]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	f.linkCalls++
	if slices.ContainsFunc(c.Applications, func(l credentialLink) bool { return l.Id == appID }) {
		writeJSON(w, http.StatusOK, c.Credential)
		return
	}
	links := f.appLinks(appID)
	entity := uuid.NewString()
	switch {
	case body.EntityId != nil:
		entity = body.EntityId.String()
		if !slices.ContainsFunc(links, func(l *credentialLink) bool { return *l.EntityId == entity }) {
			writeError(w, http.StatusBadRequest, "unknown_entity")
			return
		}
	case body.IsCrossWorkspace != nil && *body.IsCrossWorkspace:
	default:
		for _, l := range links {
			if l.IsPrimary {
				entity = *l.EntityId
			}
		}
	}
	var bottom float32
	for i, l := range slices.DeleteFunc(slices.Clone(links), func(l *credentialLink) bool { return *l.EntityId != entity || l.RoleLevel == nil }) {
		if i == 0 || *l.RoleLevel-1 < bottom {
			bottom = *l.RoleLevel - 1
		}
	}
	c.Applications = append(c.Applications, credentialLink{
		EntityId: &entity, Id: appID, IsPrimary: len(links) == 0, RoleLevel: &bottom, Url: app.Url,
	})
	writeJSON(w, http.StatusOK, c.Credential)
}

// unlinkCredential removes a link, keeping the credential. A removed primary
// is succeeded from the same lane if possible, otherwise from another lane.
func (f *fakeAPI) unlinkCredential(w http.ResponseWriter, r *http.Request) {
	c, ok := f.creds[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	var body heist.UnlinkCredentialJSONBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	appID := body.ApplicationId.String()
	f.linkCalls++
	i := slices.IndexFunc(c.Applications, func(l credentialLink) bool { return l.Id == appID })
	if i < 0 {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	removed := c.Applications[i]
	c.Applications = slices.Delete(c.Applications, i, i+1)
	if removed.IsPrimary {
		f.promoteSuccessor(appID, *removed.EntityId)
	}
	writeJSON(w, http.StatusOK, c.Credential)
}

// promoteSuccessor makes the most privileged link in the lane the primary,
// or the most privileged link in another lane when the lane is empty.
func (f *fakeAPI) promoteSuccessor(appID, entity string) {
	var best *credentialLink
	for _, sameLane := range []bool{true, false} {
		for _, l := range f.appLinks(appID) {
			if (*l.EntityId == entity) == sameLane && (best == nil || level(l) > level(best)) {
				best = l
			}
		}
		if best != nil {
			best.IsPrimary = true
			return
		}
	}
}

// reorderCredentials orders one complete lane, most privileged first. In the
// main lane, the first credential becomes the primary.
func (f *fakeAPI) reorderCredentials(w http.ResponseWriter, r *http.Request) {
	appID := r.PathValue("id")
	if _, ok := f.apps[appID]; !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	var body heist.ReorderApplicationCredentialsJSONBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.OrderedCredentialIds) == 0 {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	f.linkCalls++
	byCredential := map[string]*credentialLink{}
	for _, id := range slices.Sorted(maps.Keys(f.creds)) {
		for i := range f.creds[id].Applications {
			if l := &f.creds[id].Applications[i]; l.Id == appID {
				byCredential[id] = l
			}
		}
	}
	first, ok := byCredential[body.OrderedCredentialIds[0].String()]
	if !ok {
		writeError(w, http.StatusBadRequest, "not_linked")
		return
	}
	entity := *first.EntityId
	lane := 0
	for _, l := range byCredential {
		if *l.EntityId == entity {
			lane++
		}
	}
	seen := map[string]bool{}
	for _, id := range body.OrderedCredentialIds {
		l, ok := byCredential[id.String()]
		if !ok || *l.EntityId != entity || seen[id.String()] {
			writeError(w, http.StatusBadRequest, "not_one_complete_lane")
			return
		}
		seen[id.String()] = true
	}
	if len(seen) != lane {
		writeError(w, http.StatusBadRequest, "not_one_complete_lane")
		return
	}
	main := false
	for id := range seen {
		main = main || byCredential[id].IsPrimary
	}
	result := []heist.Credential{}
	for i, id := range body.OrderedCredentialIds {
		l := byCredential[id.String()]
		lvl := float32(len(body.OrderedCredentialIds) - i)
		l.RoleLevel = &lvl
		if main {
			l.IsPrimary = i == 0
		}
		result = append(result, f.creds[id.String()].Credential)
	}
	writeJSON(w, http.StatusOK, result)
}
