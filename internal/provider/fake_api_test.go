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

const testToken = "test-token"

// fakeAPI is an in-memory Heist API covering the operations the provider
// uses. Tests seed and inspect its fields directly; lock mu while the
// provider may be running.
type fakeAPI struct {
	mu    sync.Mutex
	url   string
	apps  map[string]*heist.Application
	rules map[string]*heist.ScopeRule
	// scopeCalls counts scope updates, which start Heist workflows.
	scopeCalls int
	// failScope makes scope updates return a server error.
	failScope bool
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{
		apps:  map[string]*heist.Application{},
		rules: map[string]*heist.ScopeRule{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /applications", f.createApplication)
	mux.HandleFunc("GET /applications/{id}", f.getApplication)
	mux.HandleFunc("POST /applications/{id}/scope", f.updateApplicationScope)
	mux.HandleFunc("POST /scope/rules", f.createScopeRule)
	mux.HandleFunc("GET /scope/rules/{id}", f.getScopeRule)
	mux.HandleFunc("DELETE /scope/rules/{id}", f.deleteScopeRule)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": http.StatusText(status)}})
}
