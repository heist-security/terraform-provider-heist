package provider

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/heist-security/heist-go/heist"
)

var (
	_ resource.ResourceWithConfigure      = (*applicationCredentialsResource)(nil)
	_ resource.ResourceWithImportState    = (*applicationCredentialsResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*applicationCredentialsResource)(nil)
	_ resource.ResourceWithValidateConfig = (*applicationCredentialsResource)(nil)
)

// mainEntityKey holds, in private state, the entity ID of the lane that held
// the primary credential after the last apply: the lane block 1 manages.
const mainEntityKey = "main_entity"

func newApplicationCredentialsResource() resource.Resource {
	return &applicationCredentialsResource{}
}

type applicationCredentialsResource struct {
	client *heist.ClientWithResponses
}

type applicationCredentialsModel struct {
	ApplicationID types.String `tfsdk:"application_id"`
	Tenants       types.List   `tfsdk:"tenant"`
}

type tenantModel struct {
	CredentialIDs types.List   `tfsdk:"credential_ids"`
	EntityID      types.String `tfsdk:"entity_id"`
}

var tenantType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"credential_ids": types.ListType{ElemType: types.StringType},
	"entity_id":      types.StringType,
}}

// tenant is a configured tenant block: credential IDs, most privileged
// first, with "" for IDs not yet known, and the lane's entity ID if known.
type tenant struct {
	credentials []string
	entityID    string
}

// lane is a tenant lane of an application's direct credential links.
type lane struct {
	entityID string
	members  []laneMember // most privileged first
}

type laneMember struct {
	credentialID string
	level        float64
	primary      bool
}

func (l lane) credentials() []string {
	ids := make([]string, len(l.members))
	for i, m := range l.members {
		ids[i] = m.credentialID
	}
	return ids
}

func (l lane) holdsPrimary() bool {
	return slices.ContainsFunc(l.members, func(m laneMember) bool { return m.primary })
}

func (r *applicationCredentialsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_application_credentials"
}

func (r *applicationCredentialsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The credentials an application uses and their privilege order, which Heist uses for authorization " +
			"testing. The first `tenant` block is the main tenant, which holds the primary credential; each later block " +
			"is a separate tenant. The resource is authoritative for the application's direct credential links: links " +
			"made outside Terraform show up as a diff and are removed on apply. Destroying it unlinks every credential " +
			"from the application, keeping the credentials.",
		Attributes: map[string]schema.Attribute{
			"application_id": schema.StringAttribute{
				Description:   "Application ID. Changing it replaces the resource.",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
		},
		Blocks: map[string]schema.Block{
			"tenant": schema.ListNestedBlock{
				Description: "A tenant, as a lane of credentials. The first block is the main tenant; its first " +
					"credential is the primary. Blocks are matched to existing tenants by the credentials they share, " +
					"so reordering or removing blocks doesn't move credentials between tenants.",
				Validators: []validator.List{listvalidator.IsRequired(), listvalidator.SizeAtLeast(1)},
				NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
					"credential_ids": schema.ListAttribute{
						Description: "IDs of the tenant's credentials, most privileged first.",
						Required:    true,
						ElementType: types.StringType,
						Validators:  []validator.List{listvalidator.SizeAtLeast(1)},
					},
					"entity_id": schema.StringAttribute{
						Description: "Heist's ID for the tenant. Informational; blocks are matched by their credentials.",
						Computed:    true,
					},
				}},
			},
		},
	}
}

func (r *applicationCredentialsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *applicationCredentialsResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config applicationCredentialsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tenants, diags := tenantsFrom(ctx, config.Tenants)
	resp.Diagnostics.Append(diags...)
	seen := map[string]bool{}
	for i, t := range tenants {
		for _, id := range t.credentials {
			if id == "" {
				continue
			}
			if seen[id] {
				resp.Diagnostics.AddAttributeError(path.Root("tenant").AtListIndex(i).AtName("credential_ids"),
					"Duplicate credential", fmt.Sprintf("Credential %s is listed more than once. Each credential belongs to one tenant.", id))
			}
			seen[id] = true
		}
	}
}

// ModifyPlan matches the planned tenant blocks to the lanes in state, so
// that each block's entity_id follows its lane however the blocks are
// ordered. It warns about a primary credential in the wrong lane, which
// fails on apply. It can't fail: Terraform plans an update with the prior
// state before planning a forced replacement, so an error would also block
// the -replace recovery.
func (r *applicationCredentialsResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}
	var plan, state applicationCredentialsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || plan.Tenants.IsUnknown() {
		return
	}
	planned, diags := tenantsFrom(ctx, plan.Tenants)
	resp.Diagnostics.Append(diags...)
	prior, diags := tenantsFrom(ctx, state.Tenants)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	mainEntity, diags := storedMainEntity(ctx, req.Private)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Read puts the lane holding the primary first.
	if len(prior) > 0 && mainEntity != "" && prior[0].entityID != mainEntity {
		resp.Diagnostics.AddWarning("Primary credential in the wrong tenant", misplacedPrimaryDetail(plan.ApplicationID.ValueString())+
			"\n\nApplying this plan without replacing the resource will fail.")
		return
	}
	lanes := make([]lane, len(prior))
	for i, t := range prior {
		lanes[i].entityID = t.entityID
		for _, id := range t.credentials {
			lanes[i].members = append(lanes[i].members, laneMember{credentialID: id, primary: i == 0 && len(lanes[i].members) == 0})
		}
	}
	sortLanes(lanes)
	for i, l := range matchLanes(lanes, planned) {
		entityID := types.StringUnknown()
		if l >= 0 {
			entityID = types.StringValue(lanes[l].entityID)
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("tenant").AtListIndex(i).AtName("entity_id"), entityID)...)
	}
}

func (r *applicationCredentialsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan applicationCredentialsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, plan, "", &resp.State, resp.Private, &resp.Diagnostics)
}

func (r *applicationCredentialsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state applicationCredentialsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	planned, diags := tenantsFrom(ctx, plan.Tenants)
	resp.Diagnostics.Append(diags...)
	prior, diags := tenantsFrom(ctx, state.Tenants)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// The API keeps no order between tenants, so reordering the blocks after
	// the first needs no API calls.
	if sameTenantsIgnoringOrder(planned, prior) {
		resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
		return
	}
	mainEntity, diags := storedMainEntity(ctx, req.Private)
	resp.Diagnostics.Append(diags...)
	// Keep the prior state if apply fails before changing anything.
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, plan, mainEntity, &resp.State, resp.Private, &resp.Diagnostics)
}

func (r *applicationCredentialsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state applicationCredentialsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	appID, ok := parseID(state.ApplicationID.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}
	_, err := r.client.GetApplicationWithResponse(ctx, appID)
	if heist.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read application", err.Error())
		return
	}
	prior, diags := tenantsFrom(ctx, state.Tenants)
	resp.Diagnostics.Append(diags...)
	lanes, diags := r.lanes(ctx, appID, prior)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Tenants, diags = tenantsValue(ctx, tenantsFromLanes(lanes, prior))
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Delete unlinks every credential from the application, keeping the
// credentials.
func (r *applicationCredentialsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state applicationCredentialsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	appID, ok := parseID(state.ApplicationID.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}
	lanes, diags := r.lanes(ctx, appID, nil)
	resp.Diagnostics.Append(diags...)
	for _, l := range lanes {
		for _, id := range l.credentials() {
			resp.Diagnostics.Append(r.unlink(ctx, appID, id)...)
		}
	}
}

func (r *applicationCredentialsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("application_id"), req, resp)
}

// apply changes the application's links to match the plan, then saves state
// read back from the API, including after a partial failure. A Create that
// fails after saving state leaves the resource tainted, so the next apply
// unlinks everything and starts again.
//
// Changes are applied in an order that keeps a primary credential in the
// main lane: link new credentials, move credentials into the main lane,
// unlink removed credentials, move other credentials, then reorder lanes.
// Linking an already-linked credential doesn't move it, so moving one
// unlinks it first.
//
// mainEntity is the lane block 1 managed after the last apply, or "" on
// create. If the primary is now in another lane, apply fails rather than
// moving the primary by unlinking another tenant's credentials.
func (r *applicationCredentialsResource) apply(ctx context.Context, plan applicationCredentialsModel, mainEntity string,
	state *tfsdk.State, private privateSetter, diags *diag.Diagnostics) {
	appID, ok := parseID(plan.ApplicationID.ValueString(), diags)
	if !ok {
		return
	}
	planned, d := tenantsFrom(ctx, plan.Tenants)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	lanes, d := r.lanes(ctx, appID, planned)
	diags.Append(d...)
	if diags.HasError() {
		return
	}

	misplaced := len(lanes) > 0 && lanes[0].holdsPrimary() && mainEntity != "" && lanes[0].entityID != mainEntity
	defer func() {
		after, d := r.lanes(ctx, appID, planned)
		if d.HasError() {
			diags.Append(d...)
			return
		}
		plan.Tenants, d = tenantsValue(ctx, tenantsFromLanes(after, planned))
		diags.Append(d...)
		diags.Append(state.Set(ctx, plan)...)
		if !misplaced && len(after) > 0 && after[0].holdsPrimary() {
			value, _ := json.Marshal(after[0].entityID)
			diags.Append(private.SetKey(ctx, mainEntityKey, value)...)
		}
	}()

	if misplaced {
		diags.AddError("Primary credential in the wrong tenant", misplacedPrimaryDetail(appID.String()))
		return
	}
	target := matchLanes(lanes, planned)
	entities := make([]string, len(planned))
	current := map[string]int{} // credential ID to lane index
	for i, l := range lanes {
		for _, id := range l.credentials() {
			current[id] = i
		}
	}
	wanted := map[string]bool{}
	type move struct {
		block      int
		credential string
	}
	var moves []move
	for b, t := range planned {
		if target[b] >= 0 {
			entities[b] = lanes[target[b]].entityID
		}
		for _, id := range t.credentials {
			wanted[id] = true
			if l, linked := current[id]; linked && l != target[b] {
				moves = append(moves, move{b, id})
			}
		}
	}

	link := func(b int, id string) bool {
		d := r.link(ctx, appID, id, b, &entities[b])
		diags.Append(d...)
		return !d.HasError()
	}
	relink := func(m move) bool {
		d := r.unlink(ctx, appID, m.credential)
		diags.Append(d...)
		return !d.HasError() && link(m.block, m.credential)
	}

	for b, t := range planned {
		for _, id := range t.credentials {
			if _, linked := current[id]; !linked && !link(b, id) {
				return
			}
		}
	}
	for _, m := range moves {
		if m.block == 0 && !relink(m) {
			return
		}
	}
	for _, l := range lanes {
		for _, id := range l.credentials() {
			if !wanted[id] {
				if d := r.unlink(ctx, appID, id); d.HasError() {
					diags.Append(d...)
					return
				}
			}
		}
	}
	for _, m := range moves {
		if m.block > 0 && !relink(m) {
			return
		}
	}

	linked, d := r.lanes(ctx, appID, planned)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	for _, t := range planned {
		if len(t.credentials) < 2 {
			continue
		}
		i := slices.IndexFunc(linked, func(l lane) bool { return slices.Contains(l.credentials(), t.credentials[0]) })
		if i >= 0 && ordered(linked[i], t.credentials) {
			continue
		}
		if d := r.reorder(ctx, appID, t.credentials); d.HasError() {
			diags.Append(d...)
			return
		}
	}
}

// ordered reports whether a lane already holds exactly the credentials in
// order, with distinct privilege levels and, in the main lane, the first as
// primary.
func ordered(l lane, credentials []string) bool {
	if !slices.Equal(l.credentials(), credentials) || (l.holdsPrimary() && !l.members[0].primary) {
		return false
	}
	for i := 1; i < len(l.members); i++ {
		if l.members[i].level >= l.members[i-1].level {
			return false
		}
	}
	return true
}

// link links a credential into block b's lane. Without a known lane, block 1
// links with no flags, which starts the main lane when the application has no
// links, and later blocks start a new lane. It records the lane's entity ID.
func (r *applicationCredentialsResource) link(ctx context.Context, appID uuid.UUID, credentialID string, b int, entityID *string) diag.Diagnostics {
	var diags diag.Diagnostics
	id, ok := parseID(credentialID, &diags)
	if !ok {
		return diags
	}
	body := heist.LinkCredentialJSONRequestBody{ApplicationId: appID}
	switch {
	case *entityID != "":
		entity, ok := parseID(*entityID, &diags)
		if !ok {
			return diags
		}
		body.EntityId = &entity
	case b > 0:
		cross := true
		body.IsCrossWorkspace = &cross
	}
	res, err := r.client.LinkCredentialWithResponse(ctx, id, body)
	if err == nil && res.JSON200 == nil {
		err = errMissingBody
	}
	if err != nil {
		diags.AddError("Unable to link credential", fmt.Sprintf("Linking credential %s to application %s: %s", credentialID, appID, err))
		return diags
	}
	for _, a := range res.JSON200.Applications {
		if strings.EqualFold(a.Id, appID.String()) && a.EntityId != nil {
			*entityID = *a.EntityId
		}
	}
	return diags
}

// unlink unlinks a credential from the application. A 404 means it is
// already unlinked or deleted.
func (r *applicationCredentialsResource) unlink(ctx context.Context, appID uuid.UUID, credentialID string) diag.Diagnostics {
	var diags diag.Diagnostics
	id, ok := parseID(credentialID, &diags)
	if !ok {
		return diags
	}
	_, err := r.client.UnlinkCredentialWithResponse(ctx, id, heist.UnlinkCredentialJSONRequestBody{ApplicationId: appID})
	if err != nil && !heist.IsNotFound(err) {
		diags.AddError("Unable to unlink credential", fmt.Sprintf("Unlinking credential %s from application %s: %s", credentialID, appID, err))
	}
	return diags
}

func (r *applicationCredentialsResource) reorder(ctx context.Context, appID uuid.UUID, credentials []string) diag.Diagnostics {
	var diags diag.Diagnostics
	body := heist.ReorderApplicationCredentialsJSONRequestBody{}
	for _, c := range credentials {
		id, ok := parseID(c, &diags)
		if !ok {
			return diags
		}
		body.OrderedCredentialIds = append(body.OrderedCredentialIds, id)
	}
	if _, err := r.client.ReorderApplicationCredentialsWithResponse(ctx, appID, body); err != nil {
		diags.AddError("Unable to order credentials", fmt.Sprintf("Ordering credentials of application %s: %s", appID, err))
	}
	return diags
}

// lanes lists the application's direct credential links grouped into lanes,
// each ordered most privileged first. Credentials with equal levels keep
// their order in prior. The lane holding the primary comes first, then the
// others by entity ID.
func (r *applicationCredentialsResource) lanes(ctx context.Context, appID uuid.UUID, prior []tenant) ([]lane, diag.Diagnostics) {
	var diags diag.Diagnostics
	res, err := r.client.ListCredentialsWithResponse(ctx)
	if err == nil && res.JSON200 == nil {
		err = errMissingBody
	}
	if err != nil {
		diags.AddError("Unable to list credentials", err.Error())
		return nil, diags
	}
	rank := map[string]int{}
	for _, t := range prior {
		for _, id := range t.credentials {
			if _, ok := rank[id]; !ok {
				rank[id] = len(rank)
			}
		}
	}
	byEntity := map[string]*lane{}
	for _, cred := range *res.JSON200 {
		for _, a := range cred.Applications {
			if !strings.EqualFold(a.Id, appID.String()) {
				continue
			}
			entity := ""
			if a.EntityId != nil {
				entity = *a.EntityId
			}
			if byEntity[entity] == nil {
				byEntity[entity] = &lane{entityID: entity}
			}
			// A null level is the lowest.
			level := math.Inf(-1)
			if a.RoleLevel != nil {
				level = float64(*a.RoleLevel)
			}
			byEntity[entity].members = append(byEntity[entity].members, laneMember{credentialID: cred.Id, level: level, primary: a.IsPrimary})
		}
	}
	rankOf := func(id string) int {
		if r, ok := rank[id]; ok {
			return r
		}
		return len(rank)
	}
	lanes := []lane{}
	for _, l := range byEntity {
		slices.SortFunc(l.members, func(a, b laneMember) int {
			return cmp.Or(cmp.Compare(b.level, a.level), cmp.Compare(rankOf(a.credentialID), rankOf(b.credentialID)),
				strings.Compare(a.credentialID, b.credentialID))
		})
		lanes = append(lanes, *l)
	}
	sortLanes(lanes)
	return lanes, diags
}

// sortLanes puts the lane holding the primary first, then the others by
// entity ID, so matching blocks to lanes is deterministic.
func sortLanes(lanes []lane) {
	slices.SortStableFunc(lanes, func(a, b lane) int {
		if a.holdsPrimary() != b.holdsPrimary() {
			if a.holdsPrimary() {
				return -1
			}
			return 1
		}
		return strings.Compare(a.entityID, b.entityID)
	})
}

// matchLanes maps each block to the index of an existing lane, or -1 for a
// new lane. Block 1 maps to the lane holding the primary. Each later block
// maps to the unmatched lane it shares the most credentials with, or a new
// lane if it shares none. lanes must be sorted by sortLanes.
func matchLanes(lanes []lane, blocks []tenant) []int {
	target := make([]int, len(blocks))
	used := make([]bool, len(lanes))
	for b, t := range blocks {
		target[b] = -1
		if b == 0 {
			if len(lanes) > 0 && lanes[0].holdsPrimary() {
				target[b], used[0] = 0, true
			}
			continue
		}
		best := 0
		for i, l := range lanes {
			if used[i] || l.holdsPrimary() {
				continue
			}
			if n := shared(l, t); n > best {
				target[b], best = i, n
			}
		}
		if target[b] >= 0 {
			used[target[b]] = true
		}
	}
	return target
}

func shared(l lane, t tenant) int {
	n := 0
	for _, id := range l.credentials() {
		if id != "" && slices.Contains(t.credentials, id) {
			n++
		}
	}
	return n
}

type privateSetter interface {
	SetKey(context.Context, string, []byte) diag.Diagnostics
}

// storedMainEntity returns the entity ID stored under mainEntityKey, or ""
// before the first apply and after import.
func storedMainEntity(ctx context.Context, private privateGetter) (string, diag.Diagnostics) {
	value, diags := private.GetKey(ctx, mainEntityKey)
	var entity string
	if len(value) > 0 {
		if err := json.Unmarshal(value, &entity); err != nil {
			diags.AddError("Invalid private state", err.Error())
		}
	}
	return entity, diags
}

// misplacedPrimaryDetail explains a primary credential that has moved out of
// the lane block 1 manages, for example because the main lane's last
// credential was deleted. No API operation moves the primary between lanes.
func misplacedPrimaryDetail(appID string) string {
	return fmt.Sprintf("The primary credential of application %s has moved out of the tenant that the first tenant "+
		"block manages, so that tenant is no longer the main tenant. This happens when the main "+
		"tenant's last credential is deleted, for example by replacing a heist_credential without "+
		"create_before_destroy. The API can't move the primary between tenants.\n\n"+
		"Replace this resource to unlink every credential and link them again with the first block as the main "+
		"tenant:\n\n  terraform apply -replace=heist_application_credentials.<name>", appID)
}

// tenantsFromLanes orders lanes as tenant blocks: the lane holding the
// primary first, then the others in prior's block order, matched by entity
// ID or else by a shared credential, with lanes not in prior at the end.
func tenantsFromLanes(lanes []lane, prior []tenant) []tenant {
	position := func(l lane) int {
		for i, t := range prior {
			if t.entityID != "" && t.entityID == l.entityID {
				return i
			}
		}
		for i, t := range prior {
			if shared(l, t) > 0 {
				return i
			}
		}
		return len(prior)
	}
	others := slices.Clone(lanes)
	var tenants []tenant
	if len(others) > 0 && others[0].holdsPrimary() {
		tenants = append(tenants, tenant{credentials: others[0].credentials(), entityID: others[0].entityID})
		others = others[1:]
	}
	slices.SortStableFunc(others, func(a, b lane) int { return cmp.Compare(position(a), position(b)) })
	for _, l := range others {
		tenants = append(tenants, tenant{credentials: l.credentials(), entityID: l.entityID})
	}
	return tenants
}

// sameTenantsIgnoringOrder reports whether two sets of blocks differ at most
// in the order of the blocks after the first.
func sameTenantsIgnoringOrder(a, b []tenant) bool {
	key := func(ts []tenant) []string {
		keys := make([]string, len(ts))
		for i, t := range ts {
			if slices.Contains(t.credentials, "") {
				return nil
			}
			keys[i] = strings.Join(t.credentials, ",")
		}
		if len(keys) > 1 {
			slices.Sort(keys[1:])
		}
		return keys
	}
	ka, kb := key(a), key(b)
	return len(ka) > 0 && slices.Equal(ka, kb)
}

// tenantsFrom converts tenant blocks, with "" for unknown credential IDs and
// entity IDs.
func tenantsFrom(ctx context.Context, l types.List) ([]tenant, diag.Diagnostics) {
	var diags diag.Diagnostics
	if l.IsNull() || l.IsUnknown() {
		return nil, diags
	}
	var models []tenantModel
	diags.Append(l.ElementsAs(ctx, &models, false)...)
	tenants := make([]tenant, len(models))
	for i, m := range models {
		tenants[i].entityID = m.EntityID.ValueString()
		if m.CredentialIDs.IsUnknown() {
			continue
		}
		var ids []types.String
		diags.Append(m.CredentialIDs.ElementsAs(ctx, &ids, false)...)
		for _, id := range ids {
			tenants[i].credentials = append(tenants[i].credentials, id.ValueString())
		}
	}
	return tenants, diags
}

// tenantsValue converts lanes read from the API to tenant blocks.
func tenantsValue(ctx context.Context, tenants []tenant) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	models := make([]tenantModel, len(tenants))
	for i, t := range tenants {
		var d diag.Diagnostics
		models[i].CredentialIDs, d = types.ListValueFrom(ctx, types.StringType, t.credentials)
		diags.Append(d...)
		models[i].EntityID = types.StringValue(t.entityID)
	}
	l, d := types.ListValueFrom(ctx, tenantType, models)
	diags.Append(d...)
	return l, diags
}
