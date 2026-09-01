// openapi.go — generate OpenAPI 3 YAML for the public + admin servers from
// the same handler/DTO AST walk that produces docs/reference/http-api.md.
//
// Why this exists. The old hand-written docs/api/{admin,public}-api.yaml
// drifted from the handlers (multiple audits caught wire-shape mismatches)
// and was deleted in the v2 docs revamp. The repo's stance is that the
// handler source + DTO struct tags are the only ground truth (see the
// memory note `feedback_openapi_not_ground_truth`). This emitter restores
// the machine-readable OpenAPI surface for tooling consumers (Swagger UI,
// openapi-validator, client codegen) **without** reintroducing drift: the
// YAML is produced from the same `buildHTTPModel` walk as the Markdown
// reference, so a handler / DTO change updates both in lockstep when
// `make docs-gen` runs.
//
// Per-route request/response/error metadata comes from the existing
// `routeBodyHints` map (also the source the Markdown reference uses).
// That map carries `{{dto:X}}` placeholders + `**Response NNN**` markers +
// `**Errors** — NNN \`code\“ lists; this file parses those strings into
// structured OpenAPI operation parts. Any route without a hint entry gets
// a minimal but valid operation entry — losing schema-bound bodies for it,
// but never producing an invalid spec.
//
// Output: docs/api/admin-api.yaml and docs/api/public-api.yaml. Wired into
// `make docs-gen` via the `all` subcommand, and into `make docs-check`'s
// `git diff --exit-code` guard so a stale file fails CI.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// openAPISpecVersion is the version stamped in `info.version`. Bump when the
// docs-published wire surface itself moves (not every code edit).
const openAPISpecVersion = "0.1.0"

// -----------------------------------------------------------------------------
// OpenAPI 3.0.3 document model — yaml-tagged subset just rich enough for
// the routes + DTOs this codebase ships. All fields use `omitempty` so the
// emitted YAML stays terse for routes that don't need every facet.
// -----------------------------------------------------------------------------

type openAPIDoc struct {
	OpenAPI    string                     `yaml:"openapi"`
	Info       openAPIInfo                `yaml:"info"`
	Servers    []openAPIServer            `yaml:"servers,omitempty"`
	Tags       []openAPITag               `yaml:"tags,omitempty"`
	Paths      map[string]openAPIPathItem `yaml:"paths"`
	Components openAPIComponents          `yaml:"components,omitempty"`
}

type openAPIInfo struct {
	Title       string `yaml:"title"`
	Version     string `yaml:"version"`
	Description string `yaml:"description,omitempty"`
}

type openAPIServer struct {
	URL         string `yaml:"url"`
	Description string `yaml:"description,omitempty"`
}

type openAPITag struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
}

type openAPIPathItem struct {
	Get        *openAPIOperation  `yaml:"get,omitempty"`
	Post       *openAPIOperation  `yaml:"post,omitempty"`
	Put        *openAPIOperation  `yaml:"put,omitempty"`
	Patch      *openAPIOperation  `yaml:"patch,omitempty"`
	Delete     *openAPIOperation  `yaml:"delete,omitempty"`
	Parameters []openAPIParameter `yaml:"parameters,omitempty"`
}

type openAPIOperation struct {
	OperationID string                     `yaml:"operationId,omitempty"`
	Summary     string                     `yaml:"summary,omitempty"`
	Description string                     `yaml:"description,omitempty"`
	Tags        []string                   `yaml:"tags,omitempty"`
	Parameters  []openAPIParameter         `yaml:"parameters,omitempty"`
	RequestBody *openAPIRequestBody        `yaml:"requestBody,omitempty"`
	Responses   map[string]openAPIResponse `yaml:"responses"`
	Security    []map[string][]string      `yaml:"security,omitempty"`
}

type openAPIParameter struct {
	Name        string         `yaml:"name"`
	In          string         `yaml:"in"`
	Required    bool           `yaml:"required,omitempty"`
	Description string         `yaml:"description,omitempty"`
	Schema      *openAPISchema `yaml:"schema,omitempty"`
}

type openAPIRequestBody struct {
	Required bool                        `yaml:"required,omitempty"`
	Content  map[string]openAPIMediaType `yaml:"content"`
}

type openAPIMediaType struct {
	Schema *openAPISchema `yaml:"schema,omitempty"`
}

type openAPIResponse struct {
	Description string                      `yaml:"description"`
	Content     map[string]openAPIMediaType `yaml:"content,omitempty"`
}

type openAPIComponents struct {
	Schemas         map[string]*openAPISchema        `yaml:"schemas,omitempty"`
	SecuritySchemes map[string]openAPISecurityScheme `yaml:"securitySchemes,omitempty"`
}

type openAPISecurityScheme struct {
	Type         string `yaml:"type"`
	Scheme       string `yaml:"scheme,omitempty"`
	BearerFormat string `yaml:"bearerFormat,omitempty"`
	Name         string `yaml:"name,omitempty"`
	In           string `yaml:"in,omitempty"`
	Description  string `yaml:"description,omitempty"`
}

// openAPISchema covers $ref, primitives, arrays, and object schemas. Most
// docsgen-emitted field types map to either {type, format} or {type: array,
// items}; DTO references become {$ref}. The catch-all `AdditionalProperties`
// is `any` so we can emit either `true` (free-form) or another schema.
type openAPISchema struct {
	Ref                  string                    `yaml:"$ref,omitempty"`
	Type                 string                    `yaml:"type,omitempty"`
	Format               string                    `yaml:"format,omitempty"`
	Items                *openAPISchema            `yaml:"items,omitempty"`
	Properties           map[string]*openAPISchema `yaml:"properties,omitempty"`
	Required             []string                  `yaml:"required,omitempty"`
	Nullable             bool                      `yaml:"nullable,omitempty"`
	Description          string                    `yaml:"description,omitempty"`
	Enum                 []string                  `yaml:"enum,omitempty"`
	AdditionalProperties any                       `yaml:"additionalProperties,omitempty"`
}

// -----------------------------------------------------------------------------
// Cobra command
// -----------------------------------------------------------------------------

func newOpenAPICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "openapi",
		Short: "Generate OpenAPI 3 YAML for the public + admin servers (docs/api/{public,admin}-api.yaml)",
		RunE: func(cmd *cobra.Command, args []string) error {
			admPath, pubPath, err := runOpenAPIGen()
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\nwrote %s\n", pubPath, admPath)
			return nil
		},
	}
}

// runOpenAPIGen builds the HTTP model (same one the Markdown reference uses),
// splits routes by server, and writes the two YAML files. Returns
// (adminPath, publicPath).
func runOpenAPIGen() (string, string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", "", fmt.Errorf("locate repo root: %w", err)
	}
	model, err := buildHTTPModel(root)
	if err != nil {
		return "", "", fmt.Errorf("build http model: %w", err)
	}
	pub, adm := partitionRoutesByServer(model.Routes)

	dir := filepath.Join(root, "docs", "api")
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: docs/ dir is world-readable by design
		return "", "", fmt.Errorf("create %s: %w", dir, err)
	}

	pubDoc := buildOpenAPI("public", pub, model.DTOs)
	admDoc := buildOpenAPI("admin", adm, model.DTOs)

	pubPath := filepath.Join(dir, "public-api.yaml")
	if err := writeOpenAPI(pubPath, pubDoc); err != nil {
		return "", "", fmt.Errorf("write %s: %w", pubPath, err)
	}
	admPath := filepath.Join(dir, "admin-api.yaml")
	if err := writeOpenAPI(admPath, admDoc); err != nil {
		return "", "", fmt.Errorf("write %s: %w", admPath, err)
	}
	return admPath, pubPath, nil
}

func writeOpenAPI(path string, doc openAPIDoc) error {
	var buf strings.Builder
	buf.WriteString("# generated by tools/docsgen; do not edit. Re-run: make docs-gen\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(buf.String()), 0o644) //nolint:gosec // G306: generated docs are world-readable
}

// -----------------------------------------------------------------------------
// Doc construction
// -----------------------------------------------------------------------------

func buildOpenAPI(server string, routes []httpRoute, allDTOs []httpDTO) openAPIDoc {
	// Stable route order — sorted by path then method — keeps the YAML
	// deterministic across runs so docs-check's git-diff guard is meaningful.
	sorted := append([]httpRoute(nil), routes...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Path != sorted[j].Path {
			return sorted[i].Path < sorted[j].Path
		}
		return sorted[i].Method < sorted[j].Method
	})

	// Index every captured DTO by its Go type name so the type mapper can
	// resolve `RefDTO` -> $ref when a field references another captured DTO.
	dtoByName := map[string]httpDTO{}
	for _, d := range allDTOs {
		dtoByName[d.Name] = d
	}

	// Track which DTOs are referenced from this server's routes (directly via
	// hints, plus transitively via field RefDTOs). We only emit referenced
	// schemas to keep the YAML focused per server.
	refs := map[string]bool{}

	doc := openAPIDoc{
		OpenAPI: "3.0.3",
		Info: openAPIInfo{
			Title:       openAPITitle(server),
			Version:     openAPISpecVersion,
			Description: openAPIDescription(server),
		},
		Servers: []openAPIServer{{
			URL:         "http://localhost:" + serverPort(server),
			Description: "local development (default port)",
		}},
		Paths: map[string]openAPIPathItem{},
	}

	for _, r := range sorted {
		op, pathParams := buildOperation(r, dtoByName, refs)
		item := doc.Paths[r.Path]
		// Path parameters live at the path-item level (shared across methods).
		if len(item.Parameters) == 0 && len(pathParams) > 0 {
			item.Parameters = pathParams
		}
		switch strings.ToUpper(r.Method) {
		case "GET":
			item.Get = op
		case "POST":
			item.Post = op
		case "PUT":
			item.Put = op
		case "PATCH":
			item.Patch = op
		case "DELETE":
			item.Delete = op
		}
		doc.Paths[r.Path] = item
	}

	doc.Components = openAPIComponents{
		Schemas:         buildSchemas(allDTOs, dtoByName, refs),
		SecuritySchemes: serverSecuritySchemes(server),
	}
	doc.Tags = buildTags(sorted)
	return doc
}

func serverPort(server string) string {
	if server == "admin" {
		return "9001"
	}
	return "9000"
}

func openAPITitle(server string) string {
	if server == "admin" {
		return "Authplane Authserver — Admin API"
	}
	return "Authplane Authserver — Public API"
}

func openAPIDescription(server string) string {
	base := "Generated from the authserver handler source by `tools/docsgen`. " +
		"The human-readable companion reference is `docs/reference/http-api.md`; this YAML is its " +
		"OpenAPI 3.0.3 projection for tooling consumers (Swagger UI, openapi-validator, " +
		"client codegen, contract testing). Run `make docs-gen` to regenerate."
	if server == "admin" {
		return base + "\n\nThe admin server (default `:9001`) requires bearer authentication with " +
			"`AUTHPLANE_ADMIN_API_KEY`. It carries privileged operations and must never be exposed " +
			"to the public internet."
	}
	return base + "\n\nThe public server (default `:9000`) hosts the OAuth 2.1 / OIDC / MCP " +
		"endpoints clients and agents interact with. Most endpoints are unauthenticated at the " +
		"transport layer; per-grant authentication is in the request body (`client_id`/`client_secret`, " +
		"`subject_token`, DPoP proofs, …)."
}

func serverSecuritySchemes(server string) map[string]openAPISecurityScheme {
	if server == "admin" {
		return map[string]openAPISecurityScheme{
			"AdminAPIKey": {
				Type: "http", Scheme: "bearer",
				Description: "Bearer auth using `AUTHPLANE_ADMIN_API_KEY`. The admin server has no other " +
					"auth mode; every protected route requires this header.",
			},
		}
	}
	return map[string]openAPISecurityScheme{
		"OAuth2Bearer": {
			Type: "http", Scheme: "bearer", BearerFormat: "JWT",
			Description: "OAuth 2.1 access token issued by `/oauth/token` (or via federation through " +
				"`/oidc/start` -> `/oidc/callback`).",
		},
		"SessionCookie": {
			Type: "apiKey", In: "cookie", Name: "authplane_session",
			Description: "Browser session cookie set by the AS login + consent flows. Used by " +
				"the human-driven endpoints (`/oauth/authorize`, `/connect/{provider}`, …).",
		},
	}
}

// buildTags derives a small, stable tag set from the route paths (top-level
// path segment after the leading slash, normalised). Tools like Swagger UI
// use tags to group operations in the sidebar.
func buildTags(routes []httpRoute) []openAPITag {
	seen := map[string]bool{}
	for _, r := range routes {
		t := tagFromPath(r.Path)
		seen[t] = true
	}
	out := make([]openAPITag, 0, len(seen))
	for t := range seen {
		out = append(out, openAPITag{Name: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func tagFromPath(p string) string {
	p = strings.TrimPrefix(p, "/")
	if i := strings.Index(p, "/"); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return "root"
	}
	return p
}

// -----------------------------------------------------------------------------
// Per-operation construction
// -----------------------------------------------------------------------------

func buildOperation(r httpRoute, dtoByName map[string]httpDTO, refs map[string]bool) (*openAPIOperation, []openAPIParameter) {
	op := &openAPIOperation{
		OperationID: operationID(r),
		Summary:     summaryFor(r),
		Tags:        []string{tagFromPath(r.Path)},
		Responses:   map[string]openAPIResponse{},
	}

	// Security per auth mode (matches the Markdown reference's "Auth — …" line).
	switch r.AuthMode {
	case "admin-api-key":
		op.Security = []map[string][]string{{"AdminAPIKey": {}}}
	case "session":
		op.Security = []map[string][]string{{"SessionCookie": {}}}
	case "metrics-basic-auth":
		// Prometheus basic-auth is uncommon and isn't a securityScheme above;
		// surface it in the description so consumers know it's expected.
		op.Description = "Authenticated via Prometheus-style HTTP Basic against the " +
			"`metrics.basic_auth_*` config; not modeled as an OpenAPI security scheme."
	}

	// What the endpoint does, in prose. OpenAPI-only: the Markdown reference
	// carries this through routeBodyHints, which the projection below consumes
	// structurally instead. Without it an operation whose only description is a
	// routeNotes caveat reads as if the caveat were its purpose.
	if desc := routeDescriptions[r.Method+" "+r.Path]; desc != "" {
		if op.Description != "" {
			op.Description += " "
		}
		op.Description += desc
	}

	// Behavioral caveats (same source the Markdown "**Note**" paragraph uses),
	// so client codegen and Swagger UI carry them too.
	if note := routeNotes[r.Method+" "+r.Path]; note != "" {
		if op.Description != "" {
			op.Description += " "
		}
		// Uppercase the leading rune, not the leading byte — a note starting
		// with a multi-byte rune would otherwise be split mid-UTF-8.
		first, size := utf8.DecodeRuneInString(note)
		op.Description += string(unicode.ToUpper(first)) + note[size:]
	}

	// Parse the hand-curated hint (same source the Markdown uses).
	hint := routeBodyHints[r.Method+" "+r.Path]
	parsed := parseHint(hint)

	// Request body.
	if parsed.requestDTO != "" {
		markRef(parsed.requestDTO, dtoByName, refs)
		op.RequestBody = &openAPIRequestBody{
			Required: true,
			Content: map[string]openAPIMediaType{
				"application/json": {Schema: refSchema(parsed.requestDTO)},
			},
		}
	} else if parsed.formEncoded {
		op.RequestBody = &openAPIRequestBody{
			Required: true,
			Content: map[string]openAPIMediaType{
				"application/x-www-form-urlencoded": {Schema: &openAPISchema{
					Type:                 "object",
					Description:          "Form-encoded grant parameters; concrete fields depend on `grant_type`. See `docs/reference/http-api.md` for the per-grant breakdown.",
					AdditionalProperties: true,
				}},
			},
		}
	}

	// Successful responses parsed from the hint (status -> DTO refs).
	for _, sr := range parsed.successResponses {
		desc := defaultResponseDescription(sr.status)
		resp := openAPIResponse{Description: desc}
		if len(sr.dtoNames) > 0 {
			// First DTO drives the schema; the rest are mentioned in description
			// (the OAuth token endpoint legitimately has two shapes — token vs.
			// token-exchange — joined with "or"). One full-fidelity ref is more
			// useful than no schema at all.
			markRef(sr.dtoNames[0], dtoByName, refs)
			resp.Content = map[string]openAPIMediaType{
				"application/json": {Schema: refSchema(sr.dtoNames[0])},
			}
			if len(sr.dtoNames) > 1 {
				resp.Description += " (Alternate shape: `" + sr.dtoNames[1] + "` — see the human-readable reference for the discriminator.)"
				for _, extra := range sr.dtoNames[1:] {
					markRef(extra, dtoByName, refs)
				}
			}
		}
		op.Responses[sr.status] = resp
	}

	// Error responses parsed from the hint (status -> error code list). If
	// the hint also names a shared error-body DTO (e.g. OAuthErrorResponse),
	// attach it as the response schema so codegen can decode error payloads.
	if parsed.errorDTO != "" {
		markRef(parsed.errorDTO, dtoByName, refs)
	}
	for status, codes := range parsed.errors {
		desc := defaultResponseDescription(status)
		if len(codes) > 0 {
			desc += " (`error` values: " + strings.Join(quoteList(codes), ", ") + ")"
		}
		// Don't overwrite a 2xx success entry that happens to collide.
		if _, exists := op.Responses[status]; exists {
			continue
		}
		resp := openAPIResponse{Description: desc}
		if parsed.errorDTO != "" {
			resp.Content = map[string]openAPIMediaType{
				"application/json": {Schema: refSchema(parsed.errorDTO)},
			}
		}
		op.Responses[status] = resp
	}

	// Fallback: every operation needs at least one response per OpenAPI 3.
	if len(op.Responses) == 0 {
		op.Responses["default"] = openAPIResponse{
			Description: "See `docs/reference/http-api.md` for the response shape.",
		}
	}

	return op, pathParameters(r.Path)
}

// summaryFor produces a short one-liner suitable for OpenAPI's `summary` —
// the per-route entry the Markdown reference already encodes via section
// headings.
func summaryFor(r httpRoute) string {
	return fmt.Sprintf("`%s %s`", r.Method, r.Path)
}

// operationID is a stable identifier per (method, path), useful for codegen
// tooling. It mirrors the anchor docsgen emits in the Markdown reference.
func operationID(r httpRoute) string {
	return routeAnchor(r)
}

func defaultResponseDescription(status string) string {
	switch status {
	case "200":
		return "OK"
	case "201":
		return "Created"
	case "204":
		return "No Content"
	case "400":
		return "Bad Request"
	case "401":
		return "Unauthorized"
	case "403":
		return "Forbidden"
	case "404":
		return "Not Found"
	case "405":
		return "Method Not Allowed"
	case "409":
		return "Conflict"
	case "429":
		return "Too Many Requests"
	case "500":
		return "Internal Server Error"
	}
	return "Status " + status
}

func quoteList(codes []string) []string {
	out := make([]string, len(codes))
	for i, c := range codes {
		out[i] = "`" + c + "`"
	}
	return out
}

// pathParameters scans a path like `/admin/clients/{id}/grants/{name}` and
// returns parameters for every `{seg}`. Schema is string by default — every
// path param in this codebase is an identifier (id, slug, jti, name, …).
func pathParameters(path string) []openAPIParameter {
	re := regexp.MustCompile(`\{([^/}]+)\}`)
	var out []openAPIParameter
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(path, -1) {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, openAPIParameter{
			Name:     name,
			In:       "path",
			Required: true,
			Schema:   &openAPISchema{Type: "string"},
		})
	}
	return out
}

func refSchema(dtoName string) *openAPISchema {
	return &openAPISchema{Ref: "#/components/schemas/" + pascal(dtoName)}
}

// markRef tags a DTO (by Go type name) as referenced from a route so
// buildSchemas includes it. Also walks the DTO's fields to mark any
// transitively-referenced DTOs.
func markRef(name string, dtoByName map[string]httpDTO, refs map[string]bool) {
	if name == "" || refs[name] {
		return
	}
	d, ok := dtoByName[name]
	if !ok {
		// Unknown DTO (typo in hint, helper type defined elsewhere) — still
		// record it so the buildSchemas error path can surface a clear note.
		refs[name] = true
		return
	}
	refs[name] = true
	for _, f := range d.Fields {
		if f.RefDTO != "" {
			markRef(f.RefDTO, dtoByName, refs)
		}
	}
}

// -----------------------------------------------------------------------------
// Hint parsing — extract structured per-route metadata from the hand-curated
// `routeBodyHints` strings.
// -----------------------------------------------------------------------------

type parsedHint struct {
	requestDTO       string
	formEncoded      bool
	successResponses []successResponse // ordered: 2xx codes the hint mentions
	errors           map[string][]string
	errorDTO         string // optional: shared error-response body (e.g. `OAuthErrorResponse`)
}

type successResponse struct {
	status   string
	dtoNames []string
}

var (
	hintDTORE     = regexp.MustCompile(`\{\{dto:([A-Za-z][A-Za-z0-9_]*)\}\}`)
	hintRequestRE = regexp.MustCompile(`(?s)\*\*Request\*\*[^*]*?(?:\{\{dto:([A-Za-z][A-Za-z0-9_]*)\}\}|form-encoded)`)
	// Matches only the HEADER of a response block. The body is sliced between
	// consecutive headers by the caller rather than captured here.
	//
	// It used to capture the body with a consumed `**` terminator, which ate the
	// opening marker of the NEXT response: FindAllStringSubmatch resumed past it
	// and silently dropped every other one, so three documented responses became
	// two. Go's regexp is RE2 and has no lookahead, so the terminator cannot
	// simply be made non-consuming — hence the index walk.
	hintResponseRE = regexp.MustCompile(`\*\*Response (\d{3})\*\*`)
	hintErrorsRE   = regexp.MustCompile(`(?s)\*\*Errors\*\*([^*]*?)(?:\*\*|\z)`)
	// hintStatusCodeRE matches "NNN `code`" where NNN is a real 3-digit HTTP
	// status, not the tail of a longer number. The `(^|\D)` anchor avoids
	// matching "749" inside "RFC 6749 `invalid_request`".
	hintStatusCodeRE = regexp.MustCompile(`(?:^|\D)(\d{3})\s+\x60([A-Za-z][A-Za-z0-9_]*)\x60`)
	hintRFCErrorRE   = regexp.MustCompile(`\x60([a-z][a-z0-9_]+)\x60`) // RFC 6749 codes — `invalid_request`, etc.
)

func parseHint(hint string) parsedHint {
	out := parsedHint{errors: map[string][]string{}}
	if hint == "" {
		return out
	}

	// Request body.
	if m := hintRequestRE.FindStringSubmatch(hint); m != nil {
		if m[1] != "" {
			out.requestDTO = m[1]
		} else {
			out.formEncoded = true
		}
	}

	// Success responses. Each "**Response NNN**" header owns the text up to the
	// next header, or to the end of the hint for the last one — sliced by index
	// so no marker is consumed and none is skipped.
	headers := hintResponseRE.FindAllStringSubmatchIndex(hint, -1)
	for i, h := range headers {
		status := hint[h[2]:h[3]]

		// A segment ends at the next response header, or — for the last one — at
		// whatever marker comes after it. Running the last segment to the end of
		// the hint would swallow the **Errors** block, so any {{dto:…}} cited
		// there would be attributed to the final success response.
		end := len(hint)
		if i+1 < len(headers) {
			end = headers[i+1][0]
		} else if next := strings.Index(hint[h[1]:], "**"); next >= 0 {
			end = h[1] + next
		}
		segment := hint[h[1]:end]
		var dtos []string
		for _, dm := range hintDTORE.FindAllStringSubmatch(segment, -1) {
			dtos = append(dtos, dm[1])
		}
		out.successResponses = append(out.successResponses, successResponse{status: status, dtoNames: dtos})
	}

	// Errors segment — collect status->code lists. Two shapes coexist:
	//   "**Errors** — 400 `invalid_request`, 401 `invalid_admin_key`"
	//   "**Errors** — RFC 6749 `invalid_request`, `invalid_client`, …"  (no status)
	// The first form pins codes to specific statuses; the second is a general
	// pool — assign those to 400 since OAuth errors land there per RFC 6749 §5.2.
	if m := hintErrorsRE.FindStringSubmatch(hint); m != nil {
		segment := m[1]
		usedStatus := false
		for _, sm := range hintStatusCodeRE.FindAllStringSubmatch(segment, -1) {
			status, code := sm[1], sm[2]
			out.errors[status] = append(out.errors[status], code)
			usedStatus = true
		}
		if !usedStatus {
			for _, em := range hintRFCErrorRE.FindAllStringSubmatch(segment, -1) {
				out.errors["400"] = append(out.errors["400"], em[1])
			}
		}
		// A shared error body DTO may be cited inside the Errors segment
		// (e.g. OAuth /token: "Body: {{dto:OAuthErrorResponse}}"). Pick the
		// first such reference; that schema is then attached to every error
		// status in this operation.
		if dm := hintDTORE.FindStringSubmatch(segment); dm != nil {
			out.errorDTO = dm[1]
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// Schema construction — every captured DTO becomes a component schema. We
// also keep a transitively-reachable filter so per-server YAMLs don't list
// the entire universe of DTOs.
// -----------------------------------------------------------------------------

func buildSchemas(allDTOs []httpDTO, dtoByName map[string]httpDTO, refs map[string]bool) map[string]*openAPISchema {
	// Walk transitive refs one more time so anything referenced by an already-
	// referenced DTO is also included.
	for name := range refs {
		markRef(name, dtoByName, refs)
	}

	out := map[string]*openAPISchema{}
	for _, d := range allDTOs {
		if !refs[d.Name] {
			continue
		}
		out[pascal(d.Name)] = dtoToSchema(d)
	}
	return out
}

func dtoToSchema(d httpDTO) *openAPISchema {
	s := &openAPISchema{
		Type:        "object",
		Description: strings.TrimSpace(d.Comment),
		Properties:  map[string]*openAPISchema{},
	}
	var required []string
	for _, f := range d.Fields {
		if f.JSONName == "" || f.JSONName == "-" {
			continue
		}
		s.Properties[f.JSONName] = fieldToSchema(f)
		if f.Required {
			required = append(required, f.JSONName)
		}
	}
	if len(required) > 0 {
		sort.Strings(required)
		s.Required = required
	}
	return s
}

func fieldToSchema(f httpDTOField) *openAPISchema {
	sc := typeStringToSchema(f.Type, f.RefDTO)
	if note := strings.TrimSpace(f.Notes); note != "" {
		sc.Description = note
	}
	return sc
}

// -----------------------------------------------------------------------------
// Go type string -> OpenAPI schema. Covers the patterns docsgen actually
// emits today (sample from the rendered http-api.md DTO tables):
//
//   string, *string, int, int32, int64, uint*, float64, bool
//   time.Time, *time.Time
//   []X, *[]X
//   map[K]V, *map[K]V
//   json.RawMessage / *json.RawMessage
//   <bare type name> when RefDTO is set -> $ref
//
// Pointer wrappers map to `nullable: true` and drop the `*` for the inner
// type. Enum-typed fields (e.g. `client.Status`) fall back to string — the
// enum value list isn't currently captured by docsgen.
// -----------------------------------------------------------------------------

func typeStringToSchema(t, refDTO string) *openAPISchema {
	t = strings.TrimSpace(t)
	nullable := false
	if strings.HasPrefix(t, "*") {
		nullable = true
		t = t[1:]
	}
	sc := innerTypeToSchema(t, refDTO)
	if nullable {
		sc.Nullable = true
	}
	return sc
}

func innerTypeToSchema(t, refDTO string) *openAPISchema {
	// Slice.
	if strings.HasPrefix(t, "[]") {
		inner := typeStringToSchema(strings.TrimPrefix(t, "[]"), refDTO)
		return &openAPISchema{Type: "array", Items: inner}
	}
	// Map.
	if strings.HasPrefix(t, "map[") {
		// map[K]V — value type is everything after the matching "]".
		if idx := strings.Index(t, "]"); idx > 4 {
			valType := t[idx+1:]
			val := typeStringToSchema(valType, refDTO)
			return &openAPISchema{Type: "object", AdditionalProperties: val}
		}
	}
	// Time.
	if t == "time.Time" {
		return &openAPISchema{Type: "string", Format: "date-time"}
	}
	if t == "time.Duration" {
		return &openAPISchema{Type: "string", Format: "duration"}
	}
	// JSON RawMessage — opaque blob, but documented as object/any.
	if t == "json.RawMessage" {
		return &openAPISchema{
			Description:          "Opaque JSON value (passthrough).",
			AdditionalProperties: true,
		}
	}
	// Primitives.
	switch t {
	case "string":
		return &openAPISchema{Type: "string"}
	case "bool":
		return &openAPISchema{Type: "boolean"}
	case "int", "int32":
		return &openAPISchema{Type: "integer", Format: "int32"}
	case "int64", "uint64", "uint", "uint32":
		return &openAPISchema{Type: "integer", Format: "int64"}
	case "float32", "float64":
		return &openAPISchema{Type: "number", Format: "double"}
	}
	// Captured DTO reference.
	if refDTO != "" {
		return refSchema(refDTO)
	}
	// Qualified type without a captured DTO (e.g. `client.Status`,
	// `client.RegistrationSource`) — fall back to string. These are enum
	// aliases over string; the enum values aren't currently captured.
	if strings.Contains(t, ".") {
		return &openAPISchema{Type: "string"}
	}
	// Last-resort: emit string + note. Better than silently dropping.
	return &openAPISchema{
		Type:        "string",
		Description: "type `" + t + "` — see `docs/reference/http-api.md`",
	}
}

// pascal turns a Go type name into a PascalCase OpenAPI schema name. Unexported
// helper types in the admin package (clientView, createUserRequest) become
// ClientView, CreateUserRequest — the conventional OpenAPI form. Names that
// are already exported pass through unchanged.
func pascal(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = []rune(strings.ToUpper(string(r[0])))[0]
	return string(r)
}
