/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package admission verifies API-server authentication tokens for admission webhooks.
// It provides an HTTP handler and a verifier for already-decoded requests. Both
// require the webhook's configured audience; failed verification never reaches
// the downstream admission handler.
//
// Review-only walkthrough: start at 1.) on WithTokenVerification, or 2.) for a
// framework that already decodes AdmissionReviews. Numbers identify function
// notes, not declaration order. This library has no main function.
package admission // import "k8s.io/component-helpers/auth/admission"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/component-helpers/auth/admission/internal/oidc"
	"k8s.io/component-helpers/auth/admission/internal/verify"
	"k8s.io/klog/v2"
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

// 20.) Import-time setup, before the consumer's main: AddToScheme registers v1
// AdmissionReview types for the shared Kubernetes decoder. Must panics only if
// registration fails; importing this package does not discover signing keys.
func init() {
	utilruntime.Must(admissionv1.AddToScheme(scheme))
}

const defaultMaxBodyBytes int64 = 8 << 20 // 8 MiB

// Keep denial messages generic to avoid exposing token or claim details.
const genericDenyMessage = "webhook token verification failed"

var errVerificationFailed = errors.New(genericDenyMessage)

// AdmissionHandler decides an already-verified admission request. The HTTP
// adapter copies the response and sets its UID before writing it.
type AdmissionHandler func(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse

// Option configures [WithTokenVerification] or [NewVerifier].
type Option func(*builder)

// remoteSet prevents an injected HTTP client from selecting remote mode.
type builder struct {
	remoteSet  bool
	issuer     string
	audience   string
	httpClient *http.Client

	explicitAudience bool

	// Tests can override discovery without selecting remote mode.
	inClusterURL    string
	inClusterClient *http.Client

	maxBody int64
}

// newBuilder returns a builder seeded with the handler defaults, ready for
// options to mutate.
//
// 5.) Both startup constructors allocate these private defaults before applying
// options. This is configuration assembly only; it performs no token or key work.
func newBuilder() *builder {
	return &builder{maxBody: defaultMaxBodyBytes}
}

// withMaxBodyBytes lets tests cover the body limit without exposing another
// configuration knob on the public webhook API.
//
// 21.) Test seam: the export_test wrapper applies a small limit to exercise
// rejection cheaply. Production callers retain the fixed 8 MiB default.
func withMaxBodyBytes(n int64) Option {
	return func(b *builder) {
		if n > 0 {
			b.maxBody = n
		}
	}
}

// WithRemoteIssuer selects remote OIDC verification. Both issuer and audience
// are required; an incomplete pair never falls back to in-cluster discovery.
// client is used for discovery and JWKS requests; use one without credentials
// because the advertised JWKS URI may have a different origin. A nil client
// uses the default transport.
//
// 4.) Setup option for a nonlocal issuer: captures issuer, audience, and client
// for either constructor. The closure selects remote mode; discovery happens
// later in buildVerifier, not when this option is created.
func WithRemoteIssuer(issuer, audience string, client *http.Client) Option {
	return func(b *builder) {
		b.remoteSet = true
		b.issuer = issuer
		b.audience = audience
		b.httpClient = client
	}
}

// WithAudience sets the expected audience for in-cluster verification. Use the
// webhook's exact configured URL, including any trailing slash, or
// https://<name>.<namespace>.svc:<port><path> for a Service reference (default
// port 443, path "/"). Never derive it from the request or token. Empty values
// or combining this option with [WithRemoteIssuer] fail at construction.
//
// 3.) Setup option: application code passes a trusted deployment audience to
// either constructor. The returned closure only records configuration; it does
// not infer the expected audience from a request, token, or network lookup.
func WithAudience(audience string) Option {
	return func(b *builder) {
		b.explicitAudience = true
		b.audience = audience
	}
}

// withInClusterEndpoint replaces in-cluster discovery for tests without changing modes.
//
// 22.) Test seam: supply a controlled API-server endpoint and HTTP client without
// selecting remote mode. Real in-cluster callers use projected ServiceAccount
// credentials through internal/oidc instead of this private option.
func withInClusterEndpoint(apiServerURL string, client *http.Client) Option {
	return func(b *builder) {
		b.inClusterURL = apiServerURL
		b.inClusterClient = client
	}
}

// Handler serves verified admission requests and exposes HealthCheck for readiness.
type Handler struct {
	verifier *Verifier
	next     AdmissionHandler
	maxBody  int64
}

// WithTokenVerification wraps next with verification of v1 AdmissionReviews.
// Configure admissionReviewVersions as ["v1"]. Supply [WithAudience] for
// in-cluster use or [WithRemoteIssuer] for other issuers.
// Missing credentials or undecodable requests return HTTP 401; decoded reviews
// with invalid tokens return HTTP 200/Allowed:false so failurePolicy: Ignore
// cannot override the denial. Use failurePolicy: Fail if missing credentials
// or an unavailable webhook must block admission. A nil next panics.
//
// 1.) Startup entrypoint: application setup (often main) calls admission.WithTokenVerification
// and registers the returned handler with its HTTP mux. Construction establishes
// issuer/key trust; next is the application's later per-request admission policy.
func WithTokenVerification(ctx context.Context, next AdmissionHandler, opts ...Option) (*Handler, error) {
	if next == nil {
		panic("admission: next AdmissionHandler must not be nil")
	}

	b := newBuilder()
	for _, opt := range opts {
		opt(b)
	}

	v, err := b.buildVerifier(ctx)
	if err != nil {
		return nil, err
	}
	return newHandler(v, next, b.maxBody), nil
}

// buildVerifier validates the expected audience before doing discovery. An
// inbound request and its bearer token cannot establish the webhook's identity.
//
// 6.) Startup trust selection: reject missing/conflicting audience settings,
// then construct the local or remote OIDC authenticator behind internal/verify.
// These constructors do discovery and load usable signing keys before serving.
func (b *builder) buildVerifier(ctx context.Context) (*verify.Verifier, error) {
	if b.remoteSet && b.explicitAudience {
		return nil, errors.New("admission: WithAudience cannot be combined with WithRemoteIssuer")
	}
	if b.remoteSet {
		if b.issuer == "" || b.audience == "" {
			return nil, errors.New("admission: remote verification requires both an issuer and an audience")
		}
		return oidc.NewRemoteVerifier(ctx, b.issuer, b.audience, b.httpClient)
	}
	if !b.explicitAudience || b.audience == "" {
		return nil, errors.New("admission: in-cluster verification requires WithAudience set to the webhook's configured URL or Service audience")
	}
	return oidc.NewLocalKeySetVerifier(ctx, b.inClusterURL, b.audience, b.inClusterClient)
}

// 7.) After trust construction, retain the shared public Verifier, callback,
// and body limit. This wiring does not process a request or run the callback.
func newHandler(v *verify.Verifier, next AdmissionHandler, maxBody int64) *Handler {
	return &Handler{verifier: &Verifier{verifier: v}, next: next, maxBody: maxBody}
}

// ServeHTTP implements http.Handler.
//
// 8.) Request entrypoint: net/http invokes this registered handler for each
// incoming request. Extract the bearer, decode once, and call Verify before
// dispatching the decoded request to next; never call policy on a denial.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// No request UID is available to echo before decoding the body.
	token, ok := BearerToken(r)
	if !ok {
		denyPreDecode(ctx, w, "no bearer token presented")
		return
	}

	review, reason, ok := h.decodeReview(r)
	if !ok {
		denyPreDecode(ctx, w, reason)
		return
	}
	req := review.Request

	if err := h.verifier.Verify(ctx, req, token); err != nil {
		writeResponse(w, req, deniedResponse())
		return
	}

	klog.FromContext(ctx).V(4).Info("Admission webhook token verified")
	writeResponse(w, req, h.next(ctx, req))
}

// denyPreDecode returns a generic 401 when there is no request UID to echo.
//
// 15.) ServeHTTP's early failure path has no decoded request UID. Log the local
// reason and emit only a generic HTTP 401, without calling the policy callback.
func denyPreDecode(ctx context.Context, w http.ResponseWriter, reason string) {
	klog.FromContext(ctx).V(2).Info("Admission webhook token verification denied", "reason", reason)
	http.Error(w, genericDenyMessage, http.StatusUnauthorized)
}

// deniedResponse returns an explicit denial that failurePolicy: Ignore cannot override.
//
// 16.) For a decoded request, build Allowed:false with a generic status. The
// surrounding writeResponse still uses HTTP 200; this is an admission denial,
// not a transport failure that failurePolicy: Ignore could skip.
func deniedResponse() *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: genericDenyMessage,
			Code:    http.StatusUnauthorized,
		},
	}
}

// writeResponse wraps the downstream response in a v1 AdmissionReview and
// writes it as HTTP 200 JSON. A nil response fails closed as a denial.
//
// 17.) Final HTTP step: copy the callback/denial response to set this request's
// UID, wrap it in v1 AdmissionReview JSON, and return HTTP 200. A nil callback
// response is replaced by a denial rather than treated as permission.
func writeResponse(w http.ResponseWriter, req *admissionv1.AdmissionRequest, resp *admissionv1.AdmissionResponse) {
	if resp == nil {
		resp = deniedResponse()
	}
	// A downstream may reuse a response across concurrent requests.
	response := *resp
	response.UID = req.UID
	out := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: admissionv1.SchemeGroupVersion.String(),
			Kind:       "AdmissionReview",
		},
		Response: &response,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// decodeReview limits the body and returns a non-sensitive reason for invalid reviews.
//
// 10.) Request decoding: read and close the body once under the size cap, then
// use Kubernetes' registered deserializer to require a nonnil AdmissionRequest.
// Decoding establishes shape, not caller authenticity or admission permission.
func (h *Handler) decodeReview(r *http.Request) (review *admissionv1.AdmissionReview, reason string, ok bool) {
	if r.Body == nil {
		return nil, "request body is not a decodable AdmissionReview", false
	}
	// Read one byte past the limit so an over-limit body is rejected rather than
	// silently decoding truncated bytes.
	buf, err := io.ReadAll(io.LimitReader(r.Body, h.maxBody+1))
	_ = r.Body.Close()
	if err != nil {
		return nil, "request body is not a decodable AdmissionReview", false
	}
	if int64(len(buf)) > h.maxBody {
		return nil, "request body exceeds the configured limit", false
	}
	obj, _, err := codecs.UniversalDeserializer().Decode(buf, nil, &admissionv1.AdmissionReview{})
	if err != nil {
		return nil, "request body is not a decodable AdmissionReview", false
	}
	ar, ok := obj.(*admissionv1.AdmissionReview)
	if !ok || ar.Request == nil {
		return nil, "request body is not a decodable AdmissionReview", false
	}
	return ar, "", true
}

// checkObjectGroup ensures both embedded objects agree with the admitted Kind.
// The signed token authorizes req.Resource.Group. Only known subresources may
// switch object groups (for example Deployment /scale carries autoscaling Scale,
// and Pod /eviction carries policy Eviction). An arbitrary SubResource is not a
// group authorization.
//
// 12.) Verify calls this after authorizing the resource group. Check current and
// old payloads against the reviewed Kind, allowing only the listed cross-group
// subresource shapes; this is not a full Kubernetes object/schema validation.
func checkObjectGroup(req *admissionv1.AdmissionRequest) error {
	if req == nil {
		return errors.New("admission request is nil")
	}
	group, version, kind := req.Resource.Group, "", ""
	// Kind is optional on the wire for ordinary resources; subresources cannot
	// safely fall back to Resource.Group because their object group may differ.
	kindSpecified := req.Kind.Group != "" || req.Kind.Version != "" || req.Kind.Kind != ""
	if req.SubResource != "" && !kindSpecified {
		return errors.New("subresource admission request has no kind")
	}
	if kindSpecified {
		if req.Kind.Version == "" || req.Kind.Kind == "" {
			return errors.New("admission request kind is incomplete")
		}
		if req.Kind.Group != req.Resource.Group {
			// Kubernetes has a few subresources whose request object belongs to a
			// different API group. An arbitrary SubResource or Kind must not grant
			// access to a group outside the token's resource-group attestation.
			switch {
			case req.SubResource == "scale" && req.Kind.Group == "autoscaling" && req.Kind.Version == "v1" && req.Kind.Kind == "Scale":
			case req.Resource.Group == "" && req.Resource.Resource == "pods" && req.SubResource == "eviction" && req.Kind.Group == "policy" && req.Kind.Version == "v1" && req.Kind.Kind == "Eviction":
			case req.Resource.Group == "" && req.Resource.Resource == "serviceaccounts" && req.SubResource == "token" && req.Kind.Group == "authentication.k8s.io" && req.Kind.Version == "v1" && req.Kind.Kind == "TokenRequest":
			default:
				return fmt.Errorf("object kind group %q differs from authorized resource group %q", req.Kind.Group, req.Resource.Group)
			}
		}
		group, version, kind = req.Kind.Group, req.Kind.Version, req.Kind.Kind
	}
	if err := checkExtensionObjectGroup("object", req.Object, group, version, kind); err != nil {
		return err
	}
	return checkExtensionObjectGroup("oldObject", req.OldObject, group, version, kind)
}

// 13.) Normalize each Object/OldObject from raw JSON or a framework-decoded
// runtime.Object, then pass its bytes to the same metadata check.
func checkExtensionObjectGroup(name string, extension runtime.RawExtension, group, version, kind string) error {
	raw := extension.Raw
	if len(raw) == 0 && extension.Object != nil {
		var err error
		raw, err = json.Marshal(extension.Object)
		if err != nil {
			return fmt.Errorf("%s is undecodable: %w", name, err)
		}
	}
	return checkRawObjectGroup(name, raw, group, version, kind)
}

// checkRawObjectGroup checks TypeMeta of each nonempty admitted object without
// interpreting the resource's subresource-specific wire shape.
//
// 14.) Inspect only apiVersion/kind and compare with the expected group/GVK.
// Absent objects are permitted by AdmissionReview shapes; present malformed or
// mismatched objects fail. Resource fields remain the policy callback's concern.
func checkRawObjectGroup(name string, raw []byte, group, version, kind string) error {
	if len(raw) == 0 {
		return nil
	}
	var tm metav1.TypeMeta
	if err := json.Unmarshal(raw, &tm); err != nil {
		return fmt.Errorf("%s is undecodable: %w", name, err)
	}
	if tm.APIVersion == "" || tm.Kind == "" {
		return fmt.Errorf("%s has no apiVersion or kind", name)
	}
	gv, err := schema.ParseGroupVersion(tm.APIVersion)
	if err != nil {
		return fmt.Errorf("%s apiVersion %q is invalid: %w", name, tm.APIVersion, err)
	}
	if gv.Version == "" {
		return fmt.Errorf("%s apiVersion %q is missing a version", name, tm.APIVersion)
	}
	if gv.Group != group {
		return fmt.Errorf("%s group %q differs from admitted kind group %q", name, gv.Group, group)
	}
	if (version != "" && gv.Version != version) || (kind != "" && tm.Kind != kind) {
		return fmt.Errorf("%s GVK %s %q differs from the admitted kind", name, gv.String(), tm.Kind)
	}
	return nil
}

// Verifier verifies bearer tokens for already-decoded admission requests — the
// entry point for consumers (for example controller-runtime) that decode the
// AdmissionReview themselves. Obtain one from [NewVerifier]. It wraps the
// internal policy verifier so no internal package appears in this module's public
// surface.
type Verifier struct {
	verifier *verify.Verifier
}

// NewVerifier builds a Verifier for an already-decoded AdmissionRequest.
// [WithAudience] selects automatic in-cluster issuer/key discovery bound to the
// webhook's configured audience. [WithRemoteIssuer] supplies an issuer and
// audience for out-of-cluster use. A decoded request has no trusted endpoint
// identity, so supplying neither option fails at construction.
//
// 2.) Alternative startup entrypoint: a framework adapter builds this verifier
// during setup, then calls Verify for each decoded request. The adapter, not
// this constructor, owns HTTP decoding, policy execution, and response writing.
func NewVerifier(ctx context.Context, opts ...Option) (*Verifier, error) {
	b := newBuilder()
	for _, opt := range opts {
		opt(b)
	}
	v, err := b.buildVerifier(ctx)
	if err != nil {
		return nil, err
	}
	return &Verifier{verifier: v}, nil
}

// Verify checks token against the KEP-6060 contract for an already-decoded
// AdmissionRequest.
//
// It returns nil on success and the same generic error for every denial,
// including a nil request. The specific reason is logged, not returned.
//
// 11.) Shared per-request gate: ServeHTTP and decoded-request adapters enter here.
// internal/verify authenticates the bearer and checks req.Resource.Group; then
// object checks constrain the payload. Success does not run admission policy.
func (v *Verifier) Verify(ctx context.Context, req *admissionv1.AdmissionRequest, token string) error {
	if req == nil {
		klog.FromContext(ctx).V(2).Info("Webhook token verification denied", "reason", "request body is not a decodable AdmissionReview")
		return errVerificationFailed
	}
	if err := v.verifier.Verify(ctx, token, req.Resource.Group); err != nil {
		return errVerificationFailed
	}
	// The attestation covers the resource group, but known subresources may carry
	// an object from another group. Bind both objects to the reviewed Kind.
	if err := checkObjectGroup(req); err != nil {
		klog.FromContext(ctx).V(2).Info("Webhook token verification denied",
			"reason", "admitted object does not match AdmissionReview kind", "detail", err.Error())
		return errVerificationFailed
	}
	return nil
}

// HealthCheck probes whether trusted issuer signing keys remain available.
// Construction already required a receiver-owned audience; readiness never
// grants permission to accept tokens for an unknown audience.
//
// 18.) A decoded-request consumer may call this from its readiness probe. It
// refreshes trusted signing keys through internal/verify; it does not verify a
// request or register a readiness URL for the application.
func (v *Verifier) HealthCheck() error {
	return v.verifier.HealthCheck()
}

// BearerToken extracts the token from an "Authorization: Bearer <token>" header,
// mirroring k8s.io/apiserver/pkg/authentication/request/bearertoken so this
// adapter does not drift from the apiserver's parsing. ok is false for a missing
// header, a non-Bearer scheme, or an empty token. It is exported so a caller that
// decodes the review itself can obtain the token for [Verifier.Verify].
//
// 9.) Header parsing for ServeHTTP or a framework's own HTTP boundary. The
// returned string is still untrusted; only Verifier.Verify authenticates it.
func BearerToken(r *http.Request) (token string, ok bool) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return "", false
	}
	parts := strings.SplitN(auth, " ", 3)
	if len(parts) < 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", false
	}
	token = parts[1]
	if token == "" {
		return "", false
	}
	return token, true
}

// HealthCheck reports whether the trusted issuer key set is ready. The
// expected audience was bound to the webhook configuration at construction.
//
// 19.) HTTP-handler readiness delegates to the same Verifier used by ServeHTTP.
// The application must wire this probe separately; it is not admission policy.
func (h *Handler) HealthCheck() error {
	return h.verifier.HealthCheck()
}
