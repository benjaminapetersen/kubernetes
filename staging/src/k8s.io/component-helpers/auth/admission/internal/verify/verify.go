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

package verify

import (
	"context"
	"errors"
	"slices"

	"k8s.io/klog/v2"
)

// wildcardAPIGroup is the admissionReviewAPIGroups value that authorizes every API group.
const wildcardAPIGroup = "*"

// Reasons are logged; callers get one denial to avoid claim enumeration.
var errVerificationFailed = errors.New("webhook token verification failed")

// TokenAuthenticator verifies a token and returns its signed admissionReviewAPIGroups.
// Implementations must complete cryptographic and standard-claim checks before
// returning groups on success, including when reusing a previously verified token.
type TokenAuthenticator interface {
	// AuthenticateToken returns verified groups; callers ignore them on error.
	AuthenticateToken(ctx context.Context, rawToken string) (admissionReviewAPIGroups []string, err error)

	// BindAudience fixes a receiver-configured audience and rejects conflicting binds.
	BindAudience(audience string) error

	// HealthCheck reports signing-key readiness for the bound audience.
	HealthCheck() error
}

// Verifier checks a verified token's API-group attestation.
type Verifier struct {
	authenticator TokenAuthenticator
}

// NewVerifier returns a Verifier backed by authenticator.
// 49.) OIDC's local/remote constructors wrap their authenticator at setup.
// This stores the backend only; it does not validate it or authenticate a token.
func NewVerifier(authenticator TokenAuthenticator) (*Verifier, error) {
	return &Verifier{authenticator: authenticator}, nil
}

// Verify checks whether the signed attestation authorizes reviewAPIGroup.
// It returns one generic error for any denial and logs the reason.
// 50.) admission.Verifier passes the bearer and req.Resource.Group here.
// Exact group or "*" matching runs on every request, including OIDC cache hits;
// no admission business policy or live webhook-object lookup is performed here.
func (v *Verifier) Verify(ctx context.Context, rawToken string, reviewAPIGroup string) error {
	logger := klog.FromContext(ctx)

	groups, err := v.authenticator.AuthenticateToken(ctx, rawToken)
	if err != nil {
		logger.V(2).Info("Webhook token verification denied",
			"reason", "token authentication failed",
			"detail", err.Error())
		return errVerificationFailed
	}

	if !slices.Contains(groups, reviewAPIGroup) && !slices.Contains(groups, wildcardAPIGroup) {
		logger.V(2).Info("Webhook token verification denied",
			"reason", "token admissionReviewAPIGroups does not authorize the review's API group")
		return errVerificationFailed
	}

	return nil
}

// BindAudience fixes the expected audience on the authenticator.
// 51.) The local OIDC constructor confirms its trusted setup audience here;
// binding checks are delegated, not inferred from the current HTTP request.
func (v *Verifier) BindAudience(audience string) error {
	return v.authenticator.BindAudience(audience)
}

// HealthCheck reports whether the authenticator's signing keys are ready.
// 52.) admission.Verifier (also via Handler) delegates readiness here.
// The OIDC backend may refresh signing keys; readiness authenticates no request.
func (v *Verifier) HealthCheck() error {
	return v.authenticator.HealthCheck()
}
