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

package oidc_test

import (
	"context"
	"testing"
)

// TestRemoteVerifier_MalformedKubernetesClaims checks that a locally signed token
// with a scalar kubernetes.io claim yields only the generic verification failure.
func TestRemoteVerifier_MalformedKubernetesClaims(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t)

	claims := ts.baseClaims()
	// Replace the kubernetes.io object with a scalar: go-oidc's Verify still
	// passes (it only inspects iss/aud/exp/sub), but decoding into the private
	// claims struct fails.
	claims["kubernetes.io"] = "not-an-object"

	err := v.Verify(context.Background(), ts.sign(t, claims), testAPIGroup)
	if err == nil {
		t.Fatal("expected verification to fail on an undecodable kubernetes.io claim")
	}
	if err == nil || err.Error() != "webhook token verification failed" {
		t.Fatalf("expected generic verification failure, got %v", err)
	}
	// Anti-enumeration: the caller-facing message must not leak decode detail.
	if msg := err.Error(); msg != "webhook token verification failed" {
		t.Errorf("caller-visible error = %q, want the generic message", msg)
	}
}
