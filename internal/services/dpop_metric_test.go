package services

import (
	"errors"
	"fmt"
	"testing"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
)

func TestDPoPRejectReason(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		// ErrDPoPProofTooLarge also matches ErrDPoPInvalidProof; the more
		// specific label must win.
		{"too large", crypto.ErrDPoPProofTooLarge, "too_large"},
		{"too large wrapped", fmt.Errorf("validate: %w", crypto.ErrDPoPProofTooLarge), "too_large"},
		{"invalid proof", domain.ErrDPoPInvalidProof, "invalid_proof"},
		{"replay", domain.ErrDPoPReplay, "replay"},
		{"nonce required", domain.ErrDPoPNonceRequired, "nonce_required"},
		{"nonce mismatch", domain.ErrDPoPNonceMismatch, "nonce_mismatch"},
		{"other", errors.New("boom"), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dpopRejectReason(tt.err); got != tt.want {
				t.Fatalf("dpopRejectReason(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}
