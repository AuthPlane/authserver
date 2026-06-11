package admin

import (
	"context"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// KeyAdmin is the local interface for key administration.
// The JWKSService implements both methods.
type KeyAdmin interface {
	BuildJWKS(ctx context.Context) (*jose.JSONWebKeySet, error)
	RotateKey(ctx context.Context) (*output.SigningKey, error)
}

// KeysDeps holds optional key management dependencies for the admin server.
type KeysDeps struct {
	KeyAdmin KeyAdmin
	Audit    AuditRecorder
}

// keysAdminHandler serves admin key management endpoints.
type keysAdminHandler struct {
	keyAdmin KeyAdmin
	audit    AuditRecorder
	obs      *observability.Provider
}

func (h *keysAdminHandler) handleListKeys(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.obs.Tracer.Start(r.Context(), "keysAdminHandler.handleListKeys")
	defer span.End()

	jwks, err := h.keyAdmin.BuildJWKS(ctx)
	if err != nil {
		h.obs.Logger.ErrorContext(ctx, "admin list keys failed", "error", err)
		writeAdminError(w, http.StatusInternalServerError, "internal error")
		return
	}

	views := make([]keyView, 0, len(jwks.Keys))
	for i := range jwks.Keys {
		k := &jwks.Keys[i]
		status := "previous"
		if i == 0 {
			status = "current"
		}
		views = append(views, keyView{
			KeyID:     k.KeyID,
			Algorithm: k.Algorithm,
			Use:       k.Use,
			Status:    status,
		})
	}

	shared.WriteJSON(w, http.StatusOK, listKeysResponse{Keys: views})
}

func (h *keysAdminHandler) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.obs.Tracer.Start(r.Context(), "keysAdminHandler.handleRotateKey")
	defer span.End()

	key, err := h.keyAdmin.RotateKey(ctx)
	if err != nil {
		h.obs.Logger.ErrorContext(ctx, "admin key rotation failed", "error", err)
		writeAdminError(w, http.StatusInternalServerError, "key rotation failed")
		return
	}

	h.obs.Logger.InfoContext(ctx, "admin key rotated", "kid", key.KeyID, "alg", key.Algorithm)

	if h.audit != nil {
		h.audit.Record(ctx, audit.Event{
			Action:    audit.ActionKeyRotated,
			ActorID:   "admin",
			Detail:    "admin rotated signing key: kid=" + key.KeyID,
			CreatedAt: time.Now().UTC(),
		})
	}

	shared.WriteJSON(w, http.StatusOK, rotateKeyResponse{
		KeyID:     key.KeyID,
		Algorithm: key.Algorithm,
	})
}
