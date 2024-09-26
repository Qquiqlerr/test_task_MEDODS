package auth

import (
	"github.com/go-chi/render"
	"log/slog"
	"net"
	"net/http"
	"testMedods/internal/config"
	"testMedods/internal/jwt"
)

type NewSessionCreater interface {
	CreateNewSession(GUID, hash string) (uuid string, err error)
}

type TokenRequest struct {
	GUID string `json:"GUID"`
}
type TokenResponse struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

func GetJWTPair(log *slog.Logger, creator NewSessionCreater, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		refresh, err := jwt.NewRefreshToken()
		if err != nil {
			log.Error("Failed to generate refresh token")
			render.Status(r, http.StatusInternalServerError)
			return
		}
		hash, err := jwt.HashRefreshToken(refresh)
		if err != nil {
			log.Error("Failed to create hash")
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, render.ContentTypeJSON)
			return
		}
		var request TokenRequest
		err = render.DecodeJSON(r.Body, &request)
		if request.GUID == "" {
			log.Error("Empty guid")
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, render.ContentTypeJSON)
			return
		}
		if err != nil {
			log.Error("Invalid request")
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, render.ContentTypeJSON)
			return
		}
		uuid, err := creator.CreateNewSession(request.GUID, hash)
		if err != nil {
			log.Error("Failed to create hash")
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, render.ContentTypeJSON)
			return
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		access, err := jwt.NewAccessToken(request.GUID, uuid, ip, cfg.AccessExp, cfg.Secret)
		if err != nil {
			log.Error("Failed to create hash")
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, render.ContentTypeJSON)
			return
		}
		log.Info("Token pair generated")
		render.JSON(w, r, TokenResponse{
			Access:  access,
			Refresh: refresh,
		})
	}
}
