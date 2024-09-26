package auth

import (
	"errors"
	"github.com/go-chi/render"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"net"
	"net/http"
	"testMedods/internal/config"
	"testMedods/internal/email"
	"testMedods/internal/jwt"
)

type RefreshRequest struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}
type RefreshResponse struct {
	NewAccess  string `json:"new_access"`
	NewRefresh string `json:"new_refresh"`
}

type RefreshProcessor interface {
	CheckRefreshToken(refreshHash string) (uuid string)
	UpdateTokenPair(refresh, lastHash string) error
}

func RefreshToken(log *slog.Logger, refreshProcessor RefreshProcessor, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request RefreshRequest
		err := render.DecodeJSON(r.Body, &request)

		claims := jwt.GetAccessClaims(request.Access)
		lastGUID := claims["guid"].(string)
		lastUUID := claims["uuid"].(string)

		if err != nil {
			log.Error("Invalid request body")
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, render.ContentTypeJSON)
			return
		}
		if err != nil {
			log.Error("Failed to hash", err)
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, render.ContentTypeJSON)
			return
		}
		hash := refreshProcessor.CheckRefreshToken(lastUUID)
		if hash == "" {
			log.Error("unknown access token", err)
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, render.ContentTypeJSON)
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(request.Refresh))
		if err != nil {
			log.Error("invalid refresh token: ", err)
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, render.ContentTypeJSON)
			return
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		ok, err := jwt.ValidateAccessTokenAndIP(request.Access, cfg.Secret, ip)
		if !ok {
			if errors.Is(err, jwt.ErrUnknownToken) {
				log.Error("Unknown access token")
				render.Status(r, http.StatusForbidden)
				render.JSON(w, r, render.ContentTypeJSON)
				return
			} else if errors.Is(err, jwt.ErrIPChanged) {
				email.SendMessage(lastGUID)
			} else {
				log.Error("Access token is invalid: ", err)
				render.Status(r, http.StatusForbidden)
				render.JSON(w, r, render.ContentTypeJSON)
				return
			}
		}

		newAccess, err := jwt.NewAccessToken(lastGUID, lastUUID, ip, cfg.AccessExp, cfg.Secret)
		if err != nil {
			log.Error("Failed to generate access token: ", err)
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, render.ContentTypeJSON)
			return
		}
		newRefresh, err := jwt.NewRefreshToken()
		if err != nil {
			log.Error("Failed to generate refresh token: ", err)
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, render.ContentTypeJSON)
			return
		}
		newRefreshHash, _ := jwt.HashRefreshToken(newRefresh)
		err = refreshProcessor.UpdateTokenPair(newRefreshHash, lastUUID)
		if err != nil {
			log.Error("Failed to update pair:", err)
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, render.ContentTypeJSON)
			return
		}
		render.JSON(w, r, RefreshResponse{
			NewRefresh: newRefresh,
			NewAccess:  newAccess,
		})
	}

}
