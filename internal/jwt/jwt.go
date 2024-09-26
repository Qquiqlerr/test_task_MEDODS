package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"time"
)

var (
	ErrIPChanged    = errors.New("IP changed")
	ErrUnknownToken = errors.New("unknown token")
)

type HashGetter interface {
	GetRefreshTokenHash(GUID string) (string, error)
}

func NewAccessToken(GUID string, UUID, ip string, duration time.Duration, secret string) (string, error) {

	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)
	claims["guid"] = GUID
	claims["ip"] = ip
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["uuid"] = UUID
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func NewRefreshToken() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	refreshToken := base64.StdEncoding.EncodeToString(randomBytes)
	return refreshToken, err
}

func HashRefreshToken(refreshToken string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
func ValidateRefreshToken(GUID, refreshToken string, db HashGetter) (bool, error) {
	storedHash, err := db.GetRefreshTokenHash(GUID)
	if err != nil {
		return false, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(refreshToken))
	if err != nil {
		return false, err
	}
	return true, nil
}

func ValidateAccessTokenAndIP(tokenString, secret, currentIP string) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	claims, ok := token.Claims.(jwt.MapClaims)
	if token.Valid && ok {
		storedIP := claims["ip"]
		if storedIP != currentIP {
			return false, ErrIPChanged
		}
		return true, nil
	}
	return false, fmt.Errorf("token is invalid: %s", err.Error())
}
func GetAccessClaims(tokenString string) jwt.MapClaims {
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(""), nil
	})
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return jwt.MapClaims{}
	}
	return claims
}
