package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"

	"github.com/golang-jwt/jwt/v5"
)

const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

const keyId = "flight_price-service"

type Claims struct {
	jwt.RegisteredClaims
	Roles []string `json:"roles"`
}

func (c Claims) IsAuthorized(roles ...string) bool {
	for _, has := range c.Roles {
		if slices.Contains(roles, has) {
			return true
		}
	}
	return false
}

type Auth struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyId      string
}

func NewAuth() (*Auth, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %w", err)
	}

	a := Auth{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyId:      keyId,
	}

	return &a, nil
}

func (a *Auth) GenerateToken(claims Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodPS256, claims)
	token.Header["kid"] = a.keyId

	signedToken, err := token.SignedString(a.privateKey)
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}

	return signedToken, nil
}

func (a *Auth) ValidateToken(tokenStr string) (Claims, error) {
	var claims Claims
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSAPSS); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return a.publicKey, nil
	})

	if err != nil {
		return Claims{}, fmt.Errorf("error parsing token: %w", err)
	}

	if !token.Valid {
		return Claims{}, errors.New("invalid generated token")
	}

	return claims, nil
}
