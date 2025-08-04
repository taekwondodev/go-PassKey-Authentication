package repository

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/customerrors"
	"golang.org/x/crypto/argon2"
)

func (r *repository) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	tokenHash := r.hashToken(token)
	redisKey := fmt.Sprintf("blacklist:%s", tokenHash)

	exists, err := r.client.Exists(ctx, redisKey).Result()
	if err != nil {
		return false, customerrors.ErrInternalServer
	}

	return exists > 0, nil
}

func (r *repository) BlacklistToken(ctx context.Context, token string, expiration time.Time) error {
	tokenHash := r.hashToken(token)
	redisKey := fmt.Sprintf("blacklist:%s", tokenHash)

	ttl := time.Until(expiration)
	if ttl <= 0 {
		return nil
	}

	err := r.client.SetArgs(ctx, redisKey, "1", redis.SetArgs{
		Mode: "NX",
		TTL:  ttl,
	}).Err()

	return err
}

func (r *repository) hashToken(token string) string {
	hash := argon2.IDKey(
		[]byte(token),
		r.hashSalt,
		3,
		64*1024,
		4,
		32,
	)
	return hex.EncodeToString(hash)
}
