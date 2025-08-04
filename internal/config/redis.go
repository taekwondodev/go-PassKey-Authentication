package config

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisConfig struct {
	Client   *redis.Client
	HashSalt []byte
}

func ConnectRedis() (*RedisConfig, error) {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		return nil, fmt.Errorf("REDIS_URL not defined")
	}

	salt := os.Getenv("HASH_SALT")
	if salt == "" {
		return nil, fmt.Errorf("HASH_SALT not defined")
	}
	hashSalt := []byte(salt)

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid REDIS_URL: %w", err)
	}

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisConfig{
		Client:   client,
		HashSalt: hashSalt,
	}, nil
}
