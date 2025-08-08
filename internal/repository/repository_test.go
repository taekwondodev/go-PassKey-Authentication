package repository

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/redis/go-redis/v9"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/db"
)

func setupMockDB(t *testing.T) (pgxmock.PgxPoolIface, *db.Queries) {
	mockDB, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("Failed to create pgxmock: %v", err)
	}

	queries := db.New(mockDB)

	t.Cleanup(func() {
		mockDB.Close()
	})

	return mockDB, queries
}

func setupMockRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	t.Cleanup(func() {
		client.Close()
		mr.Close()
	})

	return mr, client
}

func setupMockRepo(t *testing.T) (pgxmock.PgxPoolIface, *miniredis.Miniredis, UserRepository) {
	mockDB, queries := setupMockDB(t)
	mr, redisClient := setupMockRedis(t)

	repo := &repository{
		queries:  queries,
		client:   redisClient,
		hashSalt: []byte("test-hash-salt"),
	}

	return mockDB, mr, repo
}

func setupRepoWithoutRedis(t *testing.T) (pgxmock.PgxPoolIface, UserRepository) {
	mockDB, queries := setupMockDB(t)

	repo := &repository{
		queries:  queries,
		client:   nil, // No Redis client
		hashSalt: []byte("test-hash-salt"),
	}

	return mockDB, repo
}

/*********************************************************************************************/
