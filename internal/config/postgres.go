package config

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type postgres struct {
	Db        *sql.DB
	dbConnStr string
}

func New() (*postgres, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s sslrootcert=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_DB"),
		os.Getenv("DB_SSLMODE"),
		os.Getenv("DB_SSLROOTCERT"),
	)
	if connStr == "" {
		return nil, fmt.Errorf("DB connection string not defined")
	}

	return &postgres{
		Db:        nil,
		dbConnStr: connStr,
	}, nil
}

func (p *postgres) Init() error {
	var err error

	p.Db, err = sql.Open("pgx", p.dbConnStr)
	if err != nil {
		return err
	}

	p.Db.SetMaxOpenConns(25)
	p.Db.SetMaxIdleConns(10)
	p.Db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err = p.Db.PingContext(ctx); err != nil {
		if strings.Contains(err.Error(), "certificate") {
			return err
		}
		return err
	}

	fmt.Println("Connection to database successfully!")
	return nil
}

func (p *postgres) Close() {
	if p.Db == nil {
		return
	}

	p.Db.Close()
	fmt.Println("Connection to database closed!")
}
