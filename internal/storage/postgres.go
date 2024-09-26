package storage

import (
	"database/sql"
	"fmt"
	_ "github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"os"
	"time"
)

type Storage struct {
	db *sql.DB
}

func waitForDB(dsn string) error {
	for i := 0; i < 30; i++ {
		db, err := sql.Open("pgx", dsn)
		if err == nil {
			defer db.Close()
			if err = db.Ping(); err == nil {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("could not connect to database")
}

func New() (*Storage, error) {
	host := os.Getenv("DB_HOST")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	DBAddress := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable",
		host, user, password, dbname)
	err := waitForDB(DBAddress)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", DBAddress)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS token_sessions (
							uuid uuid NOT NULL,
							guid VARCHAR(36) NOT NULL,
							refresh_hash VARCHAR(64) NOT NULL
						) ;`)
	if err != nil {
		return nil, err
	}
	return &Storage{db: db}, nil
}

func (s *Storage) CreateNewSession(GUID, hash string) (uuid string, err error) {
	stmt, err := s.db.Prepare(`INSERT INTO token_sessions(uuid, guid, refresh_hash) VALUES (gen_random_uuid(), $1, $2) returning uuid;`)
	if err != nil {
		return "", err
	}
	err = stmt.QueryRow(GUID, hash).Scan(&uuid)
	if err != nil {
		return "", err
	}
	return uuid, nil
}

func (s *Storage) CheckRefreshToken(uuid string) (hash string) {
	row := s.db.QueryRow(`SELECT refresh_hash from token_sessions where uuid = $1;`, uuid)
	row.Scan(&hash)
	return hash
}
func (s *Storage) UpdateTokenPair(refreshHash, lastHash string) error {
	stmt, err := s.db.Prepare(`UPDATE token_sessions SET refresh_hash = $1 WHERE uuid = $2`)
	if err != nil {
		return err
	}
	_, err = stmt.Exec(refreshHash, lastHash)
	return err
}
