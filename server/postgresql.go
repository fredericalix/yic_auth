package main

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/gofrs/uuid"

	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/fredericalix/yic_auth"
)

// PostgreSQL handle the storage of auth service
type PostgreSQL struct {
	db *sql.DB
}

// NewPostgreSQL create a new PostgreSQL
func NewPostgreSQL(uri string) *PostgreSQL {
	db, err := sql.Open("postgres", uri)
	if err != nil {
		return nil
	}
	// test the connection
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	pg := &PostgreSQL{db: db}
	if err := pg.createSchema(); err != nil {
		panic(err)
	}
	return pg
}

func (pg *PostgreSQL) createSchema() (err error) {
	query := `CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
	CREATE TABLE IF NOT EXISTS account (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		email TEXT UNIQUE NOT NULL,
		validated BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE UNIQUE INDEX IF NOT EXISTS account_email_idx ON account ((lower(email)));`
	_, err = pg.db.Query(query)
	if err != nil {
		return
	}

	query = `CREATE TABLE IF NOT EXISTS app_token (
		token TEXT PRIMARY KEY,
		validation_token TEXT,
		aid UUID REFERENCES account(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		roles JSONB NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		expired_at TIMESTAMPTZ NOT NULL
	);
	CREATE INDEX IF NOT EXISTS app_token_valid_idx ON app_token (validation_token);
	ALTER TABLE app_token DROP CONSTRAINT app_token_aid_fkey;
	ALTER TABLE app_token ADD CONSTRAINT app_token_aid_fkey FOREIGN KEY (aid) REFERENCES account(id) ON DELETE CASCADE;`
	_, err = pg.db.Query(query)
	if err != nil {
		return
	}

	return
}

// NewAccount insert a new user Account in the DB
func (pg *PostgreSQL) NewAccount(a *auth.Account) error {
	query := `INSERT INTO account(email, validated, created_at)
	VALUES($1,$2,$3)
	returning id;`
	err := pg.db.QueryRow(query, a.Email, a.Validated, a.CreatedAt).Scan(&a.ID)
	if err != nil {
		return err
	}
	return err
}

// DeleteAccount remove account and each associate app_token
func (pg *PostgreSQL) DeleteAccount(aid uuid.UUID) error {
	query := `DELETE FROM account WHERE id = $1;`
	_, err := pg.db.Exec(query, aid)
	return err
}

// ListAccount find every account
func (pg *PostgreSQL) ListAccount() ([]auth.Account, error) {
	query := "SELECT id, email, validated, created_at FROM account;"
	rows, err := pg.db.Query(query)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var as []auth.Account
	for rows.Next() {
		var a auth.Account
		err := rows.Scan(&a.ID, &a.Email, &a.Validated, &a.CreatedAt)
		if err != nil {
			continue
		}
		as = append(as, a)
	}
	return as, nil
}

// GetAccountByEmail find an user Account from its Email
func (pg *PostgreSQL) GetAccountByEmail(email string) (*auth.Account, error) {
	var a auth.Account
	query := `SELECT id, email, validated, created_at
	FROM account
	WHERE email = $1;`
	err := pg.db.QueryRow(query, email).Scan(&a.ID, &a.Email, &a.Validated, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// NewAppToken insert a new application token for a user
func (pg *PostgreSQL) NewAppToken(a *auth.AppToken) error {
	roles, err := json.Marshal(a.Roles)
	if err != nil {
		return err
	}
	query := `INSERT INTO app_token(token, aid, name, type, roles, 
		validation_token, created_at, updated_at, expired_at) 
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9);`
	_, err = pg.db.Exec(query, a.Token, a.AID, a.Name, a.Type, roles, a.ValidToken,
		a.CreatedAt, a.UpdatedAt, a.ExpiredAt)
	return err
}

// GetAccountFromToken find an user Account from an app token
func (pg *PostgreSQL) GetAccountFromToken(token string) (*auth.Account, error) {
	query := `SELECT a.id, a.email, a.validated, a.created_at
	FROM account AS a
	LEFT JOIN app_token AS t ON t.aid = a.id
	WHERE t.token = ($1);`
	var a auth.Account
	err := pg.db.QueryRow(query, token).Scan(&a.ID, &a.Email, &a.Validated, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// AllAppToken get every AppToken
func (pg *PostgreSQL) AllAppToken() ([]auth.AppToken, error) {
	query := `SELECT
	a.id,
	a.email,
	a.validated,
	a.created_at,
	t.token,
	t.aid,
	t.name,
	t.type,
	t.roles,
	t.created_at,
	t.updated_at,
	t.expired_at
	FROM account AS a LEFT JOIN app_token AS t ON a.id = t.aid
	WHERE t.validation_token IS NULL AND t.expired_at > now();`
	var res []auth.AppToken
	rows, err := pg.db.Query(query)
	if err == sql.ErrNoRows {
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var roles []byte
		var at auth.AppToken
		at.Account = new(auth.Account)
		err = rows.Scan(
			&at.Account.ID,
			&at.Account.Email,
			&at.Account.Validated,
			&at.Account.CreatedAt,
			&at.Token,
			&at.AID,
			&at.Name,
			&at.Type,
			&roles,
			&at.CreatedAt,
			&at.UpdatedAt,
			&at.ExpiredAt,
		)
		if err != nil {
			continue
		}
		err = json.Unmarshal(roles, &at.Roles)
		if err != nil {
			continue
		}
		res = append(res, at)
	}

	return res, nil
}

// GetAppToken find an AppToken and its associte Account from the token
func (pg *PostgreSQL) GetAppToken(token string) (*auth.AppToken, error) {
	var roles []byte
	query := `SELECT
	a.id,
	a.email,
	a.validated,
	a.created_at,
	t.token,
	t.aid,
	t.name,
	t.type,
	t.roles,
	t.created_at,
	t.updated_at,
	t.expired_at
	FROM account AS a LEFT JOIN app_token AS t ON a.id = t.aid
	WHERE t.token = $1 AND t.validation_token IS NULL;`
	at := new(auth.AppToken)
	at.Account = new(auth.Account)
	err := pg.db.QueryRow(query, token).Scan(
		&at.Account.ID,
		&at.Account.Email,
		&at.Account.Validated,
		&at.Account.CreatedAt,
		&at.Token,
		&at.AID,
		&at.Name,
		&at.Type,
		&roles,
		&at.CreatedAt,
		&at.UpdatedAt,
		&at.ExpiredAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(roles, &at.Roles)
	if err != nil {
		return nil, err
	}
	return at, nil
}

// UpdateAppToken update the date of last renew
func (pg *PostgreSQL) UpdateAppToken(token string) error {
	query := `UPDATE app_token
	SET updated_at = $2
	WHERE token = $1;`
	_, err := pg.db.Exec(query, token, time.Now())
	return err
}

// Validate an AppToken
func (pg *PostgreSQL) Validate(vtoken string, vtime time.Time) (at *auth.AppToken, err error) {
	tx, err := pg.db.Begin()
	if err != nil {
		return nil, err
	}
	query := `UPDATE app_token
	SET validation_token = NULL, expired_at = $2
	WHERE validation_token = $1
	RETURNING token, aid;`
	var token string
	var aid uuid.UUID
	err = tx.QueryRow(query, vtoken, vtime).Scan(&token, &aid)
	if err == sql.ErrNoRows {
		tx.Rollback()
		return nil, nil
	}
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	query = `UPDATE account
	SET validated = TRUE
	WHERE id = $1;`
	_, err = tx.Exec(query, aid)
	if err != nil {
		return nil, tx.Rollback()
	}
	tx.Commit()

	return pg.GetAppToken(token)
}

// FindAppTokensFromAID find every AppToken from a given Account ID
func (pg *PostgreSQL) FindAppTokensFromAID(aid uuid.UUID) ([]auth.AppToken, error) {
	var as []auth.AppToken
	query := `SELECT 
	token,
	aid,
	name,
	type,
	roles,
	validation_token,
	created_at,
	updated_at,
	expired_at
	FROM app_token
	WHERE aid = $1
	ORDER BY updated_at`
	rows, err := pg.db.Query(query, aid)
	if err == sql.ErrNoRows {
		return as, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var roles []byte
		var vtoken sql.NullString
		var at auth.AppToken
		err = rows.Scan(
			&at.Token,
			&at.AID,
			&at.Name,
			&at.Type,
			&roles,
			&vtoken,
			&at.CreatedAt,
			&at.UpdatedAt,
			&at.ExpiredAt,
		)
		if err != nil {
			return nil, err
		}
		if vtoken.Valid {
			at.ValidToken = vtoken.String
		}
		err = json.Unmarshal(roles, &at.Roles)
		if err != nil {
			return nil, err
		}
		as = append(as, at)
	}
	return as, nil
}

// DeleteAppToken remove an app token. Return an error (sql.ErrNoRows) if it does not exist.
func (pg *PostgreSQL) DeleteAppToken(aid uuid.UUID, token string) error {
	query := `DELETE FROM app_token WHERE aid = $1 and token = $2`
	res, err := pg.db.Exec(query, aid, token)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
