package config

import (
	"fmt"
	"strings"
	"time"
)

const (
	minIdempotencyTTL     = time.Minute
	maxIdempotencyTTL     = 7 * 24 * time.Hour
	defaultIdempotencyTTL = 24 * time.Hour
	minIdempotencyKeyLen  = 32
)

// loadIdempotency reads the idempotency switches (#216, part B). The key file
// reuses loadOrGenerateSecret: 0700 directory, 0600 regular file owned by the
// UI user, atomic first creation, never regenerated on restart. A file that is
// present but unsafe or malformed refuses startup; no error text carries a key.
func loadIdempotency(getenv func(string) string, cfg *Config) error {
	var err error
	if cfg.IdempotencyEnabled, err = boolEnv(getenv, "UI_IDEMPOTENCY_ENABLED", false); err != nil {
		return err
	}
	cfg.IdempotencyTTL = defaultIdempotencyTTL
	if raw := strings.TrimSpace(getenv("UI_IDEMPOTENCY_TTL")); raw != "" {
		ttl, err := time.ParseDuration(raw)
		if err != nil || ttl < minIdempotencyTTL || ttl > maxIdempotencyTTL {
			return fmt.Errorf("UI_IDEMPOTENCY_TTL must be a duration between %s and %s", minIdempotencyTTL, maxIdempotencyTTL)
		}
		cfg.IdempotencyTTL = ttl
	}
	cfg.IdempotencyKeyFile = strings.TrimSpace(getenv("UI_IDEMPOTENCY_KEY_FILE"))
	if cfg.IdempotencyKeyFile == "" {
		return nil
	}
	value, err := loadOrGenerateSecret(cfg.IdempotencyKeyFile)
	if err != nil {
		return fmt.Errorf("UI_IDEMPOTENCY_KEY_FILE: %w", err)
	}
	keys := strings.Fields(value)
	if len(keys) < 1 || len(keys) > 2 {
		return fmt.Errorf("UI_IDEMPOTENCY_KEY_FILE must hold one key, or the current and the previous key on two lines")
	}
	for _, k := range keys {
		if len(k) < minIdempotencyKeyLen {
			return fmt.Errorf("UI_IDEMPOTENCY_KEY_FILE keys must be at least %d characters", minIdempotencyKeyLen)
		}
	}
	cfg.IdempotencyKey = keys[0]
	if len(keys) == 2 {
		cfg.IdempotencyPreviousKey = keys[1]
	}
	return nil
}
