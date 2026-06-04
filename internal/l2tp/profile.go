package l2tp

import (
	"fmt"
	"os"
	"sync"

	"github.com/dimaskiddo/swan-ng/internal/log"
	"gopkg.in/yaml.v3"
)

// L2TPProfile represents a single L2TP user profile loaded from YAML.
type L2TPProfile struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// ProfileUserDB implements UserDatabase by loading credentials from
// L2TP profile YAML files in profile.d/.
// Thread-safe for concurrent CHAP lookups.
type ProfileUserDB struct {
	mu    sync.RWMutex
	users map[string]string // username → password
}

// NewProfileUserDB creates an empty profile user database.
func NewProfileUserDB() *ProfileUserDB {
	return &ProfileUserDB{
		users: make(map[string]string),
	}
}

// LoadProfiles loads L2TP user profiles from the given file paths.
// Each file contains a single L2TPProfile (username + password).
// Existing users are preserved; new files add or overwrite entries.
func (db *ProfileUserDB) LoadProfiles(paths []string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	loaded := 0
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Warn("l2tp: failed to read profile",
				"path", path,
				"error", err.Error(),
			)

			continue
		}

		var profile L2TPProfile
		if err := yaml.Unmarshal(data, &profile); err != nil {
			log.Warn("l2tp: failed to parse profile",
				"path", path,
				"error", err.Error(),
			)

			continue
		}

		if profile.Username == "" {
			log.Warn("l2tp: profile missing username", "path", path)
			continue
		}

		db.users[profile.Username] = profile.Password
		loaded++

		log.Debug("l2tp: loaded profile", "username", profile.Username, "path", path)
	}

	log.Info("l2tp: profiles loaded",
		"total", loaded,
		"users", len(db.users),
	)

	return nil
}

// LookupUser returns the password for a given username.
// Implements the UserDatabase interface.
func (db *ProfileUserDB) LookupUser(username string) (string, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	password, found := db.users[username]
	return password, found
}

// UserCount returns the number of loaded users.
func (db *ProfileUserDB) UserCount() int {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return len(db.users)
}

// Reload clears existing users and reloads from the given paths.
// Used for hot-reload support.
func (db *ProfileUserDB) Reload(paths []string) error {
	db.mu.Lock()
	db.users = make(map[string]string)
	db.mu.Unlock()

	return db.LoadProfiles(paths)
}

// String returns a summary of loaded users (without passwords).
func (db *ProfileUserDB) String() string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	usernames := make([]string, 0, len(db.users))
	for u := range db.users {
		usernames = append(usernames, u)
	}

	return fmt.Sprintf("ProfileUserDB{users=%d}", len(usernames))
}
