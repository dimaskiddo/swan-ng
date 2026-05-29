package config

import (
	"context"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// Watcher monitors the profile.d/ directory for changes and triggers
// a callback when profiles are added, modified, or removed.
// It respects the hot_reload.enabled toggle in the configuration.
type Watcher struct {
	fsWatcher  *fsnotify.Watcher
	profileDir string
	enabled    bool
	debounce   time.Duration
}

// NewWatcher creates a new config file watcher for the profile.d/ directory.
// The profileDir is resolved relative to the config file path.
// If hot_reload.enabled is false, the watcher is created but Start() will
// log a message and return immediately without watching.
func NewWatcher(configPath string, cfg *Config) (*Watcher, error) {
	cfgDir := filepath.Dir(configPath)
	profileDir := filepath.Join(cfgDir, "profile.d")

	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &Watcher{
		fsWatcher:  fw,
		profileDir: profileDir,
		enabled:    cfg.IPSec.HotReload || cfg.IKEv2.HotReload || cfg.L2TP.HotReload,
		debounce:   500 * time.Millisecond,
	}, nil
}

// Start begins watching the profile.d/ directory for changes.
// When a change is detected, the onChange callback is invoked after a
// debounce period to batch rapid successive changes.
// The watcher runs until the context is cancelled.
func (w *Watcher) Start(ctx context.Context, onChange func()) {
	if !w.enabled {
		log.Info("hot-reload disabled, profile.d watcher not started")
		return
	}

	if err := w.fsWatcher.Add(w.profileDir); err != nil {
		log.Error("failed to watch profile directory",
			"dir", w.profileDir,
			"error", err,
		)
		return
	}

	log.Info("hot-reload watcher started", "dir", w.profileDir)

	go func() {
		var debounceTimer *time.Timer

		for {
			select {
			case <-ctx.Done():
				log.Debug("config watcher shutting down")
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				return

			case event, ok := <-w.fsWatcher.Events:
				if !ok {
					return
				}

				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
					continue
				}

				log.Debug("profile change detected",
					"file", event.Name,
					"op", event.Op.String(),
				)

				if debounceTimer != nil {
					debounceTimer.Stop()
				}

				debounceTimer = time.AfterFunc(w.debounce, func() {
					log.Info("applying hot-reloaded profile changes",
						"trigger", event.Name,
					)
					onChange()
				})

			case err, ok := <-w.fsWatcher.Errors:
				if !ok {
					return
				}

				log.Warn("config watcher error", "error", err)
			}
		}
	}()
}

// Close stops the watcher and releases resources.
func (w *Watcher) Close() error {
	return w.fsWatcher.Close()
}
