package dump

import (
	"context"
	"log"
	"time"
)

// Saver writes the running state of every device to its config file.
type Saver interface {
	SaveAll() error
}

// Service saves configs at startup, every interval and on shutdown.
type Service struct {
	interval time.Duration
	saver    Saver
}

// NewService creates a new dump service.
func NewService(interval time.Duration, saver Saver) *Service {
	return &Service{interval: interval, saver: saver}
}

// Start runs until ctx is cancelled.
func (s *Service) Start(ctx context.Context) {
	s.save("Initial")

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.save("Final")
			return
		case <-ticker.C:
			s.save("Periodic")
		}
	}
}

func (s *Service) save(kind string) {
	if err := s.saver.SaveAll(); err != nil {
		log.Printf("%s config dump failed: %v", kind, err)
	}
}
