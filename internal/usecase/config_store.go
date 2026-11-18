package usecase

import (
	"errors"
	"fmt"
	"log"

	"github.com/suquant/wgrest/internal/domain/entity"
	"github.com/suquant/wgrest/internal/infrastructure/wgquick"
	"github.com/suquant/wgrest/internal/infrastructure/wireguard"
)

// configStore keeps each device's wg-quick file in step with the running
// interface. It is the only code that writes those files.
type configStore struct {
	wgClient   *wireguard.Client
	wgquickSvc *wgquick.Service
}

// save writes the running state of a device to its config file. When apply is
// given, it also changes the wg-quick options found in the file. It returns
// the options the file ends up with.
func (s configStore) save(name string, apply func(*entity.QuickOptions)) (entity.QuickOptions, error) {
	var opts entity.QuickOptions
	err := s.wgquickSvc.Update(name, func(cfg *wgquick.Config) error {
		device, err := s.wgClient.Get(name)
		if err != nil {
			return err
		}
		peers, err := s.wgClient.ListPeers(name)
		if err != nil {
			return err
		}

		cfg.SetRunning(device, peers)
		opts = cfg.Options()
		if apply != nil {
			apply(&opts)
			cfg.SetOptions(opts)
		}
		return nil
	})
	return opts, err
}

// saveOrLog is for API calls that already changed the running interface:
// failing them would hide that change, so a failed save is logged instead.
func (s configStore) saveOrLog(name string, apply func(*entity.QuickOptions)) entity.QuickOptions {
	opts, err := s.save(name, apply)
	if err != nil {
		log.Printf("Config for %s was not saved: %v", name, err)
	}
	return opts
}

// saveAll saves every running device.
func (s configStore) saveAll() error {
	devices, err := s.wgClient.List()
	if err != nil {
		return err
	}

	var errs []error
	for _, d := range devices {
		if _, err := s.save(d.Name, nil); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.Name, err))
		}
	}
	return errors.Join(errs...)
}

// describe adds what the config file knows to a running device.
func (s configStore) describe(device *entity.Device) {
	if cfg, err := s.wgquickSvc.LoadConfig(device.Name); err == nil {
		device.QuickOptions = cfg.Options()
	}
}
