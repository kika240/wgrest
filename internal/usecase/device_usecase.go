package usecase

import (
	"log"

	"github.com/suquant/wgrest/internal/domain/entity"
	"github.com/suquant/wgrest/internal/infrastructure/wgquick"
	"github.com/suquant/wgrest/internal/infrastructure/wireguard"
)

// DeviceUseCase handles business logic for device operations.
type DeviceUseCase struct {
	wgClient   *wireguard.Client
	wgquickSvc *wgquick.Service
	configs    configStore
}

// NewDeviceUseCase creates a new device use case.
func NewDeviceUseCase(
	wgClient *wireguard.Client,
	wgquickSvc *wgquick.Service,
) *DeviceUseCase {
	return &DeviceUseCase{
		wgClient:   wgClient,
		wgquickSvc: wgquickSvc,
		configs:    configStore{wgClient: wgClient, wgquickSvc: wgquickSvc},
	}
}

// ListDevices returns all devices (running + config-only) with pagination.
func (uc *DeviceUseCase) ListDevices(page, perPage int) ([]entity.Device, int, error) {
	runningDevices, err := uc.wgClient.List()
	if err != nil {
		return nil, 0, err
	}

	runningNames := make(map[string]bool)
	for _, d := range runningDevices {
		runningNames[d.Name] = true
	}

	for i := range runningDevices {
		runningDevices[i].Running = true
		uc.configs.describe(&runningDevices[i])
	}

	configDeviceNames := uc.wgquickSvc.ListConfigDevices()
	var configOnlyDevices []entity.Device
	for _, name := range configDeviceNames {
		if runningNames[name] {
			continue
		}
		device := entity.Device{Name: name}
		if cfg, err := uc.wgquickSvc.LoadConfig(name); err == nil {
			device = cfg.Device(name)
		} else {
			log.Printf("Config for %s could not be read: %v", name, err)
		}
		configOnlyDevices = append(configOnlyDevices, device)
	}

	// Merge: running first, then config-only
	devices := append(runningDevices, configOnlyDevices...)
	total := len(devices)

	if perPage <= 0 {
		perPage = 100
	}
	if page < 0 {
		page = 0
	}

	start := page * perPage
	if start >= len(devices) {
		return []entity.Device{}, total, nil
	}

	end := start + perPage
	if end > len(devices) {
		end = len(devices)
	}

	return devices[start:end], total, nil
}

// GetDevice returns a device by name (running or config-only).
func (uc *DeviceUseCase) GetDevice(name string) (*entity.Device, error) {
	device, err := uc.wgClient.Get(name)
	if err == nil {
		device.Running = true
		uc.configs.describe(device)
		return device, nil
	}

	cfg, cfgErr := uc.wgquickSvc.LoadConfig(name)
	if cfgErr != nil {
		return nil, err
	}
	d := cfg.Device(name)
	return &d, nil
}

// CreateDevice creates a new device and writes its wg-quick config.
func (uc *DeviceUseCase) CreateDevice(req entity.DeviceCreateOrUpdateRequest) (*entity.Device, error) {
	device, err := uc.wgClient.Create(req)
	if err != nil {
		return nil, err
	}
	uc.applyOptions(device, req)
	return device, nil
}

// UpdateDevice updates a device and writes its wg-quick config.
func (uc *DeviceUseCase) UpdateDevice(name string, req entity.DeviceCreateOrUpdateRequest) (*entity.Device, error) {
	device, err := uc.wgClient.Update(name, req)
	if err != nil {
		return nil, err
	}
	uc.applyOptions(device, req)
	return device, nil
}

// applyOptions applies the request's wg-quick options on top of what the
// config file already has, and saves the result.
func (uc *DeviceUseCase) applyOptions(device *entity.Device, req entity.DeviceCreateOrUpdateRequest) {
	device.QuickOptions = uc.configs.saveOrLog(device.Name, req.ApplyOptions)
}

// SaveAll saves the running state of every device to its config file.
func (uc *DeviceUseCase) SaveAll() error {
	return uc.configs.saveAll()
}

// DeleteDevice deletes a device.
func (uc *DeviceUseCase) DeleteDevice(name string) error {
	return uc.wgClient.Delete(name)
}

// Up brings up a WireGuard interface using wg-quick.
func (uc *DeviceUseCase) Up(name string) error {
	return uc.wgquickSvc.Up(name)
}

// Down brings down a WireGuard interface using wg-quick.
func (uc *DeviceUseCase) Down(name string) error {
	return uc.wgquickSvc.Down(name)
}
