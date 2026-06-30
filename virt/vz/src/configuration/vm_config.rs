use objc2::rc::Retained;
use objc2_virtualization::{
    VZDirectorySharingDeviceConfiguration, VZEntropyDeviceConfiguration,
    VZMemoryBalloonDeviceConfiguration, VZNetworkDeviceConfiguration, VZSerialPortConfiguration,
    VZSocketDeviceConfiguration, VZStorageDeviceConfiguration, VZVirtualMachineConfiguration,
};

use crate::configuration::boot_loader::BootLoader;
use crate::configuration::{GenericPlatform, LinuxBootLoader};
use crate::device::{
    EntropyDeviceConfiguration, MemoryBalloonDeviceConfiguration, NetworkDeviceConfiguration,
    SerialPortConfiguration, SocketDeviceConfiguration, StorageDeviceConfiguration,
    VirtioFileSystemDeviceConfiguration,
};
use crate::error::VzError;
use crate::utils::{is_os_version_at_least, vz_virtual_machine_is_supported};

#[derive(Debug, Clone)]
pub struct VirtualMachineConfiguration {
    inner: Retained<VZVirtualMachineConfiguration>,
    storage_devices: Vec<StorageDeviceConfiguration>,
    network_devices: Vec<NetworkDeviceConfiguration>,
    serial_ports: Vec<SerialPortConfiguration>,
    socket_devices: Vec<SocketDeviceConfiguration>,
    entropy_devices: Vec<EntropyDeviceConfiguration>,
    directory_sharing_devices: Vec<VirtioFileSystemDeviceConfiguration>,
    memory_balloon_devices: Vec<MemoryBalloonDeviceConfiguration>,
}

impl VirtualMachineConfiguration {
    pub(crate) fn new() -> Result<Self, VzError> {
        validate_support()?;
        Ok(Self {
            inner: unsafe { VZVirtualMachineConfiguration::new() },
            storage_devices: Vec::new(),
            network_devices: Vec::new(),
            serial_ports: Vec::new(),
            socket_devices: Vec::new(),
            entropy_devices: Vec::new(),
            directory_sharing_devices: Vec::new(),
            memory_balloon_devices: Vec::new(),
        })
    }

    pub(crate) fn set_cpu_count(&mut self, cpu_count: usize) {
        unsafe {
            self.inner.setCPUCount(cpu_count);
        }
    }

    pub(crate) fn set_memory_size(&mut self, memory_size_bytes: u64) {
        unsafe {
            self.inner.setMemorySize(memory_size_bytes);
        }
    }

    pub(crate) fn set_boot_loader(&mut self, boot_loader: LinuxBootLoader) {
        unsafe {
            self.inner.setBootLoader(Some(boot_loader.as_inner()));
        }
    }

    pub(crate) fn set_platform(&mut self, platform: GenericPlatform) {
        unsafe {
            self.inner.setPlatform(platform.as_inner());
        }
    }

    pub(crate) fn add_entropy_device(&mut self, device: EntropyDeviceConfiguration) {
        self.entropy_devices.push(device);
    }

    pub(crate) fn add_memory_balloon_device(&mut self, device: MemoryBalloonDeviceConfiguration) {
        self.memory_balloon_devices.push(device);
    }

    pub(crate) fn add_network_device(&mut self, device: NetworkDeviceConfiguration) {
        self.network_devices.push(device);
    }

    pub(crate) fn add_serial_port(&mut self, port: SerialPortConfiguration) {
        self.serial_ports.push(port);
    }

    pub(crate) fn add_socket_device(&mut self, device: SocketDeviceConfiguration) {
        self.socket_devices.push(device);
    }

    pub(crate) fn add_storage_device(&mut self, device: StorageDeviceConfiguration) {
        self.storage_devices.push(device);
    }

    pub(crate) fn add_directory_share(&mut self, device: VirtioFileSystemDeviceConfiguration) {
        self.directory_sharing_devices.push(device);
    }

    pub(crate) fn build(mut self) -> Result<Retained<VZVirtualMachineConfiguration>, VzError> {
        self.validate()?;
        self.apply_devices();

        unsafe {
            self.inner
                .validateWithError()
                .map_err(|err| VzError::Backend(err.to_string()))?;
        }

        Ok(self.inner)
    }

    fn validate(&self) -> Result<(), VzError> {
        if self.serial_ports.is_empty() {
            return Err(VzError::InvalidConfiguration {
                reason: "at least one serial port must be configured".to_string(),
            });
        }

        Ok(())
    }

    fn apply_devices(&mut self) {
        unsafe {
            if !self.storage_devices.is_empty() {
                let refs: Vec<&VZStorageDeviceConfiguration> = self
                    .storage_devices
                    .iter()
                    .map(|device| device.as_inner())
                    .collect();
                self.inner
                    .setStorageDevices(&objc2_foundation::NSArray::from_slice(&refs));
            }

            if !self.network_devices.is_empty() {
                let refs: Vec<&VZNetworkDeviceConfiguration> = self
                    .network_devices
                    .iter()
                    .map(|device| device.as_inner())
                    .collect();
                self.inner
                    .setNetworkDevices(&objc2_foundation::NSArray::from_slice(&refs));
            }

            if !self.serial_ports.is_empty() {
                let refs: Vec<&VZSerialPortConfiguration> = self
                    .serial_ports
                    .iter()
                    .map(|port| port.as_inner())
                    .collect();
                self.inner
                    .setSerialPorts(&objc2_foundation::NSArray::from_slice(&refs));
            }

            if !self.socket_devices.is_empty() {
                let refs: Vec<&VZSocketDeviceConfiguration> = self
                    .socket_devices
                    .iter()
                    .map(|device| device.as_inner())
                    .collect();
                self.inner
                    .setSocketDevices(&objc2_foundation::NSArray::from_slice(&refs));
            }

            if !self.entropy_devices.is_empty() {
                let refs: Vec<&VZEntropyDeviceConfiguration> = self
                    .entropy_devices
                    .iter()
                    .map(|device| device.as_inner())
                    .collect();
                self.inner
                    .setEntropyDevices(&objc2_foundation::NSArray::from_slice(&refs));
            }

            if !self.directory_sharing_devices.is_empty() {
                let refs: Vec<&VZDirectorySharingDeviceConfiguration> = self
                    .directory_sharing_devices
                    .iter()
                    .map(|device| device.as_inner())
                    .collect();
                self.inner
                    .setDirectorySharingDevices(&objc2_foundation::NSArray::from_slice(&refs));
            }

            if !self.memory_balloon_devices.is_empty() {
                let refs: Vec<&VZMemoryBalloonDeviceConfiguration> = self
                    .memory_balloon_devices
                    .iter()
                    .map(|device| device.as_inner())
                    .collect();
                self.inner
                    .setMemoryBalloonDevices(&objc2_foundation::NSArray::from_slice(&refs));
            }
        }
    }
}

fn validate_support() -> Result<(), VzError> {
    if !is_os_version_at_least(11, 0, 0) {
        return Err(VzError::UnsupportedHost {
            reason: "Virtualization.framework requires macOS 11 or newer".to_string(),
        });
    }

    if !vz_virtual_machine_is_supported() {
        return Err(VzError::UnsupportedHost {
            reason: "Virtualization.framework is not supported on this host".to_string(),
        });
    }

    Ok(())
}
