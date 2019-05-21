# Windows driver for Compute Engine Virtual Ethernet

This repository contains the source for building a NDIS miniport driver for the
Compute Engine Virtual Ethernet device.

This driver as well as the GCE VM virtual device are in Early Access stage [1],
the feature is available to a closed group of testers.

[1] https://cloud.google.com/terms/launch-stages

# Supported Hardware

The driver here binds to a single PCI device id used by the virtual Ethernet
device found in some Compute Engine VMs.

Field         | Value    | Comments
------------- | -------- | --------
Vendor ID     | `0x1AE0` | Google
Device ID     | `0x0042` |
Sub-vendor ID | `0x1AE0` | Google
Sub-device ID | `0x0058` |
Revision ID   | `0x0`    |
Device Class  | `0x200`  | Ethernet

# Supported Windows Kernel

6.1, 6.2, 6.3, 10.0

# Installation

## Googet Package

Official driver is packaged using [GooGet](https://github.com/google/googet) and
published through GCP repositories. All Google Cloud Windows images are
preconfigured with the GooGet tool and GCP repositories. If you need to install
GooGet and set up repositories yourself, see
[Packaging and package distribution](https://github.com/GoogleCloudPlatform/compute-image-windows#packaging-and-package-distribution).

To install or upgrade the gvnic driver, run the following command:

```
googet install google-compute-engine-driver-gvnic
```

## GitHub

If you downloaded the source from GitHub, you will need to install WDK from
[Microsoft](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
and compile the driver locally with:

```
msbuild /t:build gvnic.vcxproj /p:Configuration=[CONFIGURATION] /p:Platform=[PLATFORM]
```

Please follow Microsoft
[documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/) for
additional steps on sigining/deployment.

# Configuration

## gvnic_helper: netsh plugin
This repository also contains a netsh plugin for configuring the adapter
settings through a command line. Use `netsh gvnic` to see the usages.

```
The following commands are available:

Commands in this context:
?              - Displays a list of commands.
dump           - Displays a configuration script.
help           - Displays a list of commands.
reset          - Resets the parameter values to their default values
restart        - Restarts the device.
set            - Sets the value of the given parameter.
show           - Displays show commands
```
