# STM32MP2 Scripts

Utility scripts for working with STM32MP25x microprocessors.

## `security/bsec/bsec_status.sh`

Reads and decodes the full OTP (One-Time Programmable) fuse map of an STM32MP25x SoC via the Linux NVMEM sysfs interface (backed by OP-TEE BSEC PTA).

### What it shows

| Section | Description |
|---|---|
| **Lifecycle** | BSEC open/closed state derived from close (`s`) and re-open (`r`) counters, remaining re-open attempts |
| **Device ID** | Serial number, wafer/lot ID, part number (RPN), silicon revision |
| **Package** | Package type decoded from OTP word 122 (TFBGA 361+25, 257+25, 196+25) |
| **Security config** | Word 124 flags — ST engineering mode lock status |
| **Crypto keys** | ST public key area (words 120–127) and middle OTP root-of-trust key hashes (words 128–255) with automatic block detection |
| **Upper OTP** | Checks words 256–367 for leaked secret material (expected all-zero in open state) |
| **Board ID & MAC** | ST board identifier (word 246) and MAC address extraction (words 247–248) |
| **Calibration** | Scans remaining lower OTP for any non-zero undecoded words |
| **Usage summary** | Per-region statistics with a visual progress bar |

### Requirements

- Linux running on an STM32MP25x target with OP-TEE
- NVMEM device available at `/sys/bus/nvmem/devices/stm32-romem0/nvmem`

### Usage

Copy the script to the target board (e.g. via `scp`) and run it:

```bash
scp security/bsec/bsec_status.sh root@<target_ip>:/tmp/
ssh root@<target_ip> /tmp/bsec_status.sh
```

You can also specify a different NVMEM device:

```bash
./bsec_status.sh stm32-romem1
```

### Access path

```
Linux userspace → sysfs NVMEM → OP-TEE BSEC PTA → hardware fuse array
```

### Reference

Based on the STM32MP25x reference manual **RM0457**.
