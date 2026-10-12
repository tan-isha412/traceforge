"""How much data was written to / read from a USB storage device while it was attached.

Only the operating system's per-disk I/O counters are read: no file names, no contents. The agent
samples them while the device is attached (the counters disappear the moment it is unplugged) and
reports the totals with the disconnect event.

  Linux    /sys/block/<disk>/stat for the block devices under the USB device's sysfs path
  Windows  WMI: Win32_DiskDrive (matched by the USBSTOR serial) -> Win32_PerfRawData_PerfDisk_PhysicalDisk
"""

import glob
import os
import sys
import time

SECTOR = 512  # /sys/block/*/stat counts 512-byte sectors regardless of the disk's real sector size


def _linux_disks(sys_path: str) -> list[str]:
    return sorted({os.path.basename(p) for p in glob.glob(os.path.join(sys_path, "**", "block", "*"), recursive=True)})


def _linux_counters(disks: list[str]) -> tuple[int, int] | None:
    read = written = 0
    try:
        for disk in disks:
            with open(f"/sys/block/{disk}/stat") as f:
                fields = f.read().split()
            read += int(fields[2]) * SECTOR
            written += int(fields[6]) * SECTOR
    except (OSError, IndexError, ValueError):
        return None
    return read, written


def _windows_disk_index(serial: str | None) -> int | None:
    if not serial:
        return None
    import wmi

    for drive in wmi.WMI().Win32_DiskDrive(InterfaceType="USB"):
        if serial.upper() in (drive.PNPDeviceID or "").upper():
            return int(drive.Index)
    return None


def _windows_counters(index: int) -> tuple[int, int] | None:
    import wmi

    for disk in wmi.WMI().Win32_PerfRawData_PerfDisk_PhysicalDisk():
        if (disk.Name or "").split(" ")[0] == str(index):
            # Raw "bytes/sec" counters are cumulative byte totals; the per-second rate is derived by the OS.
            return int(disk.DiskReadBytesPersec), int(disk.DiskWriteBytesPersec)
    return None


class TransferMeter:
    """Created when a storage device connects; sample() every few seconds; totals() at disconnect."""

    def __init__(self, serial: str | None = None, sys_path: str | None = None):
        self.started = time.monotonic()
        self.first: tuple[int, int] | None = None
        self.last: tuple[int, int] | None = None
        self._read = None
        try:
            if sys.platform.startswith("linux") and sys_path:
                disks = _linux_disks(sys_path)
                if disks:
                    self._read = lambda: _linux_counters(disks)
            elif sys.platform == "win32":
                index = _windows_disk_index(serial)
                if index is not None:
                    self._read = lambda: _windows_counters(index)
        except Exception as exc:  # metering is a nice-to-have; it never stops the agent
            print(f"transfer metering unavailable: {exc.__class__.__name__}: {exc}")
        self.sample()

    @property
    def available(self) -> bool:
        return self._read is not None and self.first is not None

    def sample(self) -> None:
        if self._read is None:
            return
        try:
            now = self._read()
        except Exception:
            now = None
        if now is not None:
            self.first = self.first or now
            self.last = now

    def totals(self) -> dict | None:
        if not self.available or self.last is None:
            return None
        return {
            "bytes_read": max(self.last[0] - self.first[0], 0),
            "bytes_written": max(self.last[1] - self.first[1], 0),
            "duration_s": round(time.monotonic() - self.started, 1),
        }
