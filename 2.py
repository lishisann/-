#!/usr/bin/env python3
import getpass     #  User name
import os
import platform
import re
import socket      # Host name


def get_kernel_version():
    return platform.uname().release  # Kernel version


def get_distro_info():
    try:
        with open('/etc/os-release', 'r') as f:
            content = f.read()

        name_match = re.search(r'PRETTY_NAME="([^"]+)"', content)
        if name_match:
            return name_match.group(1)

        name_match = re.search(r'NAME="([^"]+)"', content)
        version_match = re.search(r'VERSION="([^"]+)"', content)
        if name_match and version_match:
            return f"{name_match.group(1)} {version_match.group(1)}"

    except FileNotFoundError:
        pass


def get_memory_info():
    try:
        with open('/proc/meminfo', 'r') as f:
            meminfo = f.read()

        mem_total = re.search(r'MemTotal:\s+(\d+)\s+kB', meminfo)
        mem_free = re.search(r'MemFree:\s+(\d+)\s+kB', meminfo)
        mem_available = re.search(r'MemAvailable:\s+(\d+)\s+kB', meminfo)
        swap_total = re.search(r'SwapTotal:\s+(\d+)\s+kB', meminfo)    # Podk. file
        swap_free = re.search(r'SwapFree:\s+(\d+)\s+kB', meminfo)

        total_mb = int(mem_total.group(1)) // 1024 if mem_total else 0  # To MB
        free_mb = int(mem_free.group(1)) // 1024 if mem_free else 0
        available_mb = int(mem_available.group(1)) // 1024 if mem_available else 0
        swap_total_mb = int(swap_total.group(1)) // 1024 if swap_total else 0
        swap_free_mb = int(swap_free.group(1)) // 1024 if swap_free else 0

        return {
            'total': total_mb,
            'free': free_mb,
            'available': available_mb,
            'swap_total': swap_total_mb,
            'swap_free': swap_free_mb
        }
    except Exception as e:
        return {'error': str(e)}


def get_processor_count():
    try:
        return os.cpu_count()  # Processors count
    except:
        return 0


def get_architecture():
    return platform.machine()  # Architecture


def get_load_average():
    try:
        with open('/proc/loadavg', 'r') as f:
            loadavg = f.read().strip().split()

        return [float(x) for x in loadavg[:3]]  # Medium (1, 5 and 15 min)
    except:
        return [0.0, 0.0, 0.0]


def get_mounted_disks():
    disks = []
    try:
        with open('/proc/mounts', 'r') as f:
            mounts = f.readlines()

        for mount in mounts:
            parts = mount.split()
            if len(parts) >= 3:
                device, mount_point, fs_type = parts[0], parts[1], parts[2]

                if any(skip in device for skip in  # Skip virtual file systems
                       ['proc', 'sysfs', 'devpts', 'tmpfs', 'cgroup', 'mqueue', 'devtmpfs', 'securityfs', 'debugfs',
                        'pstore', 'binfmt_misc', 'fusectl', 'gvfs', 'fuse.rclone']):
                    continue

                if any(skip in mount_point for skip in ['/proc', '/sys', '/dev', '/run', '/snap']):
                    continue

                try:
                    stat = os.statvfs(mount_point)

                    total_bytes = stat.f_blocks * stat.f_frsize
                    free_bytes = stat.f_bfree * stat.f_frsize
                    available_bytes = stat.f_bavail * stat.f_frsize

                    total_gb = total_bytes / (1024 ** 3)  # To GB
                    free_gb = free_bytes / (1024 ** 3)
                    available_gb = available_bytes / (1024 ** 3)

                    disks.append({
                        'mount_point': mount_point,
                        'device': device,
                        'fs_type': fs_type,
                        'total_gb': round(total_gb, 1),  # Okrug.
                        'free_gb': round(free_gb, 1),
                        'available_gb': round(available_gb, 1)
                    })
                except OSError:
                    continue

        return disks
    except Exception as e:
        return [{'error': str(e)}]


def get_user_info():
    try:
        username = getpass.getuser()
        hostname = socket.gethostname()
        return username, hostname  #
    except:
        return "unknown", "unknown"


def get_virtual_memory():
    try:
        with open('/proc/meminfo', 'r') as f:
            meminfo = f.read()

        vmalloc_match = re.search(r'VmallocTotal:\s+(\d+)\s+kB', meminfo)
        if vmalloc_match:
            vmalloc_kb = int(vmalloc_match.group(1))  # In KB
            return vmalloc_kb // 1024  # To MB

        return 0
    except:
        return 0


def main():
    # OS and kernel
    distro = get_distro_info()
    kernel = get_kernel_version()
    print(f"OS: {distro}")
    print(f"Kernel: Linux {kernel}")

    # Architecture
    arch = get_architecture()
    print(f"Architecture: {arch}")

    # Host name and user
    username, hostname = get_user_info()
    print(f"Hostname: {hostname}")
    print(f"User: {username}")

    # Op. memory
    mem_info = get_memory_info()
    if 'error' not in mem_info:
        print(f"RAM: {mem_info['available']}MB available / {mem_info['total']}MB total")
        print(f"Swap: {mem_info['swap_total']}MB total / {mem_info['swap_free']}MB free")
    else:
        print(f"RAM: Error - {mem_info['error']}")

    # Virt. memory
    vmem = get_virtual_memory()
    print(f"Virtual memory: {vmem} MB")

    # Processors
    processors = get_processor_count()
    print(f"Processors: {processors}")

    # Load system
    load_avg = get_load_average()
    print(f"Load average: {load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}")

    # Disks
    print("Drives:")
    disks = get_mounted_disks()
    for disk in disks:
        if 'error' not in disk:
            print(
                f"  {disk['mount_point']:12} {disk['fs_type']:8} {disk['free_gb']}GB free / {disk['total_gb']}GB total")
        else:
            print(f"  Error reading disk info: {disk['error']}")


if __name__ == "__main__":
    main()  
