import ctypes
from ctypes import wintypes
import sys
import os


def _get_windows_name(major, minor, build):
    # Версия Windows 10/11
    if major == 10:
        if build >= 22000:
            return f"Windows 11 (Build {build})"
        else:
            return f"Windows 10 (Build {build})"

    # Версия Windows 6.x (Vista, 7, 8, 8.1)
    elif major == 6:
        if minor == 3:
            return f"Windows 8.1 (Build {build})"
        elif minor == 2:
            return f"Windows 8 (Build {build})"
        elif minor == 1:
            return f"Windows 7 (Build {build})"
        elif minor == 0:
            return f"Windows Vista (Build {build})"

    # Версия Windows 5.x (2000, XP, Server 2003)
    elif major == 5:
        if minor == 2:
            return f"Windows Server 2003 (Build {build})"
        elif minor == 1:
            return f"Windows XP (Build {build})"
        elif minor == 0:
            return f"Windows 2000 (Build {build})"

    return f"Windows {major}.{minor} (Build {build})"


class SystemInfo:
    def __init__(self):
        # Системные библиотеки Windows для вызова их функций
        self.kernel32 = ctypes.windll.kernel32
        self.psapi = ctypes.windll.psapi
        self.advapi32 = ctypes.windll.advapi32
        self.shell32 = ctypes.windll.shell32
        self.ntdll = ctypes.windll.ntdll

    def get_os_version(self):
        # 1 способ
        try:
            # Создаем структуру для хранения информации о версии Windows
            class OSVERSIONINFOEXW(ctypes.Structure):
                # Какие данные будет хранить структура:
                _fields_ = [
                    ("dwOSVersionInfoSize", wintypes.DWORD),  # Размер структуры
                    ("dwMajorVersion", wintypes.DWORD),  # Основной номер версии
                    ("dwMinorVersion", wintypes.DWORD),  # Дополнительный
                    ("dwBuildNumber", wintypes.DWORD),  # Номер сборки
                    ("dwPlatformId", wintypes.DWORD),  # Идентификатор платформы
                    ("szCSDVersion", wintypes.WCHAR * 128),  # Информация о сервис-паке
                    ("wServicePackMajor", wintypes.WORD),  # Основной номер сервис-пака
                    ("wServicePackMinor", wintypes.WORD),  # Дополнительный номер сервис-пака
                    ("wSuiteMask", wintypes.WORD),  # Информация о редакции Windows
                    ("wProductType", wintypes.BYTE),  # Тип продукта
                    ("wReserved", wintypes.BYTE)  # Зарезервированное поле
                ]

            version_info = OSVERSIONINFOEXW()
            version_info.dwOSVersionInfoSize = ctypes.sizeof(OSVERSIONINFOEXW)

            if self.kernel32.GetVersionExW(ctypes.byref(version_info)):
                major = version_info.dwMajorVersion
                minor = version_info.dwMinorVersion
                build = version_info.dwBuildNumber
                return _get_windows_name(major, minor, build)

        except Exception as e:
            print(f"Error with GetVersionEx: {e}")

        # 2 способ
        try:
            class OSVERSIONINFOEXW(ctypes.Structure):
                _fields_ = [
                    ("dwOSVersionInfoSize", wintypes.DWORD),
                    ("dwMajorVersion", wintypes.DWORD),
                    ("dwMinorVersion", wintypes.DWORD),
                    ("dwBuildNumber", wintypes.DWORD),
                    ("dwPlatformId", wintypes.DWORD),
                    ("szCSDVersion", wintypes.WCHAR * 128),
                    ("wServicePackMajor", wintypes.WORD),
                    ("wServicePackMinor", wintypes.WORD),
                    ("wSuiteMask", wintypes.WORD),
                    ("wProductType", wintypes.BYTE),
                    ("wReserved", wintypes.BYTE)
                ]

            version_info = OSVERSIONINFOEXW()
            version_info.dwOSVersionInfoSize = ctypes.sizeof(OSVERSIONINFOEXW)

            # Из системной библиотеки ntdll
            RtlGetVersion = self.ntdll.RtlGetVersion
            RtlGetVersion.argtypes = [ctypes.POINTER(OSVERSIONINFOEXW)]
            RtlGetVersion.restype = ctypes.c_long

            result = RtlGetVersion(ctypes.byref(version_info))

            # Если все хорошо
            if result == 0:
                major = version_info.dwMajorVersion
                minor = version_info.dwMinorVersion
                build = version_info.dwBuildNumber
                return _get_windows_name(major, minor, build)

        except Exception as e:
            print(f"Error with RtlGetVersion: {e}")

        # 3 способ
        try:
            # Встроенная функиця питона
            win_ver = sys.getwindowsversion()
            major, minor, build = win_ver.major, win_ver.minor, win_ver.build
            return _get_windows_name(major, minor, build)
        except Exception as e:
            print(f"Error with sys.getwindowsversion: {e}")

    def get_memory_info(self):
        try:
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", wintypes.DWORD),  # Размер структуры
                    ("dwMemoryLoad", wintypes.DWORD),  # Процент использования памяти
                    ("ullTotalPhys", ctypes.c_ulonglong),  # Всего оп. памяти (в байтах)
                    ("ullAvailPhys", ctypes.c_ulonglong),  # Доступно оп. памяти
                    ("ullTotalPageFile", ctypes.c_ulonglong),  # Всего в файле подкачки
                    ("ullAvailPageFile", ctypes.c_ulonglong),  # Доступно
                    ("ullTotalVirtual", ctypes.c_ulonglong),  # Всего виртуальной памяти
                    ("ullAvailVirtual", ctypes.c_ulonglong),  # Доступно
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)  # Расширенная виртуальная память
                ]

            memory_status = MEMORYSTATUSEX()
            memory_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)

            if self.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory_status)):
                # Перевод из байт в Мб (делим на 1024*1024)
                total_phys_mb = memory_status.ullTotalPhys // (1024 * 1024)
                avail_phys_mb = memory_status.ullAvailPhys // (1024 * 1024)
                # Сколько занято (всего - доступно)
                used_phys_mb = total_phys_mb - avail_phys_mb
                # Получаем процент исп.
                memory_load = memory_status.dwMemoryLoad
                # Переводим вирт. память в Мб
                total_virtual_mb = memory_status.ullTotalVirtual // (1024 * 1024)

                # Словарь с информацией о памяти
                return {
                    'total_phys_mb': total_phys_mb,  # Всего оп. памяти
                    'used_phys_mb': used_phys_mb,  # Используется
                    'avail_phys_mb': avail_phys_mb,  # Доступно
                    'memory_load': memory_load,  # Процент использования
                    'total_virtual_mb': total_virtual_mb  # Всего вирт. памяти
                }

        except Exception as e:
            print(f"Error getting memory info: {e}")

        return None

    def get_processor_info(self):
        try:
            # Структура об информации о процессоре и системе
            class SYSTEM_INFO(ctypes.Structure):
                _fields_ = [
                    ("wProcessorArchitecture", wintypes.WORD),  # Архитектура процессора
                    ("wReserved", wintypes.WORD),  # Зарезервированное поле
                    ("dwPageSize", wintypes.DWORD),  # Размер страницы памяти
                    ("lpMinimumApplicationAddress", wintypes.LPVOID),  # Минимальный адрес памяти
                    ("lpMaximumApplicationAddress", wintypes.LPVOID),  # Максимальный
                    ("dwActiveProcessorMask", wintypes.LPVOID),  # Маска активных процессоров
                    ("dwNumberOfProcessors", wintypes.DWORD),  # Кол-во процессоров
                    ("dwProcessorType", wintypes.DWORD),  # Тип
                    ("dwAllocationGranularity", wintypes.DWORD),  # Гранулярность выделения памяти
                    ("wProcessorLevel", wintypes.WORD),  # Уровень
                    ("wProcessorRevision", wintypes.WORD)  # Ревизия
                ]

            system_info = SYSTEM_INFO()
            self.kernel32.GetSystemInfo(ctypes.byref(system_info))

            arch_map = {
                0: "x86",  # 32-битная
                6: "IA-64",  # Intel Itanium
                9: "x64 (AMD64)",  # 64-битная
                12: "ARM"  # ARM
            }
            architecture = arch_map.get(system_info.wProcessorArchitecture, "Unknown")

            return {
                'architecture': architecture,
                'cores': system_info.dwNumberOfProcessors  # Кол-во ядер процессора
            }

        except Exception as e:
            print(f"Error getting processor info: {e}")

        return None

    def get_computer_name(self):
        try:
            size = wintypes.DWORD()
            # Необходимый размер буфера для имени компьютера
            self.kernel32.GetComputerNameW(None, ctypes.byref(size))

            if size.value > 0:
                buffer = ctypes.create_unicode_buffer(size.value)
                # Получаем само имя компьютера в буфер
                if self.kernel32.GetComputerNameW(buffer, ctypes.byref(size)):
                    return buffer.value

        except Exception as e:
            print(f"Error getting computer name: {e}")

        return "Unknown"

    def get_user_name(self):
        try:
            size = wintypes.DWORD()
            self.advapi32.GetUserNameW(None, ctypes.byref(size))

            if size.value > 0:
                buffer = ctypes.create_unicode_buffer(size.value)
                if self.advapi32.GetUserNameW(buffer, ctypes.byref(size)):
                    return buffer.value

        except Exception as e:
            print(f"Error getting user name: {e}")

        return "Unknown"

    def get_pagefile_info(self):
        try:
            # Структура для хранения информации о производительности
            class PERFORMANCE_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),  # Размер структуры
                    ("CommitTotal", ctypes.c_size_t),  # Всего выделено памяти
                    ("CommitLimit", ctypes.c_size_t),  # Макс. лимит памяти
                    ("CommitPeak", ctypes.c_size_t),  # Пиковое знач. памяти
                    ("PhysicalTotal", ctypes.c_size_t),  # Всего физи. памяти
                    ("PhysicalAvailable", ctypes.c_size_t),  # Доступно
                    ("SystemCache", ctypes.c_size_t),  # Размер системного кэша
                    ("KernelTotal", ctypes.c_size_t),  # Всего памяти ядра
                    ("KernelPaged", ctypes.c_size_t),  # Выгружаемая память ядра
                    ("KernelNonpaged", ctypes.c_size_t),  # Невыгружаемая память ядра
                    ("PageSize", ctypes.c_size_t),  # Размер страницы памяти
                    ("HandleCount", wintypes.DWORD),  # Количество открытых объектов
                    ("ProcessCount", wintypes.DWORD),  # Количество процессов
                    ("ThreadCount", wintypes.DWORD)  # Количество потоков
                ]

            perf_info = PERFORMANCE_INFORMATION()
            perf_info.cb = ctypes.sizeof(PERFORMANCE_INFORMATION)

            if self.psapi.GetPerformanceInfo(ctypes.byref(perf_info), perf_info.cb):
                # Размер страницы памяти
                page_size = perf_info.PageSize
                # Текущий размер файла подкачки в Мб
                commit_total = perf_info.CommitTotal * page_size // (1024 * 1024)
                # Макс. размер файла подкачки
                commit_limit = perf_info.CommitLimit * page_size // (1024 * 1024)

                return {
                    'current_size_mb': commit_total,
                    'limit_mb': commit_limit
                }

        except Exception as e:
            print(f"Error getting pagefile info: {e}")

        return None

    def get_drives_info(self):
        try:
            drives = []  # Список для хранения информации о дисках
            drive_bits = self.kernel32.GetLogicalDrives()

            # Буквы дисков от A до Z
            for drive_letter in range(65, 91):  # 65 = 'A', 90 = 'Z'
                # Сущ. ли диск с этой буквой
                if drive_bits & (1 << (drive_letter - 65)):
                    drive_path = f"{chr(drive_letter)}:\\"

                    try:
                        free_bytes = ctypes.c_ulonglong()  # Свободное место
                        total_bytes = ctypes.c_ulonglong()  # Общий размер диска
                        free_to_caller = ctypes.c_ulonglong()  # Доступно

                        # Сколько места на диске
                        if self.kernel32.GetDiskFreeSpaceExW(
                                drive_path,  # Какой диск проверяем
                                ctypes.byref(free_to_caller),
                                ctypes.byref(total_bytes),
                                ctypes.byref(free_bytes)
                        ):
                            fs_name = ctypes.create_unicode_buffer(32)  # Поле на 32 символа

                            # Какая файловая система на диске
                            if self.kernel32.GetVolumeInformationW(
                                    drive_path,
                                    None, 0,  # Название не надо
                                    None, 0,  # Серийный номер не надо
                                    None,  # Длину файлов не надо
                                    fs_name,
                                    ctypes.sizeof(fs_name)
                            ):
                                fs_type = fs_name.value
                            else:
                                fs_type = "Unknown"

                            drives.append({
                                'drive': drive_path,  # Буква
                                'fs_type': fs_type,  # Тип системы
                                'total_gb': total_bytes.value // (1024 ** 3),  # Байты в Гб
                                'free_gb': free_bytes.value // (1024 ** 3)
                            })

                    except Exception:
                        continue

            return drives

        except Exception as e:
            print(f"Error getting drives info: {e}")

        return []

    def print_system_info(self):
        # Версия ОС
        os_version = self.get_os_version()
        print(f"OS: {os_version}")

        # Имя комп.
        print(f"Computer Name: {self.get_computer_name()}")
        # Имя пользователя
        print(f"User: {self.get_user_name()}")

        # Процессор
        proc_info = self.get_processor_info()
        if proc_info:
            print(f"Architecture: {proc_info['architecture']}")  # Архитектура
            print(f"Processors: {proc_info['cores']}")  # Кол-во ядер

        # Память
        mem_info = self.get_memory_info()
        if mem_info:
            # Используется / всего оп. памяти
            print(f"RAM: {mem_info['used_phys_mb']}MB / {mem_info['total_phys_mb']}MB")
            print(f"Virtual Memory: {mem_info['total_virtual_mb']}MB")  # Виртуальная память
            print(f"Memory Load: {mem_info['memory_load']}%")  # Процент исп. памяти

        # Файл подкачки
        pagefile_info = self.get_pagefile_info()
        if pagefile_info:
            # Текущий размер / макс. размер файла
            print(f"Pagefile: {pagefile_info['current_size_mb']}MB / {pagefile_info['limit_mb']}MB")

        # Диски
        print("Drives:")
        drives = self.get_drives_info()
        for drive in drives:
            # Выводим: буква, тип файловой системы, свободно/всего
            print(f"  - {drive['drive']} ({drive['fs_type']}): "
                  f"{drive['free_gb']} GB free / {drive['total_gb']} GB total")


def main():
    try:
        if os.name != 'nt':
            print("This program works only on Windows systems")
            return

        sys_info = SystemInfo()
        sys_info.print_system_info()

    except Exception as e:
        print(f"Fatal error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
