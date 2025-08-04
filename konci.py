import os
import time

# --- Configuration ---
# Set the path to the directory and the file you want to monitor and delete.
# This script will specifically target '/content/logs/miner.log'.
target_dir = "/content/logs"
target_file = "miner.log"
full_path = os.path.join(target_dir, target_file)

# --- Main Logic ---
print(f"Starting file watcher script. Monitoring for '{full_path}'...")
print("Press Ctrl+C to stop the script at any time.")

try:
    # Run a continuous loop to check for the file
    while True:
        # Check if the file exists at the specified path
        if os.path.exists(full_path):
            print(f"\n--- Alert! File '{target_file}' found. Attempting to delete...")
            try:
                # Use os.remove() to delete the file
                os.remove(full_path)
                print(f"Successfully deleted '{full_path}'.")
            except OSError as e:
                # Handle potential errors, such as permission denied
                print(f"Error: Could not delete the file. {e}")
        else:
            # If the file doesn't exist, just print a status update
            print(f"File '{full_path}' not found. All clear.", end='\r')

        # Pause the script for a short duration to avoid high CPU usage
        time.sleep(1)

except KeyboardInterrupt:
    # Allow the user to gracefully stop the script with Ctrl+C
    print("\n\nScript stopped by user.")
except Exception as e:
    # Catch any other unexpected errors
    print(f"\nAn unexpected error occurred: {e}")
finally:
    print("Exiting file watcher.")
