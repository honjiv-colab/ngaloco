# xelis_miner.py

import subprocess
import time
import sys
import os

# --- Configuration Section ---
# Replace these values with your personal information
# -----------------------------
# Your Xelis wallet address
WALLET_ADDRESS = "krxXJMWJKW" 

# Your worker name (optional, but good for tracking)
WORKER_NAME = "cuki"

# The mining pool address and port
# This has been updated to the Kryptex pool.
POOL_URL = "xel.kryptex.network:7019"

# Path to the OneZeroMiner executable
# On Linux, make sure the file is executable (e.g., chmod +x onezerominer)
# On Windows, it would be "onezerominer.exe"
MINER_EXECUTABLE = "/content/onezerominer/onezerominer" 

# The mining algorithm for Xelis
ALGORITHM = "xelishashv2"
# -----------------------------


def start_miner():
    """
    Constructs the command and starts the OneZeroMiner process.
    """
    # Create the list of arguments for the subprocess.
    # The miner's output will be displayed directly in the console.
    # OneZeroMiner does not create a log file unless --log-file is specified.
    command = [
        MINER_EXECUTABLE,
        "--algo", ALGORITHM,
        "--wallet", f"{WALLET_ADDRESS}.{WORKER_NAME}",
        "--pool", POOL_URL
    ]

    print("Starting Xelis miner with the following command:")
    print(" ".join(command))
    print("-" * 40)

    try:
        # Use subprocess.run to execute the miner.
        # It's a blocking call, meaning the script will wait until the miner stops.
        subprocess.run(command, check=True)
    except FileNotFoundError:
        print(f"Error: Miner executable not found at '{MINER_EXECUTABLE}'.")
        print("Please check the MINER_EXECUTABLE path in the script.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error: Miner exited with a non-zero status code: {e.returncode}")
        print("This may indicate a configuration issue or a crash.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopping miner as requested by the user.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Check if the miner executable exists and is executable
    if not os.path.isfile(MINER_EXECUTABLE):
        print(f"Error: The miner executable '{MINER_EXECUTABLE}' does not exist.")
        sys.exit(1)
    
    if not os.access(MINER_EXECUTABLE, os.X_OK):
        print(f"Error: The miner executable '{MINER_EXECUTABLE}' is not executable.")
        print("On Linux, you may need to run 'chmod +x {MINER_EXECUTABLE}' to fix this.")
        sys.exit(1)

    start_miner()
