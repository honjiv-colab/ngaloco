#!/bin/bash

# Run kkonci.py for 1 minute
echo "Running kkonci.py for 1 minute..."
python kkonci.py &
KKONCI_PID=$!
sleep 60
kill $KKONCI_PID
echo "kkonci.py finished its 1-minute run."

# Kill all sys_updater processes
echo "Killing all sys_updater processes..."
killall sys_updater
echo "All sys_updater processes killed."

# Run kkonci.py for a random time between 5 and 7 minutes
RANDOM_TIME=$(( ( RANDOM % 3 + 5 ) * 60 )) # Generates a random number between 5 and 7, then converts to seconds
echo "Running kkonci.py for a random time of $((RANDOM_TIME / 60)) minutes..."
python kkonci.py &
KKONCI_PID=$!
sleep $RANDOM_TIME
kill $KKONCI_PID
echo "kkonci.py finished its random-time run."

echo "Script complete."
