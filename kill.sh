#!/bin/bash

# Find the PIDs of the processes with the name "./init.sh"
pids=$(pgrep -f './init.sh')

# Check if any process is found
if [ -n "$pids" ]; then
  echo "Killing processes with PIDs: $pids"
  for pid in $pids; do
    kill "$pid"
    if [ $? -eq 0 ]; then
      echo "Process $pid killed successfully."
    else
      echo "Failed to kill process $pid."
    fi
  done
else
  echo "No processes with the name './init.sh' found."
fi

