#!/usr/bin/env python3
"""
Script to monitor authentication server logs in real-time.
"""

import os
import sys
import time
import subprocess
from datetime import datetime

LOG_FILE = "auth_server.log"

def tail_file(file_path, n=100):
    """Tail the last n lines of a file."""
    if not os.path.exists(file_path):
        return f"Log file not found: {file_path}"
        
    try:
        result = subprocess.run(
            ["tail", "-n", str(n), file_path], 
            capture_output=True, 
            text=True, 
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error reading log file: {str(e)}"

def monitor():
    """Monitor log file continuously."""
    if not os.path.exists(LOG_FILE):
        print(f"Creating log file: {LOG_FILE}")
        with open(LOG_FILE, "w") as f:
            f.write(f"Log file created at {datetime.now()}\n")
    
    print(f"Monitoring log file: {LOG_FILE}")
    print("Press Ctrl+C to exit")
    print()
    
    # Start at the end of the file
    last_size = os.path.getsize(LOG_FILE)
    
    try:
        while True:
            current_size = os.path.getsize(LOG_FILE)
            
            # If file has grown
            if current_size > last_size:
                # Read only the new content
                with open(LOG_FILE, "r") as f:
                    f.seek(last_size)
                    new_content = f.read()
                    
                # Print new content without clearing screen
                if new_content.strip():
                    print(new_content, end="")
                    
                last_size = current_size
                
            time.sleep(0.5)  # Check every half second
    except KeyboardInterrupt:
        print("\nExiting...")

if __name__ == "__main__":
    monitor() 