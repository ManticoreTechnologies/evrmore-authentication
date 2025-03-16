#!/usr/bin/env python3
"""
Evrmore Authentication CLI
--------------------------
Command-line interface for Evrmore Authentication system.
"""

import sys
import os
import argparse
import subprocess
import logging
from evrmore_authentication.bin.install import install_system

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("cli")

def start_server(host="0.0.0.0", port=8000, daemon=False):
    """Start the Evrmore Authentication server."""
    logger.info(f"Starting Evrmore Authentication server on {host}:{port}...")
    
    cmd = [sys.executable, "-m", "scripts.run_api_server", "--host", host, "--port", str(port)]
    
    if daemon:
        # Run in background with nohup
        cmd = ["nohup"] + cmd + ["&"]
        subprocess.Popen(" ".join(cmd), shell=True, 
                         stdout=open(os.devnull, 'w'),
                         stderr=subprocess.STDOUT)
        logger.info("Server started in background.")
    else:
        # Run in foreground
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            logger.info("Server stopped.")

def stop_server():
    """Stop the Evrmore Authentication server."""
    logger.info("Stopping Evrmore Authentication server...")
    
    # Find the process
    try:
        # Using pgrep to find the process
        result = subprocess.run(
            ["pgrep", "-f", "scripts.run_api_server"],
            capture_output=True,
            text=True
        )
        
        if not result.stdout.strip():
            logger.info("No running server found.")
            return
            
        pids = result.stdout.strip().split('\n')
        for pid in pids:
            if pid:
                logger.info(f"Stopping process {pid}...")
                subprocess.run(["kill", pid])
                
        logger.info("Server stopped.")
    except subprocess.CalledProcessError:
        logger.error("Failed to find the server process.")
        
def check_status():
    """Check if the server is running."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", "scripts.run_api_server"],
            capture_output=True,
            text=True
        )
        
        if result.stdout.strip():
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                if pid:
                    logger.info(f"Server is running (PID: {pid}).")
            return True
        else:
            logger.info("Server is not running.")
            return False
    except subprocess.CalledProcessError:
        logger.error("Failed to check server status.")
        return False

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Evrmore Authentication CLI",
        prog="evrmore-authentication"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Install command
    install_parser = subparsers.add_parser("install", help="Install Evrmore Authentication system")
    install_parser.add_argument("--systemd", action="store_true", help="Install systemd service")
    install_parser.add_argument("--db-path", help="Custom database path")
    install_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    install_parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    install_parser.add_argument("--no-init-db", action="store_true", help="Skip database initialization")
    install_parser.add_argument("--register-client", action="store_true", help="Register default OAuth client")
    
    # Start command
    start_parser = subparsers.add_parser("start", help="Start the Evrmore Authentication server")
    start_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    start_parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    start_parser.add_argument("--daemon", action="store_true", help="Run server in background")
    
    # Stop command
    stop_parser = subparsers.add_parser("stop", help="Stop the Evrmore Authentication server")
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Check if the server is running")
    
    # Parse arguments
    args = parser.parse_args()
    
    if args.command == "install":
        install_system(
            install_systemd=args.systemd,
            db_path=args.db_path,
            host=args.host,
            port=args.port,
            init_db=not args.no_init_db,
            register_client=args.register_client
        )
    elif args.command == "start":
        start_server(host=args.host, port=args.port, daemon=args.daemon)
    elif args.command == "stop":
        stop_server()
    elif args.command == "status":
        check_status()
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()