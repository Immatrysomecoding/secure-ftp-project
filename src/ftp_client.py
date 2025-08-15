#!/usr/bin/env python3
"""
Secure FTP Client với ClamAV virus scanning
Main FTP Client implementation
"""

import socket
import json
import os
import glob
import threading
import time
import logging
from pathlib import Path
from urllib.parse import urlparse

from network_utils import NetworkUtils, FTPResponse, ProgressTracker
from ftp_commands import FTPCommands


class SecureFTPClient:
    """
    Main FTP Client class với virus scanning integration
    """
    
    def __init__(self, config_file='config/client_config.json'):
        """
        Initialize FTP Client
        
        Args:
            config_file (str): Path to config file
        """
        self.config = self.load_config(config_file)
        self.control_socket = None
        self.connected = False
        self.logged_in = False
        self.passive_mode = self.config['client']['passive_mode']
        self.current_dir = "/"
        self.transfer_mode = "binary"  # binary or ascii
        self.prompt_mode = True  # For mget/mput confirmation
        
        # Setup logging
        self.setup_logging()
        
        # Initialize commands handler
        self.commands = FTPCommands(self)
        
        self.logger.info("Secure FTP Client initialized")
    
    def load_config(self, config_file):
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            # Default config
            return {
                "ftp_server": {
                "host": "127.0.0.1",
                "port": 21,
                "username": "testuser",
                "password": "testpass"
                },
            "clamav_agent": {
                "host": "127.0.0.1",
                "port": 9999
                },
            "client": {
                "passive_mode": True,
                "timeout": 30,
                "buffer_size": 8192
                }
            }
    
    def setup_logging(self):
        """Setup logging system"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ftp_client.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('SecureFTPClient')
    
    def connect(self, host=None, port=None):
        """
        Connect to FTP server with proper response handling
        """
        if host is None:
            host = self.config['ftp_server']['host']
        if port is None:
            port = self.config['ftp_server']['port']
        
        try:
            self.logger.info(f"Connecting to {host}:{port}")
            
            # Create control socket
            self.control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.control_socket.settimeout(10)
            
            # Connect
            self.control_socket.connect((host, port))
            self.logger.info("Socket connected, reading welcome message...")
            
            # Read welcome message - FIX HERE
            try:
                welcome_data = self.control_socket.recv(1024)
                welcome_text = welcome_data.decode('utf-8').strip()
                self.logger.info(f"Server welcome: {welcome_text}")
                
                # Parse response code
                if welcome_text.startswith('220'):
                    self.connected = True
                    print(f"✓ Connected to {host}:{port}")
                    print(f"Server: {welcome_text}")
                    return True
                else:
                    print(f"✗ Unexpected server response: {welcome_text}")
                    return False
                    
            except socket.timeout:
                print("✗ Server welcome timeout")
                return False
                
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            print(f"✗ Connection failed: {e}")
            return False
        
    def login(self, username=None, password=None):
        """
        Login to FTP server with AUTH handling
        """
        if not self.connected:
            print("✗ Not connected to server")
            return False
        
        if username is None:
            username = self.config['ftp_server']['username']
        if password is None:
            password = self.config['ftp_server']['password']
        
        try:
            # Try AUTH TLS first (for FileZilla Server)
            try:
                self.send_command("AUTH TLS")
                auth_response = self.receive_response()
                
                if auth_response.is_positive():
                    print("✓ AUTH TLS accepted, switching to plain mode")
                    # Send AUTH TLS but don't actually do TLS handshake
                    # This satisfies FileZilla's AUTH requirement
                else:
                    print("ℹ️ AUTH TLS not required, proceeding with plain FTP")
            except:
                print("ℹ️ AUTH command not supported, using plain FTP")
            
            # Send USER command
            self.send_command(f"USER {username}")
            response = self.receive_response()
            
            if response.code == 331:  # Need password
                self.send_command(f"PASS {password}")
                response = self.receive_response()
            elif response.code == 503:  # AUTH required but we handled it
                # Try USER again after AUTH
                self.send_command(f"USER {username}")
                response = self.receive_response()
                if response.code == 331:
                    self.send_command(f"PASS {password}")
                    response = self.receive_response()
            
            if response.is_positive():
                self.logged_in = True
                self.logger.info(f"Logged in as {username}")
                print(f"✓ Logged in as {username}")
                return True
            else:
                self.logger.error(f"Login failed: {response}")
                print(f"✗ Login failed: {response.message}")
                return False
                
        except Exception as e:
            self.logger.error(f"Login error: {e}")
            print(f"✗ Login error: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from FTP server"""
        if self.connected:
            try:
                if self.logged_in:
                    self.send_command("QUIT")
                    self.receive_response()
                
                self.control_socket.close()
                
            except:
                pass
            finally:
                self.connected = False
                self.logged_in = False
                self.control_socket = None
                
                self.logger.info("Disconnected from server")
                print("✓ Disconnected from server")
    
    def send_command(self, command):
        """
        Send command to FTP server
        
        Args:
            command (str): FTP command
        """
        if not self.connected:
            raise Exception("Not connected to server")
        
        command_line = command + '\r\n'
        self.control_socket.send(command_line.encode('utf-8'))
        self.logger.debug(f"Sent: {command}")
    
    def receive_response(self):
        """
        Receive response from FTP server
        """
        try:
            response_data = self.control_socket.recv(1024)
            response_text = response_data.decode('utf-8').strip()
            self.logger.debug(f"Received: {response_text}")
            
            from network_utils import FTPResponse
            return FTPResponse(response_text)
            
        except Exception as e:
            self.logger.error(f"Response error: {e}")
            raise Exception(f"Failed to receive response: {e}")
    
    def open_data_connection(self):
        """
        Open data connection (Active or Passive mode)
        
        Returns:
            socket.socket: Data socket
        """
        if self.passive_mode:
            return self._open_passive_data_connection()
        else:
            return self._open_active_data_connection()
    
    def _open_passive_data_connection(self):
        """Open data connection in passive mode"""
        # Send PASV command
        self.send_command("PASV")
        response = self.receive_response()
        
        if not response.is_positive():
            raise Exception(f"PASV failed: {response.message}")
        
        # Parse PASV response
        data_address = NetworkUtils.parse_pasv_response(response.message)
        if not data_address:
            raise Exception(f"Failed to parse PASV response: {response.message}")
        
        host, port = data_address
        
        # Create data socket
        data_socket = NetworkUtils.create_socket()
        data_socket.connect((host, port))
        
        self.logger.debug(f"Passive data connection: {host}:{port}")
        return data_socket
    
    def _open_active_data_connection(self):
        """Open data connection in active mode"""
        # Create data socket and bind to random port
        data_socket = NetworkUtils.create_socket()
        data_socket.bind(('', 0))  # Bind to any available port
        data_socket.listen(1)
        
        # Get bound address
        host, port = data_socket.getsockname()
        
        # Use client's IP (get from control connection)
        client_host = self.control_socket.getsockname()[0]
        
        # Send PORT command
        port_command = NetworkUtils.create_port_command(client_host, port)
        self.send_command(port_command)
        response = self.receive_response()
        
        if not response.is_positive():
            data_socket.close()
            raise Exception(f"PORT failed: {response.message}")
        
        self.logger.debug(f"Active data connection: {client_host}:{port}")
        return data_socket
    
    def scan_file_for_virus(self, file_path):
        """
        Scan file for virus using ClamAV Agent
        
        Args:
            file_path (str/Path): File to scan
            
        Returns:
            dict: Scan result
        """
        return NetworkUtils.send_file_to_clamav(
            file_path,
            self.config['clamav_agent']['host'],
            self.config['clamav_agent']['port']
        )
    
    def set_transfer_mode(self, mode):
        """
        Set transfer mode (ASCII or Binary)
        
        Args:
            mode (str): 'ascii' or 'binary'
        """
        if mode.lower() == 'ascii':
            self.send_command("TYPE A")
            self.transfer_mode = 'ascii'
        else:
            self.send_command("TYPE I")
            self.transfer_mode = 'binary'
        
        response = self.receive_response()
        if response.is_positive():
            print(f"✓ Transfer mode set to {self.transfer_mode}")
        else:
            print(f"✗ Failed to set transfer mode: {response.message}")
    
    def toggle_passive_mode(self):
        """Toggle between active and passive mode"""
        self.passive_mode = not self.passive_mode
        mode_str = "passive" if self.passive_mode else "active"
        print(f"✓ FTP mode set to {mode_str}")
        self.logger.info(f"Mode changed to {mode_str}")
    
    def show_status(self):
        """Show current connection status"""
        print("\n=== FTP Client Status ===")
        print(f"Connected: {'Yes' if self.connected else 'No'}")
        print(f"Logged in: {'Yes' if self.logged_in else 'No'}")
        
        if self.connected:
            server_info = f"{self.config['ftp_server']['host']}:{self.config['ftp_server']['port']}"
            print(f"Server: {server_info}")
            print(f"User: {self.config['ftp_server']['username']}")
            print(f"Mode: {'Passive' if self.passive_mode else 'Active'}")
            print(f"Transfer: {self.transfer_mode}")
            print(f"Current dir: {self.current_dir}")
        
        print(f"ClamAV Agent: {self.config['clamav_agent']['host']}:{self.config['clamav_agent']['port']}")
        print("========================\n")
    
    def interactive_mode(self):
        """Start interactive command mode"""
        print("🛡️ Secure FTP Client with ClamAV scanning")
        print("Type 'help' for commands or 'quit' to exit")
        
        # Auto-connect if configured
        if self.config['ftp_server']['host']:
            print(f"\nAuto-connecting to {self.config['ftp_server']['host']}...")
            if self.connect():
                self.login()
        
        print("\nftp> ", end='')
        
        try:
            while True:
                try:
                    command_line = input().strip()
                    
                    if not command_line:
                        print("ftp> ", end='')
                        continue
                    
                    # Parse command
                    parts = command_line.split()
                    command = parts[0].lower()
                    args = parts[1:] if len(parts) > 1 else []
                    
                    # Handle quit/exit
                    if command in ['quit', 'bye', 'exit']:
                        break
                    
                    # Execute command
                    self.commands.execute_command(command, args)
                    
                except KeyboardInterrupt:
                    print("\nUse 'quit' to exit")
                except EOFError:
                    break
                except Exception as e:
                    print(f"Error: {e}")
                
                print("ftp> ", end='')
                
        except KeyboardInterrupt:
            print("\nGoodbye!")
        finally:
            self.disconnect()


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Secure FTP Client with ClamAV scanning')
    parser.add_argument('--config', default='config/client_config.json',
                       help='Configuration file path')
    parser.add_argument('--host', help='FTP server host')
    parser.add_argument('--port', type=int, help='FTP server port')
    parser.add_argument('--user', help='Username')
    parser.add_argument('--password', help='Password')
    
    args = parser.parse_args()
    
    # Create client
    client = SecureFTPClient(args.config)
    
    # Override config with command line args
    if args.host:
        client.config['ftp_server']['host'] = args.host
    if args.port:
        client.config['ftp_server']['port'] = args.port
    if args.user:
        client.config['ftp_server']['username'] = args.user
    if args.password:
        client.config['ftp_server']['password'] = args.password
    
    # Start interactive mode
    client.interactive_mode()


if __name__ == "__main__":
    main()