#!/usr/bin/env python3
"""
FTP Commands Implementation
Implements all required FTP commands with virus scanning
"""

import os
import glob
import time
from pathlib import Path
from network_utils import NetworkUtils, ProgressTracker

import sys
sys.path.append('.')
from network_utils import NetworkUtils, ProgressTracker


class FTPCommands:
    """
    FTP Commands implementation class
    """
    
    def __init__(self, client):
        """
        Initialize with FTP client reference
        
        Args:
            client: SecureFTPClient instance
        """
        self.client = client
    
    def execute_command(self, command, args):
        """
        Execute FTP command
        
        Args:
            command (str): Command name
            args (list): Command arguments
        """
        command_map = {
            # File and Directory Operations
            'ls': self.cmd_ls,
            'dir': self.cmd_ls,
            'cd': self.cmd_cd,
            'cwd': self.cmd_cd,
            'pwd': self.cmd_pwd,
            'mkdir': self.cmd_mkdir,
            'rmdir': self.cmd_rmdir,
            'delete': self.cmd_delete,
            'del': self.cmd_delete,
            'rename': self.cmd_rename,
            
            # Upload and Download
            'get': self.cmd_get,
            'recv': self.cmd_get,
            'put': self.cmd_put,
            'send': self.cmd_put,
            'mget': self.cmd_mget,
            'mput': self.cmd_mput,
            
            # Session Management  
            'open': self.cmd_open,
            'close': self.cmd_close,
            'ascii': self.cmd_ascii,
            'binary': self.cmd_binary,
            'passive': self.cmd_passive,
            'status': self.cmd_status,
            'prompt': self.cmd_prompt,
            
            # Help
            'help': self.cmd_help,
            '?': self.cmd_help,
        }
        
        if command in command_map:
            try:
                command_map[command](args)
            except Exception as e:
                print(f"Command failed: {e}")
                self.client.logger.error(f"Command {command} failed: {e}")
        else:
            print(f"Unknown command: {command}")
            print("Type 'help' for available commands")
    
    def _check_connection(self):
        """Check if connected and logged in"""
        if not self.client.connected:
            print("✗ Not connected to server. Use 'open' command.")
            return False
        if not self.client.logged_in:
            print("✗ Not logged in. Please login first.")
            return False
        return True
    
    # File and Directory Operations
    
    def cmd_ls(self, args):
        """List files and directories"""
        if not self._check_connection():
            return
        
        try:
            # Fix: Use client's data connection method
            if self.client.passive_mode:
                # Send PASV command
                self.client.send_command("PASV")
                response = self.client.receive_response()
                
                if response.is_positive():
                    # Simple PASV parsing
                    import re
                    match = re.search(r'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', response.message)
                    if match:
                        h1, h2, h3, h4, p1, p2 = map(int, match.groups())
                        host = f"{h1}.{h2}.{h3}.{h4}"
                        port = p1 * 256 + p2
                        
                        # Create data socket
                        import socket
                        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        data_socket.connect((host, port))
                    else:
                        print("✗ Failed to parse PASV response")
                        return
                else:
                    print(f"✗ PASV failed: {response.message}")
                    return
            else:
                # Active mode - simplified
                print("✗ Active mode not fully implemented for LIST")
                return
            
            # Send LIST command  
            path = args[0] if args else ""
            self.client.send_command(f"LIST {path}")
            
            # Check response
            response = self.client.receive_response()
            
            if response.is_positive_preliminary():
                # Receive directory listing
                listing_data = b''
                try:
                    while True:
                        chunk = data_socket.recv(8192)
                        if not chunk:
                            break
                        listing_data += chunk
                except:
                    pass
                
                data_socket.close()
                
                # Wait for completion response
                response = self.client.receive_response()
                
                if response.is_positive():
                    listing = listing_data.decode('utf-8').strip()
                    if listing:
                        print(listing)
                    else:
                        print("Directory is empty")
                else:
                    print(f"✗ LIST failed: {response.message}")
            else:
                print(f"✗ LIST failed: {response.message}")
                
        except Exception as e:
            print(f"✗ LIST error: {e}")
    
    def cmd_cd(self, args):
        """Change directory"""
        if not self._check_connection():
            return
        
        if not args:
            print("Usage: cd <directory>")
            return
        
        try:
            directory = args[0]
            self.client.send_command(f"CWD {directory}")
            response = self.client.receive_response()
            
            if response.is_positive():
                print(f"✓ Changed to directory: {directory}")
                # Update current directory
                if directory == "..":
                    self.client.current_dir = "/".join(self.client.current_dir.split("/")[:-1]) or "/"
                elif directory.startswith("/"):
                    self.client.current_dir = directory
                else:
                    self.client.current_dir = f"{self.client.current_dir}/{directory}".replace("//", "/")
            else:
                print(f"✗ CWD failed: {response.message}")
                
        except Exception as e:
            print(f"✗ CD error: {e}")
    
    def cmd_pwd(self, args):
        """Print working directory"""
        if not self._check_connection():
            return
        
        try:
            self.client.send_command("PWD")
            response = self.client.receive_response()
            
            if response.is_positive():
                print(f"Current directory: {response.message}")
                # Extract directory from response
                if '"' in response.message:
                    start = response.message.find('"')
                    end = response.message.find('"', start + 1)
                    if start != -1 and end != -1:
                        self.client.current_dir = response.message[start+1:end]
            else:
                print(f"✗ PWD failed: {response.message}")
                
        except Exception as e:
            print(f"✗ PWD error: {e}")
    
    def cmd_mkdir(self, args):
        """Create directory"""
        if not self._check_connection():
            return
        
        if not args:
            print("Usage: mkdir <directory>")
            return
        
        try:
            directory = args[0]
            self.client.send_command(f"MKD {directory}")
            response = self.client.receive_response()
            
            if response.is_positive():
                print(f"✓ Directory created: {directory}")
            else:
                print(f"✗ MKDIR failed: {response.message}")
                
        except Exception as e:
            print(f"✗ MKDIR error: {e}")
    
    def cmd_rmdir(self, args):
        """Remove directory"""
        if not self._check_connection():
            return
        
        if not args:
            print("Usage: rmdir <directory>")
            return
        
        try:
            directory = args[0]
            self.client.send_command(f"RMD {directory}")
            response = self.client.receive_response()
            
            if response.is_positive():
                print(f"✓ Directory removed: {directory}")
            else:
                print(f"✗ RMDIR failed: {response.message}")
                
        except Exception as e:
            print(f"✗ RMDIR error: {e}")
    
    def cmd_delete(self, args):
        """Delete file"""
        if not self._check_connection():
            return
        
        if not args:
            print("Usage: delete <filename>")
            return
        
        try:
            filename = args[0]
            self.client.send_command(f"DELE {filename}")
            response = self.client.receive_response()
            
            if response.is_positive():
                print(f"✓ File deleted: {filename}")
            else:
                print(f"✗ DELETE failed: {response.message}")
                
        except Exception as e:
            print(f"✗ DELETE error: {e}")
    
    def cmd_rename(self, args):
        """Rename file"""
        if not self._check_connection():
            return
        
        if len(args) != 2:
            print("Usage: rename <old_name> <new_name>")
            return
        
        try:
            old_name, new_name = args
            
            # Send RNFR (rename from)
            self.client.send_command(f"RNFR {old_name}")
            response = self.client.receive_response()
            
            if response.is_positive_intermediate():
                # Send RNTO (rename to)
                self.client.send_command(f"RNTO {new_name}")
                response = self.client.receive_response()
                
                if response.is_positive():
                    print(f"✓ File renamed: {old_name} → {new_name}")
                else:
                    print(f"✗ RENAME failed: {response.message}")
            else:
                print(f"✗ RENAME failed: {response.message}")
                
        except Exception as e:
            print(f"✗ RENAME error: {e}")
    
    # Upload and Download Operations
    
    def cmd_get(self, args):
        """Download file from server"""
        if not self._check_connection():
            return
        
        if not args:
            print("Usage: get <remote_file> [local_file]")
            return
        
        remote_file = args[0]
        local_file = args[1] if len(args) > 1 else remote_file
        
        try:
            # Open data connection
            data_socket = self.client.open_data_connection()
            
            # Send RETR command
            self.client.send_command(f"RETR {remote_file}")
            response = self.client.receive_response()
            
            if response.is_positive_preliminary():
                # Accept connection for active mode
                if not self.client.passive_mode:
                    conn, addr = data_socket.accept()
                    data_socket = conn
                
                print(f"Downloading {remote_file}...")
                
                # Create progress tracker
                progress = ProgressTracker(description=f"GET {remote_file}")
                
                # Receive file
                success = NetworkUtils.receive_file_via_socket(
                    data_socket, 
                    local_file,
                    callback=lambda bytes_recv: progress.update(bytes_recv)
                )
                
                progress.finish()
                data_socket.close()
                
                # Wait for completion response
                response = self.client.receive_response()
                
                if success and response.is_positive():
                    print(f"✓ Downloaded: {remote_file} → {local_file}")
                else:
                    print(f"✗ Download failed: {response.message}")
                    # Clean up partial file
                    try:
                        os.remove(local_file)
                    except:
                        pass
            else:
                data_socket.close()
                print(f"✗ RETR failed: {response.message}")
                
        except Exception as e:
            print(f"✗ GET error: {e}")
    
    def cmd_put(self, args):
        """Upload file to server with virus scanning"""
        if not self._check_connection():
            return
        
        if not args:
            print("Usage: put <local_file> [remote_file]")
            return
        
        local_file = args[0]
        remote_file = args[1] if len(args) > 1 else os.path.basename(local_file)
        
        # Check if local file exists
        if not os.path.exists(local_file):
            print(f"✗ Local file not found: {local_file}")
            return
        
        try:
            # Step 1: Scan file for virus
            print(f"🛡️ Scanning {local_file} for viruses...")
            scan_result = self.client.scan_file_for_virus(local_file)
            
            if scan_result['status'] == 'INFECTED':
                print(f"🦠 VIRUS DETECTED: {scan_result['message']}")
                print(f"   Details: {scan_result['details']}")
                print("❌ Upload BLOCKED for security")
                return
            elif scan_result['status'] == 'ERROR':
                print(f"⚠️ Virus scan error: {scan_result['message']}")
                confirm = input("Continue upload without scan? (y/N): ")
                if confirm.lower() != 'y':
                    print("Upload cancelled")
                    return
            else:
                print("✅ File is clean - proceeding with upload")
            
            # Step 2: Upload file to FTP server
            data_socket = self.client.open_data_connection()
            
            # Send STOR command
            self.client.send_command(f"STOR {remote_file}")
            response = self.client.receive_response()
            
            if response.is_positive_preliminary():
                # Accept connection for active mode
                if not self.client.passive_mode:
                    conn, addr = data_socket.accept()
                    data_socket = conn
                
                print(f"Uploading {local_file}...")
                
                # Get file size for progress
                file_size = os.path.getsize(local_file)
                progress = ProgressTracker(file_size, f"PUT {local_file}")
                
                # Send file
                success = NetworkUtils.send_file_via_socket(
                    data_socket,
                    local_file,
                    callback=lambda sent, total: progress.update(sent, total)
                )
                
                progress.finish()
                data_socket.close()
                
                # Wait for completion response
                response = self.client.receive_response()
                
                if success and response.is_positive():
                    print(f"✓ Uploaded: {local_file} → {remote_file}")
                else:
                    print(f"✗ Upload failed: {response.message}")
            else:
                data_socket.close()
                print(f"✗ STOR failed: {response.message}")
                
        except Exception as e:
            print(f"✗ PUT error: {e}")
    
    def cmd_mget(self, args):
        """Download multiple files"""
        if not self._check_connection():
            return
        
        if not args:
            print("Usage: mget <pattern1> [pattern2] ...")
            return
        
        # Get file list first
        try:
            # Send LIST to get file listing
            self.client.send_command("LIST")
            response = self.client.receive_response()
            
            if response.is_positive_preliminary():
                # Get list of files (simplified)
                print("Available files:")
                self.cmd_ls([])  # Show files
                
            # For each pattern, try direct download
            for pattern in args:
                if '*' in pattern:
                    print(f"Wildcard patterns not fully supported yet")
                    print(f"Try: get {pattern.replace('*', 'filename')}")
                else:
                    # Download single file
                    self.cmd_get([pattern])
                    
        except Exception as e:
            print(f"✗ MGET error: {e}")
    
    def cmd_mput(self, args):
        """Upload multiple files with virus scanning"""
        if not self._check_connection():
            return
        
        if not args:
            print("Usage: mput <pattern1> [pattern2] ...")
            return
        
        for pattern in args:
            try:
                # Expand glob pattern
                files = glob.glob(pattern)
                
                if not files:
                    print(f"No files match pattern: {pattern}")
                    continue
                
                for file_path in files:
                    if os.path.isfile(file_path):
                        if self.client.prompt_mode:
                            confirm = input(f"Upload {file_path}? (y/n): ")
                            if confirm.lower() != 'y':
                                continue
                        
                        self.cmd_put([file_path])
                        
            except Exception as e:
                print(f"✗ MPUT error for {pattern}: {e}")
    
    # Session Management
    
    def cmd_open(self, args):
        """Open connection to FTP server"""
        if len(args) == 0:
            host = input("Host: ")
        else:
            host = args[0]
        
        port = 21
        if len(args) > 1:
            try:
                port = int(args[1])
            except ValueError:
                print("Invalid port number")
                return
        
        if self.client.connect(host, port):
            # Prompt for login
            username = input("Username: ") or "anonymous"
            
            if username == "anonymous":
                password = "anonymous@example.com"
            else:
                import getpass
                password = getpass.getpass("Password: ")
            
            self.client.login(username, password)
    
    def cmd_close(self, args):
        """Close connection to FTP server"""
        self.client.disconnect()
    
    def cmd_ascii(self, args):
        """Set ASCII transfer mode"""
        self.client.set_transfer_mode('ascii')
    
    def cmd_binary(self, args):
        """Set binary transfer mode"""
        self.client.set_transfer_mode('binary')
    
    def cmd_passive(self, args):
        """Toggle passive/active mode"""
        self.client.toggle_passive_mode()
    
    def cmd_status(self, args):
        """Show connection status"""
        self.client.show_status()
    
    def cmd_prompt(self, args):
        """Toggle prompting for mget/mput"""
        self.client.prompt_mode = not self.client.prompt_mode
        mode = "ON" if self.client.prompt_mode else "OFF"
        print(f"Interactive mode {mode}")
    
    # Help
    
    def cmd_help(self, args):
        """Show help"""
        help_text = """
🛡️ Secure FTP Client Commands:

📁 File & Directory Operations:
  ls [path]              List files and directories
  cd <directory>         Change directory  
  pwd                    Show current directory
  mkdir <directory>      Create directory
  rmdir <directory>      Remove directory
  delete <file>          Delete file
  rename <old> <new>     Rename file

📤📥 Upload & Download:
  get <remote> [local]   Download file
  put <local> [remote]   Upload file (with virus scan)
  mget <pattern>...      Download multiple files
  mput <pattern>...      Upload multiple files (with virus scan)

🔧 Session Management:
  open [host] [port]     Connect to FTP server
  close                  Disconnect from server
  ascii                  Set ASCII transfer mode
  binary                 Set binary transfer mode
  passive                Toggle passive/active mode
  status                 Show connection status
  prompt                 Toggle mget/mput prompting

❓ Help:
  help, ?                Show this help
  quit, bye, exit        Exit program

🛡️ Security Features:
  • All uploads are scanned for viruses using ClamAV
  • Infected files are blocked from upload
  • Clean files proceed to FTP server

📝 Examples:
  open ftp.example.com
  put myfile.txt
  get remotefile.txt
  mput *.txt
  cd documents
  ls
"""
        print(help_text)