#!/usr/bin/env python3
"""
Network Utilities cho FTP Client
Chứa các helper functions cho socket programming và FTP protocol
"""

import socket
import json
import time
import logging
from pathlib import Path


class NetworkUtils:
    """Utility class cho network operations"""
    
    @staticmethod
    def create_socket(timeout=30):
        """
        Tạo socket với timeout
        
        Args:
            timeout (int): Timeout in seconds
            
        Returns:
            socket.socket: Configured socket
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        return sock
    
    @staticmethod
    def send_file_to_clamav(file_path, agent_host='127.0.0.1', agent_port=9999):
        """
        Gửi file đến ClamAV Agent để quét virus
        
        Args:
            file_path (str/Path): Đường dẫn đến file
            agent_host (str): ClamAV Agent host
            agent_port (int): ClamAV Agent port
            
        Returns:
            dict: Kết quả scan {status: 'OK'/'INFECTED'/'ERROR', message: '...'}
        """
        file_path = Path(file_path).resolve()
        
        if not file_path.exists():
            return {
                'status': 'ERROR',
                'message': 'File not found',
                'details': f'File does not exist: {file_path}'
            }
        
        try:
            # Kết nối đến ClamAV Agent
            client_socket = NetworkUtils.create_socket()
            client_socket.connect((agent_host, agent_port))
            
            # Protocol: FILENAME -> SIZE -> DATA
            filename = file_path.name
            file_size = file_path.stat().st_size
            
            # Bước 1: Gửi filename
            filename_msg = f"FILENAME:{filename}"
            client_socket.send(filename_msg.encode('utf-8'))
            
            # Đợi READY
            response = client_socket.recv(1024)
            if response != b'READY':
                raise Exception(f"Unexpected response: {response}")
            
            # Bước 2: Gửi file size
            size_msg = f"SIZE:{file_size}"
            client_socket.send(size_msg.encode('utf-8'))
            
            # Đợi READY
            response = client_socket.recv(1024)
            if response != b'READY':
                raise Exception(f"Unexpected response: {response}")
            
            # Bước 3: Gửi file data
            with open(file_path, 'rb') as f:
                sent = 0
                while sent < file_size:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    client_socket.send(chunk)
                    sent += len(chunk)
            
            # Bước 4: Nhận kết quả
            result_data = client_socket.recv(4096).decode('utf-8')
            result = json.loads(result_data)
            
            client_socket.close()
            return result
            
        except Exception as e:
            return {
                'status': 'ERROR',
                'message': 'Failed to scan file',
                'details': str(e)
            }
    
    @staticmethod
    def parse_pasv_response(response):
        """
        Parse PASV response để lấy IP và port
        
        Args:
            response (str): PASV response từ FTP server
            
        Returns:
            tuple: (ip, port) hoặc None nếu lỗi
        """
        try:
            # PASV response format: "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)"
            import re
            match = re.search(r'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', response)
            
            if match:
                h1, h2, h3, h4, p1, p2 = map(int, match.groups())
                
                # Parse IP
                ip = f"{h1}.{h2}.{h3}.{h4}"
                
                # Parse port: port = p1 * 256 + p2
                port = p1 * 256 + p2
                
                return (ip, port)
            
        except Exception:
            pass
        
        return None
    
    @staticmethod
    def create_port_command(host, port):
        """
        Tạo PORT command cho Active FTP
        
        Args:
            host (str): IP address
            port (int): Port number
            
        Returns:
            str: PORT command string
        """
        try:
            # Convert IP to parts
            ip_parts = host.split('.')
            if len(ip_parts) != 4:
                raise ValueError("Invalid IP address")
            
            # Convert port: p1 = port // 256, p2 = port % 256
            p1 = port // 256
            p2 = port % 256
            
            # Create command
            port_cmd = f"PORT {','.join(ip_parts)},{p1},{p2}"
            return port_cmd
            
        except Exception as e:
            raise ValueError(f"Failed to create PORT command: {e}")
    
    @staticmethod
    def receive_data_with_timeout(sock, buffer_size=8192, timeout=30):
        """
        Nhận data với timeout
        
        Args:
            sock: Socket object
            buffer_size (int): Buffer size
            timeout (int): Timeout in seconds
            
        Returns:
            bytes: Received data
        """
        sock.settimeout(timeout)
        data = b''
        
        try:
            while True:
                chunk = sock.recv(buffer_size)
                if not chunk:
                    break
                data += chunk
                
                # Check for FTP end-of-data markers
                if data.endswith(b'\r\n'):
                    break
                    
        except socket.timeout:
            pass  # Timeout is expected for end of data
        except Exception as e:
            logging.warning(f"Data receive error: {e}")
        
        return data
    
    @staticmethod
    def send_file_via_socket(sock, file_path, callback=None):
        """
        Gửi file qua socket với progress callback
        
        Args:
            sock: Socket object
            file_path (str/Path): File to send
            callback (function): Progress callback(bytes_sent, total_bytes)
            
        Returns:
            bool: True if successful
        """
        try:
            file_path = Path(file_path)
            total_size = file_path.stat().st_size
            sent = 0
            
            with open(file_path, 'rb') as f:
                while sent < total_size:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    
                    sock.send(chunk)
                    sent += len(chunk)
                    
                    if callback:
                        callback(sent, total_size)
            
            return True
            
        except Exception as e:
            logging.error(f"File send error: {e}")
            return False
    
    @staticmethod
    def receive_file_via_socket(sock, file_path, callback=None):
        """
        Nhận file qua socket với progress callback
        
        Args:
            sock: Socket object  
            file_path (str/Path): File to save
            callback (function): Progress callback(bytes_received)
            
        Returns:
            bool: True if successful
        """
        try:
            file_path = Path(file_path)
            received = 0
            
            with open(file_path, 'wb') as f:
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    
                    f.write(chunk)
                    received += len(chunk)
                    
                    if callback:
                        callback(received)
            
            return True
            
        except Exception as e:
            logging.error(f"File receive error: {e}")
            return False


class FTPResponse:
    """Class để parse FTP responses"""
    
    def __init__(self, response_text):
        self.raw = response_text
        self.lines = response_text.strip().split('\n')
        self.code = None
        self.message = ""
        
        if self.lines:
            first_line = self.lines[0]
            if len(first_line) >= 3 and first_line[:3].isdigit():
                self.code = int(first_line[:3])
                self.message = first_line[4:] if len(first_line) > 3 else ""
    
    def is_positive(self):
        """Check if response is positive (2xx)"""
        return self.code and 200 <= self.code < 300
    
    def is_positive_preliminary(self):
        """Check if response is positive preliminary (1xx)"""
        return self.code and 100 <= self.code < 200
    
    def is_positive_intermediate(self):
        """Check if response is positive intermediate (3xx)"""
        return self.code and 300 <= self.code < 400
    
    def is_error(self):
        """Check if response is error (4xx, 5xx)"""
        return self.code and self.code >= 400
    
    def __str__(self):
        return f"FTPResponse({self.code}: {self.message})"


class ProgressTracker:
    """Class để track progress của file transfer"""
    
    def __init__(self, total_size=None, description="Transfer"):
        self.total_size = total_size
        self.description = description
        self.transferred = 0
        self.start_time = time.time()
    
    def update(self, bytes_transferred, total_bytes=None):
        """Update progress"""
        self.transferred = bytes_transferred
        if total_bytes:
            self.total_size = total_bytes
        
        self._display_progress()
    
    def _display_progress(self):
        """Display progress bar"""
        elapsed = time.time() - self.start_time
        
        if self.total_size:
            percent = (self.transferred / self.total_size) * 100
            bar_length = 30
            filled = int(bar_length * percent / 100)
            bar = '█' * filled + '░' * (bar_length - filled)
            
            speed = self.transferred / elapsed if elapsed > 0 else 0
            speed_str = self._format_bytes(speed) + "/s"
            
            size_str = f"{self._format_bytes(self.transferred)}/{self._format_bytes(self.total_size)}"
            
            print(f"\r{self.description}: |{bar}| {percent:.1f}% {size_str} {speed_str}", end='', flush=True)
        else:
            speed = self.transferred / elapsed if elapsed > 0 else 0
            speed_str = self._format_bytes(speed) + "/s"
            size_str = self._format_bytes(self.transferred)
            
            print(f"\r{self.description}: {size_str} {speed_str}", end='', flush=True)
    
    def finish(self):
        """Finish progress tracking"""
        print()  # New line
    
    @staticmethod
    def _format_bytes(bytes_val):
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f}{unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f}TB"