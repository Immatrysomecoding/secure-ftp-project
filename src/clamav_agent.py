#!/usr/bin/env python3
"""
ClamAV Agent - Virus Scanner Server
Nhận file qua socket, quét virus với ClamAV, trả về kết quả
"""

import socket
import threading
import subprocess
import json
import os
import time
import tempfile
import logging
from pathlib import Path


class ClamAVAgent:
    def __init__(self, config_file='config/agent_config.json'):
        """
        Khởi tạo ClamAV Agent
        
        Args:
            config_file (str): Đường dẫn đến file config
        """
        self.config = self.load_config(config_file)
        self.server_socket = None
        self.running = False
        self.temp_dir = Path(self.config['clamav']['temp_dir'])
        
        # Setup logging
        self.setup_logging()
        
        # Tạo temp directory
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info("ClamAV Agent initialized")
    
    def load_config(self, config_file):
        """Load configuration từ JSON file"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            return config
        except Exception as e:
            print(f"Error loading config: {e}")
            # Default config nếu file không tồn tại
            return {
                "server": {
                    "host": "0.0.0.0",
                    "port": 9999,
                    "max_connections": 5
                },
                "clamav": {
                    "command": "clamscan",
                    "temp_dir": "./temp_files",
                    "timeout": 60
                }
            }
    
    def setup_logging(self):
        """Setup logging system"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('clamav_agent.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('ClamAVAgent')
    
    def test_clamav(self):
        """
        Test xem ClamAV có hoạt động không
        
        Returns:
            bool: True nếu ClamAV OK
        """
        try:
            result = subprocess.run(
                [self.config['clamav']['command'], '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.logger.info(f"ClamAV test OK: {result.stdout.strip().split()[0]}")
                return True
            else:
                self.logger.error("ClamAV test failed")
                return False
                
        except Exception as e:
            self.logger.error(f"ClamAV test error: {e}")
            return False
    
    def scan_file(self, file_path):
        """
        Quét virus cho một file
        
        Args:
            file_path (str): Đường dẫn đến file cần quét
            
        Returns:
            dict: Kết quả scan {status: 'OK'/'INFECTED', message: '...'}
        """
        try:
            self.logger.info(f"Scanning file: {file_path}")
            
            # Chạy clamscan
            cmd = [
                self.config['clamav']['command'],
                '--no-summary',  # Không hiển thị summary
                '--infected',    # Chỉ hiển thị file bị nhiễm
                str(file_path)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config['clamav']['timeout']
            )
            
            # Phân tích kết quả
            if result.returncode == 0:
                # File sạch
                self.logger.info(f"File clean: {file_path}")
                return {
                    'status': 'OK',
                    'message': 'File is clean',
                    'details': result.stdout.strip()
                }
            elif result.returncode == 1:
                # File bị nhiễm virus
                self.logger.warning(f"File infected: {file_path}")
                return {
                    'status': 'INFECTED',
                    'message': 'Virus detected',
                    'details': result.stdout.strip()
                }
            else:
                # Lỗi khác
                self.logger.error(f"Scan error: {result.stderr}")
                return {
                    'status': 'ERROR',
                    'message': 'Scan failed',
                    'details': result.stderr.strip()
                }
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Scan timeout: {file_path}")
            return {
                'status': 'ERROR',
                'message': 'Scan timeout',
                'details': 'Scan took too long'
            }
        except Exception as e:
            self.logger.error(f"Scan exception: {e}")
            return {
                'status': 'ERROR',
                'message': 'Scan failed',
                'details': str(e)
            }
    
    def handle_client(self, client_socket, client_address):
        """
        Xử lý kết nối từ một client
        
        Args:
            client_socket: Socket của client
            client_address: Địa chỉ client
        """
        self.logger.info(f"New client connected: {client_address}")
        
        try:
            # Nhận thông tin về file sẽ được gửi
            # Protocol: 
            # 1. Client gửi: "FILENAME:<tên file>"
            # 2. Agent trả lời: "READY"
            # 3. Client gửi: "SIZE:<kích thước>"
            # 4. Agent trả lời: "READY"
            # 5. Client gửi dữ liệu file
            # 6. Agent quét và trả về kết quả
            
            # Bước 1: Nhận tên file
            filename_msg = client_socket.recv(1024).decode('utf-8')
            if not filename_msg.startswith('FILENAME:'):
                raise ValueError("Invalid protocol: expected FILENAME")
            
            filename = filename_msg[9:]  # Bỏ "FILENAME:"
            self.logger.info(f"Receiving file: {filename}")
            
            # Trả lời READY
            client_socket.send(b'READY')
            
            # Bước 2: Nhận kích thước file
            size_msg = client_socket.recv(1024).decode('utf-8')
            if not size_msg.startswith('SIZE:'):
                raise ValueError("Invalid protocol: expected SIZE")
            
            file_size = int(size_msg[5:])  # Bỏ "SIZE:"
            self.logger.info(f"File size: {file_size} bytes")
            
            # Trả lời READY
            client_socket.send(b'READY')
            
            # Bước 3: Nhận dữ liệu file
            temp_file_path = self.temp_dir / f"scan_{int(time.time())}_{filename}"
            
            with open(temp_file_path, 'wb') as f:
                received = 0
                while received < file_size:
                    chunk = client_socket.recv(min(8192, file_size - received))
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)
            
            self.logger.info(f"File received: {received}/{file_size} bytes")
            
            # Bước 4: Quét virus
            scan_result = self.scan_file(temp_file_path)
            
            # Bước 5: Gửi kết quả về client
            response = json.dumps(scan_result)
            client_socket.send(response.encode('utf-8'))
            
            self.logger.info(f"Scan complete: {scan_result['status']}")
            
            # Xóa file tạm
            try:
                temp_file_path.unlink()
                self.logger.debug(f"Temp file deleted: {temp_file_path}")
            except Exception as e:
                self.logger.warning(f"Could not delete temp file: {e}")
                
        except Exception as e:
            self.logger.error(f"Error handling client {client_address}: {e}")
            try:
                error_response = json.dumps({
                    'status': 'ERROR',
                    'message': 'Server error',
                    'details': str(e)
                })
                client_socket.send(error_response.encode('utf-8'))
            except:
                pass
        finally:
            try:
                client_socket.close()
            except:
                pass
            self.logger.info(f"Client disconnected: {client_address}")
    
    def start(self):
        """Khởi động ClamAV Agent server"""
        if not self.test_clamav():
            self.logger.error("ClamAV test failed. Cannot start server.")
            return False
        
        try:
            # Tạo server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind và listen
            host = self.config['server']['host']
            port = self.config['server']['port']
            
            self.server_socket.bind((host, port))
            self.server_socket.listen(self.config['server']['max_connections'])
            
            self.running = True
            self.logger.info(f"ClamAV Agent started on {host}:{port}")
            
            print(f"🛡️ ClamAV Agent running on {host}:{port}")
            print("Press Ctrl+C to stop")
            
            # Main server loop
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Xử lý client trong thread riêng
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except OSError:
                    # Socket đã đóng
                    if self.running:
                        self.logger.info("Server socket closed")
                    break
                except Exception as e:
                    self.logger.error(f"Server error: {e}")
                    break
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
            return False
    
    def stop(self):
        """Dừng ClamAV Agent server"""
        self.logger.info("Stopping ClamAV Agent...")
        self.running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("ClamAV Agent stopped")


def main():
    """Main function"""
    print("🛡️ Starting ClamAV Agent...")
    
    agent = ClamAVAgent()
    
    try:
        agent.start()
    except KeyboardInterrupt:
        print("\nReceived Ctrl+C, stopping...")
    finally:
        agent.stop()


if __name__ == "__main__":
    main()