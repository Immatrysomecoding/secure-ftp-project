#!/usr/bin/env python3
"""
Test setup cho Secure FTP Project
Chạy để kiểm tra environment
"""

import sys
import socket
import subprocess
import os
import json
from pathlib import Path

def test_python():
    print("🐍 Testing Python...")
    print(f"✓ Python {sys.version}")
    print(f"✓ Platform: {sys.platform}")

def test_modules():
    print("\n📦 Testing required modules...")
    required_modules = [
        'socket', 'subprocess', 'threading', 'os', 
        'glob', 'ftplib', 'argparse', 'json', 'time'
    ]
    
    for module in required_modules:
        try:
            __import__(module)
            print(f"✓ {module}")
        except ImportError:
            print(f"✗ {module} not available")

def test_clamav():
    print("\n🛡️ Testing ClamAV...")
    try:
        # Test clamscan command
        result = subprocess.run(
            ['clamscan', '--version'], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        
        if result.returncode == 0:
            version = result.stdout.strip().split('\n')[0]
            print(f"✓ ClamAV: {version}")
            return True
        else:
            print("✗ ClamAV command failed")
            print("💡 Cần cài ClamAV: https://www.clamav.net/downloads")
            return False
            
    except FileNotFoundError:
        print("✗ ClamAV not found in PATH")
        print("💡 Cần cài ClamAV và add vào PATH")
        return False
    except Exception as e:
        print(f"✗ ClamAV test error: {e}")
        return False

def test_network():
    print("\n🌐 Testing Network...")
    try:
        # Test socket creation
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('localhost', 0))
        port = sock.getsockname()[1]
        print(f"✓ Socket binding successful on port {port}")
        sock.close()
        
        return True
    except Exception as e:
        print(f"✗ Network test failed: {e}")
        return False

def create_project_structure():
    print("\n📁 Creating project structure...")
    
    directories = [
        'src',
        'tests',
        'tests/test_files', 
        'config',
        'temp_files',
        'docs'
    ]
    
    for dir_name in directories:
        Path(dir_name).mkdir(parents=True, exist_ok=True)
        print(f"✓ {dir_name}/")

def create_config_files():
    print("\n⚙️ Creating config files...")
    
    # Client config
    client_config = {
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
            "passive_mode": False,
            "timeout": 30,
            "buffer_size": 8192
        }
    }
    
    # Agent config  
    agent_config = {
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
    
    # Write config files
    with open('config/client_config.json', 'w') as f:
        json.dump(client_config, f, indent=2)
    print("✓ config/client_config.json")
    
    with open('config/agent_config.json', 'w') as f:
        json.dump(agent_config, f, indent=2)
    print("✓ config/agent_config.json")

def create_test_files():
    print("\n📝 Creating test files...")
    
    # Test file sạch
    with open('tests/test_files/clean_file.txt', 'w') as f:
        f.write("This is a clean test file.\nNo virus here!")
    print("✓ tests/test_files/clean_file.txt")
    
    # README
    readme_content = """# Secure FTP Project

## Overview
FTP Client với virus scanning sử dụng ClamAV

## Components
- FTP Client: src/ftp_client.py
- ClamAV Agent: src/clamav_agent.py

## Setup
1. Chạy: python test_setup.py
2. Cài ClamAV nếu cần
3. Setup FTP Server để test

## Usage
python src/ftp_client.py
"""
    
    with open('README.md', 'w') as f:
        f.write(readme_content)
    print("✓ README.md")

def main():
    print("🚀 Secure FTP Project Setup Test")
    print("=" * 50)
    
    test_python()
    test_modules() 
    test_network()
    clamav_ok = test_clamav()
    
    create_project_structure()
    create_config_files()
    create_test_files()
    
    print("\n" + "=" * 50)
    print("📋 Setup Summary:")
    print("✓ Project structure created")
    print("✓ Config files created") 
    print("✓ Python environment OK")
    
    if clamav_ok:
        print("✓ ClamAV ready")
        print("\n🎉 Setup hoàn tất! Sẵn sàng bắt đầu coding.")
    else:
        print("⚠️ ClamAV cần được cài đặt")
        print("\n📖 Next: Cài ClamAV trước khi tiếp tục")
    
    print("\n🔧 VS Code Tips:")
    print("- Nhấn Ctrl+` để mở terminal")
    print("- Nhấn F5 để run/debug")
    print("- Cài Python extension nếu chưa có")

if __name__ == "__main__":
    main()