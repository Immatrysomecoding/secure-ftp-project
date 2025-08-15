#!/usr/bin/env python3
"""
Entry point for Secure FTP Client
Main launcher for the FTP Client with ClamAV integration
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path
current_dir = Path(__file__).parent
src_dir = current_dir / 'src'
sys.path.insert(0, str(src_dir))

def check_environment():
    """Check if environment is properly setup"""
    print("🔍 Checking environment...")
    
    # Check if src directory exists
    if not src_dir.exists():
        print(f"❌ Source directory not found: {src_dir}")
        return False
    
    # Check required files
    required_files = [
        'ftp_client.py',
        'clamav_agent.py', 
        'network_utils.py',
        'ftp_commands.py',
        'config_manager.py'
    ]
    
    missing_files = []
    for file_name in required_files:
        file_path = src_dir / file_name
        if not file_path.exists():
            missing_files.append(file_name)
    
    if missing_files:
        print(f"❌ Missing source files: {missing_files}")
        return False
    
    # Check config directory
    config_dir = current_dir / 'config'
    if not config_dir.exists():
        print("⚠️ Config directory not found, creating...")
        config_dir.mkdir(exist_ok=True)
    
    # Check config files
    client_config = config_dir / 'client_config.json'
    if not client_config.exists():
        print("⚠️ Client config not found, will use defaults")
    
    print("✅ Environment check passed")
    return True

def main():
    """Main launcher function"""
    print("🛡️ Secure FTP Client Launcher")
    print("=" * 40)
    
    # Check environment
    if not check_environment():
        print("\n❌ Environment check failed!")
        print("Please ensure all source files are in src/ directory")
        input("Press Enter to exit...")
        sys.exit(1)
    
    try:
        # Import and run FTP client
        print("🚀 Starting FTP Client...")
        
        from ftp_client import main as ftp_main
        ftp_main()
        
    except ImportError as e:
        print(f"\n❌ Import Error: {e}")
        print("Failed to import FTP client modules")
        print("\nTroubleshooting:")
        print("1. Ensure all .py files are in src/ directory")
        print("2. Check if files have proper Python syntax")
        print("3. Run: python src/ftp_client.py directly")
        input("Press Enter to exit...")
        sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
        sys.exit(0)
        
    except Exception as e:
        print(f"\n❌ Unexpected Error: {e}")
        print("Please check the error and try again")
        input("Press Enter to exit...")
        sys.exit(1)

if __name__ == "__main__":
    main()