try:
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer
except ImportError:
    print("❌ pyftpdlib not installed")
    print("Run: pip install pyftpdlib")
    exit(1)

import os
from pathlib import Path

def setup_ftp_directory():
    """Create and setup FTP directory"""
    ftp_dir = Path("FTPData")
    ftp_dir.mkdir(exist_ok=True)
    
    # Create some test subdirectories
    (ftp_dir / "documents").mkdir(exist_ok=True)
    (ftp_dir / "uploads").mkdir(exist_ok=True)
    
    # Create a test file
    test_file = ftp_dir / "welcome.txt"
    if not test_file.exists():
        with open(test_file, 'w') as f:
            f.write("Welcome to Secure FTP Server!\n")
            f.write("This is a test file.\n")
            f.write("You can download this file to test GET command.\n")
    
    print(f"✅ FTP directory ready: {ftp_dir.absolute()}")
    return ftp_dir

def create_ftp_server():
    """Create and configure FTP server"""
    
    # Setup directory
    ftp_dir = setup_ftp_directory()
    
    # Create authorizer
    authorizer = DummyAuthorizer()
    
    # Add testuser with full permissions
    authorizer.add_user(
        username="testuser",
        password="testpass", 
        homedir=str(ftp_dir.absolute()),
        perm="elradfmwMT"  # All permissions
    )
    
    # Add anonymous user (read-only)
    authorizer.add_anonymous(
        homedir=str(ftp_dir.absolute()),
        perm="elr"  # Read and list only
    )
    
    # Create handler
    handler = FTPHandler
    handler.authorizer = authorizer
    
    # Configure passive ports (for firewall)
    handler.passive_ports = range(50000, 50100)
    
    # Set banner
    handler.banner = "🛡️ Secure FTP Test Server - Ready for virus scanning demo!"
    
    # Enable logging
    handler.log_file = "ftp_server.log"
    
    # Create server
    address = ("0.0.0.0", 2121)
    server = FTPServer(address, handler)
    
    # Server settings
    server.max_cons = 256
    server.max_cons_per_ip = 5
    
    return server

def main():
    """Main function"""
    print("🚀 Starting Simple FTP Server for Secure FTP Project")
    print("=" * 60)
    print("📡 Server: 0.0.0.0:21")
    print("👤 User: testuser / testpass (full access)")
    print("👤 User: anonymous / any@email.com (read-only)")
    print("📁 Directory: ./FTPData")
    print("🔥 Passive ports: 50000-50100")
    print("=" * 60)
    print("✅ Ready for FTP Client testing!")
    print("Press Ctrl+C to stop server")
    print()
    
    try:
        server = create_ftp_server()
        
        # Start server
        print("🟢 FTP Server is running...")
        server.serve_forever()
        
    except PermissionError:
        print("❌ Permission denied to bind port 21")
        print("💡 Try running as Administrator")
        print("💡 Or use different port: python -m pyftpdlib -p 21")
        
    except OSError as e:
        if "Address already in use" in str(e):
            print("❌ Port 21 already in use")
            print("💡 Stop FileZilla Server first")
            print("💡 Or check: netstat -an | findstr :21")
        else:
            print(f"❌ Network error: {e}")
            
    except KeyboardInterrupt:
        print("\n\n👋 FTP Server stopped gracefully")
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()