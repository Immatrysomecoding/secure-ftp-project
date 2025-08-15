import socket

def test_ftp_connection():
    try:
        print("Testing FTP connection...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        print("Connecting to 127.0.0.1:2222...")
        sock.connect(('127.0.0.1', 2222))
        
        print("Connected! Waiting for welcome message...")
        welcome = sock.recv(1024).decode('utf-8')
        print(f"✅ Server response: {welcome.strip()}")
        
        sock.close()
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

if __name__ == "__main__":
    test_ftp_connection()