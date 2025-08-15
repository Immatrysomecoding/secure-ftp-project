#!/usr/bin/env python3
"""
Configuration Manager for Secure FTP Project
Handle configuration loading, validation, and management
"""

import json
import os
from pathlib import Path


class ConfigManager:
    """Configuration management class"""
    
    def __init__(self, config_file=None):
        """
        Initialize config manager
        
        Args:
            config_file (str): Path to config file
        """
        self.config_file = config_file
        self.config = {}
        
        if config_file:
            self.load_config(config_file)
    
    def load_config(self, config_file):
        """
        Load configuration from file
        
        Args:
            config_file (str): Path to config file
        """
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
            
            # Validate config
            self.validate_config()
            
        except FileNotFoundError:
            print(f"Config file not found: {config_file}")
            self.create_default_config(config_file)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON in config file: {e}")
            raise
        except Exception as e:
            print(f"Error loading config: {e}")
            raise
    
    def save_config(self, config_file=None):
        """
        Save configuration to file
        
        Args:
            config_file (str): Path to save config
        """
        if config_file is None:
            config_file = self.config_file
        
        try:
            # Create directory if it doesn't exist
            Path(config_file).parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            
            print(f"Configuration saved to: {config_file}")
            
        except Exception as e:
            print(f"Error saving config: {e}")
            raise
    
    def validate_config(self):
        """Validate configuration structure"""
        required_sections = {
            'ftp_server': ['host', 'port', 'username', 'password'],
            'clamav_agent': ['host', 'port'],
            'client': ['passive_mode', 'timeout', 'buffer_size']
        }
        
        for section, required_keys in required_sections.items():
            if section not in self.config:
                raise ValueError(f"Missing config section: {section}")
            
            for key in required_keys:
                if key not in self.config[section]:
                    raise ValueError(f"Missing config key: {section}.{key}")
        
        # Validate types
        if not isinstance(self.config['ftp_server']['port'], int):
            raise ValueError("ftp_server.port must be integer")
        
        if not isinstance(self.config['clamav_agent']['port'], int):
            raise ValueError("clamav_agent.port must be integer")
        
        if not isinstance(self.config['client']['passive_mode'], bool):
            raise ValueError("client.passive_mode must be boolean")
        
        if not isinstance(self.config['client']['timeout'], int):
            raise ValueError("client.timeout must be integer")
        
        if not isinstance(self.config['client']['buffer_size'], int):
            raise ValueError("client.buffer_size must be integer")
    
    def create_default_config(self, config_file):
        """
        Create default configuration file
        
        Args:
            config_file (str): Path to create config file
        """
        if 'client' in config_file:
            default_config = {
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
        else:  # agent config
            default_config = {
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
        
        self.config = default_config
        self.save_config(config_file)
        print(f"Created default config: {config_file}")
    
    def get(self, key_path, default=None):
        """
        Get configuration value by dot notation
        
        Args:
            key_path (str): Dot notation key path (e.g., 'ftp_server.host')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path, value):
        """
        Set configuration value by dot notation
        
        Args:
            key_path (str): Dot notation key path
            value: Value to set
        """
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to parent
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set value
        config[keys[-1]] = value
    
    def update_from_args(self, args):
        """
        Update configuration from command line arguments
        
        Args:
            args: Parsed command line arguments
        """
        if hasattr(args, 'host') and args.host:
            self.set('ftp_server.host', args.host)
        
        if hasattr(args, 'port') and args.port:
            self.set('ftp_server.port', args.port)
        
        if hasattr(args, 'user') and args.user:
            self.set('ftp_server.username', args.user)
        
        if hasattr(args, 'password') and args.password:
            self.set('ftp_server.password', args.password)
        
        if hasattr(args, 'passive') and args.passive is not None:
            self.set('client.passive_mode', args.passive)
        
        if hasattr(args, 'timeout') and args.timeout:
            self.set('client.timeout', args.timeout)
    
    def interactive_setup(self):
        """Interactive configuration setup"""
        print("🔧 Interactive Configuration Setup")
        print("=" * 40)
        
        # FTP Server settings
        print("\n📡 FTP Server Settings:")
        host = input(f"Host [{self.get('ftp_server.host', '127.0.0.1')}]: ").strip()
        if host:
            self.set('ftp_server.host', host)
        
        port = input(f"Port [{self.get('ftp_server.port', 21)}]: ").strip()
        if port:
            try:
                self.set('ftp_server.port', int(port))
            except ValueError:
                print("Invalid port number, keeping default")
        
        username = input(f"Username [{self.get('ftp_server.username', 'anonymous')}]: ").strip()
        if username:
            self.set('ftp_server.username', username)
        
        if username and username != 'anonymous':
            import getpass
            password = getpass.getpass("Password: ")
            if password:
                self.set('ftp_server.password', password)
        
        # ClamAV Agent settings
        print("\n🛡️ ClamAV Agent Settings:")
        agent_host = input(f"Agent Host [{self.get('clamav_agent.host', '127.0.0.1')}]: ").strip()
        if agent_host:
            self.set('clamav_agent.host', agent_host)
        
        agent_port = input(f"Agent Port [{self.get('clamav_agent.port', 9999)}]: ").strip()
        if agent_port:
            try:
                self.set('clamav_agent.port', int(agent_port))
            except ValueError:
                print("Invalid port number, keeping default")
        
        # Client settings
        print("\n⚙️ Client Settings:")
        passive = input(f"Passive Mode [{self.get('client.passive_mode', False)}] (y/n): ").strip().lower()
        if passive in ['y', 'yes', 'true']:
            self.set('client.passive_mode', True)
        elif passive in ['n', 'no', 'false']:
            self.set('client.passive_mode', False)
        
        timeout = input(f"Timeout [{self.get('client.timeout', 30)}]: ").strip()
        if timeout:
            try:
                self.set('client.timeout', int(timeout))
            except ValueError:
                print("Invalid timeout, keeping default")
        
        print("\n✓ Configuration updated!")
    
    def show_config(self):
        """Display current configuration"""
        print("\n🔧 Current Configuration:")
        print("=" * 30)
        
        print(f"📡 FTP Server:")
        print(f"   Host: {self.get('ftp_server.host')}")
        print(f"   Port: {self.get('ftp_server.port')}")
        print(f"   Username: {self.get('ftp_server.username')}")
        print(f"   Password: {'*' * len(str(self.get('ftp_server.password', '')))}")
        
        print(f"\n🛡️ ClamAV Agent:")
        print(f"   Host: {self.get('clamav_agent.host')}")
        print(f"   Port: {self.get('clamav_agent.port')}")
        
        print(f"\n⚙️ Client:")
        print(f"   Passive Mode: {self.get('client.passive_mode')}")
        print(f"   Timeout: {self.get('client.timeout')}s")
        print(f"   Buffer Size: {self.get('client.buffer_size')} bytes")
        
        print("=" * 30)
    
    def test_config(self):
        """Test configuration connectivity"""
        print("\n🧪 Testing Configuration...")
        
        # Test ClamAV Agent
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((
                self.get('clamav_agent.host'),
                self.get('clamav_agent.port')
            ))
            sock.close()
            
            if result == 0:
                print("✓ ClamAV Agent: Reachable")
            else:
                print("✗ ClamAV Agent: Not reachable")
                
        except Exception as e:
            print(f"✗ ClamAV Agent test error: {e}")
        
        # Test FTP Server
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((
                self.get('ftp_server.host'),
                self.get('ftp_server.port')
            ))
            sock.close()
            
            if result == 0:
                print("✓ FTP Server: Reachable")
            else:
                print("✗ FTP Server: Not reachable")
                
        except Exception as e:
            print(f"✗ FTP Server test error: {e}")


def main():
    """Main function for config management CLI"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Configuration Manager')
    parser.add_argument('--config', default='config/client_config.json',
                       help='Configuration file path')
    parser.add_argument('--setup', action='store_true',
                       help='Run interactive setup')
    parser.add_argument('--show', action='store_true',
                       help='Show current configuration')
    parser.add_argument('--test', action='store_true',
                       help='Test configuration connectivity')
    
    args = parser.parse_args()
    
    # Create config manager
    config_manager = ConfigManager(args.config)
    
    if args.setup:
        config_manager.interactive_setup()
        config_manager.save_config()
    
    if args.show:
        config_manager.show_config()
    
    if args.test:
        config_manager.test_config()
    
    if not any([args.setup, args.show, args.test]):
        config_manager.show_config()


if __name__ == "__main__":
    main()