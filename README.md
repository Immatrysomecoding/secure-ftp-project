# 🛡️ Secure FTP Project

FTP Client with integrated ClamAV virus scanning - Network Programming Assignment

## 📋 Overview

This project implements a secure FTP client that scans all uploaded files for viruses using ClamAV before transferring them to the FTP server. The system consists of three components:

1. **FTP Client** - Custom FTP client with virus scanning integration
2. **ClamAV Agent** - Virus scanning server using ClamAV engine
3. **FTP Server** - Standard FTP server (FileZilla, vsftpd, etc.)

## 🏗️ Architecture

## ✨ Features

### FTP Client Commands

- **File Operations**: `ls`, `cd`, `pwd`, `mkdir`, `rmdir`, `delete`, `rename`
- **Transfer**: `get`, `put`, `mget`, `mput` (with virus scanning)
- **Session**: `open`, `close`, `status`, `passive`, `ascii/binary`
- **Help**: `help`, `?`

### Security Features

- ✅ All uploads scanned by ClamAV before transfer
- ✅ Infected files blocked with warning
- ✅ Socket-based communication between components
- ✅ Support for both Active and Passive FTP modes

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.7+
python --version

# ClamAV
clamscan --version
```
