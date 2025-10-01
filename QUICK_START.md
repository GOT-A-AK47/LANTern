# 🚀 Quick Start Guide - LANTern

## For Regular Users (Windows Executable)

### Download & Run
1. Download `LANTern.exe` from the `dist/` folder
2. **Double-click** `LANTern.exe` to launch
3. No installation needed!

### First Time Setup
1. **Enter your nickname**
2. **Choose a room password** (everyone needs the same password to chat)
   - OR check "Join public room" for password-free chat
3. **Pick your color** from the grid
4. Click **Join Chat**

### Usage
- **Send messages**: Type and press Enter
- **Private chat**: Double-click a username
- **Dark mode**: Click 🌙 button
- **Export chat**: Click 💾 Export button

---

## For Developers (Run from Source)

### Prerequisites
- Python 3.8+
- pip

### Installation
```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/LANTern.git
cd LANTern

# Install dependencies
pip install -r requirements.txt

# Run the app
python src/lantern.py
```

### Building Executable
```bash
# Install PyInstaller
pip install pyinstaller

# Build
pyinstaller --onefile --windowed --name LANTern src/lantern.py

# Find executable in dist/LANTern.exe
```

---

## Troubleshooting

### ❓ Can't see other users?
- Make sure everyone is on the **same network**
- Use the **same password**
- Check **firewall settings** (allow ports 5000-5001)

### ❓ Windows Security Warning?
- This is normal for unsigned executables
- Click "More info" → "Run anyway"
- The app is open-source and safe!

### ❓ Messages not sending?
- Check if the other person is still online
- Try closing and reopening the chat window

---

## Network Requirements

- **Local Network** (WiFi/Ethernet)
- **Ports**: 5000 (TCP), 5001 (UDP)
- **No Internet needed**

---

## Tips & Tricks

💡 **Use different passwords** for different groups
💡 **20 users max** for best performance
💡 **Export chats** before closing for a record
💡 **Public room** password is `lantern_public_2025`

---

## Support

- 📖 Full documentation: [README.md](README.md)
- 🐛 Report issues: [GitHub Issues](https://github.com/YOUR_USERNAME/LANTern/issues)
- 💬 Ask questions: [GitHub Discussions](https://github.com/YOUR_USERNAME/LANTern/discussions)

---

**Happy chatting! 🔦**
