# 🔦 LANTern - LAN Chat Application

**LANTern** is a lightweight, open-source peer-to-peer chat application designed for secure local network communication without requiring internet connectivity.

![Version](https://img.shields.io/badge/version-1.2.0--beta%20Lumina-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

---

## 🌟 Features

### Core Functionality
- **🔒 End-to-End Encryption** - All messages encrypted with AES-256
- **🌐 P2P Architecture** - No central server, direct peer-to-peer communication
- **📡 Auto Discovery** - Automatically finds other LANTern users on your network
- **💬 Group Chat** - Communicate with everyone on the network
- **🔐 Private Messages** - Dedicated DM windows for one-on-one conversations
- **✅ Message Delivery Confirmation** - See when messages are delivered

### User Interface
- **🎨 Custom Colors** - Choose your own username color (20+ options)
- **🌙 Dark Mode** - Easy on the eyes with persistent setting
- **👥 User List** - See who's online with real-time status
- **⌨️ Typing Indicators** - See when others are typing (no lag!)
- **📜 Scroll Features** - Auto-scroll with unread message counter
- **💾 Chat Export** - Save conversations to text files
- **🔍 Search** - Find messages with Ctrl+F highlighting
- **⌨️ Keyboard Shortcuts** - Quick actions (Ctrl+F/E/D/B/T)
- **✨ Rich Formatting** - **bold**, *italic*, `code`, auto-linked URLs
- **🔔 Notifications** - Desktop notifications for new messages & DMs
- **💾 Remember Settings** - Auto-fill last nickname & color

### Privacy & Security
- **🔑 Room Passwords** - Only users with the correct password can join
- **🤝 Handshake Verification** - Automatic key verification prevents decryption errors
- **⚠️ Password Mismatch Alerts** - Get notified when users try to join with wrong passwords
- **🌍 Public Rooms** - Optional password-free public chat
- **🛡️ Network Isolation** - Messages stay on your local network
- **🚫 No Logging** - No central server means no message history

### Performance
- **⚡ Lightweight** - Minimal resource usage
- **⚠️ Smart Warnings** - Alerts when 20+ users join (P2P performance limit)
- **🔄 Auto Reconnect** - Detects when peers disconnect
- **📡 Adaptive Broadcasting** - Adjusts network frequency based on peer count
- **🔗 Manual IP Connect** - Direct connection when broadcast fails
- **🔧 Developer Mode** - Advanced debugging (config file enabled)

---

## 📦 Installation

### 🚀 Quick Start (Windows - No Python Required)

**Download the standalone executable - no installation needed!**

1. Go to [Releases](https://github.com/GOT-A-AK47/LANTern/releases/latest)
2. Download `LANTern-v1.2.0-beta-Lumina.exe`
3. Double-click to run - that's it! ✨

> **Note:** Windows Defender may show a warning because the app is unsigned. Click "More info" → "Run anyway"

---

### 🐍 Run from Source (Python)

#### Prerequisites
- Python 3.8 or higher
- Windows, macOS, or Linux

#### Step 1: Clone the Repository
```bash
git clone https://github.com/GOT-A-AK47/LANTern.git
cd LANTern
```

#### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

#### Step 3: Run LANTern
```bash
python src/lantern.py
```

---

## 🚀 Usage

### Getting Started

1. **Launch the Application**
   ```bash
   python lantern.py
   ```

2. **Login Screen**
   - Enter your **nickname**
   - Choose a **room password** (or check "Join public room")
   - Select your **username color** from 20 options
   - Click **Join Chat**

3. **Main Chat**
   - Type messages in the input field
   - Press `Enter` or click `Send`
   - See all users in the sidebar
   - Double-click a user to open a private chat window

### Features Guide

#### 💬 Sending Messages
- **Group Chat**: Type in the main window and press Enter
- **Private Messages**: Double-click a username → Opens dedicated DM window
- **Typing Indicator**: Start typing to show others you're composing

#### 🎨 Customization
- **Dark Mode**: Click the 🌙 button in the top bar
- **User Status**: Change between Online/Away/Busy in the dropdown
- **Username Color**: Selected at login, visible to all users

#### 💾 Export Chat
- Click the **💾 Export** button
- Choose save location
- Saves entire chat history as `.txt` file

#### 🔐 Security
- **Encrypted**: All messages use AES-256 encryption
- **Password Protection**: Only users with matching passwords can communicate
- **No Internet Required**: Everything stays on your local network

---

## 🏫 Use Cases

### Education
- **Classroom Communication** - Students can collaborate without external services
- **Computer Labs** - Quick team discussions during lab sessions
- **School Projects** - Share ideas without creating accounts

### Business
- **Office Communication** - Internal team chat without internet dependency
- **Conference Rooms** - Ad-hoc meetings and discussions
- **Secure Environments** - Air-gapped networks requiring local-only communication

### Personal
- **LAN Parties** - Chat with friends while gaming
- **Home Networks** - Family communication within the house
- **Privacy-Focused** - No data leaves your network

---

## ⚙️ Configuration

### Network Settings
- **Default Port**: 5000 (TCP), 5001 (UDP broadcast)
- Ensure your firewall allows these ports for local network traffic

### Room Passwords
- **Private Rooms**: Each password creates a separate encrypted room
- **Public Room**: Uses password `lantern_public_2025`
- Users with different passwords cannot communicate

---

## 🛠️ Technical Details

### Architecture
- **Language**: Python 3
- **GUI**: Tkinter
- **Encryption**: AES-256-CFB
- **Key Derivation**: PBKDF2-HMAC-SHA256 (100,000 iterations)
- **Handshake**: SHA-256 key hash verification
- **Networking**: TCP (messages), UDP (discovery)

### File Structure
```
LANTern/
├── lantern.py          # Main application
├── requirements.txt    # Python dependencies
├── README.md          # This file
├── CHANGELOG.md       # Version history
├── LICENSE            # MIT License
├── CODE_OF_CONDUCT.md # Community guidelines
└── beta_tester/       # Beta test builds
    └── LANTern_Beta.exe
```

---

## 🐛 Troubleshooting

### Can't See Other Users
- Ensure all users are on the same network
- Check firewall settings (allow ports 5000-5001)
- Verify everyone is using the same password

### Password Mismatch Warning
- If you see "⚠️ [user] tried to join with wrong password - access denied"
- This means someone is trying to join with a different password
- This is expected behavior and prevents decryption errors
- All users must use the exact same password to communicate

### Messages Not Sending
- Check network connectivity
- Ensure recipient is still online (watch for disconnect notifications)
- Try closing and reopening DM windows

### Performance Issues
- LANTern works best with **under 20 users**
- For larger groups, consider a client-server architecture instead

---

## 🤝 Contributing

We welcome contributions! Please see our [Code of Conduct](CODE_OF_CONDUCT.md).

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Priorities
- [ ] File sharing support (drag & drop, images)
- [ ] Voice chat integration
- [ ] Mobile app versions
- [ ] Message history/persistence (local storage)
- [ ] Emoji picker
- [ ] Custom themes (beyond dark/light)
- [ ] Message reactions (👍 ❤️ 😂)
- [ ] Message editing/deletion
- [ ] Room management (create/join multiple)
- [ ] User avatars

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Tijn** - *Initial work*

---

## 🙏 Acknowledgments

- Built with Python and Tkinter
- Encryption powered by the `cryptography` library
- Inspired by the need for simple, secure local communication

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/LANTern/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/LANTern/discussions)

---

**Made with 🔦 for secure local communication**
