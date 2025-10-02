# Changelog

All notable changes to LANTern will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0-beta "Lumina"] - 2025-10-02

### Added
- **🔍 Chat Search**: Full-text search with Ctrl+F, highlights all matches in yellow
- **⌨️ Keyboard Shortcuts**:
  - Ctrl+F: Search chat
  - Ctrl+E: Export chat
  - Ctrl+D: Open DM with selected user
  - Ctrl+B: Jump to bottom
  - Ctrl+T: Toggle dark mode
- **✨ Rich Text Formatting**:
  - `**bold**` text support
  - `*italic*` text support
  - `` `code` `` inline code with syntax highlighting
  - Auto-detection and clickable URLs (https://...)
- **🔔 Desktop Notifications**:
  - Cross-platform notifications (Windows/macOS/Linux)
  - Notification for new group messages (when window unfocused)
  - Notification for new DMs (always)
  - Async notification system (non-blocking)
- **💾 Persistent Settings**:
  - Config file at `~/.lantern/config.json`
  - Remember last nickname
  - Remember last color choice
  - Remember dark mode preference
  - Auto-fill login fields
- **🔗 Manual IP Connect**: "Connect IP" button to manually connect to peers when broadcast fails
- **🔧 Developer Mode**: Enable with secret key in config file (`developer_mode_key`)
  - Shows peer IP addresses
  - Shows port and key hash on startup
  - Debug logging for connections
  - Contact developer for activation key

### Changed
- **⚡ Typing Indicator Performance**: Moved to async threads - eliminated 2s input lag
- **📡 Adaptive Broadcasting**: Broadcast interval adjusts based on peer count (5s → 7s → 10s)
- **🌙 Dark Mode**: Now persistent across sessions via config
- **👥 User Warnings**: Added info message at 10+ users, warning at 20+ users

### Fixed
- **Critical: Input Lag**: Fixed 2-second delay when typing caused by synchronous typing indicators
- **Performance**: Typing indicators no longer block UI thread

### Technical Details
- Added `MessageFormatter` class for markdown-style parsing
- Added `Notifications` class for cross-platform desktop notifications
- Added `Config` class for persistent settings management
- Modified `on_typing()` methods to use threading for async sending
- Added `webbrowser` module for URL clicking
- Updated GUI with search dialog and manual IP connect dialog
- Performance optimization: adaptive broadcast intervals based on `len(self.peers)`

---

## [1.1.0-beta] - 2025-10-02

### Added
- **Handshake Verification System**: Peers now verify encryption key compatibility before establishing connection
- **Key Hash Generation**: SHA-256 hash of encryption keys for secure verification without exposing the key
- **Password Mismatch Detection**: System detects and alerts users when someone tries to join with incorrect password
- **Peer Verification Tracking**: New `peer_verified` dictionary tracks which peers have passed handshake verification
- **Key Mismatch Callback**: `on_key_mismatch` callback notifies GUI when password mismatch occurs
- **User Notifications**: System messages alert users when someone is denied access due to wrong password

### Changed
- **Message Handling**: Messages are only accepted from verified peers
- **Peer Discovery**: Key hash is now included in presence broadcasts (UDP)
- **Peer Announcement**: Key hash is now included in direct peer announcements (TCP)
- **Decryption Logic**: Failed decryptions no longer display "[DECRYPTION FAILED]" messages to users

### Fixed
- **Decryption Errors**: Eliminated "DECRYPTION FAILED" messages caused by password mismatches
- **Security Vulnerability**: Prevented peers with different passwords from attempting encrypted communication
- **Race Condition**: Fixed issue where messages could arrive before peer verification was complete

### Technical Details
- Added `Encryption.generate_key_hash()` method for secure key verification
- Modified `LANTernNode._handle_peer()` to verify key hash on announce messages
- Modified `LANTernNode._discover_peers()` to verify key hash on presence broadcasts
- Updated `LANTernNode._broadcast_presence()` to include key hash
- Updated `LANTernNode._announce_to_peer()` to include key hash
- Added verification checks before processing 'message' and 'private_message' types

### Beta Testing
- Created `beta_tester/` directory with standalone executable
- Generated `LANTern_Beta.exe` for Windows testing

---

## [1.0.0] - 2025-10-01

### Initial Release
- End-to-end AES-256 encryption
- Peer-to-peer architecture
- Auto-discovery via UDP broadcasts
- Group chat functionality
- Private messaging with dedicated DM windows
- Message delivery confirmation
- 20+ username color options
- Dark mode support
- Typing indicators
- Chat export to text files
- Room password protection
- Public room option
- Auto-reconnect on peer disconnect
- User status (online/away/busy)
- Unread message counter
- Smart scrolling with "new messages" button
- Performance warnings for 20+ users
