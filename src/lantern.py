#!/usr/bin/env python3
"""
LANTern - Secure P2P LAN Chat Application
Version: 1.2.0-beta Lumina
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import socket
import threading
import json
import time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import uuid
from pathlib import Path
import platform
import subprocess
import re
import webbrowser


class MessageFormatter:
    """Handle message formatting (markdown-style, URLs)"""

    @staticmethod
    def parse_message(text: str) -> list:
        """Parse message into formatted segments
        Returns: [(text, format_type), ...]
        format_type: 'bold', 'italic', 'code', 'url', 'normal'
        """
        segments = []
        pos = 0

        # Combined regex for all formatting
        pattern = r'(\*\*(.+?)\*\*|\*(.+?)\*|`(.+?)`|(https?://[^\s]+))'

        for match in re.finditer(pattern, text):
            # Add normal text before match
            if match.start() > pos:
                segments.append((text[pos:match.start()], 'normal'))

            if match.group(2):  # **bold**
                segments.append((match.group(2), 'bold'))
            elif match.group(3):  # *italic*
                segments.append((match.group(3), 'italic'))
            elif match.group(4):  # `code`
                segments.append((match.group(4), 'code'))
            elif match.group(5):  # URL
                segments.append((match.group(5), 'url'))

            pos = match.end()

        # Add remaining text
        if pos < len(text):
            segments.append((text[pos:], 'normal'))

        return segments if segments else [(text, 'normal')]


class Notifications:
    """Handle desktop notifications cross-platform"""

    @staticmethod
    def show(title: str, message: str):
        """Show desktop notification"""
        try:
            system = platform.system()
            if system == "Windows":
                # Windows 10/11 toast notification
                from subprocess import run
                run([
                    "powershell", "-Command",
                    f"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; "
                    f"[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null; "
                    f"$template = @'<toast><visual><binding template=\"ToastText02\"><text id=\"1\">{title}</text><text id=\"2\">{message}</text></binding></visual></toast>'@; "
                    f"$xml = New-Object Windows.Data.Xml.Dom.XmlDocument; "
                    f"$xml.LoadXml($template); "
                    f"$toast = New-Object Windows.UI.Notifications.ToastNotification($xml); "
                    f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('LANTern').Show($toast);"
                ], shell=True, check=False)
            elif system == "Darwin":  # macOS
                subprocess.run([
                    "osascript", "-e",
                    f'display notification "{message}" with title "LANTern" subtitle "{title}"'
                ], check=False)
            elif system == "Linux":
                # Try notify-send (most Linux distros)
                subprocess.run([
                    "notify-send", title, message, "-a", "LANTern"
                ], check=False)
        except Exception:
            pass  # Silently fail if notifications aren't supported


class Config:
    """Handle configuration and persistent settings"""

    def __init__(self):
        self.config_dir = Path.home() / ".lantern"
        self.config_file = self.config_dir / "config.json"
        self.config_dir.mkdir(exist_ok=True)
        self.settings = self.load_config()

    def load_config(self) -> dict:
        """Load config from file or create default"""
        default_config = {
            "last_nickname": "",
            "last_color": "#1976D2",
            "developer_mode_key": "",  # Set to secret key to enable dev mode
            "notifications_enabled": True,
            "sound_enabled": True,
            "dark_mode": False
        }

        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    loaded = json.load(f)
                    # Merge with defaults for backwards compatibility
                    default_config.update(loaded)
                    return default_config
            except Exception:
                return default_config
        return default_config

    def save_config(self):
        """Save config to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
        except Exception as e:
            print(f"Failed to save config: {e}")

    def get(self, key: str, default=None):
        """Get config value"""
        return self.settings.get(key, default)

    def set(self, key: str, value):
        """Set config value and save"""
        self.settings[key] = value
        self.save_config()

    def is_developer_mode(self) -> bool:
        """Check if developer mode is enabled"""
        # Secret key must match to enable (contact developer for key)
        SECRET_KEY = "lantern_dev_2025"  # Change this for production
        return self.settings.get("developer_mode_key", "") == SECRET_KEY


class Encryption:
    """Handle AES-256 encryption/decryption"""

    @staticmethod
    def generate_key(password: str, salt: bytes) -> bytes:
        """Generate encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    @staticmethod
    def generate_key_hash(key: bytes) -> str:
        """Generate a hash of the key for verification"""
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key)
        return base64.b64encode(digest.finalize()).decode()[:16]

    @staticmethod
    def encrypt(message: str, key: bytes) -> str:
        """Encrypt message with AES-256"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(message.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encrypted).decode()

    @staticmethod
    def decrypt(encrypted_message: str, key: bytes) -> str:
        """Decrypt message"""
        try:
            data = base64.b64decode(encrypted_message)
            iv = data[:16]
            encrypted = data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            return (decryptor.update(encrypted) + decryptor.finalize()).decode()
        except Exception:
            return "[DECRYPTION FAILED]"


class LANTernNode:
    """P2P networking node"""

    def __init__(self, nickname: str, port: int = 5000, user_color: str = "#1976D2"):
        self.nickname = nickname
        self.port = port
        self.user_color = user_color
        self.peers = {}  # {address: nickname}
        self.peer_colors = {}  # {address: color}
        self.peer_last_seen = {}  # {address: timestamp}
        self.peer_verified = {}  # {address: bool} - Track if handshake verified
        self.encryption_key = None
        self.key_hash = None
        self.running = False
        self.server_socket = None

        # Callbacks
        self.on_message = None
        self.on_private_message = None
        self.on_peer_joined = None
        self.on_peer_left = None
        self.on_typing = None
        self.on_message_delivered = None
        self.on_peer_color_update = None
        self.on_key_mismatch = None

    def set_encryption_key(self, password: str):
        """Set encryption key from password"""
        salt = b'lantern_salt_2025'
        self.encryption_key = Encryption.generate_key(password, salt)
        self.key_hash = Encryption.generate_key_hash(self.encryption_key)

    def start(self):
        """Start the P2P node"""
        self.running = True

        # Start listening for connections
        threading.Thread(target=self._listen_for_peers, daemon=True).start()

        # Start peer discovery
        threading.Thread(target=self._discover_peers, daemon=True).start()

        # Start broadcast presence
        threading.Thread(target=self._broadcast_presence, daemon=True).start()

        # Start monitoring for disconnected peers
        threading.Thread(target=self._monitor_peers, daemon=True).start()

    def stop(self):
        """Stop the node"""
        self.running = False
        # Send goodbye to all peers
        self._send_goodbye()
        if self.server_socket:
            self.server_socket.close()

    def _send_goodbye(self):
        """Notify peers we're leaving"""
        goodbye = json.dumps({
            'type': 'goodbye',
            'nickname': self.nickname
        })

        for peer_ip in list(self.peers.keys()):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((peer_ip, self.port))
                sock.send(goodbye.encode())
                sock.close()
            except Exception:
                pass

    def _monitor_peers(self):
        """Monitor peers and detect disconnections"""
        while self.running:
            time.sleep(10)
            current_time = time.time()
            disconnected = []

            for peer_ip, last_seen in list(self.peer_last_seen.items()):
                if current_time - last_seen > 20:  # No presence in 20 seconds
                    disconnected.append(peer_ip)

            for peer_ip in disconnected:
                if peer_ip in self.peers:
                    nickname = self.peers[peer_ip]
                    del self.peers[peer_ip]
                    del self.peer_last_seen[peer_ip]
                    if self.on_peer_left:
                        self.on_peer_left(nickname)

    def _listen_for_peers(self):
        """Listen for incoming peer connections"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind(('', self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)

            while self.running:
                try:
                    conn, addr = self.server_socket.accept()
                    threading.Thread(target=self._handle_peer, args=(conn, addr), daemon=True).start()
                except socket.timeout:
                    continue
        except Exception as e:
            print(f"Error in listen: {e}")

    def _handle_peer(self, conn, addr):
        """Handle incoming peer connection"""
        try:
            data = conn.recv(4096).decode()
            message = json.loads(data)

            if message['type'] == 'announce':
                peer_nick = message['nickname']
                peer_color = message.get('color', '#1976D2')
                peer_key_hash = message.get('key_hash', '')

                # Verify key hash matches
                if peer_key_hash and peer_key_hash != self.key_hash:
                    if self.on_key_mismatch:
                        self.on_key_mismatch(peer_nick)
                    return

                is_new_peer = addr[0] not in self.peers
                self.peers[addr[0]] = peer_nick
                self.peer_colors[addr[0]] = peer_color
                self.peer_last_seen[addr[0]] = time.time()
                self.peer_verified[addr[0]] = True

                if is_new_peer and self.on_peer_joined:
                    self.on_peer_joined(peer_nick)
                if self.on_peer_color_update:
                    self.on_peer_color_update(peer_nick, peer_color)

            elif message['type'] == 'message':
                # Only accept messages from verified peers
                if addr[0] not in self.peer_verified or not self.peer_verified[addr[0]]:
                    return

                # Add peer if not already known
                if addr[0] not in self.peers and 'from' in message:
                    self.peers[addr[0]] = message['from']
                    self.peer_last_seen[addr[0]] = time.time()
                    if self.on_peer_joined:
                        self.on_peer_joined(message['from'])
                elif addr[0] in self.peers:
                    self.peer_last_seen[addr[0]] = time.time()

                encrypted_msg = message['data']
                if self.encryption_key:
                    decrypted = Encryption.decrypt(encrypted_msg, self.encryption_key)
                    if decrypted != "[DECRYPTION FAILED]" and self.on_message:
                        self.on_message(message['from'], decrypted)
                    # Send delivery confirmation
                    if 'msg_id' in message:
                        self._send_delivery_confirmation(addr[0], message['msg_id'])

            elif message['type'] == 'private_message':
                # Only accept messages from verified peers
                if addr[0] not in self.peer_verified or not self.peer_verified[addr[0]]:
                    return

                # Add peer if not already known
                if addr[0] not in self.peers and 'from' in message:
                    self.peers[addr[0]] = message['from']
                    self.peer_last_seen[addr[0]] = time.time()
                    if self.on_peer_joined:
                        self.on_peer_joined(message['from'])
                elif addr[0] in self.peers:
                    self.peer_last_seen[addr[0]] = time.time()

                encrypted_msg = message['data']
                if self.encryption_key:
                    decrypted = Encryption.decrypt(encrypted_msg, self.encryption_key)
                    if decrypted != "[DECRYPTION FAILED]" and self.on_private_message:
                        self.on_private_message(message['from'], decrypted)
                    # Send delivery confirmation
                    if 'msg_id' in message:
                        self._send_delivery_confirmation(addr[0], message['msg_id'])

            elif message['type'] == 'typing':
                # Update last seen
                if addr[0] in self.peers:
                    self.peer_last_seen[addr[0]] = time.time()
                if self.on_typing:
                    self.on_typing(message['from'], message['is_typing'])

            elif message['type'] == 'goodbye':
                peer_nick = message['nickname']
                if addr[0] in self.peers:
                    del self.peers[addr[0]]
                    if addr[0] in self.peer_last_seen:
                        del self.peer_last_seen[addr[0]]
                    if self.on_peer_left:
                        self.on_peer_left(peer_nick)

            elif message['type'] == 'delivery_confirm':
                # Update last seen
                if addr[0] in self.peers:
                    self.peer_last_seen[addr[0]] = time.time()
                if self.on_message_delivered:
                    self.on_message_delivered(message['msg_id'])

        except Exception as e:
            print(f"Error handling peer: {e}")
        finally:
            conn.close()

    def _send_delivery_confirmation(self, peer_ip: str, msg_id: str):
        """Send delivery confirmation to sender"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((peer_ip, self.port))

            confirm = json.dumps({
                'type': 'delivery_confirm',
                'msg_id': msg_id
            })
            sock.send(confirm.encode())
            sock.close()
        except Exception:
            pass

    def _discover_peers(self):
        """Listen for peer broadcasts"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', 5001))
        sock.settimeout(1.0)

        while self.running:
            try:
                data, addr = sock.recvfrom(1024)
                message = json.loads(data.decode())

                # Update last seen for known peers
                if addr[0] in self.peers:
                    self.peer_last_seen[addr[0]] = time.time()

                # Ignore our own broadcasts and already known peers
                if message['type'] == 'presence' and message['nickname'] != self.nickname and addr[0] not in self.peers:
                    peer_nick = message['nickname']
                    peer_color = message.get('color', '#1976D2')
                    peer_key_hash = message.get('key_hash', '')

                    # Verify key hash matches
                    if peer_key_hash and peer_key_hash != self.key_hash:
                        if self.on_key_mismatch:
                            self.on_key_mismatch(peer_nick)
                        continue

                    self.peers[addr[0]] = peer_nick
                    self.peer_colors[addr[0]] = peer_color
                    self.peer_last_seen[addr[0]] = time.time()
                    self.peer_verified[addr[0]] = True

                    if self.on_peer_joined:
                        self.on_peer_joined(peer_nick)
                    if self.on_peer_color_update:
                        self.on_peer_color_update(peer_nick, peer_color)

                    # Send back our presence directly to the new peer
                    self._announce_to_peer(addr[0])
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Discovery error: {e}")

    def _broadcast_presence(self):
        """Broadcast presence to LAN with adaptive interval"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        message = json.dumps({
            'type': 'presence',
            'nickname': self.nickname,
            'color': self.user_color,
            'key_hash': self.key_hash
        })

        while self.running:
            try:
                sock.sendto(message.encode(), ('<broadcast>', 5001))

                # Adaptive interval: slower when more peers (reduce network load)
                peer_count = len(self.peers)
                if peer_count > 15:
                    interval = 10  # 10 seconds with many peers
                elif peer_count > 5:
                    interval = 7   # 7 seconds with moderate peers
                else:
                    interval = 5   # 5 seconds with few peers

                time.sleep(interval)
            except Exception as e:
                print(f"Broadcast error: {e}")

    def _announce_to_peer(self, peer_ip: str):
        """Send direct announce to a specific peer"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((peer_ip, self.port))

            announce = json.dumps({
                'type': 'announce',
                'nickname': self.nickname,
                'color': self.user_color,
                'key_hash': self.key_hash
            })
            sock.send(announce.encode())
            sock.close()
        except Exception as e:
            print(f"Error announcing to {peer_ip}: {e}")

    def connect_to_peer_manually(self, peer_ip: str) -> bool:
        """Manually connect to a peer by IP address"""
        try:
            # Validate IP format
            socket.inet_aton(peer_ip)

            # Announce to peer
            self._announce_to_peer(peer_ip)
            return True
        except Exception as e:
            print(f"Failed to connect to {peer_ip}: {e}")
            return False

    def send_message(self, message: str) -> str:
        """Send encrypted message to all peers. Returns message ID."""
        if not self.encryption_key:
            return ""

        msg_id = str(uuid.uuid4())
        encrypted = Encryption.encrypt(message, self.encryption_key)

        data = json.dumps({
            'type': 'message',
            'from': self.nickname,
            'data': encrypted,
            'msg_id': msg_id
        })

        for peer_ip in list(self.peers.keys()):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((peer_ip, self.port))
                sock.send(data.encode())
                sock.close()
            except Exception as e:
                print(f"Error sending to {peer_ip}: {e}")

        return msg_id

    def send_private_message(self, target_nickname: str, message: str) -> str:
        """Send encrypted private message to specific peer. Returns message ID."""
        if not self.encryption_key:
            return ""

        # Find peer IP by nickname
        target_ip = None
        for ip, nick in self.peers.items():
            if nick == target_nickname:
                target_ip = ip
                break

        if not target_ip:
            return ""

        msg_id = str(uuid.uuid4())
        encrypted = Encryption.encrypt(message, self.encryption_key)

        data = json.dumps({
            'type': 'private_message',
            'from': self.nickname,
            'data': encrypted,
            'msg_id': msg_id
        })

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_ip, self.port))
            sock.send(data.encode())
            sock.close()
        except Exception as e:
            print(f"Error sending private message: {e}")
            return ""

        return msg_id

    def send_typing_indicator(self, is_typing: bool):
        """Send typing indicator to all peers"""
        data = json.dumps({
            'type': 'typing',
            'from': self.nickname,
            'is_typing': is_typing
        })

        for peer_ip in list(self.peers.keys()):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((peer_ip, self.port))
                sock.send(data.encode())
                sock.close()
            except Exception:
                pass


class DMWindow:
    """Separate window for direct messages with a specific user"""

    def __init__(self, parent_gui, target_nickname: str):
        self.parent_gui = parent_gui
        self.target_nickname = target_nickname
        self.pending_messages = {}
        self.typing_timer = None

        # Create new window
        self.window = tk.Toplevel(parent_gui.root)
        self.window.title(f"🔒 DM with {target_nickname}")
        self.window.geometry("500x400")

        # Top bar
        top_frame = tk.Frame(self.window, bg="#9C27B0", height=35)
        top_frame.pack(fill=tk.X)

        tk.Label(top_frame, text=f"💬 Direct Message: {target_nickname}",
                bg="#9C27B0", fg="white", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=10, pady=5)

        # Main content frame
        content_frame = tk.Frame(self.window)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Chat display
        self.chat_display = scrolledtext.ScrolledText(content_frame, wrap=tk.WORD,
                                                       state=tk.DISABLED, font=("Arial", 10))
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Typing indicator label
        self.typing_label = tk.Label(content_frame, text="", font=("Arial", 9, "italic"), fg="gray")
        self.typing_label.pack(anchor=tk.W, padx=5, pady=(0, 0))

        # Message input (fixed at bottom)
        input_frame = tk.Frame(self.window)
        input_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=5)

        self.message_entry = tk.Entry(input_frame, font=("Arial", 11))
        self.message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", lambda e: self.send_dm())
        self.message_entry.bind("<KeyPress>", self.on_typing)
        self.message_entry.bind("<KeyRelease>", self.on_typing)
        self.message_entry.focus()

        tk.Button(input_frame, text="Send", font=("Arial", 10),
                 bg="#9C27B0", fg="white", command=self.send_dm).pack(side=tk.RIGHT)

        # Add welcome message
        self.add_system_message(f"Private chat with {target_nickname}")
        self.add_system_message("Messages are end-to-end encrypted 🔒")

        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_typing(self, event=None):
        """Handle typing indicator"""
        # Cancel previous timer
        if self.typing_timer:
            self.window.after_cancel(self.typing_timer)

        # Send typing indicator asynchronously to avoid blocking UI
        if self.message_entry.get():
            threading.Thread(target=self.parent_gui.node.send_typing_indicator, args=(True,), daemon=True).start()
            # Stop typing after 2 seconds of no typing
            self.typing_timer = self.window.after(2000, lambda: threading.Thread(
                target=self.parent_gui.node.send_typing_indicator, args=(False,), daemon=True).start())
        else:
            threading.Thread(target=self.parent_gui.node.send_typing_indicator, args=(False,), daemon=True).start()

    def add_system_message(self, message: str):
        """Add system message to DM chat"""
        self.chat_display.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.chat_display.insert(tk.END, f"ℹ️  {message}\n", "system")
        self.chat_display.tag_config("system", foreground="gray", font=("Arial", 9, "italic"))
        self.chat_display.tag_config("timestamp", foreground="gray", font=("Arial", 9))
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)

    def display_message(self, sender: str, message: str, msg_id: str = None):
        """Display message in DM window with formatting"""
        self.chat_display.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")

        self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.chat_display.tag_config("timestamp", foreground="gray", font=("Arial", 9))

        # Color based on sender - use parent's color system
        if sender == self.parent_gui.node.nickname or "(You)" in sender:
            display_name = "You"
            color = self.parent_gui.get_user_color(self.parent_gui.node.nickname)
        else:
            display_name = sender
            color = self.parent_gui.get_user_color(sender)

        self.chat_display.insert(tk.END, f"{display_name}: ", f"sender_{sender}")
        self.chat_display.tag_config(f"sender_{sender}", foreground=color, font=("Arial", 10, "bold"))

        # Parse and format message
        segments = MessageFormatter.parse_message(message)
        for text, fmt in segments:
            tag_name = f"dm_msg_{fmt}_{id(text)}"
            self.chat_display.insert(tk.END, text, tag_name)

            # Apply formatting
            if fmt == 'bold':
                self.chat_display.tag_config(tag_name, font=("Arial", 10, "bold"), foreground="black")
            elif fmt == 'italic':
                self.chat_display.tag_config(tag_name, font=("Arial", 10, "italic"), foreground="black")
            elif fmt == 'code':
                self.chat_display.tag_config(tag_name, font=("Courier", 9), background="#f0f0f0", foreground="#c7254e")
            elif fmt == 'url':
                self.chat_display.tag_config(tag_name, foreground="#0066cc", underline=True, font=("Arial", 10))
                self.chat_display.tag_bind(tag_name, "<Button-1>", lambda e, url=text: webbrowser.open(url))
                self.chat_display.tag_bind(tag_name, "<Enter>", lambda e, t=tag_name: self.chat_display.config(cursor="hand2"))
                self.chat_display.tag_bind(tag_name, "<Leave>", lambda e: self.chat_display.config(cursor=""))
            else:
                self.chat_display.tag_config(tag_name, foreground="black")

        # Add delivery status if this is our message
        if msg_id and msg_id in self.pending_messages:
            self.chat_display.insert(tk.END, " ⏳", f"status_{msg_id}")

        self.chat_display.insert(tk.END, "\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)

        # Flash window if not focused
        if not self.window.focus_get():
            self.window.attributes('-topmost', True)
            self.window.attributes('-topmost', False)

    def update_message_status(self, msg_id: str):
        """Update message delivery status"""
        if msg_id in self.pending_messages:
            del self.pending_messages[msg_id]

            self.chat_display.config(state=tk.NORMAL)
            try:
                start = self.chat_display.tag_ranges(f"status_{msg_id}")
                if start:
                    self.chat_display.delete(f"status_{msg_id}.first", f"status_{msg_id}.last")
                    self.chat_display.insert(f"status_{msg_id}.first", " ✓", "delivered")
                    self.chat_display.tag_config("delivered", foreground="green")
            except Exception:
                pass
            self.chat_display.config(state=tk.DISABLED)

    def send_dm(self):
        """Send DM to target user"""
        message = self.message_entry.get().strip()
        if not message:
            return

        msg_id = self.parent_gui.node.send_private_message(self.target_nickname, message)
        if msg_id:
            self.pending_messages[msg_id] = time.time()
            self.display_message(self.parent_gui.node.nickname + " (You)", message, msg_id)
        else:
            messagebox.showerror("Error", "Failed to send message. User may be offline.")

        self.message_entry.delete(0, tk.END)

    def on_close(self):
        """Handle window close"""
        # Remove from parent's DM windows dict
        if self.target_nickname in self.parent_gui.dm_windows:
            del self.parent_gui.dm_windows[self.target_nickname]
        self.window.destroy()


class LANTernGUI:
    """Tkinter GUI for LANTern"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔦 LANTern - LAN Chat")
        self.root.geometry("700x500")

        self.node = None
        self.config = Config()
        self.dark_mode = self.config.get("dark_mode", False)
        self.typing_timer = None
        self.pending_messages = {}  # {msg_id: timestamp}
        self.user_colors = {}  # {nickname: color}
        self.unread_count = 0
        self.is_at_bottom = True
        self.user_status = "online"  # online, away, busy
        self.dm_windows = {}  # {nickname: DMWindow}

        self.setup_login_screen()

    def setup_login_screen(self):
        """Initial login screen"""
        # Expand window for better layout
        self.root.geometry("800x550")

        # Main container
        main_frame = tk.Frame(self.root, padx=30, pady=20)
        main_frame.pack(expand=True, fill=tk.BOTH)

        # Title at top (centered)
        title_frame = tk.Frame(main_frame)
        title_frame.pack(pady=(0, 20))

        tk.Label(title_frame, text="🔦 LANTern", font=("Arial", 28, "bold")).pack()
        tk.Label(title_frame, text="Secure LAN Chat", font=("Arial", 13)).pack(pady=5)

        # Content area - left and right columns
        content_frame = tk.Frame(main_frame)
        content_frame.pack(expand=True, fill=tk.BOTH)

        # LEFT COLUMN - Login details
        left_frame = tk.Frame(content_frame, padx=20)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(left_frame, text="Login Details", font=("Arial", 14, "bold")).pack(anchor=tk.W, pady=(10, 15))

        tk.Label(left_frame, text="Nickname:", font=("Arial", 11)).pack(anchor=tk.W, pady=(10, 5))
        self.nickname_entry = tk.Entry(left_frame, font=("Arial", 11), width=28)
        self.nickname_entry.pack(anchor=tk.W, pady=(0, 15))
        # Pre-fill last nickname
        last_nick = self.config.get("last_nickname", "")
        if last_nick:
            self.nickname_entry.insert(0, last_nick)

        tk.Label(left_frame, text="Room Password:", font=("Arial", 11)).pack(anchor=tk.W, pady=(0, 5))
        self.password_entry = tk.Entry(left_frame, font=("Arial", 11), width=28, show="*")
        self.password_entry.pack(anchor=tk.W, pady=(0, 15))

        # Public room checkbox
        self.public_room_var = tk.BooleanVar()
        public_check = tk.Checkbutton(left_frame, text="Join public room\n(no password needed)",
                                     variable=self.public_room_var, font=("Arial", 10),
                                     command=self.toggle_password_field, justify=tk.LEFT)
        public_check.pack(anchor=tk.W, pady=10)

        # RIGHT COLUMN - Color picker
        right_frame = tk.Frame(content_frame, padx=20)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        tk.Label(right_frame, text="Choose Your Color", font=("Arial", 14, "bold")).pack(pady=(10, 15))

        # Pre-select last color
        last_color = self.config.get("last_color", "#1976D2")
        self.selected_color = tk.StringVar(value=last_color)

        # Expanded color options with names
        self.color_options = [
            ("Blue", "#1976D2"),
            ("Green", "#388E3C"),
            ("Red", "#D32F2F"),
            ("Purple", "#7B1FA2"),
            ("Orange", "#F57C00"),
            ("Cyan", "#0097A7"),
            ("Pink", "#C2185B"),
            ("Brown", "#5D4037"),
            ("Grey", "#455A64"),
            ("Deep Orange", "#E64A19"),
            ("Teal", "#00897B"),
            ("Indigo", "#3949AB"),
            ("Lime", "#689F38"),
            ("Amber", "#FFA000"),
            ("Deep Purple", "#512DA8"),
            ("Light Blue", "#0288D1"),
            ("Yellow", "#F9A825"),
            ("Magenta", "#C2185B"),
            ("Navy", "#1565C0"),
            ("Maroon", "#6D1B7B")
        ]

        # Grid of color buttons with labels
        color_grid = tk.Frame(right_frame)
        color_grid.pack(pady=5)

        self.color_buttons = []
        for i, (name, color) in enumerate(self.color_options):
            row = i // 5
            col = i % 5

            btn_frame = tk.Frame(color_grid)
            btn_frame.grid(row=row, column=col, padx=3, pady=3)

            # Color button
            btn = tk.Button(btn_frame, bg=color, width=3, height=1,
                          command=lambda c=color, n=name: self.select_color(c, n),
                          relief=tk.RAISED, borderwidth=2, cursor="hand2")
            btn.pack()

            # Label with color name
            lbl = tk.Label(btn_frame, text=name, font=("Arial", 7), fg=color)
            lbl.pack()

            self.color_buttons.append(btn)

        # Preview label
        self.color_preview = tk.Label(right_frame, text="Preview: Your name",
                                      font=("Arial", 14, "bold"),
                                      fg=self.selected_color.get())
        self.color_preview.pack(pady=15)

        # JOIN BUTTON - centered at bottom
        button_frame = tk.Frame(main_frame)
        button_frame.pack(pady=20)

        tk.Button(button_frame, text="Join Chat", font=("Arial", 13, "bold"),
                 bg="#4CAF50", fg="white", padx=40, pady=8,
                 command=self.join_chat, cursor="hand2").pack()

    def select_color(self, color: str, name: str):
        """Update selected color when button clicked"""
        self.selected_color.set(color)
        self.color_preview.config(text=f"Preview: Your name ({name})", fg=color)

    def toggle_password_field(self):
        """Enable/disable password field based on public room checkbox"""
        if self.public_room_var.get():
            self.password_entry.config(state=tk.DISABLED)
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, "lantern_public_2025")
        else:
            self.password_entry.config(state=tk.NORMAL)
            self.password_entry.delete(0, tk.END)

    def join_chat(self):
        """Join the chat room"""
        nickname = self.nickname_entry.get().strip()

        # Use public password if checkbox is checked
        if self.public_room_var.get():
            password = "lantern_public_2025"
        else:
            password = self.password_entry.get()

        if not nickname or not password:
            messagebox.showerror("Error", "Please enter nickname and password")
            return

        # Get selected color
        user_color = self.selected_color.get()

        # Save to config
        self.config.set("last_nickname", nickname)
        self.config.set("last_color", user_color)

        # Clear login screen
        for widget in self.root.winfo_children():
            widget.destroy()

        # Setup chat screen
        is_public = self.public_room_var.get()
        self.setup_chat_screen(nickname, password, is_public, user_color)

    def setup_chat_screen(self, nickname: str, password: str, is_public: bool = False, user_color: str = "#1976D2"):
        """Main chat interface"""
        room_type = "Public Room" if is_public else "Private Room"
        self.root.title(f"🔦 LANTern - {nickname} ({room_type})")

        # Store user's chosen color
        self.user_colors[nickname] = user_color

        # Top bar
        self.top_frame = tk.Frame(self.root, bg="#2196F3", height=40)
        self.top_frame.pack(fill=tk.X)

        tk.Label(self.top_frame, text=f"Logged in as: {nickname}",
                bg="#2196F3", fg="white", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=10, pady=5)

        # User count and unread messages
        self.user_count_label = tk.Label(self.top_frame, text="👥 1 user",
                                         bg="#2196F3", fg="white", font=("Arial", 9))
        self.user_count_label.pack(side=tk.RIGHT, padx=10)

        self.unread_label = tk.Label(self.top_frame, text="",
                                     bg="#FF5722", fg="white", font=("Arial", 9, "bold"))

        # Status dropdown
        self.status_var = tk.StringVar(value="online")
        status_menu = tk.OptionMenu(self.top_frame, self.status_var, "online", "away", "busy",
                                    command=self.change_status)
        status_menu.config(bg="#2196F3", fg="white", font=("Arial", 9), highlightthickness=0)
        status_menu.pack(side=tk.RIGHT, padx=5)

        # Search button
        tk.Button(self.top_frame, text="🔍 Search", font=("Arial", 9),
                 command=self.open_search).pack(side=tk.RIGHT, padx=5)

        # Export button
        tk.Button(self.top_frame, text="💾 Export", font=("Arial", 9),
                 command=self.export_chat).pack(side=tk.RIGHT, padx=5)

        # Dark mode toggle
        tk.Button(self.top_frame, text="🌙 Dark Mode", font=("Arial", 9),
                 command=self.toggle_dark_mode).pack(side=tk.RIGHT, padx=5)

        # Main container
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Chat area
        self.chat_frame = tk.Frame(self.main_frame)
        self.chat_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Chat display with scroll button
        chat_container = tk.Frame(self.chat_frame)
        chat_container.pack(fill=tk.BOTH, expand=True)

        self.chat_display = scrolledtext.ScrolledText(chat_container, wrap=tk.WORD,
                                                       state=tk.DISABLED, font=("Arial", 10))
        self.chat_display.pack(fill=tk.BOTH, expand=True)

        # Bind scroll event
        self.chat_display.bind("<MouseWheel>", self.on_scroll)
        self.chat_display.bind("<Button-4>", self.on_scroll)
        self.chat_display.bind("<Button-5>", self.on_scroll)

        # Scroll to bottom button
        self.scroll_button = tk.Button(chat_container, text="⬇ New messages",
                                       font=("Arial", 9), bg="#FF9800", fg="white",
                                       command=self.scroll_to_bottom)
        # Initially hidden
        self.scroll_button_visible = False

        # Typing indicator label
        self.typing_label = tk.Label(self.chat_frame, text="", font=("Arial", 9, "italic"), fg="gray")
        self.typing_label.pack(anchor=tk.W, pady=(2, 0))

        # Message input
        input_frame = tk.Frame(self.chat_frame)
        input_frame.pack(fill=tk.X, pady=(5, 0))

        self.message_entry = tk.Entry(input_frame, font=("Arial", 11))
        self.message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", lambda e: self.send_message())
        self.message_entry.bind("<KeyPress>", self.on_typing)
        self.message_entry.bind("<KeyRelease>", self.on_typing)

        tk.Button(input_frame, text="Send", font=("Arial", 10),
                 bg="#4CAF50", fg="white", command=self.send_message).pack(side=tk.RIGHT)

        # Users panel
        self.users_frame = tk.Frame(self.main_frame, width=150, bg="#f0f0f0")
        self.users_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)
        self.users_frame.pack_propagate(False)

        tk.Label(self.users_frame, text="Online Users", bg="#f0f0f0",
                font=("Arial", 10, "bold")).pack(pady=5)

        self.users_list = tk.Listbox(self.users_frame, font=("Arial", 9))
        self.users_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.users_list.bind("<Double-Button-1>", self.on_user_double_click)

        # Manual connect button
        tk.Button(self.users_frame, text="➕ Connect IP", font=("Arial", 8),
                 bg="#f0f0f0", command=self.connect_manual_ip).pack(pady=5, padx=5, fill=tk.X)

        # Initialize node
        self.node = LANTernNode(nickname, user_color=user_color)
        self.node.set_encryption_key(password)
        self.node.on_message = self.on_message_received
        self.node.on_private_message = self.on_private_message_received
        self.node.on_peer_joined = self.on_peer_joined
        self.node.on_peer_left = self.on_peer_left
        self.node.on_typing = self.on_peer_typing
        self.node.on_message_delivered = self.on_message_delivered
        self.node.on_peer_color_update = self.on_peer_color_update
        self.node.on_key_mismatch = self.on_key_mismatch
        self.node.start()

        # Add self to users
        self.users_list.insert(tk.END, f"{nickname} (You)")

        # Setup keyboard shortcuts
        self.setup_keyboard_shortcuts()

        # Apply saved dark mode setting
        if self.config.get("dark_mode", False):
            self.toggle_dark_mode()

        room_msg = "public room" if is_public else "private room"
        self.add_system_message(f"Connected to LANTern network ({room_msg})")
        self.add_system_message("All messages are end-to-end encrypted 🔒")
        self.add_system_message("Double-click a user to open private chat window")
        self.add_system_message("📋 Shortcuts: Ctrl+F=Search, Ctrl+E=Export, Ctrl+D=DM, Ctrl+B=Bottom")
        self.add_system_message("✨ Formatting: **bold** *italic* `code` URLs auto-link")

        # Developer mode indicator
        if self.config.is_developer_mode():
            self.add_system_message("🔧 Developer Mode: ENABLED")
            self.add_system_message(f"🔧 Debug: Port {self.node.port}, Key hash: {self.node.key_hash}")

        # Check max users
        self.check_max_users()

    def setup_keyboard_shortcuts(self):
        """Setup global keyboard shortcuts"""
        # Export chat
        self.root.bind("<Control-e>", lambda e: self.export_chat())
        self.root.bind("<Control-E>", lambda e: self.export_chat())

        # Open DM with selected user
        self.root.bind("<Control-d>", lambda e: self.open_dm_from_selection())
        self.root.bind("<Control-D>", lambda e: self.open_dm_from_selection())

        # Jump to bottom
        self.root.bind("<Control-b>", lambda e: self.scroll_to_bottom())
        self.root.bind("<Control-B>", lambda e: self.scroll_to_bottom())

        # Toggle dark mode
        self.root.bind("<Control-t>", lambda e: self.toggle_dark_mode())
        self.root.bind("<Control-T>", lambda e: self.toggle_dark_mode())

        # Search in chat
        self.root.bind("<Control-f>", lambda e: self.open_search())
        self.root.bind("<Control-F>", lambda e: self.open_search())

    def open_search(self):
        """Open search dialog"""
        search_term = simpledialog.askstring("Search Chat", "Enter search term:")
        if search_term:
            self.search_in_chat(search_term)

    def search_in_chat(self, term: str):
        """Search for text in chat and highlight results"""
        # Remove previous search tags
        self.chat_display.tag_remove("search", "1.0", tk.END)

        if not term:
            return

        # Search for all occurrences
        start_pos = "1.0"
        match_count = 0

        while True:
            start_pos = self.chat_display.search(term, start_pos, tk.END, nocase=True)
            if not start_pos:
                break

            end_pos = f"{start_pos}+{len(term)}c"
            self.chat_display.tag_add("search", start_pos, end_pos)
            match_count += 1
            start_pos = end_pos

        # Configure search highlight
        self.chat_display.tag_config("search", background="yellow", foreground="black")

        # Scroll to first match
        if match_count > 0:
            self.chat_display.see(self.chat_display.tag_ranges("search")[0])
            self.add_system_message(f"🔍 Found {match_count} match{'es' if match_count != 1 else ''} for '{term}'")
        else:
            messagebox.showinfo("Search", f"No matches found for '{term}'")

    def open_dm_from_selection(self):
        """Open DM window for selected user"""
        selection = self.users_list.curselection()
        if selection:
            self.on_user_double_click(None)

    def connect_manual_ip(self):
        """Manually connect to a peer by IP"""
        ip_address = simpledialog.askstring(
            "Connect to Peer",
            "Enter peer IP address:\n(e.g., 192.168.1.100)",
            parent=self.root
        )

        if ip_address:
            ip_address = ip_address.strip()
            success = self.node.connect_to_peer_manually(ip_address)
            if success:
                self.add_system_message(f"🔗 Attempting connection to {ip_address}...")
            else:
                messagebox.showerror("Connection Error", f"Invalid IP address: {ip_address}")

    def toggle_dark_mode(self):
        """Toggle between light and dark mode"""
        self.dark_mode = not self.dark_mode
        self.config.set("dark_mode", self.dark_mode)

        if self.dark_mode:
            # Dark mode colors
            bg_color = "#1e1e1e"
            fg_color = "#e0e0e0"
            chat_bg = "#2d2d2d"
            users_bg = "#252525"
            top_bg = "#0d47a1"
            msg_color = "#e0e0e0"
        else:
            # Light mode colors
            bg_color = "#ffffff"
            fg_color = "#000000"
            chat_bg = "#ffffff"
            users_bg = "#f0f0f0"
            top_bg = "#2196F3"
            msg_color = "#000000"

        # Update colors
        self.main_frame.config(bg=bg_color)
        self.chat_frame.config(bg=bg_color)
        self.chat_display.config(bg=chat_bg, fg=fg_color, insertbackground=fg_color)
        self.users_frame.config(bg=users_bg)
        self.users_list.config(bg=users_bg, fg=fg_color)
        self.top_frame.config(bg=top_bg)
        self.typing_label.config(bg=bg_color)

        # Update existing message text colors
        self.chat_display.tag_config("message", foreground=msg_color)
        self.chat_display.tag_config("system", foreground="gray")

    def get_user_color(self, nickname: str) -> str:
        """Get user's chosen color or fallback to hash-based color"""
        if nickname not in self.user_colors:
            # Fallback: generate color from hash if not received yet
            colors = ["#1976D2", "#388E3C", "#D32F2F", "#7B1FA2", "#F57C00",
                     "#0097A7", "#C2185B", "#5D4037", "#455A64", "#E64A19"]
            color_index = hash(nickname) % len(colors)
            self.user_colors[nickname] = colors[color_index]
        return self.user_colors[nickname]

    def on_peer_color_update(self, nickname: str, color: str):
        """Update peer's color when received"""
        self.user_colors[nickname] = color

    def on_scroll(self, event=None):
        """Handle scroll event to check if at bottom"""
        # Check if scrolled to bottom
        self.is_at_bottom = self.chat_display.yview()[1] >= 0.99

        # Hide scroll button if at bottom
        if self.is_at_bottom and self.scroll_button_visible:
            self.scroll_button.pack_forget()
            self.scroll_button_visible = False
            self.unread_count = 0
            self.update_unread_label()

    def scroll_to_bottom(self):
        """Scroll chat to bottom"""
        self.chat_display.see(tk.END)
        self.is_at_bottom = True
        self.unread_count = 0
        self.update_unread_label()
        if self.scroll_button_visible:
            self.scroll_button.pack_forget()
            self.scroll_button_visible = False

    def show_scroll_button(self):
        """Show scroll to bottom button"""
        if not self.scroll_button_visible:
            self.scroll_button.pack(side=tk.BOTTOM, pady=5)
            self.scroll_button_visible = True

    def update_unread_label(self):
        """Update unread message count"""
        if self.unread_count > 0:
            self.unread_label.config(text=f" {self.unread_count} new ")
            self.unread_label.pack(side=tk.RIGHT, padx=5)
        else:
            self.unread_label.pack_forget()

    def check_max_users(self):
        """Check if approaching max users for P2P"""
        user_count = self.users_list.size()
        self.user_count_label.config(text=f"👥 {user_count} user{'s' if user_count != 1 else ''}")

        if user_count >= 20:
            self.add_system_message("⚠️ Warning: 20+ users detected. Performance may degrade in P2P mode.")
        elif user_count >= 10:
            self.add_system_message(f"ℹ️ {user_count} users connected. P2P works best with <20 users.")

    def change_status(self, status: str):
        """Change user status"""
        self.user_status = status
        # In future: broadcast status to peers

    def export_chat(self):
        """Export chat history to text file"""
        from tkinter import filedialog
        from datetime import datetime

        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"LANTern_chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )

        if filename:
            try:
                chat_content = self.chat_display.get("1.0", tk.END)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"LANTern Chat Export\n")
                    f.write(f"Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"{'='*50}\n\n")
                    f.write(chat_content)
                messagebox.showinfo("Success", f"Chat exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export chat: {e}")

    def on_typing(self, event=None):
        """Handle typing indicator"""
        # Cancel previous timer
        if self.typing_timer:
            self.root.after_cancel(self.typing_timer)

        # Send typing indicator asynchronously to avoid blocking UI
        if self.message_entry.get():
            threading.Thread(target=self.node.send_typing_indicator, args=(True,), daemon=True).start()
            # Stop typing after 2 seconds of no typing
            self.typing_timer = self.root.after(2000, lambda: threading.Thread(
                target=self.node.send_typing_indicator, args=(False,), daemon=True).start())
        else:
            threading.Thread(target=self.node.send_typing_indicator, args=(False,), daemon=True).start()

    def on_peer_typing(self, nickname: str, is_typing: bool):
        """Handle peer typing notification"""
        self.root.after(0, lambda: self._update_typing_indicator(nickname, is_typing))

    def _update_typing_indicator(self, nickname: str, is_typing: bool):
        """Update typing indicator display"""
        if is_typing:
            self.typing_label.config(text=f"{nickname} is typing...")
        else:
            self.typing_label.config(text="")

    def on_user_double_click(self, event):
        """Handle double-click on user to open DM window"""
        selection = self.users_list.curselection()
        if not selection:
            return

        selected_user = self.users_list.get(selection[0])

        # Don't allow DM to yourself
        if "(You)" in selected_user:
            return

        # Check if DM window already exists
        if selected_user in self.dm_windows:
            # Bring existing window to front
            self.dm_windows[selected_user].window.lift()
            self.dm_windows[selected_user].window.focus()
        else:
            # Create new DM window
            dm_window = DMWindow(self, selected_user)
            self.dm_windows[selected_user] = dm_window

    def add_system_message(self, message: str):
        """Add system message to chat"""
        self.chat_display.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.chat_display.insert(tk.END, f"ℹ️  {message}\n", "system")
        self.chat_display.tag_config("system", foreground="gray", font=("Arial", 9, "italic"))
        self.chat_display.tag_config("timestamp", foreground="gray", font=("Arial", 9))
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)

    def on_message_received(self, sender: str, message: str):
        """Callback for received messages"""
        self.root.after(0, lambda: self._display_message(sender, message))

        # Show notification if enabled and window not focused
        if self.config.get("notifications_enabled", True):
            if not self.root.focus_get():
                threading.Thread(
                    target=Notifications.show,
                    args=(f"Message from {sender}", message[:100]),
                    daemon=True
                ).start()

    def on_private_message_received(self, sender: str, message: str):
        """Callback for received private messages"""
        # Check if DM window exists for this sender
        if sender in self.dm_windows:
            # Display in existing DM window
            self.root.after(0, lambda: self.dm_windows[sender].display_message(sender, message))
        else:
            # Create new DM window and display message
            self.root.after(0, lambda: self._handle_new_dm(sender, message))

        # Show notification for DMs (higher priority)
        if self.config.get("notifications_enabled", True):
            threading.Thread(
                target=Notifications.show,
                args=(f"🔒 DM from {sender}", message[:100]),
                daemon=True
            ).start()

    def _handle_new_dm(self, sender: str, message: str):
        """Handle incoming DM from new sender"""
        # Create DM window
        dm_window = DMWindow(self, sender)
        self.dm_windows[sender] = dm_window
        # Display the message
        dm_window.display_message(sender, message)
        # Show notification in main chat
        self.add_system_message(f"💬 New DM from {sender} - Window opened")

    def _display_message(self, sender: str, message: str, msg_id: str = None):
        """Display message in chat with formatting"""
        # Track if not at bottom for unread counter
        was_at_bottom = self.is_at_bottom

        self.chat_display.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")

        self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")

        # Get user color and apply it
        user_color = self.get_user_color(sender.replace(" (You)", ""))
        self.chat_display.insert(tk.END, f"{sender}: ", f"sender_{sender}")
        self.chat_display.tag_config(f"sender_{sender}", foreground=user_color, font=("Arial", 10, "bold"))

        # Parse and format message
        segments = MessageFormatter.parse_message(message)
        for text, fmt in segments:
            tag_name = f"msg_{fmt}_{id(text)}"
            self.chat_display.insert(tk.END, text, tag_name)

            # Apply formatting
            base_color = "black" if not self.dark_mode else "#e0e0e0"
            if fmt == 'bold':
                self.chat_display.tag_config(tag_name, font=("Arial", 10, "bold"), foreground=base_color)
            elif fmt == 'italic':
                self.chat_display.tag_config(tag_name, font=("Arial", 10, "italic"), foreground=base_color)
            elif fmt == 'code':
                self.chat_display.tag_config(tag_name, font=("Courier", 9), background="#f0f0f0" if not self.dark_mode else "#3a3a3a", foreground="#c7254e" if not self.dark_mode else "#e83e8c")
            elif fmt == 'url':
                self.chat_display.tag_config(tag_name, foreground="#0066cc", underline=True, font=("Arial", 10))
                self.chat_display.tag_bind(tag_name, "<Button-1>", lambda e, url=text: webbrowser.open(url))
                self.chat_display.tag_bind(tag_name, "<Enter>", lambda e, t=tag_name: self.chat_display.config(cursor="hand2"))
                self.chat_display.tag_bind(tag_name, "<Leave>", lambda e: self.chat_display.config(cursor=""))
            else:
                self.chat_display.tag_config(tag_name, foreground=base_color)

        # Add delivery status if this is our message
        if msg_id and msg_id in self.pending_messages:
            self.chat_display.insert(tk.END, " ⏳", f"status_{msg_id}")

        self.chat_display.insert(tk.END, "\n")

        # Only auto-scroll if was at bottom
        if was_at_bottom:
            self.chat_display.see(tk.END)
        else:
            # Show scroll button and increment unread
            if "(You)" not in sender:  # Don't count our own messages
                self.unread_count += 1
                self.update_unread_label()
                self.show_scroll_button()

        self.chat_display.config(state=tk.DISABLED)

    def _display_private_message(self, sender: str, recipient: str, message: str, msg_id: str = None):
        """Display private message in chat"""
        self.chat_display.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")

        self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.chat_display.insert(tk.END, f"🔒 {sender} → {recipient}: ", "private_sender")
        self.chat_display.insert(tk.END, f"{message}", "private_message")

        # Add delivery status if this is our message
        if msg_id and msg_id in self.pending_messages:
            self.chat_display.insert(tk.END, " ⏳", f"status_{msg_id}")

        self.chat_display.insert(tk.END, "\n")

        self.chat_display.tag_config("private_sender", foreground="purple", font=("Arial", 10, "bold"))
        self.chat_display.tag_config("private_message", foreground="purple", font=("Arial", 10, "italic"))
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)

    def on_message_delivered(self, msg_id: str):
        """Handle message delivery confirmation"""
        self.root.after(0, lambda: self._update_message_status(msg_id))

    def _update_message_status(self, msg_id: str):
        """Update message delivery status"""
        # Check main chat pending messages
        if msg_id in self.pending_messages:
            del self.pending_messages[msg_id]

            # Update the checkmark in the chat
            self.chat_display.config(state=tk.NORMAL)

            # Find and update the status tag
            try:
                start = self.chat_display.tag_ranges(f"status_{msg_id}")
                if start:
                    self.chat_display.delete(f"status_{msg_id}.first", f"status_{msg_id}.last")
                    self.chat_display.insert(f"status_{msg_id}.first", " ✓", "delivered")
                    self.chat_display.tag_config("delivered", foreground="green")
            except Exception:
                pass

            self.chat_display.config(state=tk.DISABLED)

        # Check DM windows for pending messages
        for dm_window in self.dm_windows.values():
            if msg_id in dm_window.pending_messages:
                dm_window.update_message_status(msg_id)

    def on_peer_joined(self, nickname: str):
        """Callback when peer joins"""
        self.root.after(0, lambda: self._add_peer(nickname))

    def on_peer_left(self, nickname: str):
        """Callback when peer leaves"""
        self.root.after(0, lambda: self._remove_peer(nickname))

    def _add_peer(self, nickname: str):
        """Add peer to users list"""
        self.users_list.insert(tk.END, nickname)
        self.add_system_message(f"✅ {nickname} joined the chat")

        # Developer mode: show peer IP
        if self.config.is_developer_mode():
            for ip, nick in self.node.peers.items():
                if nick == nickname:
                    self.add_system_message(f"🔧 Debug: {nickname} @ {ip}")
                    break

        self.check_max_users()

    def _remove_peer(self, nickname: str):
        """Remove peer from users list"""
        # Find and remove from listbox
        for i in range(self.users_list.size()):
            if self.users_list.get(i) == nickname:
                self.users_list.delete(i)
                break
        self.add_system_message(f"❌ {nickname} left the chat")
        self.check_max_users()

    def on_key_mismatch(self, nickname: str):
        """Callback when a peer has a different encryption key"""
        self.root.after(0, lambda: self.add_system_message(
            f"⚠️ {nickname} tried to join with wrong password - access denied"))

    def send_message(self):
        """Send message"""
        message = self.message_entry.get().strip()
        if not message:
            return

        msg_id = self.node.send_message(message)

        if msg_id:
            self.pending_messages[msg_id] = time.time()
            # Display own message with pending status
            self._display_message(self.node.nickname + " (You)", message, msg_id)

        self.message_entry.delete(0, tk.END)
        self.node.send_typing_indicator(False)

    def run(self):
        """Start GUI"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def on_closing(self):
        """Handle window close"""
        if self.node:
            self.node.stop()
        self.root.destroy()


if __name__ == "__main__":
    app = LANTernGUI()
    app.run()
