#!/usr/bin/env python3
import asyncio
import json
import logging
import os
import platform
import random
import socket
import time
import hashlib
import sqlite3
import struct
import subprocess
import sys
import shutil
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, Dict, List, Optional, Tuple, Callable, Any, Set

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from textual.css.query import NoMatches
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.reactive import reactive
from textual.widgets import Footer, Header, Input, Static
from textual.widgets import Footer, Header, Input, RichLog
from rich.text import Text

import signal
import asyncio

_shutdown_triggered = False 

def install_graceful_shutdown_handlers(app, *, show_ui_notice: bool = True):

    def _ui_notice_threadsafe(msg: str, security: bool) -> None:
        if not show_ui_notice:
            return
        try:
            app.call_from_thread(app.show_status, msg, security=security)
        except Exception:
            pass

    def _shutdown_threadsafe(sig_label: str) -> None:
        global _shutdown_triggered
        if _shutdown_triggered:
            return
        _shutdown_triggered = True
        logger.warning("Initiating graceful shutdown from %s.", sig_label)
        _ui_notice_threadsafe(f"{sig_label} received – shutting down…", True)
        try:
            app.call_from_thread(app.exit)
        except Exception:
            # fallback
            try:
                app.exit()
            except Exception:
                logger.exception("Failed to exit app in signal handler.")

    def _make_handler(sig_label: str):
        def _handler(sig, frame):
            logger.warning("%s received.", sig_label)
            _shutdown_threadsafe(sig_label)
        return _handler

    for sig_name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"):
        if hasattr(signal, sig_name):
            try:
                signal.signal(getattr(signal, sig_name), _make_handler(sig_name))
            except Exception:
                pass

    # Windows: Fn+B / Ctrl+Break
    if hasattr(signal, "SIGBREAK"):
        try:
            signal.signal(signal.SIGBREAK, _make_handler("SIGBREAK"))
        except Exception:
            pass

# Constants
TCP_PORT = 37021
NONCE_SIZE = 12  # Correct for ChaCha20Poly1305
MAX_MESSAGE_SIZE = 4096
REPLAY_CACHE_SIZE = 1000
KEY_ROTATION_INTERVAL = 3600  # Rotate keys every hour
RATE_LIMIT_WINDOW = 10  # 10 seconds
RATE_LIMIT_COUNT = 20  # Max 20 messages per window
HANDSHAKE_TIMEOUT = 90 
HANDSHAKE_DELAYS = (8, 12, 16)   
MAX_CONNECT_RETRIES = len(HANDSHAKE_DELAYS)
SHOW_SENSITIVE = False      
PROTOCOL_VERSION = 1  # Added protocol version constant

# Flood / Rate-limit UI behavior
RATE_LIMIT_ALERT_INTERVAL = 5   
RATE_LIMIT_DROP_THRESHOLD = 200    
RATE_LIMIT_SILENT = False          

# New TOFU database path
TOFU_DB_PATH = "peer_fingerprints.db"

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename="p2pchat.log",
    filemode="a",
    force=True,
)

logger = logging.getLogger("p2pchat")
logger.setLevel(logging.WARNING)
logger.propagate = False

# Tor configuration
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
TOR_DATA_DIR = "tordata"
TOR_SERVICE_DIR = os.path.join(TOR_DATA_DIR, "hidden_service")
TOR_HOSTNAME_FILE = os.path.join(TOR_SERVICE_DIR, "hostname")

class PeerDatabase:
    """TOFU database for storing peer fingerprints"""
    def __init__(self, db_path: str = TOFU_DB_PATH):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._create_table()
        # Set secure permissions
        os.chmod(db_path, 0o600)

    def _create_table(self):
        with self.conn:
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS peers (
                onion_address TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL
            )
            """)

    def get_fingerprint(self, onion_address: str) -> Optional[str]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT fingerprint FROM peers WHERE onion_address = ?", (onion_address,))
        row = cursor.fetchone()
        return row[0] if row else None

    def save_fingerprint(self, onion_address: str, fingerprint: str):
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO peers (onion_address, fingerprint) VALUES (?, ?)",
                (onion_address, fingerprint)
            )

    def close(self):
        self.conn.close()

@dataclass
class Peer:
    onion_address: str  # Peer's .onion address
    identity_key: Ed25519PublicKey  # Long-term identity key
    nickname: str
    color: str
    writer: Optional[asyncio.StreamWriter] = None
    sent_messages: int = 0
    received_messages: int = 0
    last_seen: float = field(default_factory=time.time)
    fingerprint: str = ""  # Identity key fingerprint
    session_start: float = field(default_factory=time.time)
    session_ephemeral_key: Optional[X25519PublicKey] = None  # Current session key

@dataclass
class SecureSession:
    cipher: ChaCha20Poly1305
    nonce_prefix: bytes  # 4-byte random prefix for nonce
    created_at: float = field(default_factory=time.time)
    key_expiry: float = field(default_factory=lambda: time.time() + KEY_ROTATION_INTERVAL)
    nonce_counter: int = 0  # For structured nonces
    last_nonce_time: float = field(default_factory=time.time)

@dataclass
class ChatMessage:
    content: str
    sender: str
    color: str
    timestamp: float = field(default_factory=time.time)
    ttl: float = 300  # 5 minutes default TTL
    message_id: str = field(default_factory=lambda: os.urandom(16).hex())

    def is_expired(self) -> bool:
        return time.time() - self.timestamp > self.ttl

class ReplayCache:
    """Persistent replay attack protection using SQLite with automatic expiry"""
    def __init__(self, db_path: str = "replay_cache.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._create_table()
        # Set secure permissions
        os.chmod(db_path, 0o600)
        # In-memory cache for quick lookups
        self.cache: Set[bytes] = set()
        self._load_cache()

    def _create_table(self):
        with self.conn:
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS nonces (
                nonce BLOB PRIMARY KEY,
                timestamp REAL
            )
            """)
            # Create index for faster cleanup
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON nonces(timestamp)")
            # Table for tracking message IDs to prevent broadcast loops
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS message_ids (
                message_id TEXT PRIMARY KEY,
                timestamp REAL
            )
            """)
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_msg_timestamp ON message_ids(timestamp)")

    def _load_cache(self):
        """Load recent nonces into memory"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT nonce FROM nonces WHERE timestamp > ?", 
                       (time.time() - 86400,))  # Last 24 hours
        self.cache = {row[0] for row in cursor.fetchall()}
        # Load recent message IDs
        cursor.execute("SELECT message_id FROM message_ids WHERE timestamp > ?",
                      (time.time() - 300,))  # Last 5 minutes
        self.message_ids = {row[0] for row in cursor.fetchall()}

    def add_nonce(self, nonce: bytes):
        """Add nonce to cache with timestamp"""
        if nonce in self.cache:
            return False

        self.cache.add(nonce)
        with self.conn:
            self.conn.execute("INSERT OR IGNORE INTO nonces (nonce, timestamp) VALUES (?, ?)",
                              (nonce, time.time()))
        return True

    def check_nonce(self, nonce: bytes) -> bool:
        """Check if nonce exists in cache"""
        return nonce in self.cache

    def add_message_id(self, message_id: str):
        """Add message ID to prevent broadcast loops"""
        if message_id in self.message_ids:
            return False

        self.message_ids.add(message_id)
        with self.conn:
            self.conn.execute("INSERT OR IGNORE INTO message_ids (message_id, timestamp) VALUES (?, ?)",
                              (message_id, time.time()))
        return True

    def check_message_id(self, message_id: str) -> bool:
        """Check if message ID exists in cache"""
        return message_id in self.message_ids

    def cleanup(self):
        """Remove expired nonces (older than 24 hours) and message IDs (older than 5 min)"""
        expiry_time = time.time() - 86400
        msg_expiry_time = time.time() - 300
        with self.conn:
            self.conn.execute("DELETE FROM nonces WHERE timestamp < ?", (expiry_time,))
            self.conn.execute("DELETE FROM message_ids WHERE timestamp < ?", (msg_expiry_time,))
        # Also clean in-memory cache
        self._load_cache()

    def close(self):
        self.conn.close()

class IdentityManager:
    """Manages long-term cryptographic identity"""
    def __init__(self):
        self.identity_key = self._generate_or_load_identity()
        
    def _generate_or_load_identity(self) -> Ed25519PrivateKey:
        """Load or generate Ed25519 identity key"""
        key_file = "identity.key"
        if os.path.exists(key_file):
            try:
                with open(key_file, "rb") as f:
                    return Ed25519PrivateKey.from_private_bytes(f.read())
            except Exception:
                logger.warning("Invalid identity file, generating new key")
                
        # Generate new identity
        new_key = Ed25519PrivateKey.generate()
        with open(key_file, "wb") as f:
            f.write(new_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ))
        return new_key
        
    def get_public_bytes(self) -> bytes:
        """Get public key bytes for sharing"""
        return self.identity_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
    def sign(self, data: bytes) -> bytes:
        """Sign data with identity key"""
        return self.identity_key.sign(data)

class TorManager:
    """Manages Tor process and hidden service"""
    def __init__(self):
        self.process = None
        self.onion_address = None
        self.tor_executable = self.find_tor()
        
    def find_tor(self) -> str:
        """Locate Tor executable"""
        # First check if tor is in the current directory
        if platform.system() == "Windows":
            local_tor = "tor.exe"
        else:
            local_tor = "tor"
            
        if os.path.exists(local_tor):
            return os.path.abspath(local_tor)
            
        # Check system PATH
        tor_path = shutil.which("tor")
        if tor_path:
            return tor_path
            
        raise FileNotFoundError("Tor executable not found. Please install Tor or place it in the application directory.")
        
    def start_tor(self) -> str:
        """Start Tor process and configure hidden service (synchronous)"""
        # Create data directory if not exists
        os.makedirs(TOR_DATA_DIR, exist_ok=True)
        os.makedirs(TOR_SERVICE_DIR, exist_ok=True)
        
        torrc_content = f"""
        SocksPort {TOR_SOCKS_PORT}
        ControlPort {TOR_CONTROL_PORT}
        DataDirectory {TOR_DATA_DIR}
        HiddenServiceDir {TOR_SERVICE_DIR}
        HiddenServicePort {TCP_PORT} 127.0.0.1:{TCP_PORT}
        """ 
        torrc_path = os.path.join(TOR_DATA_DIR, "torrc")
        with open(torrc_path, "w") as f:
            f.write(torrc_content)
            
        # Start Tor process
        self.process = subprocess.Popen(
            [self.tor_executable, "-f", torrc_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for hidden service to be created
        logger.info("Waiting for Tor to start and create hidden service...")
        for _ in range(30):  # Wait up to 30 seconds
            if os.path.exists(TOR_HOSTNAME_FILE):
                with open(TOR_HOSTNAME_FILE, "r") as f:
                    self.onion_address = f.read().strip()
                logger.info(f"Tor hidden service created: {self.onion_address}")
                return self.onion_address
            time.sleep(1)
            
        raise RuntimeError("Failed to create Tor hidden service")
        
    def stop_tor(self):
        """Stop Tor process"""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None

class Socks5Connection:
    ERROR_MAP = {
        0x01: "General SOCKS server failure",
        0x02: "Connection not allowed by ruleset",
        0x03: "Network unreachable",
        0x04: "Host unreachable",
        0x05: "Connection refused by destination",
        0x06: "TTL expired",
        0x07: "Command not supported",
        0x08: "Address type not supported",
    }

    @staticmethod
    async def open_connection(
        host: str,
        port: int,
        proxy_host: str = "127.0.0.1",
        proxy_port: int = TOR_SOCKS_PORT,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

        writer.write(b"\x05\x01\x00")          # VER=5, NMETHODS=1, METHODS=[0x00]
        await writer.drain()
        if await reader.readexactly(2) != b"\x05\x00":
            writer.close()
            await writer.wait_closed()
            raise ConnectionError("SOCKS5 negotiation failed (auth)")

        host_bytes: bytes
        atyp: int
        try:
            socket.inet_aton(host)
            atyp = 0x01  # IPv4
            host_bytes = socket.inet_aton(host)
        except OSError:
            try:
                # IPv6
                socket.inet_pton(socket.AF_INET6, host)
                atyp = 0x04
                host_bytes = socket.inet_pton(socket.AF_INET6, host)
            except OSError:
                atyp = 0x03
                host_bytes = host.encode("idna")
                if len(host_bytes) > 255:
                    raise ValueError("Hostname too long for SOCKS5")

        req = bytearray([0x05, 0x01, 0x00, atyp])  # VER, CMD=CONNECT, RSV
        if atyp == 0x03:
            req.append(len(host_bytes))
        req.extend(host_bytes)
        req.extend(struct.pack(">H", port))
        writer.write(req)
        await writer.drain()

        ver, rep, _, rep_atyp = await reader.readexactly(4)
        if ver != 0x05:
            writer.close()
            await writer.wait_closed()
            raise ConnectionError("Invalid SOCKS5 version in reply")

        if rep != 0x00:
            reason = Socks5Connection.ERROR_MAP.get(rep, f"Unknown error 0x{rep:02x}")
            writer.close()
            await writer.wait_closed()
            raise ConnectionError(f"SOCKS5 connect failed: {reason}")

        if rep_atyp == 0x01:      
            await reader.readexactly(4 + 2)
        elif rep_atyp == 0x04:    
            await reader.readexactly(16 + 2)
        elif rep_atyp == 0x03:    
            dom_len = await reader.readexactly(1)
            await reader.readexactly(dom_len[0] + 2)
        else:
            writer.close()
            await writer.wait_closed()
            raise ConnectionError("SOCKS5 gave unsupported ATYP")

        return reader, writer

class P2PChatCore:
    def __init__(self, ui_callback: Callable[[str, Any], None] = None):
        self.nickname = self.generate_nickname()
        self.color = self.random_color()
        self.identity = IdentityManager()
        self.identity_pubkey = self.identity.get_public_bytes()
        self.tor = TorManager()
        self.peer_db = PeerDatabase()  # TOFU database
        
        self.peers: Dict[str, Peer] = {}  # Keyed by onion address
        self.sessions: Dict[str, SecureSession] = {}  # Keyed by onion address
        self.messages: List[ChatMessage] = []
        
        self.tcp_server = None
        self.running = False
        self.ui_callback = ui_callback
        self.replay_cache = ReplayCache()
        
        self.stats = {
            "sent": 0,
            "received": 0,
            "replayed": 0,
            "invalid": 0,
            "signature_fail": 0,
            "rate_limited": 0,
            "forwarded": 0,
            "loop_detected": 0,
            "tofu_warnings": 0  # Track TOFU warnings
        }
        
        # For key rotation
        self.key_rotation_task = None
        # Rate limiting structures
        self.rate_limit_windows: Dict[str, Deque[float]] = defaultdict(deque)
        self.rate_limit_lock = asyncio.Lock()
        self.rate_limit_alert_state: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"last_alert": 0.0, "dropped": 0}
        )

    def generate_nickname(self) -> str:
        """Generate random animal-themed nickname with length limit"""
        adjectives = ["swift", "clever", "silent", "mystic", "golden", "crimson"]
        animals = ["fox", "wolf", "eagle", "bear", "raven", "lion"]
        nickname = f"{random.choice(adjectives)}-{random.choice(animals)}"
        return nickname[:32]  # Enforce nickname length limit

    def random_color(self) -> str:
        """Generate random rich-compatible color"""
        colors = ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]
        return f"bold {random.choice(colors)}"

    def notify_ui(self, event: str, data: Any = None):
        """Send event to UI layer"""
        if self.ui_callback:
            self.ui_callback(event, data)

    def generate_fingerprint(self, key: bytes) -> str:
        """Generate human-readable fingerprint for key verification"""
        return hashlib.sha256(key).hexdigest()[:12].upper()

    async def start_tcp_server(self):
        """Start TCP listener for incoming connections"""
        self.tcp_server = await asyncio.start_server(
            self.handle_connection,
            "127.0.0.1", 
            TCP_PORT,
            reuse_address=True
        )
        logger.info(f"TCP server started on port {TCP_PORT}")
        self.notify_ui("status", f"Listening on 127.0.0.1:{TCP_PORT}")

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming TCP connection with robust handshake and authentication."""
        addr = writer.get_extra_info('peername')
        logger.info(f"New connection from {addr}")

        peer_onion_address: Optional[str] = None

        try:
            ephemeral_private = X25519PrivateKey.generate()
            ephemeral_public = ephemeral_private.public_key()
            ephemeral_public_bytes = ephemeral_public.public_bytes_raw()

            data_to_sign = ephemeral_public_bytes + self.tor.onion_address.encode()
            signature = self.identity.sign(data_to_sign)

            our_key_msg = json.dumps({
                "type": "handshake",
                "version": PROTOCOL_VERSION,
                "identity_pubkey": self.identity_pubkey.hex(),
                "ephemeral_pubkey": ephemeral_public_bytes.hex(),
                "signature": signature.hex(),
                "nickname": self.nickname,
                "onion_address": self.tor.onion_address,
            }).encode() + b"\n"
            writer.write(our_key_msg)
            await writer.drain()

            handshake = await self._do_handshake(reader)
            if handshake is None:
                logger.warning(f"peer at {addr} never completed handshake")
                return

            peer_version = handshake.get("version", 0)
            if peer_version != PROTOCOL_VERSION:
                self.notify_ui("security", f"⚠️ Protocol version mismatch (ours: {PROTOCOL_VERSION}, theirs: {peer_version})")
                logger.warning(f"Protocol version mismatch with {addr}: {peer_version}")
                return

            try:
                peer_identity_pubkey = Ed25519PublicKey.from_public_bytes(
                    bytes.fromhex(handshake["identity_pubkey"])
                )
                peer_ephemeral_pubkey_bytes = bytes.fromhex(handshake["ephemeral_pubkey"])
                peer_signature = bytes.fromhex(handshake["signature"])

                peer_onion_address = handshake.get("onion_address", "").strip().lower()
                if not peer_onion_address.endswith(".onion"):
                    logger.warning(f"Peer sent invalid onion address: {peer_onion_address!r}")
                    return

                data_to_verify = peer_ephemeral_pubkey_bytes + peer_onion_address.encode()
                peer_identity_pubkey.verify(peer_signature, data_to_verify)

                peer_ephemeral_pubkey = X25519PublicKey.from_public_bytes(peer_ephemeral_pubkey_bytes)

            except (KeyError, ValueError, TypeError) as e:
                logger.warning(f"Invalid public key from {addr}: {e}")
                return
            except Exception as e:
                self.stats["signature_fail"] += 1
                logger.warning(f"Signature verification failed for {addr}: {e}")
                return

            if handshake["identity_pubkey"] == self.identity_pubkey.hex():
                logger.info("Ignoring self-connection")
                self.notify_ui("status", "⚠️ Ignored self-connection")
                return

            stored_fingerprint = self.peer_db.get_fingerprint(peer_onion_address)
            current_fingerprint = self.generate_fingerprint(handshake["identity_pubkey"].encode())
            if stored_fingerprint and stored_fingerprint != current_fingerprint:
                self.stats["tofu_warnings"] += 1
                self.notify_ui(
                    "security",
                    f"⚠️ WARNING: Key changed for {peer_onion_address}!\n"
                    f"    Old: {stored_fingerprint}\n"
                    f"    New: {current_fingerprint}"
                )
            self.peer_db.save_fingerprint(peer_onion_address, current_fingerprint)

            shared_key = ephemeral_private.exchange(peer_ephemeral_pubkey)
            derived_key = self.derive_key(
                shared_key,
                self.identity.identity_key.public_key(), 
                peer_identity_pubkey,
                role="responder",
            )

            nonce_prefix = os.urandom(4)
            cipher = ChaCha20Poly1305(derived_key)
            session = SecureSession(cipher, nonce_prefix)

            peer = Peer(
                onion_address=peer_onion_address,
                identity_key=peer_identity_pubkey,
                nickname=handshake.get("nickname", "unknown")[:32],
                color=self.random_color(),
                writer=writer,
                fingerprint=current_fingerprint,
                session_ephemeral_key=peer_ephemeral_pubkey,
            )
            self.peers[peer_onion_address] = peer
            self.sessions[peer_onion_address] = session
            self.notify_ui("peer_update")
            self.notify_ui("security", f"🔑 New peer: {peer.nickname} (Fingerprint: {peer.fingerprint})")

            await self.send_message(f"{peer.nickname} joined the chat", peer_onion_address, is_system=True)

            while self.running:
                try:
                    data = await asyncio.wait_for(reader.readline(), timeout=300.0)
                    if not data:
                        break
                    if len(data) > MAX_MESSAGE_SIZE:
                        logger.warning(f"Message too large from {peer_onion_address}")
                        break
                    await self.handle_encrypted_data(data, peer_onion_address)
                except asyncio.TimeoutError:
                    try:
                        await self.send_message("", peer_onion_address, is_ping=True)
                    except Exception:
                        break
                except (ConnectionResetError, BrokenPipeError):
                    break

        except (ValueError, KeyError) as e:
            logger.error(f"Protocol error with {addr}: {e}")
        except (ConnectionError, asyncio.IncompleteReadError, OSError) as e:
            logger.info(f"Connection closed by {addr}: {e}")
        finally:
            if peer_onion_address:
                await self.cleanup_peer(peer_onion_address)
            else:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass


    def derive_key(self, shared_key: bytes, 
                  local_identity: Ed25519PublicKey, 
                  peer_identity: Ed25519PublicKey,
                  role: str) -> bytes:
        """Derive session key using HKDF with identity binding"""
        # Convert public keys to bytes
        local_pubkey = local_identity.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        peer_pubkey = peer_identity.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Sort keys to ensure consistent ordering
        initiator_pubkey, responder_pubkey = sorted([local_pubkey, peer_pubkey])
        
        # Create HKDF context
        info = b"p2pchat-key-derivation:" + initiator_pubkey + b":" + responder_pubkey
        
        # Derive key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info
        )
        return hkdf.derive(shared_key)

    def generate_nonce(self, onion_address: str) -> bytes:
        """Generate structured nonce: 4-byte prefix + 8-byte counter"""
        session = self.sessions[onion_address]
        # Pack counter (8 bytes)
        nonce_counter = struct.pack(">Q", session.nonce_counter)
        session.nonce_counter += 1
        return session.nonce_prefix + nonce_counter
        
    async def _do_handshake(self, reader: asyncio.StreamReader) -> dict | None:
        for timeout in HANDSHAKE_DELAYS:
            try:
                data = await asyncio.wait_for(reader.readline(), timeout=timeout)
            except asyncio.TimeoutError:
                self.notify_ui("status",
                f"retrying handshake (timeout {timeout}s)")
                continue
                    
            if not data:
                return None

            try:
                # Enforce message size limit
                if len(data) > MAX_MESSAGE_SIZE:
                    logger.warning("Handshake message too large")
                    return None
                    
                msg = json.loads(data.decode())
            except json.JSONDecodeError:
                continue           # ignore garbage line and retry

            if msg.get("type") == "handshake":
                return msg        

        return None

    async def check_rate_limit(self, onion_address: str) -> bool:
        """Check if peer is within rate limits"""
        async with self.rate_limit_lock:
            now = time.time()
            timestamps = self.rate_limit_windows[onion_address]
            
            # Remove expired timestamps (older than window)
            while timestamps and timestamps[0] <= now - RATE_LIMIT_WINDOW:
                timestamps.popleft()
                
            # Check if under limit
            if len(timestamps) < RATE_LIMIT_COUNT:
                timestamps.append(now)
                return True
            return False

    async def broadcast_message(self, message: ChatMessage, exclude_onion: Optional[str] = None):
        """Broadcast message to all connected peers except the sender"""
        for onion_address, peer in list(self.peers.items()):
            # Skip excluded address (usually the original sender)
            if onion_address == exclude_onion:
                continue
                
            # Skip peers without active connection
            if not peer.writer or peer.writer.is_closing():
                continue
                
            try:
                await self._send_chat_message(
                    message.content,
                    onion_address,
                    message_id=message.message_id
                )
                self.stats["forwarded"] += 1
            except Exception as e:
                logger.error(f"Broadcast to {onion_address} failed: {e}")

    async def handle_encrypted_data(self, data: bytes, onion_address: str):
        """Decrypt and process incoming message with replay protection"""
        try:
            packet = json.loads(data.decode())
            nonce = bytes.fromhex(packet["nonce"])
            ciphertext = bytes.fromhex(packet["ciphertext"])
            
            # Validate nonce length
            if len(nonce) != NONCE_SIZE:
                logger.warning(f"Invalid nonce length from {onion_address}")
                return
                
            session = self.sessions.get(onion_address)
            if not session:
                raise ValueError("No session for peer")
            
            # Replay protection using persistent cache
            if self.replay_cache.check_nonce(nonce):
                self.stats["replayed"] += 1
                logger.warning(f"Replayed message from {onion_address}")
                return
                
            # Add to replay cache
            self.replay_cache.add_nonce(nonce)
            
            # Decrypt message
            plaintext = session.cipher.decrypt(nonce, ciphertext, None)
            message = json.loads(plaintext.decode())
            
            # Handle ping messages (keep-alive)
            if message.get("type") == "ping":
                return
                
            # Process message
            if message["type"] == "chat":
                if not await self.check_rate_limit(onion_address):
                    self.stats["rate_limited"] += 1
                    st = self.rate_limit_alert_state[onion_address]
                    st["dropped"] += 1
                    now = time.time()
                    if not RATE_LIMIT_SILENT and (now - st["last_alert"] >= RATE_LIMIT_ALERT_INTERVAL):
                        peer = self.peers.get(onion_address)
                        name = peer.nickname if peer else onion_address
                        dropped = st["dropped"]
                        st["dropped"] = 0       
                        st["last_alert"] = now
                        self.notify_ui("security", f"Flood: Dropped {dropped} message(s) from {name} (rate exceeded)")
                        logger.warning(f"Rate limit flood: dropped {dropped} from {onion_address}")
                    if RATE_LIMIT_DROP_THRESHOLD and self.stats["rate_limited"] >= RATE_LIMIT_DROP_THRESHOLD:
                        peer = self.peers.get(onion_address)
                        who = peer.nickname if peer else onion_address
                        logger.warning(f"Dropping peer {who} after flood threshold.")
                        self.notify_ui("security", f"⛔ Disconnected {who} (Flood)")
                        await self.cleanup_peer(onion_address)
                        
                    return

                ttl = message.get("ttl", 300)
                message_id = message.get("message_id", "")
                
                # Check if we've already seen this message (loop prevention)
                if self.replay_cache.check_message_id(message_id):
                    self.stats["loop_detected"] += 1
                    logger.info(f"Ignoring duplicate message {message_id}")
                    return
                    
                # Add message ID to prevent loops
                self.replay_cache.add_message_id(message_id)
                
                # Create chat message with ID
                chat_msg = ChatMessage(
                    content=message["content"],
                    sender=self.peers[onion_address].nickname,
                    color=self.peers[onion_address].color,
                    ttl=ttl,
                    message_id=message_id
                )
                self.messages.append(chat_msg)
                self.stats["received"] += 1
                self.peers[onion_address].received_messages += 1
                self.notify_ui("new_message", chat_msg)
                
                # Broadcast to other peers
                await self.broadcast_message(chat_msg, exclude_onion=onion_address)
                
            elif message["type"] == "system":
                chat_msg = ChatMessage(
                    content=message["content"],
                    sender="System",
                    color="bold yellow"
                )
                self.messages.append(chat_msg)
                self.notify_ui("new_message", chat_msg)
                
            # Handle key rotation requests
            elif message["type"] == "key_rotation":
                await self.handle_key_rotation(onion_address, message)
                
        except (InvalidTag, ValueError) as e:
            self.stats["invalid"] += 1
            logger.error(f"Decryption failed for {onion_address}: {e}")
        except (KeyError, json.JSONDecodeError) as e:
            logger.error(f"Invalid message format from {onion_address}: {e}")

    async def handle_key_rotation(self, onion_address: str, message: Dict):
        """Perform key rotation for perfect forward secrecy"""
        try:
            peer = self.peers.get(onion_address)
            if not peer:
                return
                
            # Verify signature on new ephemeral key
            new_ephemeral_bytes = bytes.fromhex(message["ephemeral_pubkey"])
            signature = bytes.fromhex(message["signature"])
            data_to_verify = new_ephemeral_bytes + peer.onion_address.encode()
            peer.identity_key.verify(signature, data_to_verify)
            
            # Create new ephemeral key object
            new_ephemeral_key = X25519PublicKey.from_public_bytes(new_ephemeral_bytes)
            
            # Generate our new ephemeral key
            our_new_private = X25519PrivateKey.generate()
            our_new_public = our_new_private.public_key()
            our_new_public_bytes = our_new_public.public_bytes_raw()
            
            # Sign our new key
            data_to_sign = our_new_public_bytes + self.tor.onion_address.encode()
            our_signature = self.identity.sign(data_to_sign)
            
            # Send our new key to peer
            rotation_msg = json.dumps({
                "type": "key_rotation",
                "ephemeral_pubkey": our_new_public_bytes.hex(),
                "signature": our_signature.hex()
            }).encode() + b"\n"
            
            peer.writer.write(rotation_msg)
            await peer.writer.drain()
            
            # Compute new shared secret
            new_shared_key = our_new_private.exchange(new_ephemeral_key)
            derived_key = self.derive_key(
                new_shared_key,
                self.identity.identity_key.public_key(),
                peer.identity_key,
                role="responder" if peer.writer else "initiator"
            )
            
            # Update session with new key
            self.sessions[onion_address].cipher = ChaCha20Poly1305(derived_key)
            self.sessions[onion_address].key_expiry = time.time() + KEY_ROTATION_INTERVAL
            
            # Update peer's ephemeral key
            peer.session_ephemeral_key = new_ephemeral_key
            
            logger.info(f"Key rotation completed for {onion_address}")
            self.notify_ui("security", f"🔄 Rotated keys for {peer.nickname}")
            
        except Exception as e:
            logger.error(f"Key rotation failed for {onion_address}: {e}")
            await self.cleanup_peer(onion_address)

    async def _send_chat_message(self, content: str, onion_address: str, message_id: str):
        """Internal method to send chat message with specified ID"""
        session = self.sessions.get(onion_address)
        if not session:
            logger.error(f"No session for {onion_address}")
            return
            
        peer = self.peers.get(onion_address)
        if not peer or not peer.writer or peer.writer.is_closing():
            logger.error(f"No active connection to {onion_address}")
            await self.cleanup_peer(onion_address)
            return
            
        # Create message payload with message ID
        payload = json.dumps({
            "type": "chat",
            "content": content,
            "timestamp": time.time(),
            "message_id": message_id
        }).encode()
        
        # Generate structured nonce
        nonce = self.generate_nonce(onion_address)
        ciphertext = session.cipher.encrypt(nonce, payload, None)
        
        # Create network packet
        packet = json.dumps({
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }).encode() + b"\n"
        
        try:
            peer.writer.write(packet)
            await peer.writer.drain()
            self.stats["sent"] += 1
            peer.sent_messages += 1
        except (ConnectionError, OSError) as e:
            logger.error(f"Send failed to {onion_address}: {e}")
            await self.cleanup_peer(onion_address)

    async def send_message(self, content: str, onion_address: str, 
                          is_system=False, is_ping=False):
        """Encrypt and send message to peer using stored writer"""
        if not is_system and not is_ping:
            # Create message with unique ID
            chat_msg = ChatMessage(
                content=content,
                sender=self.nickname,
                color=self.color
            )
            # Send to specified peer
            await self._send_chat_message(content, onion_address, chat_msg.message_id)
            
            # Add to local display
            self.messages.append(chat_msg)
            self.notify_ui("new_message", chat_msg)
            
            # Broadcast to all other peers
            await self.broadcast_message(chat_msg, exclude_onion=onion_address)
            return
            
        # Existing code for system/ping messages
        session = self.sessions.get(onion_address)
        if not session:
            logger.error(f"No session for {onion_address}")
            return
            
        peer = self.peers.get(onion_address)
        if not peer or not peer.writer or peer.writer.is_closing():
            logger.error(f"No active connection to {onion_address}")
            await self.cleanup_peer(onion_address)
            return
            
        # Create message payload
        message_type = "system" if is_system else "ping" if is_ping else "chat"
        payload = json.dumps({
            "type": message_type,
            "content": content,
            "timestamp": time.time()
        }).encode()
        
        # Generate structured nonce
        nonce = self.generate_nonce(onion_address)
        ciphertext = session.cipher.encrypt(nonce, payload, None)
        
        # Create network packet
        packet = json.dumps({
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }).encode() + b"\n"
        
        try:
            peer.writer.write(packet)
            await peer.writer.drain()
            if not is_ping:
                self.stats["sent"] += 1
                peer.sent_messages += 1
            
            # For local display (only for actual chat messages)
            if not is_system and not is_ping:
                chat_msg = ChatMessage(
                    content=content,
                    sender=self.nickname,
                    color=self.color
                )
                self.messages.append(chat_msg)
                self.notify_ui("new_message", chat_msg)
        except (ConnectionError, OSError) as e:
            logger.error(f"Send failed to {onion_address}: {e}")
            await self.cleanup_peer(onion_address)

    async def connect_to_peer(self, target: str):
        """Initiate authenticated connection to another peer via Tor"""
        try:
            # Parse target (onion_address:port)
            if ":" in target:
                host, port_str = target.split(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    self.notify_ui("status", "Invalid port number")
                    return
            else:
                host = target
                port = TCP_PORT
                
            # TOFU verification
            stored_fingerprint = self.peer_db.get_fingerprint(host)
            
            if host in self.peers:
                peer = self.peers[host]
                dead = peer.writer is None or peer.writer.is_closing()
                if not dead:
                    try:
                        peer.writer.write(b"")   # Check if connection is alive
                        await peer.writer.drain()
                    except Exception:
                        dead = True
                if dead:
                    await self.cleanup_peer(host)   
                else:
                    self.notify_ui("status", "Already connected to this peer")
                    return

            # Connect via Tor SOCKS5 proxy
            reader, writer = await Socks5Connection.open_connection(host, port)
            
            # Generate ephemeral key for this session
            ephemeral_private = X25519PrivateKey.generate()
            ephemeral_public = ephemeral_private.public_key()
            ephemeral_public_bytes = ephemeral_public.public_bytes_raw()
            
            # Sign ephemeral public key with identity key and include our onion address
            data_to_sign = ephemeral_public_bytes + self.tor.onion_address.encode()
            signature = self.identity.sign(data_to_sign)
            
            # Send handshake
            handshake = json.dumps({
                "type": "handshake",
                "version": PROTOCOL_VERSION,
                "identity_pubkey": self.identity_pubkey.hex(),
                "ephemeral_pubkey": ephemeral_public_bytes.hex(),
                "signature": signature.hex(),
                "nickname": self.nickname,
                "onion_address": self.tor.onion_address
            }).encode() + b"\n"
            
            writer.write(handshake)
            await writer.drain()
            
            response = await self._do_handshake(reader)
            if response is None:
                self.notify_ui("status", "handshake failed after several retries")
                writer.close()
                await writer.wait_closed()
                return

            # Version negotiation
            peer_version = response.get("version", 0)
            if peer_version != PROTOCOL_VERSION:
                self.notify_ui("security", 
                              f"⚠️ Protocol version mismatch (ours: {PROTOCOL_VERSION}, theirs: {peer_version})")
                logger.warning(f"Protocol version mismatch with {host}:{port}: {peer_version}")
                writer.close()
                await writer.wait_closed()
                return

            try:
                # Verify peer's identity
                peer_identity_pubkey = Ed25519PublicKey.from_public_bytes(
                    bytes.fromhex(response["identity_pubkey"])
                )
                
                # Verify ephemeral key signature includes onion address
                peer_ephemeral_pubkey_bytes = bytes.fromhex(response["ephemeral_pubkey"])
                peer_signature = bytes.fromhex(response["signature"])
                peer_onion_address = response.get("onion_address", "")
                data_to_verify = peer_ephemeral_pubkey_bytes + peer_onion_address.encode()
                peer_identity_pubkey.verify(peer_signature, data_to_verify)
                
                peer_ephemeral_pubkey = X25519PublicKey.from_public_bytes(
                    peer_ephemeral_pubkey_bytes
                )
            except (KeyError, ValueError, TypeError) as e:
                logger.warning(f"Invalid public key from {host}:{port}: {e}")
                writer.close()
                await writer.wait_closed()
                self.notify_ui("status", "Invalid public key")
                return
            except Exception as e:
                self.stats["signature_fail"] += 1
                logger.warning(f"Signature verification failed for {host}:{port}: {e}")
                writer.close()
                await writer.wait_closed()
                self.notify_ui("status", "Signature verification failed")
                return
                
            # Skip connection to self
            if response["identity_pubkey"] == self.identity_pubkey.hex():
                logger.info("Ignoring self-connection")
                self.notify_ui("status", "⚠️ Ignored self-connection")
                writer.close()
                await writer.wait_closed()
                return
                
            # TOFU verification
            current_fingerprint = self.generate_fingerprint(response["identity_pubkey"].encode())
            if stored_fingerprint and stored_fingerprint != current_fingerprint:
                self.stats["tofu_warnings"] += 1
                self.notify_ui("security", 
                              f"⚠️ WARNING: Key changed for {host}!\n"
                              f"    Old: {stored_fingerprint}\n"
                              f"    New: {current_fingerprint}")
            
            # Save/update fingerprint in TOFU database
            self.peer_db.save_fingerprint(host, current_fingerprint)
                
            # Derive shared key with HKDF
            shared_key = ephemeral_private.exchange(peer_ephemeral_pubkey)
            derived_key = self.derive_key(
                shared_key,
                self.identity.identity_key.public_key(),
                peer_identity_pubkey,
                role="initiator"
            )
            
            # Create session with derived key and random nonce prefix
            nonce_prefix = os.urandom(4)  # 4-byte random nonce prefix
            cipher = ChaCha20Poly1305(derived_key)
            session = SecureSession(cipher, nonce_prefix)
            
            # Create peer object with identity reference
            peer = Peer(
                onion_address=host,
                identity_key=peer_identity_pubkey,
                nickname=response.get("nickname", "unknown")[:32],  # Enforce nickname length
                color=self.random_color(),
                writer=writer,
                fingerprint=current_fingerprint,
                session_ephemeral_key=peer_ephemeral_pubkey
            )
            
            self.peers[host] = peer
            self.sessions[host] = session
            self.notify_ui("peer_update")
            self.notify_ui("security", f"🔑 Connected to {peer.nickname} (Fingerprint: {peer.fingerprint})")
            
            # Send welcome message
            await self.send_message(
                f"{self.nickname} joined the chat", 
                host,
                is_system=True
            )
            
            # Start message handler
            asyncio.create_task(self._reader_loop(reader, host))

        except (OSError, asyncio.TimeoutError, ConnectionRefusedError) as e:
            logger.error(f"Connection to {target} failed: {e}")
            self.notify_ui("status", f"Connection failed: {e}")
        except (ValueError, KeyError) as e:
            logger.error(f"Handshake failed with {target}: {e}")
            self.notify_ui("status", f"Handshake failed: {e}")

    async def cleanup_peer(self, onion_address: str):
        """Safely remove peer from system"""
        if onion_address in self.peers:
            peer = self.peers.pop(onion_address)
            # Close writer if exists
            if peer.writer and not peer.writer.is_closing():
                try:
                    peer.writer.close()
                    await peer.writer.wait_closed()  # Ensure proper closure
                except Exception:
                    pass
                    
            chat_msg = ChatMessage(
                content=f"{peer.nickname} left the chat",
                sender="System",
                color="bold yellow"
            )
            self.messages.append(chat_msg)
            self.notify_ui("new_message", chat_msg)
            self.notify_ui("status", f"Peer disconnected: {peer.nickname}")
            
        if onion_address in self.sessions:
            del self.sessions[onion_address]
            
        self.notify_ui("peer_update")

    async def cleanup_expired_messages(self):
        """Periodically remove expired messages"""
        while self.running:
            self.messages = [msg for msg in self.messages if not msg.is_expired()]
            await asyncio.sleep(10)

    async def rotate_keys(self):
        """Periodically rotate session keys for perfect forward secrecy"""
        while self.running:
            await asyncio.sleep(KEY_ROTATION_INTERVAL)
            now = time.time()
            for onion_address, session in list(self.sessions.items()):
                if now > session.key_expiry:
                    logger.info(f"Rotating keys for {onion_address}")
                    peer = self.peers.get(onion_address)
                    if not peer or not peer.writer or peer.writer.is_closing():
                        continue
                        
                    try:
                        # Generate new ephemeral key
                        new_ephemeral_private = X25519PrivateKey.generate()
                        new_ephemeral_public = new_ephemeral_private.public_key()
                        new_ephemeral_bytes = new_ephemeral_public.public_bytes_raw()
                        
                        # Sign new key
                        data_to_sign = new_ephemeral_bytes + self.tor.onion_address.encode()
                        signature = self.identity.sign(data_to_sign)
                        
                        # Send key rotation request
                        rotation_msg = json.dumps({
                            "type": "key_rotation",
                            "ephemeral_pubkey": new_ephemeral_bytes.hex(),
                            "signature": signature.hex()
                        }).encode() + b"\n"
                        
                        peer.writer.write(rotation_msg)
                        await peer.writer.drain()
                        
                        # Update our ephemeral key
                        session.key_expiry = time.time() + KEY_ROTATION_INTERVAL
                    except Exception as e:
                        logger.error(f"Key rotation failed for {onion_address}: {e}")
                        await self.cleanup_peer(onion_address)

    async def handle_command(self, command: str):
        """Process user commands securely"""
        parts = command.split()
        if not parts:
            return
            
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd == "connect":
            if len(args) < 1:
                self.notify_ui("status", "Usage: /connect <onion_address>[:port]")
                return
                
            await self.connect_to_peer(args[0])
            
        elif cmd == "peers":
            self.notify_ui("status", "Connected peers:")
            for peer in self.peers.values():
                self.notify_ui("status", f"  {peer.nickname} ({peer.onion_address}) - {peer.fingerprint}")
                
        elif cmd == "stats":
            self.notify_ui("status", "Session statistics:")
            self.notify_ui("status", f"  Messages sent: {self.stats['sent']}")
            self.notify_ui("status", f"  Messages received: {self.stats['received']}")
            self.notify_ui("status", f"  Replayed messages blocked: {self.stats['replayed']}")
            self.notify_ui("status", f"  Invalid messages blocked: {self.stats['invalid']}")
            self.notify_ui("status", f"  Signature failures: {self.stats['signature_fail']}")
            self.notify_ui("status", f"  Messages forwarded: {self.stats['forwarded']}")
            self.notify_ui("status", f"  Rate-limited messages: {self.stats['rate_limited']}")
            self.notify_ui("status", f"  Loop-detected messages: {self.stats['loop_detected']}")
            self.notify_ui("status", f"  TOFU warnings: {self.stats['tofu_warnings']}")
            
        elif cmd == "verify":
            if len(args) < 2:
                self.notify_ui("status", "Usage: /verify <nickname> <fingerprint>")
                return
                
            nickname = args[0]
            fingerprint = args[1].upper()
            
            for peer in self.peers.values():
                if peer.nickname == nickname:
                    if peer.fingerprint == fingerprint:
                        self.notify_ui("security", f"✅ Verified {nickname} ({fingerprint})")
                    else:
                        self.notify_ui("security", f"❌ Mismatch for {nickname} (expected {fingerprint}, got {peer.fingerprint})")
                    return
                    
            self.notify_ui("status", f"Peer not found: {nickname}")
            
        elif cmd == "onion":
            if self.tor.onion_address:
                self.notify_ui("status", f"Your .onion address: {self.tor.onion_address}")
            else:
                self.notify_ui("status", "Onion address not available")
            
        elif cmd == "quit":
            self.running = False
            self.notify_ui("quit")
            
        elif cmd == "help":
            self.notify_ui("status", "Available commands:")
            self.notify_ui("status", "  /connect <onion[:port]> - Connect to peer")
            self.notify_ui("status", "  /peers                 - List connected peers")
            self.notify_ui("status", "  /verify <n> <fp>       - Verify peer fingerprint")
            self.notify_ui("status", "  /stats                 - Show session statistics")
            self.notify_ui("status", "  /onion                 - Show your onion address")
            self.notify_ui("status", "  /copyonion              - copy the address")
            self.notify_ui("status", "  /quit                  - Exit application")
            self.notify_ui("status", "  /help                  - Show this help")

        elif cmd == "copyonion":
            if self.tor.onion_address:
                try:
                    import pyperclip
                    pyperclip.copy(self.tor.onion_address)
                    self.notify_ui("status", " Onion address copied to clipboard!")
                except ImportError:
                    self.notify_ui("status", " pyperclip not installed. Run: pip install pyperclip")
            else:
                self.notify_ui("status", "Onion address not available.")

            
        else:
            self.notify_ui("status", f"Unknown command: {cmd}")
    
    async def _reader_loop(
            self,
            reader: asyncio.StreamReader,
            onion_address: str
            ) -> None:
            try:
                while self.running:
                    try:
                        data = await asyncio.wait_for(reader.readline(), timeout=300.0)
                        if not data:          
                            break
                            
                        # Enforce message size limit
                        if len(data) > MAX_MESSAGE_SIZE:
                            logger.warning(f"Message too large from {onion_address}")
                            break
                            
                        await self.handle_encrypted_data(data, onion_address)
                    except asyncio.TimeoutError:
                        # Send ping to check connection
                        try:
                            await self.send_message("", onion_address, is_ping=True)
                        except Exception:
                            break
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                pass
            finally:
                await self.cleanup_peer(onion_address)

    async def start(self):
        """Start the P2P chat core with all background tasks"""
        self.running = True
        
        # Start Tor in a thread to avoid blocking
        try:
            self.tor.onion_address = await asyncio.to_thread(self.tor.start_tor)
            self.notify_ui("status", f"Tor started. Your .onion address: {self.tor.onion_address}")
        except Exception as e:
            logger.error(f"Failed to start Tor: {e}")
            self.notify_ui("status", f"Tor failed to start: {e}")
            self.running = False
            return
            
        # Start TCP server
        await self.start_tcp_server()
        asyncio.create_task(self.cleanup_expired_messages())
        self.key_rotation_task = asyncio.create_task(self.rotate_keys())

    async def stop(self):
        """Gracefully stop the P2P chat core"""
        self.running = False
        
        # Cancel background tasks
        if self.key_rotation_task:
            self.key_rotation_task.cancel()
        
        # Close all peer connections
        for onion_address in list(self.peers.keys()):
            await self.cleanup_peer(onion_address)
            
        # Close servers
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()
            
        # Clean up databases
        self.replay_cache.cleanup()
        self.replay_cache.close()
        self.peer_db.close()
        
        # Stop Tor
        self.tor.stop_tor()

class ChatLog(RichLog):
    """Widget to display chat messages"""
    def add_message(self, message: ChatMessage):
        """Add a new message to the log"""
        # Create formatted message
        timestamp = datetime.fromtimestamp(message.timestamp).strftime("%H:%M:%S")
        formatted = f"[dim]{timestamp}[/] [{message.color}]{message.sender}[/]: {message.content}"
        
        # Update content
        self.write(Text.from_markup(formatted))

class PeerList(Static):
    """Widget to display peers and stats with security info"""
    def update_data(self, peers: Dict, stats: Dict):
        """Update peer and stat data with security context"""
        content = "[b]Peers:[/b]\n"
        if not peers:
            content += "  No peers connected\n"
        else:
            for peer in peers.values():
                duration = int(time.time() - peer.session_start)
                content += (
                    f"  [{peer.color}]{peer.nickname}[/] @ "
                    f"{peer.onion_address}\n"
                )
                if SHOW_SENSITIVE:
                    content += f"    Fingerprint: {peer.fingerprint}\n"
                content += f"    Duration: {duration}s\n"
        
        content += "\n[b]Stats:[/b]\n"
        content += f"  Sent: {stats.get('sent', 0)}\n"
        content += f"  Received: {stats.get('received', 0)}\n"
        content += f"  Blocked (replay): {stats.get('replayed', 0)}\n"
        content += f"  Blocked (invalid): {stats.get('invalid', 0)}\n"
        content += f"  Signature failures: {stats.get('signature_fail', 0)}\n"
        content += f"  Forwarded: {stats.get('forwarded', 0)}\n"
        content += f"  Rate-limited: {stats.get('rate_limited', 0)}\n"
        content += f"  Loop-detected: {stats.get('loop_detected', 0)}\n"
        content += f"  TOFU warnings: {stats.get('tofu_warnings', 0)}\n"
        
        self.update(content)

class StatusBar(Static):
    """Status bar at the bottom for notifications with security alerts"""
    def set_message(self, text: str, is_security=False):
        """Set status message with security context"""
        prefix = "⚠️ " if is_security else ""
        self.update(f"[{'red' if is_security else 'dim'}]{prefix}{text}")

class ChatApp(App):
    """Main Textual application for P2P chat with Tor hidden services"""
    CSS = """
    #chat-log {
        height: 1fr;
        border: solid $accent;
        padding: 1;
        overflow-y: scroll;
    }
    #peer-list {
        width: 30%;
        border: solid $accent;
        padding: 1;
        background: $panel;
        overflow-y: auto;
    }
    #status-bar {
        height: 1;
        background: $panel;
        padding: 0 1;
    }
    .security {
        color: red;
    }
    """
    
    BINDINGS = [
        ("ctrl+c", "quit", "Quit"),
        ("f1", "help", "Help"),
    ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.chat_core = P2PChatCore(ui_callback=self.handle_core_event)

    def compose(self) -> ComposeResult:
        """Create child widgets for the app"""
        yield Header()
        with Container():
            with Horizontal():
                yield ChatLog(id="chat-log")
                yield PeerList(id="peer-list")
            yield StatusBar(id="status-bar")
            yield Input(placeholder="Type a message or /command...", id="message-input")
        yield Footer()

    async def on_mount(self) -> None:
        self.title = f"SecureP2P Chat - {self.chat_core.nickname}"
        identity_fp = self.chat_core.generate_fingerprint(
            self.chat_core.identity_pubkey
        )
        if SHOW_SENSITIVE:
            self.sub_title = f"Identity: {identity_fp}"
        else:
            self.sub_title = ""
        self.query_one(Input).focus()
        await self.chat_core.start()

    async def on_unmount(self) -> None:
        """Clean up when app is closing"""
        await self.chat_core.stop()

    def handle_core_event(self, event_type: str, data: Any = None):
        try:
            if event_type == "new_message":
                self.query_one(ChatLog).add_message(data)
            elif event_type == "peer_update":
                self.query_one(PeerList).update_data(
                    self.chat_core.peers,
                    self.chat_core.stats,
                )
            elif event_type == "status":
                self.query_one(StatusBar).set_message(data)
            elif event_type == "security":
                self.query_one(StatusBar).set_message(data, is_security=True)
            elif event_type == "quit":
                self.exit()
        except NoMatches:
            pass

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle message input securely"""
        input_widget = event.input
        text = input_widget.value.strip()
        if not text:
            return
        input_widget.value = ""
        
        if text.startswith("/"):
            await self.chat_core.handle_command(text[1:])
        else:
            # Broadcast to all connected peers
            for onion_address in list(self.chat_core.peers.keys()):
                await self.chat_core.send_message(text, onion_address)

    def action_help(self) -> None:
        """Show help information"""
        self.query_one(StatusBar).set_message(
            "Commands: /connect, /peers, /verify, /stats, /onion, /quit , /copyonion , /help"
        )

    def action_quit(self) -> None:
        """Quit the application securely"""
        self.exit()

if __name__ == "__main__":
    app = ChatApp()
    install_graceful_shutdown_handlers(app, show_ui_notice=True)
    try:
        app.run()
    except KeyboardInterrupt:
        logger.warning("KeyboardInterrupt top-level.")

