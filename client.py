import socket
import os
import struct
import subprocess
import secrets
import hashlib
import hmac
import logging
import tempfile
import sys
import time
import asyncio
from datetime import datetime
from typing import Optional, Tuple
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF, PBKDF2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QHBoxLayout,
                            QWidget, QLabel, QStatusBar, QSystemTrayIcon, QMenu, QAction, QMessageBox,
                            QStyle, QStyleFactory, QGroupBox, QGridLayout, QDialog, QLineEdit, QTableWidget,
                            QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject, QThread
from PyQt5.QtGui import QFont, QIcon, QColor, QTextCursor
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding
import uuid
import winreg
import ctypes
import traceback
import random

# Setup logging with rotation
from logging.handlers import RotatingFileHandler
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = RotatingFileHandler('client.log', maxBytes=1024*1024, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Default configuration
DEFAULT_CONFIG = {
    'SERVER_HOST': '127.0.0.1',
    'SERVER_PORT': 12345,
    'CLIENT_PASSPHRASE': 'your_secure_passphrase_here'
}

# Initialize configuration
HOST = DEFAULT_CONFIG['SERVER_HOST']
PORT = DEFAULT_CONFIG['SERVER_PORT']
CLIENT_PASSPHRASE = DEFAULT_CONFIG['CLIENT_PASSPHRASE'].encode()

# Debug environment variables
logger.info("Current working directory: %s", os.getcwd())
logger.info("Connection settings:")
logger.info("SERVER_HOST: %s", HOST)
logger.info("SERVER_PORT: %s", PORT)
logger.info("CLIENT_PASSPHRASE: %s", "Set" if CLIENT_PASSPHRASE else "Not Set")

# Security constants
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
BUFFER_SIZE = 4096
CONNECTION_TIMEOUT = 30
HEARTBEAT_INTERVAL = 30
MAX_RETRIES = 3
RETRY_DELAY = 1
MAX_COMMAND_SIZE = 1024
COMMAND_TIMEOUT = 30
ALLOWED_COMMANDS = {'ping', 'status', 'info'}

# Derive base key with random salt
SALT = secrets.token_bytes(16)
BASE_KEY = PBKDF2(CLIENT_PASSPHRASE, SALT, dkLen=32, count=100000)

# Constants
FRAME_HEADER = struct.Struct('!I')

# Add required crypto functions
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

class SecurityError(Exception):
    """Base class for security-related exceptions"""
    pass

class FileValidationError(SecurityError):
    """Raised when file validation fails"""
    pass

class CommandError(Exception):
    """Raised when command execution fails"""
    pass

class TaskStatus:
    PENDING = "Pending"
    RUNNING = "Running"
    COMPLETED = "Completed"
    FAILED = "Failed"

class LogSignals(QObject):
    """Signals for thread-safe logging"""
    log_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str)  # New signal for connection status updates

class AsyncClient(QThread):
    def __init__(self, signal_handler: LogSignals):
        super().__init__()
        self.signal_handler = signal_handler
        self.running = True
        self.connected = False
        self.session_key = None
        self.reader = None
        self.writer = None
        self.last_heartbeat = time.time()
        self.heartbeat_timeout = 90
        self.retry_count = 0
        self.max_retries = 5
        self.retry_delay = 1
        self.max_retry_delay = 300
        self.connection_state = "disconnected"
        self.last_connection_attempt = 0
        self.connection_lock = asyncio.Lock()
        self.message_queue = asyncio.Queue()
        self.heartbeat_task = None
        self.message_task = None

    async def connect(self):
        try:
            async with self.connection_lock:
                if self.connected:
                    logger.info("[CONNECT] Already connected, skipping connect.")
                    return True

                current_time = time.time()
                if current_time - self.last_connection_attempt < self.retry_delay:
                    logger.info("[CONNECT] Throttling connection attempts.")
                    return False

                self.last_connection_attempt = current_time
                self.connection_state = "connecting"
                self._update_status("connecting")

                # Clean up previous connection resources if they exist
                if self.writer:
                    try:
                        self.writer.close()
                        await self.writer.wait_closed()
                    except Exception as e_close:
                        logger.error(f"[CONNECT] Error closing previous writer: {e_close}")
                    finally:
                        self.writer = None
                        self.reader = None

                try:
                    logger.info(f"[CONNECT] Calling asyncio.open_connection({HOST}, {PORT})...")
                    self.reader, self.writer = await asyncio.wait_for(
                        asyncio.open_connection(HOST, PORT),
                        timeout=5.0
                    )
                    logger.info("[CONNECT] TCP connection established.")
                    # Optimize socket settings
                    sock = self.writer.get_extra_info('socket')
                    try:
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        logger.info("[CONNECT] Set TCP_NODELAY.")
                    except Exception as e:
                        logger.error(f"[CONNECT] Error setting TCP_NODELAY: {e}")
                    try:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                        logger.info("[CONNECT] Set SO_KEEPALIVE.")
                    except Exception as e:
                        logger.error(f"[CONNECT] Error setting SO_KEEPALIVE: {e}")
                    if sys.platform == 'win32':
                        if hasattr(sock, 'ioctl'):
                            try:
                                sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 30000, 10000))
                                logger.info("[CONNECT] Set SIO_KEEPALIVE_VALS.")
                            except Exception as e:
                                logger.error(f"[CONNECT] Error setting SIO_KEEPALIVE_VALS: {e}")
                        else:
                            logger.warning("[CONNECT] sock.ioctl not available on this socket type; skipping SIO_KEEPALIVE_VALS.")
                    self.connected = True
                    self.connection_state = "connected"
                    self._update_status("connected")
                    self.retry_count = 0
                    self.retry_delay = 1
                    return True
                except Exception as e:
                    logger.error(f"[CONNECT] Exception during open_connection or socket setup: {e}\n{traceback.format_exc()}")
                    self.connection_state = "failed"
                    self._update_status("failed")
                    self.retry_count += 1
                    self.retry_delay = min(self.retry_delay * 2, self.max_retry_delay)
                    if self.writer:
                        try:
                            self.writer.close()
                        except Exception as e_close_fail:
                            logger.error(f"[CONNECT] Error closing writer after connect attempt failed: {e_close_fail}")
                        finally:
                            self.writer = None
                            self.reader = None
                    return False
        except Exception as e_outer:
            logger.error(f"[CONNECT] Outer exception in connect: {e_outer}\n{traceback.format_exc()}")
            if self.writer:
                try:
                    self.writer.close()
                except Exception:
                    pass
                finally:
                    self.writer = None
                    self.reader = None
            return False

    async def send_heartbeat(self):
        """Send heartbeats to keep the connection alive and verify server responsiveness."""
        last_success = time.time()
        consecutive_failures = 0
        
        try:
            while self.running and self.connected:
                try:
                    logger.debug("[HEARTBEAT] Sending heartbeat...")
                    await self.send_framed_message(b"HEARTBEAT")
                    last_success = time.time()
                    consecutive_failures = 0
                    
                    # Signal successful heartbeat to UI
                    if hasattr(self, 'signal_handler') and self.signal_handler:
                        self.signal_handler.status_signal.emit("connected")
                    
                    # Adjust sleep time based on network health
                    heartbeat_interval = HEARTBEAT_INTERVAL
                    if consecutive_failures > 0:
                        # More frequent checks if we've had failures
                        heartbeat_interval = max(5, HEARTBEAT_INTERVAL // 2)
                        
                    # Sleep before next heartbeat
                    await asyncio.sleep(heartbeat_interval)
                    
                except asyncio.CancelledError:
                    logger.info("[HEARTBEAT] Heartbeat task cancelled")
                    raise  # Re-raise to be handled in the caller
                    
                except Exception as e:
                    consecutive_failures += 1
                    logger.error(f"[HEARTBEAT] Error sending heartbeat ({consecutive_failures}): {e}")
                    
                    # If too much time has passed since last successful heartbeat
                    # or we've had too many consecutive failures, mark as disconnected
                    if consecutive_failures >= 3 or (time.time() - last_success) > self.heartbeat_timeout:
                        logger.error(f"[HEARTBEAT] Connection lost after {consecutive_failures} failed heartbeats")
                        if self.signal_handler:
                            self.signal_handler.log_signal.emit(f"Connection lost after {consecutive_failures} failed heartbeats")
                            self.signal_handler.status_signal.emit("disconnected")
                        self.connected = False
                        break
                        
                    # Short sleep before retry when we've had a failure
                    await asyncio.sleep(3)
                    
        except asyncio.CancelledError:
            logger.info("[HEARTBEAT] Heartbeat task exiting due to cancellation")
        except Exception as e:
            logger.error(f"[HEARTBEAT] Unhandled exception in heartbeat task: {e}\n{traceback.format_exc()}")
        finally:
            logger.info("[HEARTBEAT] Heartbeat task exiting")
            # Ensure UI knows we're no longer connected
            if hasattr(self, 'signal_handler') and self.signal_handler:
                self.signal_handler.status_signal.emit("disconnected")

    async def handle_messages(self):
        while self.running and self.connected:
            try:
                # Read message header
                header = await self.reader.readexactly(4)
                length = struct.unpack('!I', header)[0]
                
                if length > MAX_FILE_SIZE:
                    raise SecurityError("Message size exceeds maximum allowed size")

                # Read encrypted data
                encrypted_data = await self.reader.readexactly(length)
                message = decrypt_data(encrypted_data, self.session_key).decode()
                self.last_heartbeat = time.time()

                if message == "HEARTBEAT":
                    continue  # Skip logging heartbeats
                elif message == "FILE_TRANSFER":
                    await self.handle_file_transfer()
                else:
                    await self.message_queue.put(message)

            except asyncio.IncompleteReadError:
                break
            except Exception:
                break

    async def handle_connection(self):
        while self.running:
            try:
                logger.info("[CONN] Checking connection state...")
                if not self.connected:
                    if self.retry_count >= self.max_retries:
                        logger.warning(f"[CONN] Max retries ({self.max_retries}) reached, sleeping for {self.max_retry_delay}s before next attempt...")
                        await asyncio.sleep(self.max_retry_delay)
                        self.retry_count = 0
                        continue

                    # Validate host and port before attempting connection
                    try:
                        # Check host format
                        ip_parts = HOST.split('.')
                        if len(ip_parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in ip_parts):
                            if HOST != 'localhost' and not HOST.startswith('127.'):
                                logger.warning(f"[CONN] Suspicious host format: {HOST}. This might cause connection issues.")
                        
                        # Check port range
                        if not isinstance(PORT, int) or PORT < 1024 or PORT > 65535:
                            logger.warning(f"[CONN] Port {PORT} is outside the recommended range (1024-65535)")
                            
                        logger.info(f"[CONN] Connection target: {HOST}:{PORT}")
                    except Exception as e:
                        logger.warning(f"[CONN] Error validating host/port: {e}")

                    # Implement an exponential backoff with randomization (jitter)
                    current_delay = self.retry_delay * (0.9 + 0.2 * random.random())  # +/- 10% jitter
                    logger.info(f"[CONN] Attempting to connect (retry {self.retry_count}, delay {current_delay:.1f}s)...")
                    
                    if not await self.connect():
                        self.retry_count += 1
                        self.retry_delay = min(self.retry_delay * 2, self.max_retry_delay)
                        logger.warning(f"[CONN] Connection attempt failed, sleeping for {current_delay:.1f}s before retry {self.retry_count+1}/{self.max_retries}...")
                        await asyncio.sleep(current_delay + 2)  # Add extra delay to avoid rapid dupes
                        continue

                try:
                    logger.info("[CONN] Performing DH key exchange...")
                    self.session_key = await self.perform_dh_key_exchange()
                    self.connection_state = "authenticated"
                    self._update_status("authenticated")
                    self.connected = True  # Only set to True after successful key exchange
                    self.retry_count = 0   # Reset retry count on success
                    self.retry_delay = 1   # Reset delay to initial value
                    logger.info("[CONN] Authenticated with server.")
                    
                    # Update the UI to reflect authenticated status
                    if hasattr(self, 'signal_handler') and self.signal_handler:
                        self.signal_handler.log_signal.emit("Connected and authenticated with server")
                    
                    # Start heartbeat and message handling tasks
                    self.heartbeat_task = asyncio.create_task(self.send_heartbeat())
                    self.message_task = asyncio.create_task(self.handle_messages())
                    
                    # Wait for tasks to complete or the connection to be closed
                    done, pending = await asyncio.wait(
                        [self.heartbeat_task, self.message_task],
                        return_when=asyncio.FIRST_COMPLETED
                    )
                    
                    # If we reach here, one of the tasks has completed or failed
                    # Cancel remaining tasks
                    for task in pending:
                        logger.info("[CONN] Cancelling pending task after a task completed")
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                    
                    # Check if connection is still marked as connected
                    if self.connected:
                        # Something went wrong - a task ended while connection should be active
                        logger.warning("[CONN] A connection task terminated unexpectedly")
                        self.connected = False
                        self.connection_state = "disconnected"
                        self._update_status("disconnected")
                        
                        # Check tasks for exceptions
                        for task in done:
                            if task.exception():
                                logger.error(f"[CONN] Task failed with exception: {task.exception()}")
                            else:
                                logger.warning(f"[CONN] Task completed normally but should have kept running")
                        
                        # Wait a bit before reconnection attempt
                        await asyncio.sleep(2)
                        
                    # If we get here, we need to reconnect
                    continue
                    
                except SecurityError as se:
                    logger.error(f"[CONN] SecurityError: {se}\n{traceback.format_exc()}")
                    self.connected = False
                    self.connection_state = "failed"
                    self._update_status("failed")
                    # Progressive backoff on errors
                    if "Failed to receive parameters" in str(se) or "Connection lost" in str(se):
                        # More serious network issues, use longer delay
                        wait_time = min(5 + self.retry_count * 2, 30)
                        logger.info(f"[CONN] Network error detected, waiting {wait_time}s before retry...")
                        await asyncio.sleep(wait_time)
                    else:
                        # Other security errors
                        wait_time = min(2 + self.retry_count, 15)
                        await asyncio.sleep(wait_time)
                    continue
                except Exception as e:
                    logger.error(f"[CONN] Exception during authentication: {e}\n{traceback.format_exc()}")
                    self.connected = False
                    self.connection_state = "error"
                    self._update_status("error")
                    # Use exponential backoff for unspecified errors
                    wait_time = min(2 * (2 ** min(self.retry_count, 4)), 60)
                    logger.info(f"[CONN] Error during authentication, waiting {wait_time}s before retry...")
                    await asyncio.sleep(wait_time)
                    continue

            except asyncio.CancelledError:
                logger.info("[CONN] Connection handler cancelled.")
                self.connected = False
                self.connection_state = "disconnected"
                self._update_status("disconnected")
                # Clean up any running tasks
                if hasattr(self, 'heartbeat_task') and self.heartbeat_task:
                    self.heartbeat_task.cancel()
                if hasattr(self, 'message_task') and self.message_task:
                    self.message_task.cancel()
                break
            except Exception as e:
                logger.error(f"[CONN] Outer exception: {e}\n{traceback.format_exc()}")
                self.connected = False
                self.connection_state = "error"
                self._update_status("error")
                await asyncio.sleep(5)  # Use fixed delay for outer loop exceptions

    def run(self):
        while self.running:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self.handle_connection())
            except Exception as e_run:
                logger.error(f"Exception in AsyncClient.run outer loop: {e_run}")
            finally:
                self.connected = False # Ensure disconnected state
                if self.writer:
                    self.writer.close() # Initiate close
                    try:
                        # Best effort to wait for close, with a timeout if possible, 
                        # but run_until_complete might not be usable if loop is already closed/stopping
                        if loop.is_running():
                           loop.run_until_complete(asyncio.wait_for(self.writer.wait_closed(), timeout=1.0))
                        # else: just rely on close() having been called
                    except Exception as e_wait_closed:
                        logger.error(f"Error during writer.wait_closed() in AsyncClient.run finally: {e_wait_closed}")
                if loop and not loop.is_closed():
                    loop.close()
                time.sleep(self.retry_delay) # Use existing retry delay for backoff

    def stop(self):
        self.running = False
        if self.writer:
            try:
                self.writer.close()
            except Exception as e_close_writer:
                logger.error(f"Error closing writer in AsyncClient.stop(): {e_close_writer}")
        
        self.connection_state = "disconnected"
        
        if self.heartbeat_task:
            try:
                self.heartbeat_task.cancel()
            except Exception as e_cancel_hb:
                logger.error(f"Error cancelling heartbeat task: {e_cancel_hb}")
        if self.message_task:
            try:
                self.message_task.cancel()
            except Exception as e_cancel_msg:
                logger.error(f"Error cancelling message task: {e_cancel_msg}")

        # Give the thread a chance to finish its run method's finally block.
        # This should be called from the thread that wants to stop this QThread.
        if QThread.currentThread() != self: # Ensure not called from within the thread itself
            if not self.wait(2000): # Wait for 2 seconds
                logger.warning("AsyncClient thread did not terminate gracefully within timeout.")
        else:
            logger.debug("AsyncClient.stop() called from within its own thread. Not waiting.")

    async def perform_dh_key_exchange(self):
        try:
            logger.info("[DH] Starting key exchange with server...")
            # Configure socket for better reliability
            sock = self.writer.get_extra_info('socket')
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Use smaller buffers to match server changes
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
            
            if sys.platform == 'win32':
                if hasattr(sock, 'ioctl'):
                    try:
                        sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 30000, 10000))
                        logger.info("[DH] Set SIO_KEEPALIVE_VALS.")
                    except Exception as e:
                        logger.error(f"[DH] Error setting SIO_KEEPALIVE_VALS: {e}")
                else:
                    logger.warning("[DH] sock.ioctl not available on this socket type; skipping SIO_KEEPALIVE_VALS.")

            # Wait a bit before starting the exchange to ensure server is ready
            await asyncio.sleep(0.5)
            
            logger.info("[DH] Waiting for server parameters...")
            # Receive server's parameters with improved retry logic
            max_retries = 3
            retry_delay = 0.5  # Start with longer delay
            
            for attempt in range(max_retries):
                try:
                    logger.info(f"[DH] Waiting for server parameters (attempt {attempt+1})...")
                    
                    # Set a timeout for the read operation
                    try:
                        # Try to get the socket from reader
                        reader_sock = self.reader._transport.get_extra_info('socket')
                        if reader_sock:
                            # Save original timeout
                            orig_timeout = reader_sock.gettimeout()
                            # Set a timeout just for this operation
                            reader_sock.settimeout(5.0)
                    except Exception as e:
                        logger.warning(f"[DH] Could not set socket timeout: {e}")
                    
                    try:
                        # Read header in smaller chunks if needed
                        header = await asyncio.wait_for(self.reader.readexactly(4), timeout=5.0)
                        param_len = struct.unpack('!I', header)[0]
                        if param_len > 8192:  # Increased max size but still have a limit
                            raise SecurityError("Invalid parameter size")
                            
                        logger.info(f"[DH] Server parameter header received. Expected size: {param_len} bytes")
                        
                        # Read parameters in chunks with progress tracking
                        param_bytes = b''
                        bytes_received = 0
                        chunk_size = 512
                        
                        # Use a timer to show progress periodically
                        last_log_time = time.time()
                        
                        while bytes_received < param_len:
                            # Read a chunk of data with timeout
                            try:
                                chunk = await asyncio.wait_for(
                                    self.reader.read(min(chunk_size, param_len - bytes_received)),
                                    timeout=3.0
                                )
                                if not chunk:  # EOF reached
                                    if bytes_received == 0:
                                        raise SecurityError("Connection closed by server before sending parameters")
                                    else:
                                        raise SecurityError(f"Connection closed by server after receiving {bytes_received}/{param_len} bytes")
                            except asyncio.TimeoutError:
                                raise SecurityError(f"Timeout reading parameters after receiving {bytes_received}/{param_len} bytes")
                                
                            param_bytes += chunk
                            bytes_received += len(chunk)
                            
                            # Log progress every second
                            current_time = time.time()
                            if current_time - last_log_time > 1.0:
                                logger.info(f"[DH] Received {bytes_received}/{param_len} bytes ({bytes_received/param_len:.1%}) of parameters")
                                last_log_time = current_time
                            
                            # Small pause between reads to avoid overwhelming CPU
                            await asyncio.sleep(0.001)
                        
                        logger.info(f"[DH] Successfully received all {bytes_received} bytes of parameters")
                        break  # Exit retry loop if successful
                    
                    finally:
                        # Restore original timeout
                        try:
                            if 'reader_sock' in locals() and 'orig_timeout' in locals():
                                reader_sock.settimeout(orig_timeout)
                        except Exception as e:
                            logger.warning(f"[DH] Could not restore socket timeout: {e}")
                
                except asyncio.IncompleteReadError as e:
                    logger.error(f"[DH] Error receiving parameters: {e}")
                    if attempt == max_retries - 1:
                        raise SecurityError(f"Failed to receive parameters after {max_retries} attempts: {e}")
                    # Check if connection is still alive before retrying
                    if self.writer.is_closing() or not self.connected:
                        raise SecurityError("Connection lost during parameter reception")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 1.5  # More gradual backoff
                
                except asyncio.TimeoutError:
                    logger.error(f"[DH] Timeout while receiving parameters (attempt {attempt+1})")
                    if attempt == max_retries - 1:
                        raise SecurityError(f"Timed out receiving parameters after {max_retries} attempts")
                    # Check if connection is still alive before retrying
                    if self.writer.is_closing() or not self.connected:
                        raise SecurityError("Connection lost due to timeout")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 1.5
                    
                except Exception as e:
                    logger.error(f"[DH] Error receiving parameters: {e}\n{traceback.format_exc()}")
                    if attempt == max_retries - 1:
                        raise SecurityError(f"Failed to receive parameters after {max_retries} attempts: {e}")
                    # Check if connection is still alive before retrying
                    if self.writer.is_closing() or not self.connected:
                        raise SecurityError(f"Connection lost during parameter reception: {e}")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 1.5
            
            try:
                logger.info("[DH] Loading server parameters...")
                parameters = serialization.load_pem_parameters(param_bytes, backend=default_backend())
                private_key = parameters.generate_private_key()
                public_key = private_key.public_key()
                logger.info("[DH] Successfully generated key pair from server parameters")
            except Exception as e:
                logger.error(f"[DH] Failed to load parameters or generate keys: {e}\n{traceback.format_exc()}")
                raise SecurityError(f"Failed to process DH parameters: {e}")

            # Receive server's public key with similar improved retry logic
            retry_delay = 0.5
            for attempt in range(max_retries):
                try:
                    logger.info(f"[DH] Waiting for server public key (attempt {attempt+1})...")
                    
                    # Read header with timeout
                    header = await asyncio.wait_for(self.reader.readexactly(4), timeout=5.0)
                    pub_len = struct.unpack('!I', header)[0]
                    if pub_len > 8192:
                        raise SecurityError("Invalid public key size")
                        
                    logger.info(f"[DH] Server public key header received. Expected size: {pub_len} bytes")
                    
                    # Read public key in chunks
                    server_pub_bytes = b''
                    bytes_received = 0
                    chunk_size = 512
                    
                    while bytes_received < pub_len:
                        chunk = await asyncio.wait_for(
                            self.reader.read(min(chunk_size, pub_len - bytes_received)),
                            timeout=3.0
                        )
                        if not chunk:
                            if bytes_received == 0:
                                raise SecurityError("Connection closed by server before sending public key")
                            else:
                                raise SecurityError(f"Connection closed by server after receiving {bytes_received}/{pub_len} bytes of public key")
                        
                        server_pub_bytes += chunk
                        bytes_received += len(chunk)
                        await asyncio.sleep(0.001)  # Small pause between reads
                    
                    logger.info(f"[DH] Successfully received all {bytes_received} bytes of server public key")
                    break  # Exit retry loop if successful
                    
                except (asyncio.IncompleteReadError, asyncio.TimeoutError) as e:
                    logger.error(f"[DH] Error receiving server public key: {e}")
                    if attempt == max_retries - 1:
                        raise SecurityError(f"Failed to receive server public key after {max_retries} attempts: {e}")
                    if self.writer.is_closing() or not self.connected:
                        raise SecurityError("Connection lost during public key reception")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 1.5
                    
                except Exception as e:
                    logger.error(f"[DH] Error receiving server public key: {e}\n{traceback.format_exc()}")
                    if attempt == max_retries - 1:
                        raise SecurityError(f"Failed to receive server public key after {max_retries} attempts: {e}")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 1.5

            # Load server public key
            try:
                logger.info("[DH] Loading server public key...")
                server_pub_key = serialization.load_pem_public_key(server_pub_bytes, backend=default_backend())
                logger.info("[DH] Successfully loaded server public key")
            except Exception as e:
                logger.error(f"[DH] Failed to load server public key: {e}\n{traceback.format_exc()}")
                raise SecurityError(f"Failed to process server public key: {e}")

            # Send our public key with improved retry logic
            pub_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            retry_delay = 0.5
            for attempt in range(max_retries):
                try:
                    logger.info(f"[DH] Sending our public key to server (attempt {attempt+1})...")
                    
                    # Send length header
                    self.writer.write(struct.pack('!I', len(pub_bytes)))
                    await self.writer.drain()
                    
                    # Send public key in smaller chunks
                    chunk_size = 512
                    total_sent = 0
                    while total_sent < len(pub_bytes):
                        end_pos = min(total_sent + chunk_size, len(pub_bytes))
                        chunk = pub_bytes[total_sent:end_pos]
                        self.writer.write(chunk)
                        await asyncio.wait_for(self.writer.drain(), timeout=3.0)
                        total_sent += len(chunk)
                        await asyncio.sleep(0.002)  # 2ms delay between chunks
                    
                    logger.info(f"[DH] Successfully sent all {len(pub_bytes)} bytes of our public key")
                    break  # Exit retry loop if successful
                    
                except asyncio.TimeoutError:
                    logger.error(f"[DH] Timeout sending our public key (attempt {attempt+1})")
                    if attempt == max_retries - 1:
                        raise SecurityError(f"Failed to send public key after {max_retries} attempts: timeout")
                    if self.writer.is_closing() or not self.connected:
                        raise SecurityError("Connection lost while sending public key (timeout)")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 1.5
                    
                except Exception as e:
                    logger.error(f"[DH] Error sending our public key: {e}\n{traceback.format_exc()}")
                    if attempt == max_retries - 1:
                        raise SecurityError(f"Failed to send public key after {max_retries} attempts: {e}")
                    if self.writer.is_closing() or not self.connected:
                        raise SecurityError(f"Connection lost while sending public key: {e}")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 1.5

            # Generate session key from shared secret
            try:
                logger.info("[DH] Generating session key...")
                shared_secret = private_key.exchange(server_pub_key)
                session_key = hashlib.sha256(shared_secret).digest()
                logger.info("[DH] Key exchange complete.")
                return session_key
            except Exception as e:
                logger.error(f"[DH] Failed to generate session key: {e}\n{traceback.format_exc()}")
                self.connected = False
                if self.writer and not self.writer.is_closing():
                    try:
                        self.writer.close()
                    except Exception as e_close:
                        logger.error(f"Error closing writer in session key generation exception handler: {e_close}")
                raise SecurityError(f"Failed to generate session key: {e}")

        except Exception as e:
            self.connected = False
            if self.writer and not self.writer.is_closing():
                try:
                    self.writer.close()
                    await self.writer.wait_closed()
                except Exception as e_close:
                    logger.error(f"Error closing writer in perform_dh_key_exchange exception handler: {e_close}")
            logger.error(f"[DH] Key exchange failed: {e}\n{traceback.format_exc()}")
            raise SecurityError(f"Key exchange failed: {e}")

    async def send_framed_message(self, data: bytes):
        try:
            encrypted_data = encrypt_data(data, self.session_key)
            message = FRAME_HEADER.pack(len(encrypted_data)) + encrypted_data
            self.writer.write(message)
            await self.writer.drain()
        except Exception as e:
            raise SecurityError(f"Failed to send message: {e}")

    async def handle_file_transfer(self):
        try:
            # Receive file hash
            header = await asyncio.wait_for(self.reader.readexactly(4), timeout=10.0)
            hash_len = struct.unpack('!I', header)[0]
            
            if hash_len > 1024:  # Reasonable max hash length
                raise SecurityError("Invalid hash size")
            
            encrypted_hash = await asyncio.wait_for(self.reader.readexactly(hash_len), timeout=10.0)
            file_hash = decrypt_data(encrypted_hash, self.session_key).decode()
            
            # Receive file size
            header = await asyncio.wait_for(self.reader.readexactly(4), timeout=10.0)
            size_len = struct.unpack('!I', header)[0]
            
            if size_len > 8:  # Size should be a 64-bit integer (8 bytes)
                raise SecurityError("Invalid size data")
            
            encrypted_size = await asyncio.wait_for(self.reader.readexactly(size_len), timeout=10.0)
            file_size = struct.unpack('!Q', decrypt_data(encrypted_size, self.session_key))[0]
            
            if file_size > MAX_FILE_SIZE:
                raise SecurityError(f"File too large: {file_size} bytes")
            
            # Receive file data with progress tracking
            header = await asyncio.wait_for(self.reader.readexactly(4), timeout=10.0)
            data_len = struct.unpack('!I', header)[0]
            
            if data_len > MAX_FILE_SIZE or data_len != file_size:
                raise SecurityError(f"Invalid file data size: expected {file_size}, got {data_len}")
            
            # Log the file transfer start
            if self.signal_handler:
                self.signal_handler.log_signal.emit(f"Receiving file ({data_len} bytes)...")
            
            # Receive encrypted data in chunks with progress tracking
            encrypted_data = bytearray()
            bytes_received = 0
            chunk_size = 4096
            last_progress = 0
            
            while bytes_received < data_len:
                chunk = await asyncio.wait_for(
                    self.reader.read(min(chunk_size, data_len - bytes_received)),
                    timeout=30.0
                )
                
                if not chunk:
                    raise SecurityError(f"Connection lost during file transfer after receiving {bytes_received}/{data_len} bytes")
                
                encrypted_data.extend(chunk)
                bytes_received += len(chunk)
                
                # Update progress (about every 10%)
                progress = int(bytes_received * 100 / data_len)
                if progress - last_progress >= 10:
                    if self.signal_handler:
                        self.signal_handler.log_signal.emit(f"File transfer: {progress}% ({bytes_received}/{data_len} bytes)")
                    last_progress = progress
            
            # Decrypt and verify file
            try:
                file_data = decrypt_data(bytes(encrypted_data), self.session_key)
                
                # Verify file integrity
                computed_hash = hashlib.sha256(file_data).hexdigest()
                if computed_hash != file_hash:
                    raise FileValidationError(f"File hash verification failed: expected {file_hash}, got {computed_hash}")
                
                # Save file to downloads directory with timestamp
                downloads_dir = os.path.join(os.path.expanduser('~'), 'Downloads', 'PyRat')
                os.makedirs(downloads_dir, exist_ok=True)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                file_path = os.path.join(downloads_dir, f"received_file_{timestamp}")
                
                with open(file_path, 'wb') as f:
                    f.write(file_data)
                
                if self.signal_handler:
                    self.signal_handler.log_signal.emit(f"File saved to: {file_path}")
                
                return file_path
                
            except Exception as e:
                if self.signal_handler:
                    self.signal_handler.log_signal.emit(f"Error processing received file: {e}")
                raise
            
        except asyncio.TimeoutError:
            if self.signal_handler:
                self.signal_handler.log_signal.emit("File transfer timed out")
            return None
        except Exception as e:
            if self.signal_handler:
                self.signal_handler.log_signal.emit(f"File transfer failed: {e}")
            return None

    def _update_status(self, status):
        """Update status via signal if signal handler is available"""
        if hasattr(self, 'signal_handler') and self.signal_handler:
            try:
                self.signal_handler.status_signal.emit(status)
            except Exception as e:
                logger.error(f"Error sending status signal: {e}")

class ClientGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Remote Access Client")
        self.setGeometry(100, 100, 800, 600)
        
        # Initialize logging components
        self.log_signals = LogSignals()
        self.log_signals.log_signal.connect(self.append_log_thread_safe)
        self.log_signals.status_signal.connect(self.update_connection_status)
        
        # Initialize client
        self.client = AsyncClient(self.log_signals)
        self.client.start()
        
        # Initialize GUI
        self.init_gui()
        
        # Set up system tray
        self.setup_tray_icon()

    def init_gui(self):
        """Initialize the GUI components with a modern, clean design"""
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(12, 12, 12, 12)

        # Apply a modern style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #F5F5F5;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #CCCCCC;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 5px;
            }
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #0D47A1;
            }
            QPushButton:disabled {
                background-color: #BDBDBD;
                color: #757575;
            }
            QTextEdit {
                background-color: #FFFFFF;
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                padding: 4px;
                font-family: 'Consolas', monospace;
            }
            QLabel {
                font-size: 11pt;
            }
        """)

        # Status group
        status_group = QGroupBox("Connection Status")
        status_layout = QVBoxLayout(status_group)
        
        # Status indicator with icon
        status_header = QHBoxLayout()
        status_icon = QLabel()
        status_icon.setPixmap(self.style().standardPixmap(QStyle.SP_MediaStop).scaled(16, 16))
        self.status_icon = status_icon
        
        status_label = QLabel("Status:")
        status_label.setStyleSheet("font-weight: bold;")
        
        self.status_indicator = QLabel("Disconnected")
        self.status_indicator.setStyleSheet("color: #f44336; font-weight: bold;")
        
        status_header.addWidget(status_icon)
        status_header.addWidget(status_label)
        status_header.addWidget(self.status_indicator)
        status_header.addStretch()
        status_layout.addLayout(status_header)
        
        # Connection info
        self.connection_info = QLabel("Not connected")
        status_layout.addWidget(self.connection_info)
        
        main_layout.addWidget(status_group)

        # Log group
        log_group = QGroupBox("Connection Log")
        log_layout = QVBoxLayout(log_group)
        
        # Log text area
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #FFFFFF;
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                padding: 8px;
                font-family: 'Consolas', monospace;
                font-size: 10pt;
            }
        """)
        log_layout.addWidget(self.log_text)
        
        main_layout.addWidget(log_group)

        # Control buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        self.connect_button = QPushButton("Connect")
        self.connect_button.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        self.connect_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #43A047;
            }
            QPushButton:pressed {
                background-color: #388E3C;
            }
        """)
        self.connect_button.clicked.connect(self.toggle_connection)
        
        self.clear_button = QPushButton("Clear Logs")
        self.clear_button.setIcon(self.style().standardIcon(QStyle.SP_DialogResetButton))
        self.clear_button.setStyleSheet("""
            QPushButton {
                background-color: #9E9E9E;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #757575;
            }
            QPushButton:pressed {
                background-color: #616161;
            }
        """)
        self.clear_button.clicked.connect(self.clear_logs)
        
        button_layout.addWidget(self.connect_button)
        button_layout.addWidget(self.clear_button)
        button_layout.addStretch()
        
        main_layout.addLayout(button_layout)

    def append_log_thread_safe(self, message: str):
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.log_text.append(f"[{timestamp}] {message}")
            self.log_text.verticalScrollBar().setValue(self.log_text.verticalScrollBar().maximum())
        except Exception as e:
            logger.error(f"Error appending log: {e}")

    def toggle_connection(self):
        """Toggle connection state between connected and disconnected."""
        try:
            if not self.client.connected:
                # User wants to connect
                self.status_indicator.setText("Connecting...")
                self.status_indicator.setStyleSheet("color: #FFC107; font-weight: bold;")
                self.connect_button.setText("Disconnect")
                
                # Reset client connection if needed
                if self.client.connection_state == "disconnected":
                    # Start a connection attempt if not already in progress
                    self.client.retry_count = 0
                    self.client.retry_delay = 1
                    self.client.connection_state = "connecting"
                    
                # Log the action
                self.append_log_thread_safe("Initiating connection to server...")
            else:
                # User wants to disconnect
                self.connect_button.setText("Connect")
                self.status_indicator.setText("Disconnecting...")
                self.status_indicator.setStyleSheet("color: #FF9800; font-weight: bold;")
                
                # Log the action
                self.append_log_thread_safe("Disconnecting from server...")
                
                # Stop the client connection
                self.client.stop()
                
                # After a brief delay, update UI to show disconnected state
                QTimer.singleShot(500, self.update_disconnected_state)
                
        except Exception as e:
            logger.error(f"Error in toggle_connection: {e}")
            self.append_log_thread_safe(f"Error toggling connection: {e}")

    def update_disconnected_state(self):
        """Update UI elements to reflect disconnected state"""
        if not self.client.connected:
            self.status_indicator.setText("Disconnected")
            self.status_indicator.setStyleSheet("color: #f44336; font-weight: bold;")
            self.connection_info.setText("Not connected")
            self.append_log_thread_safe("Disconnected from server")

    def update_connection_status(self, status):
        """Update the connection status display in the UI"""
        try:
            logger.info(f"UI status update: {status}")
            
            if status == "authenticated" or status == "connected":
                self.status_indicator.setText("Connected")
                self.status_indicator.setStyleSheet("color: #4CAF50; font-weight: bold;")
                self.connection_info.setText(f"Connected to {HOST}:{PORT}")
                self.connect_button.setText("Disconnect")
                self.connect_button.setIcon(self.style().standardIcon(QStyle.SP_MediaStop))
                self.connect_button.setStyleSheet("""
                    QPushButton {
                        background-color: #F44336;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        padding: 8px 16px;
                        font-weight: bold;
                    }
                    QPushButton:hover {
                        background-color: #E53935;
                    }
                    QPushButton:pressed {
                        background-color: #D32F2F;
                    }
                """)
                # Update status icon
                self.status_icon.setPixmap(self.style().standardPixmap(QStyle.SP_DialogApplyButton).scaled(16, 16))
                
            elif status == "connecting":
                self.status_indicator.setText("Connecting...")
                self.status_indicator.setStyleSheet("color: #FFC107; font-weight: bold;")
                # Update status icon
                self.status_icon.setPixmap(self.style().standardPixmap(QStyle.SP_BrowserReload).scaled(16, 16))
                
            elif status == "disconnected" or status == "failed" or status == "error":
                self.status_indicator.setText("Disconnected")
                self.status_indicator.setStyleSheet("color: #f44336; font-weight: bold;")
                self.connection_info.setText("Not connected")
                self.connect_button.setText("Connect")
                self.connect_button.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
                self.connect_button.setStyleSheet("""
                    QPushButton {
                        background-color: #4CAF50;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        padding: 8px 16px;
                        font-weight: bold;
                    }
                    QPushButton:hover {
                        background-color: #43A047;
                    }
                    QPushButton:pressed {
                        background-color: #388E3C;
                    }
                """)
                # Update status icon
                self.status_icon.setPixmap(self.style().standardPixmap(QStyle.SP_MediaStop).scaled(16, 16))
                
        except Exception as e:
            logger.error(f"Error updating connection status: {e}")

    def clear_logs(self):
        self.log_text.clear()

    def closeEvent(self, event):
        reply = QMessageBox.question(
            self,
            'Confirm Exit',
            'Are you sure you want to exit?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            logger.info("Client GUI closing. Stopping AsyncClient...")
            self.client.stop() # This will now block for a bit due to self.wait() in stop()
            logger.info("AsyncClient signaled to stop. Quitting QApplication.")
            QApplication.quit() # Ensure Qt event loop is terminated
            event.accept()
        else:
            logger.info("Client GUI close cancelled by user.")
            event.ignore()

    def setup_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        
        # Create tray menu
        tray_menu = QMenu()
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        tray_menu.addAction(show_action)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

def validate_environment() -> bool:
    """Validate the client environment before starting."""
    try:
        # Check if required environment variables are set
        if not CLIENT_PASSPHRASE:
            logger.error("CLIENT_PASSPHRASE is not set")
            return False
            
        # Check if server host and port are valid
        if not HOST or not PORT:
            logger.error("Invalid server configuration")
            return False
            
        # Check if port is in valid range
        if not (1024 <= PORT <= 65535):
            logger.error("Port must be between 1024 and 65535")
            return False
            
        return True
    except Exception as e:
        logger.error(f"Environment validation failed: {e}")
        return False

def main():
    if not validate_environment():
        logger.error("Environment validation failed")
        return

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = ClientGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()