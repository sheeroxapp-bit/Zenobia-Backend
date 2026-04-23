import asyncio
import websockets
import json
import os
import logging
import threading
import uuid
import re
from datetime import datetime
from typing import Dict, Any, List
from config import Config
from models.ai_model import AIModel
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import base64
import hashlib
import bcrypt
import jwt
from cryptography.fernet import Fernet
import subprocess
import tempfile
import shutil
import socket
import psutil
import platform
import multiprocessing
import concurrent.futures
from functools import partial
import traceback
import pkg_resources
import importlib
import cffi
import ctypes
import ctypes.util
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('zenobia-server')

# Global variables
AUTH_TOKENS = {}  # Store active tokens
USER_GROUPS = {}  # Store user groups and their members
GROUP_AGENTS = {}  # Store agents for each group
ROOT_PASSWORD = os.getenv("ROOT_PASSWORD", "7Xroot_2025")  # Load from env vars
SANDBOX_DIR = "./sandbox"
MALWARE_DATABASE = "./malware_db"
REQUIREMENTS_FILE = "./requirements.txt"
PACKAGES_DIR = "./packages"
PYTHON_EXTENSIONS = ['.py', '.pyc', '.pyo']
CPP_EXTENSIONS = ['.cpp', '.h', '.hpp', '.cc']
JAVA_EXTENSIONS = ['.java']
RUST_EXTENSIONS = ['.rs']
GO_EXTENSIONS = ['.go']
C_EXTENSIONS = ['.c', '.h']
PHP_EXTENSIONS = ['.php']
JS_EXTENSIONS = ['.js', '.jsx', '.ts', '.tsx']
RUBY_EXTENSIONS = ['.rb']
SWIFT_EXTENSIONS = ['.swift']
KOTLIN_EXTENSIONS = ['.kt', '.kts']

# Create directories if they don't exist
for dir_path in [SANDBOX_DIR, MALWARE_DATABASE, PACKAGES_DIR]:
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)

# Encryption key for sensitive data
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# CFFI for C/C++ integration
ffi = cffi.FFI()
ffi.set_source("_zenobia_c", """
    #include <stdio.h>
    #include <stdlib.h>
    
    // Example C function
    int add_numbers(int a, int b) {
        return a + b;
    }
    
    // Example C++ function
    extern "C" {
        int multiply_numbers(int a, int b) {
            return a * b;
        }
    }
""")

# Compile C/C++ code
ffi.compile()

# Import compiled C/C++ code
c_module = ffi.verify("""
    int add_numbers(int a, int b);
    int multiply_numbers(int a, int b);
""", libraries=["zenobia_c"])

class NewDataHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            logger.info(f"Detected new file: {event.src_path}")
            # Reload knowledge base when new files appear
            try:
                ai_model.ingest_data()
                logger.info("Knowledge base updated successfully")
            except Exception as e:
                logger.error(f"Error updating knowledge base: {str(e)}")

class AuthHandler:
    def __init__(self):
        self.api_keys = {}
        self.active_sessions = {}
        self.users = {}  # Store user credentials
        self.user_groups = {}  # Store user's group memberships
    
    def register_user(self, user_id: str, password: str) -> bool:
        """Register a new user with password hashing."""
        try:
            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            self.users[user_id] = hashed_password
            return True
        except Exception as e:
            logger.error(f"Error registering user: {str(e)}")
            return False
    
    def authenticate_user(self, user_id: str, password: str) -> bool:
        """Authenticate a user with password checking."""
        if user_id not in self.users:
            return False
        
        return bcrypt.checkpw(password.encode(), self.users[user_id])
    
    def generate_auth_token(self, user_id: str) -> str:
        """Generate a JWT token for a user."""
        try:
            payload = {
                'user_id': user_id,
                'exp': datetime.utcnow() + timedelta(hours=24)
            }
            token = jwt.encode(payload, ENCRYPTION_KEY, algorithm='HS256')
            AUTH_TOKENS[user_id] = token
            return token
        except Exception as e:
            logger.error(f"Error generating auth token: {str(e)}")
            return ""
    
    def verify_auth_token(self, token: str) -> bool:
        """Verify an auth token."""
        try:
            payload = jwt.decode(token, ENCRYPTION_KEY, algorithms=['HS256'])
            return True
        except Exception:
            return False
    
    def revoke_auth_token(self, user_id: str):
        """Revoke an auth token."""
        if user_id in AUTH_TOKENS:
            del AUTH_TOKENS[user_id]
    
    def is_root_user(self, user_id: str) -> bool:
        """Check if user has root privileges."""
        return user_id == "root"

class GroupManager:
    def __init__(self):
        self.groups = {}  # Store group information
        self.group_agents = {}  # Store agents for each group
        self.root_agents