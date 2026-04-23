import asyncio
import websockets
import json
import os
import logging
import threading
import uuid
import re
from datetime import datetime, timedelta
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

# Fix: Ensure imports are properly ordered and consistent
try:
    import watchdog
except ImportError:
    logger.warning("Watchdog module not found. Auto-reload functionality disabled.")
    watchdog = None

# Fix: Add missing imports
try:
    import pkg_resources
    from cryptography.fernet import Fernet
    from dotenv import load_dotenv
except ImportError as e:
    logger.error(f"Missing required dependency: {e}")
    raise SystemExit(1)

# Fix: Add missing timedelta import
from datetime import timedelta

# Server configuration
SERVER_URL = "wss://zenobia-backend.onrender.com"

# Initialize models
ai_model = AIModel()
observer = Observer()

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
        self.root_agents = {}  # Store root agent information
        self.user_groups = {}  # Store user-group relationships
        
    def create_group(self, group_id: str, owner_id: str) -> bool:
        """Create a new group."""
        if group_id in self.groups:
            return False
            
        self.groups[group_id] = {
            'owner': owner_id,
            'members': [],
            'agents': []
        }
        return True
        
    def join_group(self, user_id: str, group_id: str) -> bool:
        """Join a group."""
        if group_id not in self.groups:
            return False
            
        if user_id not in self.groups[group_id]['members']:
            self.groups[group_id]['members'].append(user_id)
            self.user_groups[user_id] = group_id
        return True
        
    def leave_group(self, user_id: str, group_id: str) -> bool:
        """Leave a group."""
        if group_id not in self.groups:
            return False
            
        if user_id in self.groups[group_id]['members']:
            self.groups[group_id]['members'].remove(user_id)
            if user_id in self.user_groups:
                del self.user_groups[user_id]
        return True
        
    def is_owner(self, user_id: str, group_id: str) -> bool:
        """Check if user is owner of group."""
        if group_id not in self.groups:
            return False
        return self.groups[group_id]['owner'] == user_id
        
    def get_group_members(self, group_id: str) -> List[str]:
        """Get list of group members."""
        if group_id not in self.groups:
            return []
        return self.groups[group_id]['members']
        
    def add_agent_to_group(self, agent_id: str, group_id: str) -> bool:
        """Add agent to group."""
        if group_id not in self.groups:
            return False
            
        if agent_id not in self.groups[group_id]['agents']:
            self.groups[group_id]['agents'].append(agent_id)
        return True
        
    def remove_agent_from_group(self, agent_id: str, group_id: str) -> bool:
        """Remove agent from group."""
        if group_id not in self.groups:
            return False
            
        if agent_id in self.groups[group_id]['agents']:
            self.groups[group_id]['agents'].remove(agent_id)
        return True

# Initialize components
auth_handler = AuthHandler()
group_manager = GroupManager()

# Start watchdog observer
observer.schedule(NewDataHandler(), SANDBOX_DIR, recursive=True)
observer.start()

async def handle_client(websocket, path):
    """Handle incoming WebSocket connections."""
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                action = data.get('action')
                
                if action == 'chat':
                    # Process chat message
                    text = data.get('text', '')
                    response = ai_model.generate_response(text)
                    await websocket.send(json.dumps({
                        'action': 'chat',
                        'data': response
                    }))
                    
                elif action == 'login':
                    # Handle login
                    user_id = data.get('user_id', '')
                    password = data.get('password', '')
                    
                    if auth_handler.authenticate_user(user_id, password):
                        token = auth_handler.generate_auth_token(user_id)
                        await websocket.send(json.dumps({
                            'action': 'login_success',
                            'token': token
                        }))
                    else:
                        await websocket.send(json.dumps({
                            'action': 'login_error',
                            'error': 'Invalid credentials'
                        }))
                        
                elif action == 'register':
                    # Handle registration
                    user_id = data.get('user_id', '')
                    password = data.get('password', '')
                    
                    if auth_handler.register_user(user_id, password):
                        await websocket.send(json.dumps({
                            'action': 'register_success'
                        }))
                    else:
                        await websocket.send(json.dumps({
                            'action': 'register_error',
                            'error': 'Registration failed'
                        }))
                        
            except Exception as e:
                logger.error(f"Error processing message: {str(e)}")
                await websocket.send(json.dumps({
                    'action': 'error',
                    'error': str(e)
                }))
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")
    finally:
        observer.stop()
        observer.join()

async def main():
    """Main server loop."""
    server = await websockets.serve(
        handle_client,
        SERVER_URL.split(":")[0],
        int(SERVER_URL.split(":")[1]),
        ssl=None
    )
    
    logger.info(f"Server started at {SERVER_URL}")
    await server.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
