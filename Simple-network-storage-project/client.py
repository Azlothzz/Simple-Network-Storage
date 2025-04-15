import socket
import json
import base64
import os
import re
import time
import logging
import sqlite3
import hashlib
import pyotp
import shutil
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
# from api_user import get_session_token, store_session

# Project root directory and database path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'storage.db')

# server settings
HOST = 'localhost'
PORT = 9999
MAX_BUFFER_SIZE = 4096

# setting logs
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SecureStorage')

_session_tokens = {}  # Store session data by username

def store_session(username, session_data):
    """Stores user's session token and data"""
    _session_tokens[username] = session_data
    
def get_session_token(username):
    """Get the user's session token"""
    if username in _session_tokens:
        return _session_tokens[username].get("session_id")
    return None

def clear_session(username):
    """Clearing User Sessions"""
    if username in _session_tokens:
        del _session_tokens[username]
def clear_screen():
    """Clear screen, compatible with Windows and Unix"""
    os.system("cls" if os.name == "nt" else "clear")

def input_with_validation(prompt: str, allow_empty: bool = False) -> str:
    """Get user input and validate it"""
    while True:
        value = input(prompt).strip()
        if value or allow_empty:
            return value
        print("Input cannot be empty, please try again.")

def send_request(request):
    """Send a request to the server and receive a response"""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))
        client.send(json.dumps(request).encode())
        response = b""
        while True:
            chunk = client.recv(MAX_BUFFER_SIZE)
            if not chunk:
                break
            response += chunk
            if len(chunk) < MAX_BUFFER_SIZE:
                break
        client.close()
        return json.loads(response.decode())
    except Exception as e:
        print(f"Communication Error: {e}")
        return {"status": "error", "message": str(e)}

def derive_encryption_key(username, password="file_encryption_key"):
    """Deriving encryption keys"""
    salt = username.encode()
    key = PBKDF2(password, salt, dkLen=32, count=1000, hmac_hash_module=SHA256)
    return key

def register_user(username, password):
    """register user"""
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    request = {"action": "register", "username": username, "password_hash": password_hash}
    response = send_request(request)
    print(f"register: {username}")
    return response

def login_user(username, password, otp):
    """User login"""
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    request = {"action": "login",
               "username": username,
               "password_hash": password_hash,
               "otp_code": otp}
    response = send_request(request)
    print(f"login: {username}")
    
    # If the login is successful, store the session data
    if response.get("status") == "success" and "session_id" in response:
        store_session(username, {
            "session_id": response.get("session_id"),
            "user_id": response.get("user_id", "")
        })
        
    return response

def reset_password(username, old_password, new_password):
    """reset password"""

    session_id = get_session_token(username)
    if not session_id:
        return {"status": "error", "message": "session expired or not found"}
    old_password_hash = hashlib.sha256(old_password.encode()).hexdigest()
    new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    request = {
        "action": "reset_password",
        "username": username,
        "old_password_hash": old_password_hash,
        "new_password_hash": new_password_hash,
        "session_id": session_id
    }
    response = send_request(request)
    print(f"reset: {username} password: {response}")
    
    if response.get("status") == "success":
        # If the server requires a new login, clear the current session
        if response.get("require_relogin"):
            clear_session(username)
            print(f"Your password has been reset. Please log in again with your new password.")
    
    return response

def admin_login():
    """Admin login with fixed password for testing"""
    print("\n==== Admin Login ====")
    password = input_with_validation("Please enter the administrator password: ")
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    # Get OTP for admin
    otp = get_otp("admin")
    if not otp:
        print("Unable to generate OTP for admin")
        return False, ""

    print(f"Admin OTP: {otp}")
    user_input_otp = input_with_validation("Please enter OTP: ")

    request = {
        "action": "login",
        "username": "admin",
        "password_hash": password,
        "otp_code": user_input_otp
    }

    response = send_request(request)
    print(f"Login Response: {response}")

    if response.get("status") == "success":
        if "session_id" in response:
            store_session("admin", {
                "session_id": response.get("session_id"),
                "user_id": response.get("user_id", "")
            })
        print(f"Administrator login successful!")
        return True, "admin"
    else:
        print(f"login failed: {response.get('message', 'Unknown error')}")
        return False, ""
def download_file(username, file_id):
    try:
        session_id = get_session_token(username)
        if not session_id:
            print("session expired or not found, please login again")
            return {"status": "error", "message": "session expired or not found"}
        # verify file_id
        if not isinstance(file_id, (int, str)) or not str(file_id).isdigit():
            return {"status": "error", "message": "无效的文件 ID"}
        file_id = int(file_id)

        # send download request
        request = {"action": "download_file", "username": username, "file_id": file_id, "session_id": session_id}
        logger.debug(f"send download request: file_id={file_id}, username={username}")
        response = send_request(request)

        if response.get("status") != "success":
            print(f"download failed：{response.get('message', 'Unknown error')}")
            return response

        # Parsing encrypted packets
        encrypted_package = json.loads(base64.b64decode(response["data"]).decode())
        ciphertext = base64.b64decode(encrypted_package["ciphertext"])
        nonce = base64.b64decode(encrypted_package["nonce"])
        tag = base64.b64decode(encrypted_package["tag"])
        file_metadata = encrypted_package.get("metadata", {})

        # Get the file type and file name
        file_type = file_metadata.get("file_type", "").lower()
        display_filename = file_metadata.get("original_filename", f"file_{file_id}")
        owner_username = file_metadata.get("owner_username", username)

        #Only handle .txt 文件
        if file_type != "txt":
            print(f"Only supports downloading .txt files, current file type: {file_type}")
            return {"status": "error", "message": f"Only .txt files are supported, current type: {file_type}"}

        # Decrypting Files
        key = derive_encryption_key(owner_username)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        decrypted_content = decrypted_bytes.decode('utf-8')

        # Save files
        download_dir = os.path.join(BASE_DIR, "download")
        os.makedirs(download_dir, exist_ok=True)

        def get_unique_filename(directory, filename):
            base, ext = os.path.splitext(filename)
            counter = 1
            new_filename = filename
            while os.path.exists(os.path.join(directory, new_filename)):
                new_filename = f"{base} ({counter}){ext}"
                counter += 1
            return new_filename

        unique_filename = get_unique_filename(download_dir, display_filename)
        file_path = os.path.join(download_dir, unique_filename)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(decrypted_content)

        #Single success tip
        print(f"file: '{display_filename}' Downloaded and saved to: {file_path}")
        return {"status": "success", "message": f"files saved to {file_path}"}

    except ValueError as e:
        logger.error(f"download error: {e}")
        print(f"download error：{e}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        logger.error(f"unknown error: {type(e).__name__}: {e}")
        print(f"unknown error：{e}")
        return {"status": "error", "message": str(e)}


def get_otp(username):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT otp_secret FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()
        if result:
            totp = pyotp.TOTP(result[0], interval=300)
            return totp.now()
        else:
            print(f"user {username} not found")
            return None
    except Exception as e:
        print("wrong OTP:", e)
        return None

def send_otp_to_phone(username, otp):
    try:
        phone = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        phone.settimeout(5)  # Add timeout to prevent hanging
        phone.connect(('localhost', 8888))
        message = {'username': username, 'otp_secret': otp}
        phone.send(json.dumps(message).encode())
        response = phone.recv(1024).decode()  # Get response from OTP server
        phone.close()

        # Parse response to check success
        try:
            response_data = json.loads(response)
            if response_data.get('status') == 'success':
                return True
        except:
            pass
        return False
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return False

logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SecureStorage')



def sanitize_filename(filename):
    """Preventing Path Traversal Attacks"""
    base_filename = os.path.basename(filename)
    safe_filename = re.sub(r'[^\w\.-]', '_', base_filename)
    if not safe_filename or safe_filename in ['.', '..'] or safe_filename.startswith('.'):
        raise ValueError(f"unsafe filename: {filename}")
    return safe_filename



def upload_file(username, filename, file_content=None, file_path=None):
    try:


        session_id = get_session_token(username)
        if not session_id:
            print("session expired or not found, please login again")
            return {"status": "error", "message": "session expired or not found"}
        # Sanitize the filename for security
        safe_filename = sanitize_filename(filename)
        
        # If original filename was modified, notify user
        if safe_filename != filename:
            print(f"Note: Filename was changed to safe version '{safe_filename}'")
            
        # Handle file content from either direct content or file path
        if file_content is None and file_path is not None:
            # Validate file_path to prevent directory traversal attacks
            if not os.path.exists(file_path):
                return {"status": "error", "message": f"File not found: {file_path}"}
            
            # Check if file path is within allowed directories
            abs_path = os.path.abspath(file_path)
            
            try:
                # Read file content from the specified path
                with open(abs_path, 'rb') as f:
                    file_bytes = f.read()
            except (IOError, PermissionError) as e:
                return {"status": "error", "message": f"Cannot read file: {str(e)}"}
        elif isinstance(file_content, str):
            # If content provided as string, encode to bytes
            file_bytes = file_content.encode('utf-8')
        elif file_content is not None:
            # If content already in bytes, use directly
            file_bytes = file_content
        else:
            return {"status": "error", "message": "No file content or valid file path provided"}
            
        # Get file extension for metadata
        _, file_extension = os.path.splitext(safe_filename)

        # Get encryption key
        key = derive_encryption_key(username)

        # Generate random nonce
        nonce = get_random_bytes(12)  # AES-GCM recommended 12-byte nonce

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # Prepare file metadata
        file_metadata = {
            "original_filename": safe_filename,
            "file_type": file_extension.lstrip('.').lower(),
            "timestamp": time.time()
        }

        # Add metadata to verification data
        associated_data = json.dumps(file_metadata).encode()

        # Encrypt file content
        ciphertext, tag = cipher.encrypt_and_digest(file_bytes)

        # Prepare encrypted metadata
        encrypted_package = {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "metadata": file_metadata
        }

        # Package encrypted data as JSON and encode for transmission
        encrypted_data = base64.b64encode(json.dumps(encrypted_package).encode()).decode()

        # Send request
        request = {"action": "upload_file", "username": username, "filename": safe_filename, "data": encrypted_data, "session_id": session_id}
        response = send_request(request)
        print(f"{username} uploaded {safe_filename}: {response}")
        return response
    except ValueError as e:
        print(f"Upload error: {e}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        print(f"Encryption or upload error: {e}")
        return {"status": "error", "message": str(e)}

def edit_file(username, file_id):
    """
    Edit a .txt file by downloading it to a temporary folder 'editingfile',
    allowing user to edit, then uploading the modified content to overwrite the original file.
    """
    try:

        session_id = get_session_token(username)
        if not session_id:
            print("session expired or not found, please login again")
            return {"status": "error", "message": "session expired or not found"}
        
        # Verify file_id
        if not isinstance(file_id, (int, str)) or not str(file_id).isdigit():
            return {"status": "error", "message": "Invalid file ID"}
        file_id = int(file_id)

        # Send download request
        request = {"action": "download_file", "username": username, "file_id": file_id, "session_id": session_id}
        logger.debug(f"Sending download request: {request}")
        response = send_request(request)
        logger.debug(f"Download response: {response}")

        if response.get("status") != "success":
            print(f"{username} download file ID {file_id}: {response.get('message', 'unknown error')}")
            return response

        # Parse encrypted package
        encrypted_package = json.loads(base64.b64decode(response["data"]).decode())
        ciphertext = base64.b64decode(encrypted_package["ciphertext"])
        nonce = base64.b64decode(encrypted_package["nonce"])
        tag = base64.b64decode(encrypted_package["tag"])
        file_metadata = encrypted_package.get("metadata", {})

        # Verify file type
        file_type = file_metadata.get("file_type", "").lower()
        if file_type != "txt":
            print(f"Only supports editing .txt files, current file type: {file_type}")
            return {"status": "error", "message": f"Only .txt files can be edited, got: {file_type}"}

        # Decrypt content
        key = derive_encryption_key(username)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        decrypted_content = decrypted_bytes.decode('utf-8')

        # Create temporary editing folder
        temp_dir = os.path.join(BASE_DIR, "editingfile")
        os.makedirs(temp_dir, exist_ok=True)

        # Save file to editingfile folder
        display_filename = file_metadata.get("original_filename", f"file_{file_id}.txt")
        temp_file_path = os.path.join(temp_dir, sanitize_filename(display_filename))
        with open(temp_file_path, 'w', encoding='utf-8') as f:
            f.write(decrypted_content)

        # Prompt user to edit
        print(f"\nPlease in the folder '{temp_dir}' modify the file '{display_filename}'。")
        print("After modification, please enter '1' and press Enter to continue.")
        while True:
            user_input = input("enter: ").strip()
            if user_input == "1":
                break
            print("Please enter '1' to continue.")

        # Read modified content
        try:
            with open(temp_file_path, 'r', encoding='utf-8') as f:
                new_content = f.read()
        except (IOError, UnicodeDecodeError) as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return {"status": "error", "message": f"Failed to read modified file: {str(e)}"}

        # Re-encrypt new content
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(new_content.encode('utf-8'))

        # Prepare encrypted package
        encrypted_package = {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "metadata": {
                "original_filename": display_filename,
                "file_type": "txt",
                "timestamp": time.time()
            }
        }
        encrypted_data = base64.b64encode(json.dumps(encrypted_package).encode()).decode()

        # Send edit request
        request = {
            "action": "edit_file",
            "username": username,
            "file_id": file_id,
            "data": encrypted_data,
            "session_id": session_id
        }
        response = send_request(request)
        print(f"{username} edit ID {file_id}: {response.get('message', 'unknown error')}")

        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)

        return response

    except ValueError as e:
        logger.error(f"Edit error: {e}")
        print(f"Edit error: {e}")
        shutil.rmtree(os.path.join(BASE_DIR, "editingfile"), ignore_errors=True)
        return {"status": "error", "message": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error: {type(e).__name__}: {e}")
        print(f"Unexpected error: {e}")
        shutil.rmtree(os.path.join(BASE_DIR, "editingfile"), ignore_errors=True)
        return {"status": "error", "message": str(e)}


def delete_file(username):
    """
    List all files for the user and allow permanent deletion by file_id
    """
    try:
        
        session_id = get_session_token(username)
        if not session_id:
            print("session expired or not found, please login again")
            return {"status": "error", "message": "session expired or not found"}
        result = list_files(username)
        if result.get("status") != "success":
            print(f"Failed to get the file list: {result.get('message', 'Unknown error')}")
            return result

        files = result.get("files", [])
        if not files:
            print("file not found")
            return {"status": "success", "message": "No files to delete"}

        # Display file list
        print("\n文件列表:")
        print("-" * 50)
        for file in files:
            print(f"file ID: {file['file_id']}")
            print(f"filename: {file['filename']}")
            print(f"size: {file['file_size']} 字节")
            print(f"update time: {file['upload_date']}")
            print(f"last modified: {file['last_modified']}")
            print("-" * 50)

        # Prompt for file_id
        file_id = input_with_validation("please enter delete file ID: ")
        if not file_id.isdigit():
            print("Invalid file ID，must be integer。")
            return {"status": "error", "message": "Invalid file ID"}

        file_id = int(file_id)

        # Verify file_id exists
        valid_ids = [file["file_id"] for file in files]
        if file_id not in valid_ids:
            print("file ID doesn't exist，please check input。")
            return {"status": "error", "message": "File ID not found"}

        # Send delete request
        request = {
            "action": "delete_file",
            "username": username,
            "file_id": file_id,
            "session_id": session_id
        }
        response = send_request(request)
        print(f"{username} delete file ID {file_id}: {response.get('message', 'unknown error')}")

        return response

    except ValueError as e:
        logger.error(f"Delete error: {e}")
        print(f"delete error: {e}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error: {type(e).__name__}: {e}")
        print(f"unknown error: {e}")
        return {"status": "error", "message": str(e)}

def share_file(username, filename, share_with):
    session_id = get_session_token(username)
    if not session_id:
        print("session expired or not found, please login again")
        return {"status": "error", "message": "session expired or not found"}
    


    request = {"action": "share", "username": username, "filename": filename, "share_with": share_with, "session_id": session_id}
    response = send_request(request)
    print(f"{username} 分享 {filename} 给 {share_with}: {response}")
    return response

def list_files(username):
    """list all files for the user"""
    try:
        if not username or not isinstance(username, str):
            return {"status": "error", "message": "Invalid username"}
            
        # get session token
        session_id = get_session_token(username)
        if not session_id:
            return {"status": "error", "message": "，please login first"}
            
        request = {
            "action": "list_files", 
            "username": username,
            "session_id": session_id  # add session_id to request
        }
        response = send_request(request)
        return response
    except Exception as e:
        logger.error(f"List file errors: {str(e)}")
        return {"status": "error", "message": str(e)}

def show_shared_files(username):
    session_id = get_session_token(username)
    if not session_id:
        print("session expired or not found, please login again")
        return {"status": "error", "message": "session expired or not found"}
    print(f"\nGetting files shared with {username}...")
    request = {
        "action": "list_shared_files",
        "username": username
    }
    response = send_request(request)
    if response.get("status") != "success":
        print(f"Error: Unable to get shared file: {response.get('message', 'Unknown error')}")
        return response
    shared_files = response.get("shared_files", [])
    if not shared_files:
        print("No other users have shared files with you.")
        return {"status": "info", "message": "No shared files"}
    print("\nFiles shared with you by other users:")
    print("-" * 70)
    print(f"{'File ID':<8} {'File Name':<30} {'Shared By':<15} {'Shared Date':<20}")
    print("-" * 70)
    for file in shared_files:
        file_id = file.get('file_id', 'N/A')
        filename = file.get('filename', 'Unknown')
        owner = file.get('owner_username', 'Unknown')
        shared_date = file.get('shared_date', 'Unknown')
        if len(filename) > 28:
            display_filename = filename[:25] + "..."
        else:
            display_filename = filename
        print(f"{file_id:<8} {display_filename:<30} {owner:<15} {shared_date:<20}")
    print("-" * 70)
    last_downloaded_id = None  # Prevent duplicate downloads
    while True:
        choice = input_with_validation("\nDo you want to download the shared file? (y/n): ")
        if choice.lower() not in ['y', 'n']:
            print("Please enter 'y' or 'n'")
            continue
        if choice.lower() == 'n':
            break
        file_id_str = input_with_validation("Please enter the file ID to download (or press 'q' to return): ")
        if file_id_str.lower() == 'q':
            break
        if not file_id_str.isdigit():
            print("Invalid file ID, must be a integer.")
            continue
        file_id = int(file_id_str)
        selected_file = next((f for f in shared_files if f.get('file_id') == file_id), None)
        if not selected_file:
            print(f"File with ID {file_id} not found. Please try again.")
            continue
        if file_id == last_downloaded_id:
            print("This file has just been downloaded. Please select another file or try again later.")
            continue
        logger.debug(f"Start downloading shared file ID:{file_id}")
        result = download_file(username, file_id) # Download the file
        last_downloaded_id = file_id
        break
    return {"status": "success"}


def show_files_shared_by_me(username):
    """
    Show files that the current user has shared with others
    """
    session_id = get_session_token(username)
    if not session_id:
        print("session expired or not found, please login again")
        return {"status": "error", "message": "session expired or not found"}
    print(f"\nGetting files {username} has shared with other users...")

    # Request files shared by this user
    request = {
        "action": "list_files_shared_by_me",
        "username": username,
        "session_id": session_id
    }

    response = send_request(request)

    if response.get("status") != "success":
        print(f"Error: Unable to get shared file: {response.get('message', 'Unknown error')}")
        return response

    shared_files = response.get("shared_files", [])

    if not shared_files:
        print("You have no files shared with other users.")
        return {"status": "info", "message": "no shared files"}

    # Display the shared files
    print("\nFiles you share with other users:")
    print("-" * 70)
    print(f"{'File ID':<8} {'File name':<30} {'Shared with':<15} {'Shared date':<20}")
    print("-" * 70)

    for file in shared_files:
        file_id = file.get('file_id', 'N/A')
        filename = file.get('filename', 'Unknown')
        shared_with = file.get('shared_with_username', 'Unknown')
        shared_date = file.get('shared_date', 'Unknown')

        # Truncate long filenames
        if len(filename) > 28:
            display_filename = filename[:25] + "..."
        else:
            display_filename = filename

        print(f"{file_id:<8} {display_filename:<30} {shared_with:<15} {shared_date:<20}")

    print("-" * 70)

    return {"status": "success"}
def share_file(username):
    session_id = get_session_token(username)
    #get file list
    print(f"\nGetting file list for {username}...")
    result = list_files(username)
    if result.get("status") != "success":
        print(f"Error: Unable to get file list: {result.get('message', 'Unknown error')}")
        return result
    files = result.get("files", [])
    if not files:
        print("You don't have any files to share.")
        return {"status": "error", "message": "no shared files"}
        # Display the file list with IDs
        # Display the file list with IDs
    print("\nyour file list:")
    print("-" * 50)
    for file in files:
        print(f"File ID: {file['file_id']}")
        print(f"File name: {file['filename']}")
        print(f"Size: {file['file_size']} bytes")
        print(f"Upload date: {file['upload_date']}")
        print("-" * 50)

    while True:
        file_id_str = input_with_validation("Please enter the file ID to share (or type 'q' to cancel): ")

        if file_id_str.lower() == 'q':
            print("The share operation has been cancelled.")
            return {"status": "cancelled", "message": "User cancels the operation"}

        if not file_id_str.isdigit():
            print("Invalid file ID, must be a number. Please re-enter.")
            continue

        file_id = int(file_id_str)

        # Check if ID is valid
        selected_file = next((f for f in files if f['file_id'] == file_id), None)
        if not selected_file:
            print(f"File with ID {file_id} not found. Please try again.")
            continue

        break

    # Ask for the user to share with
    share_with_username = input_with_validation("Please enter the username you want to share with: ")

    # Proceed with sharing
    filename = selected_file['filename']
    request = {
        "action": "share_file",
        "username": username,
        "filename": filename,  # Using filename instead of file_id
        "share_with_username": share_with_username
    }

    print(f"Sharing '{filename}' to {share_with_username}...")
    response = send_request(request)

    status = response.get("status", "unknown")
    message = response.get("message", "no message")

    if status == "success":
        print(f"Success: Shared '{filename}' to {share_with_username}")
    else:
        print(f"Error: Failed to share '{filename}' with {share_with_username}: {message}")

    return response


def view_logs(admin_username):
    """View system logs for the admin user"""
    session_id = get_session_token(admin_username)
    if not session_id:
        print("The administrator session has expired or does not exist, please log in again")
        return {"status": "error", "message": "admin session expired or not found"}
    request = {"action": "view_logs", "username": admin_username, "session_id": session_id}
    response = send_request(request)

    if response.get("status") == "success":
        logs = response.get("logs", [])

        if not logs:
            print("No log records found.")
            return response

        print(f"\n==== System logging ====")
        print("-" * 80)
        print(f"{'Log ID':<6} {'User':<15} {'Operation Type':<15} {'Timestamp':<22} {'Details'}")
        print("-" * 80)

        for log in logs:
            log_id = log.get('log_id', 'N/A')
            username = log.get('username', 'Unknown')
            action_type = log.get('action_type', 'Unknown')
            timestamp = log.get('timestamp', 'Unknown')
            details = log.get('action_details', '')

            # Truncate long details
            if details and len(details) > 30:
                details = details[:27] + "..."

            print(f"{log_id:<6} {username:<15} {action_type:<15} {timestamp:<22} {details}")

        print("-" * 80)

        # Option to see full details of a specific log
        while True:
            choice = input("\nView detailed log? (Enter log ID or 'q' to quit): ")

            if choice.lower() == 'q':
                break

            if choice.isdigit():
                log_id = int(choice)
                selected_log = next((log for log in logs if log.get('log_id') == log_id), None)

                if selected_log:
                    print("\n==== Log Details ====")
                    for key, value in selected_log.items():
                        print(f"{key}: {value}")
                else:
                    print(f"The log with ID {log_id} was not found.")
            else:
                print("Please enter a valid log ID or 'q' to quit.")
    else:
        print(f"Administrator {admin_username} failed to view log: {response.get('message', 'No message')}")

    return response

def handle_login():
    """Handling login logic"""
    username = input_with_validation("Please enter your username: ")
    password = input_with_validation("Please enter your password: ")

    otp = get_otp(username)
    if not otp:
        print(f"Unable to generate OTP for {username}")
        return False, ""

    print(f"sending {username} Sending OTP...")
    send_result = send_otp_to_phone(username, otp)
    if not send_result:
        print("Error: OTP service is not available. Please run OTP service first.")
        return False, ""

    print("OTP sent successfully!")

    user_input_otp = input_with_validation("Please enter OTP:")
    if user_input_otp != otp:
        print("OTP error, please try again.")
        return False, ""

    result = login_user(username, password, user_input_otp)
    if result.get("status") == "success":
        print(f"user {username} login successful！")
        return True, username
    else:
        print(f"login failed: {result.get('message', 'unknown error')}")
        return False, ""

def logout_user(username):
    """User logout"""
    # Get a session token
    session_id = get_session_token(username)
    if not session_id:
        return {"status": "success", "message": "Already logged out"}
    
    # send logout request
    request = {
        "action": "logout",
        "session_id": session_id
    }
    response = send_request(request)
    
    # Clear the local session regardless of the server response
    clear_session(username)
    print(f"Log out {username}: {response.get('message', 'Success')}")
    return response

def logged_in_menu(username):
    """Login menu"""
    while True:
        clear_screen()
        print(f"\n==== Document Management System - logged in: {username} ====")
        print("1. Reset password")
        print("2. Upload file")
        print("3. Download file")
        print("4. Check file list")
        print("5. Edit file")
        print("6. Delete file")
        print("7. Share file")
        print("8. Check files shared by me")
        print("9. Check files share to  me")
        print("10. Check logs")
        print("11. Logout")
        
        choice = input_with_validation("Please select (1-11): ")
        
        if choice == "1":
            old_password = input_with_validation("Please enter old password: ")
            new_password = input_with_validation("Please enter new password: ")
            result = reset_password(username, old_password, new_password)
            input("press enter to return ...")
        
        elif choice == "2":
            file_path = input_with_validation("Please enter file path: ")
            if not os.path.exists(file_path):
                print("file not found please check file path.")
            else:
                result = upload_file(username, os.path.basename(file_path), file_path=file_path)
            input("press enter to return ...")
        
        elif choice == "3":
            result = list_files(username)
            if result.get("status") == "success":
                files = result.get("files", [])
                if not files:
                    print("file not found")
                else:
                    print("\nfile list:")
                    print("-" * 50)
                    for file in files:
                        print(f"file ID: {file['file_id']}")
                        print(f"filename: {file['filename']}")
                        print(f"size: {file['file_size']} 字节")
                        print(f"upload date: {file['upload_date']}")
                        print(f"last modified: {file['last_modified']}")
                        print("-" * 50)
                    file_id = input_with_validation("please enter download file ID: ")
                    if not file_id.isdigit():
                        print("Invalid file ID, must be a integer.")
                    else:
                        result = download_file(username, file_id)
            else:
                print(f"error: {result.get('message', 'unknwon error')}")
            input("press enter to return ...")
        
        elif choice == "4":
            result = list_files(username)
            if result.get("status") == "success":
                files = result.get("files", [])
                if not files:
                    print("file not found")
                else:
                    print("\nfile list:")
                    print("-" * 50)
                    for file in files:
                        print(f"file ID: {file['file_id']}")
                        print(f"filename: {file['filename']}")
                        print(f"size: {file['file_size']} 字节")
                        print(f"upload date: {file['upload_date']}")
                        print(f"last modified: {file['last_modified']}")
                        print("-" * 50)
            else:
                print(f"error: {result.get('message', 'unknown error')}")
            input("press enter to return ...")
        
        elif choice == "5":
            result = list_files(username)
            if result.get("status") == "success":
                files = result.get("files", [])
                if not files:
                    print("file not found")
                else:
                    print("\nfile list:")
                    print("-" * 50)
                    for file in files:
                        print(f"file ID: {file['file_id']}")
                        print(f"filename: {file['filename']}")
                        print(f"size: {file['file_size']} 字节")
                        print(f"upload date: {file['upload_date']}")
                        print(f"last modified: {file['last_modified']}")
                        print("-" * 50)
                    file_id = input_with_validation("Please enter the file to edit ID: ")
                    if not file_id.isdigit():
                        print("Invalid file ID, must be a integer.")
                    else:
                        result = edit_file(username, file_id)
            else:
                print(f"error: {result.get('message', 'unknown error')}")
            input("press enter to return ...")
        
        elif choice == "6":
            result = delete_file(username)
            input("press enter to return ...")
        
        elif choice == "7":
            result = share_file(username)
            input("press enter to return ...")
        
        elif choice == "8":
            result = show_files_shared_by_me(username)
            input("press enter to return ...")
        
        elif choice == "9":
            result = show_shared_files(username)
            input("press enter to return ...")
        
        elif choice == "10":
            result = view_logs(username)
            input("press enter to return ...")
        
        elif choice == "11":
            print("Logging out...")
            logout_user(username)
            input("Logout completed, press Enter to return to the main menu...")
            return
        
        else:
            print("Invalid option, please select 1-11.")
            input("press enter to continue...")


def initial_menu():
    """Initial menu for the file management system"""
    while True:
        clear_screen()
        print("\n==== File Management System ====")
        print("1. Register")
        print("2. Login")
        print("3. Admin Login")
        print("4. Exit")
        
        choice = input_with_validation("Please select (1-4): ")
        
        if choice == "1":
            username = input_with_validation("Please enter username: ")
            password = input_with_validation("Please enter password: ")
            result = register_user(username, password)
            input("press enter to return ...")
        
        elif choice == "2":
            success, username = handle_login()
            if success:
                logged_in_menu(username)

        elif choice == "3":
            success, username = admin_login()
            if success:
                logged_in_menu(username)
            else:
                input("press enter to return ...")

        elif choice == "4":
            print("Exiting the system...")
            break
        
        else:
            print("Invalid option, please select 1-4.")
            input("press enter to continue...")


def main():
    """Main function"""
    clear_screen()
    print("Welcome to the File Management System！")
    initial_menu()

if __name__ == "__main__":
    main()