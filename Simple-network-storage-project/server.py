import socket
import json
import sqlite3
import time
import os
import sys
import hashlib
import secrets
import base64
import re
import logging
from concurrent.futures import ThreadPoolExecutor
import pyotp  
import datetime
SESSION_TIMEOUT = 7200  # 2 hours valid
sessions = {}

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("SecureStorage")

# Server configuration
HOST = 'localhost'
PORT = 9999
MAX_BUFFER_SIZE = 8192  # 8KB buffer for basic messages
MAX_CONNECTIONS = 10
DB_PATH = 'storage.db'
TOKEN_EXPIRY = 7200  # Session token expiry in seconds (2 hours)
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutes in seconds

# Rate limiting settings
RATE_LIMIT_WINDOW = 60  # 1 minute
RATE_LIMIT_MAX_REQUESTS = 30  # Max 30 requests per minute

# Dictionary to track rate limiting
rate_limit_tracker = {}

# Dictionary to track failed login attempts
failed_logins = {}

# Create a thread pool for handling client connections
thread_pool = ThreadPoolExecutor(max_workers=10)


def get_db_connection():
    """Create and return a database connection with proper settings"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Allow column access by name
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def close_connection(conn):
    """Safely close a database connection"""
    if conn:
        conn.close()


def check_rate_limit(ip_address):
    """
    Implement rate limiting to prevent brute force attacks
    Returns True if request should be allowed, False otherwise
    """
    current_time = time.time()

    if ip_address not in rate_limit_tracker:
        rate_limit_tracker[ip_address] = {'count': 1, 'reset_time': current_time + RATE_LIMIT_WINDOW}
        return True

    tracker = rate_limit_tracker[ip_address]

    # If window has expired, reset the counter
    if current_time > tracker['reset_time']:
        tracker['count'] = 1
        tracker['reset_time'] = current_time + RATE_LIMIT_WINDOW
        return True

    # Check if we've hit the rate limit
    if tracker['count'] >= RATE_LIMIT_MAX_REQUESTS:
        return False

    # Increment the counter and allow the request
    tracker['count'] += 1
    return True


def generate_random_token():
    """create random secure token for session"""
    return secrets.token_hex(32)


def create_session(user_id, username):  # used for login
    session_id = generate_random_token()  # create random token
    current_time = time.time()
    expiry = current_time + SESSION_TIMEOUT
    sessions[session_id] = {"user_id": user_id, "username": username, "expiry": expiry}
    return session_id
    
def validate_session(session_id, username=None):
    """validate session token"""
    current_time = time.time()
    if session_id not in sessions:
        return False
        
    session = sessions[session_id]
    # provide username and it doesn't match, return False
    if username and session["username"] != username:
        return False
        
    # check session expiry
    if session["expiry"] < current_time:
        # 清除过期会话
        del sessions[session_id]
        return False
        
    # if not username then return user_id
    if not username:
        return session["user_id"]
    return True


def generate_signature(user_id, action_type, timestamp, details=None):
    """
    Generate a digital signature for audit log non-repudiation
    This provides cryptographic proof of the action
    """
    # In a real system, this would use asymmetric cryptography
    # For simplicity, we'll use a keyed hash as signature
    server_secret = "SERVER_SECRET_KEY_CHANGE_IN_PRODUCTION"  # In production, use proper key management

    signature_data = f"{user_id}|{action_type}|{timestamp}"
    if details:
        signature_data += f"|{details}"

    signature = hashlib.sha256((signature_data + server_secret).encode()).hexdigest()
    return signature


def log_action(user_id, action_type, action_details=None, ip_address=None):
    """
    Record user actions with digital signature for non-repudiation
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        timestamp = datetime.datetime.now()

        # Generate cryptographic signature for non-repudiation
        signature = generate_signature(user_id, action_type, timestamp, action_details)

        # Insert into audit_logs table
        cursor.execute("""
            INSERT INTO audit_logs 
            (user_id, action_type, action_details, ip_address, timestamp, signature) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, action_type, action_details, ip_address, timestamp, signature))

        conn.commit()
        logger.info(f"Action logged: {action_type} by user {user_id}")
        return True
    except Exception as e:
        logger.error(f"Error logging action: {e}")
        return False
    finally:
        close_connection(conn)


def validate_input(data, regex_pattern=None):
    """
    Validate input data for common security issues
    Returns sanitized data or None if invalid
    """
    if data is None:
        return None

    # Convert to string if not already
    if not isinstance(data, str):
        data = str(data)

    # Check for SQL injection patterns
    sql_patterns = [
        "--", ";--", ";", "/*", "*/", "@@", "@",
        "EXEC", "EXECUTE", "INSERT", "DROP", "DELETE", "UPDATE", "SELECT",
        "UNION", "CREATE", "ALTER", "TRUNCATE", "DECLARE", "WAITFOR"
    ]

    # Convert to lowercase for case-insensitive comparison
    data_lower = data.lower()
    for sql_pattern in sql_patterns:  # Changed variable name here
        if sql_pattern.lower() in data_lower:
            logger.warning(f"Potential SQL injection detected: {data}")
            return None

    # Check for path traversal
    if ".." in data or "/" in data or "\\" in data:
        if not (regex_pattern and re.match(regex_pattern, data)):
            logger.warning(f"Potential path traversal detected: {data}")
            return None

    # If a specific pattern is provided, validate against it
    if regex_pattern and not re.match(regex_pattern, data):
        logger.warning(f"Input validation failed for pattern {regex_pattern}: {data}")
        return None

    return data

def handle_register(request, ip_address=None):
    """
    Handle user registration request
    """
    # Validate inputs
    username = validate_input(request.get("username"), r'^[a-zA-Z0-9_]{3,32}$')
    password_hash = request.get("password_hash")

    if not username or not password_hash:
        return {"status": "error", "message": "Invalid username or password format"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if username already exists
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return {"status": "error", "message": "Username already exists"}

        # Generate a salt and final password hash
        salt = secrets.token_hex(16)
        final_password_hash = hashlib.sha256((password_hash + salt).encode()).hexdigest()

        # Generate OTP secret for MFA
        otp_secret = pyotp.random_base32()

        # Insert new user
        cursor.execute("""
    INSERT INTO users 
    (username, password_hash, salt, creation_date, last_login, otp_secret) 
    VALUES (?, ?, ?, ?, ?, ?)
""", (username, final_password_hash, salt, datetime.datetime.now(), None, otp_secret))
        user_id = cursor.lastrowid
        conn.commit()

        # Log the registration
        log_action(user_id, "user_register", f"New user registered: {username}", ip_address)

        # Generate OTP provisioning URI for QR code
        otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(
            name=username,
            issuer_name="SecureStorage"
        )

        return {
            "status": "success",
            "message": "User registered successfully",
            "user_id": user_id,
            "otp_secret": otp_secret,
            "otp_uri": otp_uri
        }
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return {"status": "error", "message": "Registration failed"}
    finally:
        close_connection(conn)


def handle_login(request, ip_address=None):
    """
    Handle user login request with MFA
    """
    username = validate_input(request.get("username"))
    password_hash = request.get("password_hash")
    otp_code = request.get("otp_code")

    if not username or not password_hash:
        return {"status": "error", "message": "Invalid credentials"}

    # Check for brute force attempts
    current_time = time.time()
    if username in failed_logins:
        attempts, lockout_time = failed_logins[username]
        if attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
            if current_time < lockout_time:
                return {"status": "error", "message": "Account temporarily locked. Try again later."}
            else:
                # Reset failed attempts after lockout period
                failed_logins[username] = (0, 0)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user information
        cursor.execute("""
            SELECT user_id, password_hash, salt, is_admin, otp_secret 
            FROM users 
            WHERE username = ?
        """, (username,))

        user = cursor.fetchone()
        if not user:
            # Increment failed login attempts
            if username in failed_logins:
                attempts, _ = failed_logins[username]
                failed_logins[username] = (
                attempts + 1, current_time + LOCKOUT_TIME if attempts + 1 >= MAX_FAILED_LOGIN_ATTEMPTS else 0)
            else:
                failed_logins[username] = (1, 0)

            return {"status": "error", "message": "Invalid credentials"}

        # Verify password
        expected_hash = hashlib.sha256((password_hash + user['salt']).encode()).hexdigest()
        if expected_hash != user['password_hash']:
            # Increment failed login attempts
            if username in failed_logins:
                attempts, _ = failed_logins[username]
                failed_logins[username] = (
                attempts + 1, current_time + LOCKOUT_TIME if attempts + 1 >= MAX_FAILED_LOGIN_ATTEMPTS else 0)
            else:
                failed_logins[username] = (1, 0)

            return {"status": "error", "message": "Invalid credentials"}

        # Verify OTP if provided
        if otp_code:
            otp_secret = user['otp_secret']
            totp = pyotp.TOTP(otp_secret,interval=300)
            if not totp.verify(otp_code):
                # Increment failed login attempts
                if username in failed_logins:
                    attempts, _ = failed_logins[username]
                    failed_logins[username] = (
                    attempts + 1, current_time + LOCKOUT_TIME if attempts + 1 >= MAX_FAILED_LOGIN_ATTEMPTS else 0)
                else:
                    failed_logins[username] = (1, 0)

                return {"status": "error", "message": "Invalid OTP code"}

        # Create a new session
        session_id = create_session(user['user_id'], username)

        # Update last login time
        cursor.execute("""
            UPDATE users 
            SET last_login = ? 
            WHERE user_id = ?
        """, (datetime.datetime.now(), user['user_id']))

        conn.commit()

        # Log the login
        log_action(user['user_id'], "user_login", f"User logged in: {username}", ip_address)

        # Reset failed login attempts
        if username in failed_logins:
            failed_logins.pop(username)

        return {
            "status": "success",
            "message": "Login successful",
            "session_id": session_id,
            "user_id": user['user_id'],
            "is_admin": user['is_admin']
        }
    except Exception as e:
        logger.error(f"Login error: {e}")
        return {"status": "error", "message": "Login failed"}
    finally:
        close_connection(conn)


def handle_reset_password(request, ip_address=None):
    """
    Handle password reset request
    """
    # get and verify session
    session_id = request.get("session_id")
    username = validate_input(request.get("username"))
    
    # verify session validation
    if not validate_session(session_id, username):
        return {"status": "error", "message": "Invalid or expired session, please log in again"}

    old_password_hash = request.get("old_password_hash")
    new_password_hash = request.get("new_password_hash")

    if not old_password_hash or not new_password_hash:
        return {"status": "error", "message": "missing password"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # get password information
        cursor.execute("""
            SELECT user_id, password_hash, salt 
            FROM users 
            WHERE username = ?
        """, (username,))

        user = cursor.fetchone()
        if not user:
            return {"status": "error", "message": "user not found"}

        # verify old password
        expected_hash = hashlib.sha256((old_password_hash + user['salt']).encode()).hexdigest()
        if expected_hash != user['password_hash']:
            return {"status": "error", "message": "password is not correct"}

        # create new salt and hash
        new_salt = secrets.token_hex(16)
        final_new_hash = hashlib.sha256((new_password_hash + new_salt).encode()).hexdigest()

        # update password
        cursor.execute("""
            UPDATE users 
            SET password_hash = ?, salt = ? 
            WHERE username = ?
        """, (final_new_hash, new_salt, username))

        conn.commit()

        # log the password reset
        log_action(user['user_id'], "password_reset", "password is reset", ip_address)

        # tell client need to re-login
        return {
            "status": "success", 
            "message": "reset finished",
            "require_relogin": True  # need to re-login
        }
    except Exception as e:
        logger.error(f"password reset error: {e}")
        return {"status": "error", "message": "password reset failed"}
    finally:
        close_connection(conn)


def handle_upload_file(request, ip_address=None):
    """
    Handle file upload request with simplified interface
    """
    username = validate_input(request.get("username"))
    session_id = request.get("session_id")
    
    if not username:
        return {"status": "error", "message": "Invalid username"}
    
    if not validate_session(session_id, username):
        return {"status": "error", "message": "Invalid or expired session, please log in again"}
        
    # Get user_id from username
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            return {"status": "error", "message": "User not found"}
        
        user_id = user['user_id']
        
        # Get filename and data from request
        filename = validate_input(request.get("filename"), r'^[a-zA-Z0-9_\-. ]{1,255}$')
        encrypted_data_str = request.get("data")  # This contains all the encrypted package
        
        if not filename or not encrypted_data_str:
            return {"status": "error", "message": "Missing filename or file data"}
            
        # Decode the encrypted package
        try:
            encrypted_package_json = base64.b64decode(encrypted_data_str).decode()
            encrypted_package = json.loads(encrypted_package_json)
            
            # Extract data from the package
            ciphertext = base64.b64decode(encrypted_package["ciphertext"])
            nonce = encrypted_package["nonce"]  # Keep as base64 for storage
            tag = encrypted_package["tag"]      # Keep as base64 for storage
            metadata = encrypted_package.get("metadata", {})
            
            original_filename = metadata.get("original_filename", filename)
            file_size = len(ciphertext)
            
            # Generate a unique filename to prevent overwriting
            safe_filename = f"{int(time.time())}_{filename}"
            file_path = os.path.join("files", safe_filename)
            
            # Ensure the files directory exists
            os.makedirs("files", exist_ok=True)
            
            # Save the encrypted file
            with open(file_path, 'wb') as f:
                f.write(ciphertext)
                
            # Create file record
            cursor.execute("""
                INSERT INTO files 
                (filename, original_filename, owner_id, upload_date, last_modified, file_size, file_path, is_deleted) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                safe_filename,
                original_filename,
                user_id,
                datetime.datetime.now(),
                datetime.datetime.now(),
                file_size,
                file_path,
                0
            ))
            
            file_id = cursor.lastrowid
            
            # Store encryption information
            cursor.execute("""
                INSERT INTO file_keys 
                (file_id, key_encrypted, iv) 
                VALUES (?, ?, ?)
            """, (file_id, tag, nonce))  # Using tag as key_encrypted and nonce as iv
            
            conn.commit()
            
            # Log the upload
            log_action(user_id, "file_upload", f"Uploaded file: {original_filename}", ip_address)
            
            return {
                "status": "success",
                "message": "File uploaded successfully",
                "file_id": file_id
            }
            
        except json.JSONDecodeError:
            return {"status": "error", "message": "Invalid encrypted package format"}
        except KeyError as e:
            return {"status": "error", "message": f"Missing required encryption data: {str(e)}"}
            
    except Exception as e:
        logger.error(f"File upload error: {e}")
        return {"status": "error", "message": "File upload failed"}
    finally:
        close_connection(conn)
    


# setting logs
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SecureStorage')

def handle_download_file(request, ip_address=None):
    """
    Handle file download request, allowing both owner and users with share permissions
    """
    username = validate_input(request.get("username"))
    file_id = request.get("file_id")
    session_id = request.get("session_id")

    if not username or not file_id:
        logger.debug(f"Invalid input: username={username}, file_id={file_id}")
        return {"status": "error", "message": "Invalid username or file ID"}
    
    if not validate_session(session_id, username):
        return {"status": "error", "message": "Invalid or expired session, please log in again"}

    try:
        file_id = int(file_id)  # make sure file_id is integer
    except (TypeError, ValueError):
        logger.debug(f"Invalid file_id: {file_id}")
        return {"status": "error", "message": "Invalid file ID"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # get user_id
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            logger.debug(f"User not found: username={username}")
            return {"status": "error", "message": "User not found"}
        user_id = user['user_id']

        # Check if the user is the file owner or has sharing permissions
        cursor.execute("""
            SELECT f.file_id, f.filename, f.original_filename, f.file_path, f.owner_id, u.username as owner_username
            FROM files f
            JOIN users u ON f.owner_id = u.user_id
            WHERE f.file_id = ? AND f.is_deleted = 0 
            AND (f.owner_id = ? OR EXISTS (
                SELECT 1 FROM file_permissions p 
                WHERE p.file_id = f.file_id AND p.user_id = ?
            ))
        """, (file_id, user_id, user_id))

        file = cursor.fetchone()
        if not file:
            logger.debug(f"File not found or no permission: file_id={file_id}, user_id={user_id}")
            return {"status": "error", "message": "File not found or you don't have permission to download"}

        # Get the encryption key and IV
        cursor.execute("SELECT key_encrypted, iv FROM file_keys WHERE file_id = ?", (file['file_id'],))
        key_data = cursor.fetchone()
        if not key_data:
            logger.debug(f"Encryption key not found for file_id={file['file_id']}")
            return {"status": "error", "message": "Encryption key not found"}

        # Reading encrypted files
        if not os.path.exists(file['file_path']):
            logger.error(f"File path does not exist: {file['file_path']}")
            return {"status": "error", "message": "File not found on server"}
        with open(file['file_path'], 'rb') as f:
            encrypted_data = f.read()

        # verify and clean nonce and tag  Base64 encode
        try:
            nonce_clean = base64.b64encode(base64.b64decode(key_data['iv'], validate=True)).decode('utf-8')
            tag_clean = base64.b64encode(base64.b64decode(key_data['key_encrypted'], validate=True)).decode('utf-8')
        except base64.binascii.Error as e:
            logger.error(f"Invalid Base64 data: iv={key_data['iv']}, key_encrypted={key_data['key_encrypted']}, error: {e}")
            return {"status": "error", "message": f"Invalid encryption data: {str(e)}"}

        # Prepare encryption package
        encrypted_package = {
            "ciphertext": base64.b64encode(encrypted_data).decode('utf-8'),
            "nonce": nonce_clean,
            "tag": tag_clean,
            "metadata": {
                "original_filename": file['original_filename'],
                "file_type": os.path.splitext(file['original_filename'])[1].lstrip('.').lower(),
                "owner_username": file['owner_username']  # Add owner username
            }
        }

        # Record download operations
        log_action(user_id, "file_download", f"Downloaded file: {file['original_filename']}", ip_address)

        # Encoding JSON and validating
        try:
            json_str = json.dumps(encrypted_package)
            logger.debug(f"Encrypted package JSON: {json_str[:100]}...")
        except TypeError as e:
            logger.error(f"JSON encoding error: {e}, package content: {encrypted_package}")
            return {"status": "error", "message": f"JSON encoding error: {str(e)}"}

        # Returns a Base64-encoded JSON packet
        return {
            "status": "success",
            "message": "File download successful",
            "data": base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        }

    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        return {"status": "error", "message": f"Database error: {str(e)}"}
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return {"status": "error", "message": f"File not found: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error: {type(e).__name__}: {e}")
        return {"status": "error", "message": f"Unexpected error: {str(e)}"}
    finally:
        close_connection(conn)

def handle_delete_file(request, ip_address=None):
    """
    Handle file deletion request using file_id and username (hard delete)
    """
    username = validate_input(request.get("username"))
    file_id = request.get("file_id")
    session_id = request.get("session_id")

    if not username or not file_id:
        logger.debug(f"Missing username or file ID: username={username}, file_id={file_id}")
        return {"status": "error", "message": "Missing username or file ID"}
    
    if not validate_session(session_id, username):
        return {"status": "error", "message": "Invalid or expired session, please log in again"}

    try:
        file_id = int(file_id)  # Ensure file_id is integer
    except (TypeError, ValueError):
        logger.debug(f"Invalid file_id: {file_id}")
        return {"status": "error", "message": "Invalid file ID"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user_id from username
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            logger.debug(f"User not found: username={username}")
            return {"status": "error", "message": "User not found"}
        user_id = user['user_id']

        # Check if user owns the file
        cursor.execute("""
            SELECT file_id, original_filename, file_path
            FROM files
            WHERE file_id = ? AND owner_id = ? AND is_deleted = 0
        """, (file_id, user_id))

        file = cursor.fetchone()
        if not file:
            logger.debug(f"File not found or not owned: file_id={file_id}, user_id={user_id}")
            return {"status": "error", "message": "File not found or you don't have permission to delete"}

        # Delete physical file
        try:
            if os.path.exists(file['file_path']):
                os.remove(file['file_path'])
                logger.info(f"Deleted physical file: {file['file_path']}")
            else:
                logger.warning(f"Physical file not found: {file['file_path']}")
        except OSError as e:
            logger.error(f"Failed to delete physical file: {file['file_path']}, error: {e}")
            return {"status": "error", "message": f"Failed to delete file from storage: {str(e)}"}

        # Delete from file_keys table
        cursor.execute("DELETE FROM file_keys WHERE file_id = ?", (file_id,))

        # Delete from files table
        cursor.execute("DELETE FROM files WHERE file_id = ?", (file_id,))

        conn.commit()

        # Log the deletion
        log_action(user_id, "file_delete", f"Hard deleted file: {file['original_filename']}", ip_address)

        return {"status": "success", "message": "File permanently deleted"}
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        return {"status": "error", "message": f"Database error: {str(e)}"}
    except Exception as e:
        logger.error(f"File deletion error: {type(e).__name__}: {e}")
        return {"status": "error", "message": f"File deletion failed: {str(e)}"}
    finally:
        close_connection(conn)



def handle_share_file(request, ip_address=None):
    """
    Handle file sharing request
    """
    username = validate_input(request.get("username"))
    session_id = request.get("session_id")
    user_id = validate_session(session_id)
    session_id = request.get("session_id")

    if not user_id:
        return {"status": "error", "message": "Invalid or expired session"}
    
    if not validate_session(session_id, username):
        return {"status": "error", "message": "Invalid or expired session, please login again"}
        

    file_id = request.get("file_id")
    share_with_username = validate_input(request.get("share_with_username"))

    if not file_id or not share_with_username:
        return {"status": "error", "message": "Missing required information"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user owns the file
        cursor.execute("""
            SELECT file_id, original_filename
            FROM files
            WHERE file_id = ? AND owner_id = ? AND is_deleted = 0
        """, (file_id, user_id))

        file = cursor.fetchone()
        if not file:
            return {"status": "error", "message": "File not found or you don't have permission to share"}

        # Get the user ID of the user to share with
        cursor.execute("""
            SELECT user_id, username
            FROM users
            WHERE username = ?
        """, (share_with_username,))

        share_user = cursor.fetchone()
        if not share_user:
            return {"status": "error", "message": "User to share with not found"}

        # Check if already shared
        cursor.execute("""
            SELECT permission_id
            FROM file_permissions
            WHERE file_id = ? AND user_id = ?
        """, (file_id, share_user['user_id']))

        if cursor.fetchone():
            return {"status": "error", "message": "File already shared with this user"}

        # Create permission record
        cursor.execute("""
            INSERT INTO file_permissions
            (file_id, user_id, granted_by, granted_date)
            VALUES (?, ?, ?, ?)
        """, (file_id, share_user['user_id'], user_id, datetime.datetime.now()))

        conn.commit()

        # Log the sharing
        log_action(
            user_id,
            "file_share",
            f"Shared file: {file['original_filename']} with user: {share_user['username']}",
            ip_address
        )

        return {"status": "success", "message": "File shared successfully"}
    except Exception as e:
        logger.error(f"File sharing error: {e}")
        return {"status": "error", "message": "File sharing failed"}
    finally:
        close_connection(conn)


def list_user_files(request):
    """
    List all non-deleted files for a given user
    """
    try:
        session_id = request.get("session_id")
        username = validate_input(request.get("username"))
        session_id = request.get("session_id")
        
        # Verify session validity
        if not validate_session(session_id, username):
            return {"status": "error", "message": "Not logged in or the session has expired, please log in first"}
        
        if not validate_session(session_id, username):
            return {"status": "error", "message": "Invalid or expired session, please login again"}
        # Get a database connection
        conn = get_db_connection()
        cursor = conn.cursor()

        # Query User ID
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            return {"status": "error", "message": "User not found"}

        user_id = user['user_id']

        # Query all undeleted files of a user
        cursor.execute("""
            SELECT file_id, original_filename, file_size, upload_date, last_modified
            FROM files
            WHERE owner_id = ? AND is_deleted = 0
            ORDER BY upload_date DESC
        """, (user_id,))
        
        files = cursor.fetchall()

        # Formatting file lists
        file_list = []
        for file in files:
            upload_date = file['upload_date']
            last_modified = file['last_modified']
            
            # Processing string dates
            if isinstance(upload_date, str):
                try:
                    # First try the format with milliseconds
                    upload_date = datetime.datetime.strptime(upload_date, "%Y-%m-%d %H:%M:%S.%f")
                except ValueError:
                    try:
                        # Fallback to format without milliseconds
                        upload_date = datetime.datetime.strptime(upload_date, "%Y-%m-%d %H:%M:%S")
                    except ValueError as e:
                        logger.error(f"Invalid upload_date format: {upload_date}, error: {e}")
                        upload_date = datetime.datetime.now()
            if isinstance(last_modified, str):
                try:
                    # First try the format with milliseconds
                    last_modified = datetime.datetime.strptime(last_modified, "%Y-%m-%d %H:%M:%S.%f")
                except ValueError:
                    try:
                        # Fallback to format without milliseconds
                        last_modified = datetime.datetime.strptime(last_modified, "%Y-%m-%d %H:%M:%S")
                    except ValueError as e:
                        logger.error(f"Invalid last_modified format: {last_modified}, error: {e}")
                        last_modified = datetime.datetime.now()
                
            file_list.append({
                "file_id": file['file_id'],
                "filename": file['original_filename'],
                "file_size": file['file_size'],
                "upload_date": upload_date.isoformat(),
                "last_modified": last_modified.isoformat()
            })

        # Logging the action
        log_action(user_id, "list_files", f"Listed all files for user {username}")

        return {
            "status": "success",
            "message": "Files retrieved successfully",
            "files": file_list
        }

    except Exception as e:
        logger.error(f"List files error: {type(e).__name__}: {e}")
        return {"status": "error", "message": f"Failed to retrieve files: {str(e)}"}
    finally:
        close_connection(conn)

def handle_delete_file(request, ip_address=None):
    """
    Handle file deletion request using file_id and username (hard delete)
    """
    username = validate_input(request.get("username"))
    file_id = request.get("file_id")

    if not username or not file_id:
        logger.debug(f"Missing username or file ID: username={username}, file_id={file_id}")
        return {"status": "error", "message": "Missing username or file ID"}

    try:
        file_id = int(file_id)  # Ensure file_id is integer
    except (TypeError, ValueError):
        logger.debug(f"Invalid file_id: {file_id}")
        return {"status": "error", "message": "Invalid file ID"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user_id from username
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            logger.debug(f"User not found: username={username}")
            return {"status": "error", "message": "User not found"}
        user_id = user['user_id']

        # Check if user owns the file
        cursor.execute("""
            SELECT file_id, original_filename, file_path
            FROM files
            WHERE file_id = ? AND owner_id = ? AND is_deleted = 0
        """, (file_id, user_id))

        file = cursor.fetchone()
        if not file:
            logger.debug(f"File not found or not owned: file_id={file_id}, user_id={user_id}")
            return {"status": "error", "message": "File not found or you don't have permission to delete"}

        # Delete physical file
        try:
            if os.path.exists(file['file_path']):
                os.remove(file['file_path'])
                logger.info(f"Deleted physical file: {file['file_path']}")
            else:
                logger.warning(f"Physical file not found: {file['file_path']}")
        except OSError as e:
            logger.error(f"Failed to delete physical file: {file['file_path']}, error: {e}")
            return {"status": "error", "message": f"Failed to delete file from storage: {str(e)}"}

        # Delete from file_keys table
        cursor.execute("DELETE FROM file_keys WHERE file_id = ?", (file_id,))

        # Delete from files table
        cursor.execute("DELETE FROM files WHERE file_id = ?", (file_id,))

        conn.commit()

        # Log the deletion
        log_action(user_id, "file_delete", f"Hard deleted file: {file['original_filename']}", ip_address)

        return {"status": "success", "message": "File permanently deleted"}
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        return {"status": "error", "message": f"Database error: {str(e)}"}
    except Exception as e:
        logger.error(f"File deletion error: {type(e).__name__}: {e}")
        return {"status": "error", "message": f"File deletion failed: {str(e)}"}
    finally:
        close_connection(conn)


def handle_view_logs(request, ip_address=None):
    """
    Handle admin request to view audit logs
    """
    username= validate_input(request.get("username"))

    if not username:
        return {"status": "error", "message": "Invalid or expired session"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user is admin
        cursor.execute("""
            SELECT is_admin
            FROM users
            WHERE user_id = ?
        """, (username,))

        user = cursor.fetchone()
        if username!='admin':
            return {"status": "error", "message": "Admin privileges required"}

        # Get logs with limit and pagination
        limit = request.get("limit", 100)
        offset = request.get("offset", 0)

        cursor.execute("""
            SELECT l.log_id, l.user_id, u.username, l.action_type, l.action_details, 
                   l.ip_address, l.timestamp, l.signature
            FROM audit_logs l
            LEFT JOIN users u ON l.user_id = u.user_id
            ORDER BY l.timestamp DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))

        logs = [dict(row) for row in cursor.fetchall()]

        # Log the viewing of logs
        log_action(username, "view_logs", f"Viewed audit logs (limit: {limit}, offset: {offset})", ip_address)

        return {
            "status": "success",
            "message": "Logs retrieved successfully",
            "logs": logs
        }
    except Exception as e:
        logger.error(f"View logs error: {e}")
        return {"status": "error", "message": "Failed to retrieve logs"}
    finally:
        close_connection(conn)



def handle_logout(request, ip_address=None):
    """
    Handle user logout request
    """
    session_id = request.get("session_id")
    user_id = validate_session(session_id)

    if not user_id:
        return {"status": "error", "message": "Invalid or expired session"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Delete the session
        cursor.execute("""
            DELETE FROM sessions
            WHERE session_id = ?
        """, (session_id,))

        conn.commit()

        # Log the logout
        log_action(user_id, "user_logout", "User logged out", ip_address)

        return {"status": "success", "message": "Logout successful"}
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return {"status": "error", "message": "Logout failed"}
    finally:
        close_connection(conn)


def handle_edit_file(request, ip_address=None):
    """
    Handle file edit request for .txt files
    """
    username = validate_input(request.get("username"))
    file_id = request.get("file_id")
    encrypted_data_str = request.get("data")  # Base64-encoded encrypted package

    if not username or not file_id or not encrypted_data_str:
        logger.debug(f"Invalid input: username={username}, file_id={file_id}")
        return {"status": "error", "message": "Missing username, file ID, or file data"}

    try:
        file_id = int(file_id)  # Ensure file_id is integer
    except (TypeError, ValueError):
        logger.debug(f"Invalid file_id: {file_id}")
        return {"status": "error", "message": "Invalid file ID"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user_id
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            logger.debug(f"User not found: username={username}")
            return {"status": "error", "message": "User not found"}
        user_id = user['user_id']

        # Check if user owns the file and it's a .txt file
        cursor.execute("""
            SELECT f.file_id, f.filename, f.original_filename, f.file_path, f.owner_id, f.file_size
            FROM files f
            WHERE f.file_id = ? AND f.is_deleted = 0 AND f.owner_id = ?
        """, (file_id, user_id))
        file = cursor.fetchone()
        if not file:
            logger.debug(f"File not found or not owned: file_id={file_id}, user_id={user_id}")
            return {"status": "error", "message": "File not found or not owned"}

        # Get encryption key and IV
        cursor.execute("SELECT key_encrypted, iv FROM file_keys WHERE file_id = ?", (file['file_id'],))
        key_data = cursor.fetchone()
        if not key_data:
            logger.debug(f"Encryption key not found for file_id={file['file_id']}")
            return {"status": "error", "message": "Encryption key not found"}

        # Verify file type from filename
        _, ext = os.path.splitext(file['original_filename'])
        if ext.lower() != '.txt':
            logger.debug(f"File is not a .txt file: file_id={file_id}, ext={ext}")
            return {"status": "error", "message": "Only .txt files can be edited"}

        # Decode new encrypted package
        try:
            encrypted_package_json = base64.b64decode(encrypted_data_str).decode()
            encrypted_package = json.loads(encrypted_package_json)
            ciphertext = base64.b64decode(encrypted_package["ciphertext"])
            nonce = encrypted_package["nonce"]  # Base64 string
            tag = encrypted_package["tag"]      # Base64 string
            metadata = encrypted_package.get("metadata", {})
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Invalid encrypted package: {str(e)}")
            return {"status": "error", "message": "Invalid encrypted package format"}

        # Verify metadata consistency
        if metadata.get("original_filename") != file['original_filename']:
            logger.debug(f"Metadata filename mismatch: received={metadata.get('original_filename')}, expected={file['original_filename']}")
            return {"status": "error", "message": "Filename mismatch in metadata"}

        # Update file content
        try:
            with open(file['file_path'], 'wb') as f:
                f.write(ciphertext)
        except IOError as e:
            logger.error(f"Failed to write file: {file['file_path']}, error: {e}")
            return {"status": "error", "message": "Failed to update file content"}

        # Update files table
        cursor.execute("""
            UPDATE files
            SET last_modified = ?, file_size = ?
            WHERE file_id = ?
        """, (datetime.datetime.now(), len(ciphertext), file_id))

        # Update file_keys table
        cursor.execute("""
            UPDATE file_keys
            SET key_encrypted = ?, iv = ?
            WHERE file_id = ?
        """, (tag, nonce, file_id))

        conn.commit()

        # Log the edit action
        log_action(user_id, "file_edit", f"Edited file: {file['original_filename']}", ip_address)

        return {
            "status": "success",
            "message": "File edited successfully",
            "file_id": file_id
        }

    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        return {"status": "error", "message": f"Database error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error: {type(e).__name__}: {e}")
        return {"status": "error", "message": f"Unexpected error: {str(e)}"}
    finally:
        close_connection(conn)




def handle_client(client_socket, addr):
    """
    Handle a client connection
    """
    ip_address = addr[0]

    # Check rate limit
    if not check_rate_limit(ip_address):
        response = {"status": "error", "message": "Rate limit exceeded. Try again later."}
        client_socket.send(json.dumps(response).encode())
        client_socket.close()
        return

    try:
        # Receive data
        data = b""
        while True:
            chunk = client_socket.recv(MAX_BUFFER_SIZE)
            if not chunk:
                break
            data += chunk
            if len(chunk) < MAX_BUFFER_SIZE:
                break

        if not data:
            return

        # Parse the request
        request = json.loads(data.decode())

        # Get the action
        action = request.get("action")
        if not action:
            response = {"status": "error", "message": "Missing action parameter"}
            client_socket.send(json.dumps(response).encode())
            return

        # Handle different actions
        if action == "register":
            response = handle_register(request, ip_address)
        elif action == "login":
            response = handle_login(request, ip_address)
        elif action == "reset_password":
            response = handle_reset_password(request, ip_address)
        elif action == "upload_file":
            response = handle_upload_file(request, ip_address)
        elif action == "download_file":
            response = handle_download_file(request, ip_address)
        elif action == "delete_file":
            response = handle_delete_file(request, ip_address)
        elif action == "edit_file":
            response = handle_edit_file(request, ip_address)
        elif action == "share_file":
            response = handle_share_file(request, ip_address)
        elif action == "list_shared_files":
            response= handle_list_shared_files(request, ip_address)
        elif action == "list_files_shared_by_me":
            response = list_files_shared_by_me(request, ip_address)
        elif action == "list_files":
            response = list_user_files(request)
        elif action == "view_logs":
            response = handle_view_logs(request, ip_address)
        elif action == "logout":
            response = handle_logout(request, ip_address)
        else:
            response = {"status": "error", "message": "Unknown action"}

        # Send the response
        client_socket.send(json.dumps(response).encode())
    except json.JSONDecodeError:
        response = {"status": "error", "message": "Invalid JSON request"}
        client_socket.send(json.dumps(response).encode())
    except Exception as e:
        logger.error(f"Error handling client request: {e}")
        response = {"status": "error", "message": "Server error"}
        try:
            client_socket.send(json.dumps(response).encode())
        except:
            pass
    finally:
        client_socket.close()


def handle_share_file(request, ip_address=None):
    """
    Handle file sharing request
    """
    username = validate_input(request.get("username"))
    filename = validate_input(request.get("filename"))
    share_with_username = validate_input(request.get("share_with_username"))
    session_id = request.get("session_id")

    # Validate basic inputs
    if not username or not filename or not share_with_username:
        return {"status": "error", "message": "Missing required information"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user_id for the owner
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            return {"status": "error", "message": "User not found"}
        user_id = user['user_id']

        # Find the file by filename
        cursor.execute("""
            SELECT file_id, original_filename
            FROM files
            WHERE original_filename = ? AND owner_id = ? AND is_deleted = 0
        """, (filename, user_id))

        file = cursor.fetchone()
        if not file:
            return {"status": "error", "message": "File not found or you don't have permission to share"}

        file_id = file['file_id']

        # Get the user ID of the user to share with
        cursor.execute("""
            SELECT user_id, username
            FROM users
            WHERE username = ?
        """, (share_with_username,))

        share_user = cursor.fetchone()
        if not share_user:
            return {"status": "error", "message": "User to share with not found"}

        # Prevent sharing with yourself
        if share_user['user_id'] == user_id:
            return {"status": "error", "message": "You cannot share a file with yourself"}

        # Check if already shared
        cursor.execute("""
            SELECT permission_id
            FROM file_permissions
            WHERE file_id = ? AND user_id = ?
        """, (file_id, share_user['user_id']))

        if cursor.fetchone():
            return {"status": "error", "message": "File already shared with this user"}

        # Create permission record
        cursor.execute("""
            INSERT INTO file_permissions
            (file_id, user_id, granted_by, granted_date)
            VALUES (?, ?, ?, ?)
        """, (file_id, share_user['user_id'], user_id, datetime.datetime.now()))

        conn.commit()

        # Log the sharing
        log_action(
            user_id,
            "file_share",
            f"Shared file: {file['original_filename']} with user: {share_user['username']}",
            ip_address
        )

        return {
            "status": "success",
            "message": f"File '{file['original_filename']}' shared successfully with {share_user['username']}"
        }
    except Exception as e:
        logger.error(f"File sharing error: {e}")
        return {"status": "error", "message": f"File sharing failed: {str(e)}"}
    finally:
        close_connection(conn)


def handle_list_shared_files(request, ip_address=None):
    """
    Handle request to list files shared with a user
    """
    username = validate_input(request.get("username"))

    if not username:
        return {"status": "error", "message": "Invalid username"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user_id for the requesting user
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            return {"status": "error", "message": "User not found"}
        user_id = user['user_id']

        # Get all files shared with this user
        cursor.execute("""
            SELECT f.file_id, f.original_filename, f.file_size, f.upload_date, f.last_modified,
                   u.username as owner_username, p.granted_date as shared_date
            FROM file_permissions p
            JOIN files f ON p.file_id = f.file_id
            JOIN users u ON f.owner_id = u.user_id
            WHERE p.user_id = ? AND f.is_deleted = 0
            ORDER BY p.granted_date DESC
        """, (user_id,))

        shared_files = cursor.fetchall()

        # Format the results
        file_list = []
        for file in shared_files:
            # Format dates properly
            upload_date = file['upload_date']
            last_modified = file['last_modified']
            shared_date = file['shared_date']

            # Convert to ISO format if needed
            if isinstance(upload_date, datetime.datetime):
                upload_date = upload_date.isoformat()
            if isinstance(last_modified, datetime.datetime):
                last_modified = last_modified.isoformat()
            if isinstance(shared_date, datetime.datetime):
                shared_date = shared_date.isoformat()

            file_list.append({
                "file_id": file['file_id'],
                "filename": file['original_filename'],
                "file_size": file['file_size'],
                "upload_date": upload_date,
                "last_modified": last_modified,
                "owner_username": file['owner_username'],
                "shared_date": shared_date
            })

        # Log the action
        log_action(user_id, "list_shared_files", f"User {username} viewed shared files", ip_address)

        return {
            "status": "success",
            "message": "Shared files retrieved successfully",
            "shared_files": file_list
        }
    except Exception as e:
        logger.error(f"List shared files error: {type(e).__name__}: {e}")
        return {"status": "error", "message": f"Failed to retrieve shared files: {str(e)}"}
    finally:
        close_connection(conn)


def list_files_shared_by_me(request, ip_address=None):
    """
    Handle request to list files that a user has shared with others
    """
    username = validate_input(request.get("username"))

    if not username:
        return {"status": "error", "message": "Invalid username"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user_id for the requesting user
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            return {"status": "error", "message": "User not found"}
        user_id = user['user_id']

        # Get all files that this user has shared with others
        cursor.execute("""
            SELECT f.file_id, f.original_filename, u2.username as shared_with_username, 
                   p.granted_date as shared_date
            FROM file_permissions p
            JOIN files f ON p.file_id = f.file_id
            JOIN users u2 ON p.user_id = u2.user_id
            WHERE f.owner_id = ? AND f.is_deleted = 0
            ORDER BY p.granted_date DESC
        """, (user_id,))

        shared_files = cursor.fetchall()

        # Format the results
        file_list = []
        for file in shared_files:
            shared_date = file['shared_date']

            # Convert to ISO format if needed
            if isinstance(shared_date, datetime.datetime):
                shared_date = shared_date.isoformat()

            file_list.append({
                "file_id": file['file_id'],
                "filename": file['original_filename'],
                "shared_with_username": file['shared_with_username'],
                "shared_date": shared_date
            })

        # Log the action
        log_action(user_id, "list_files_shared_by_user", f"User {username} viewed files they shared", ip_address)

        return {
            "status": "success",
            "message": "Shared files retrieved successfully",
            "shared_files": file_list
        }
    except Exception as e:
        logger.error(f"List files shared by user error: {type(e).__name__}: {e}")
        return {"status": "error", "message": f"Failed to retrieve shared files: {str(e)}"}
    finally:
        close_connection(conn)

def main():
    """
    Main server function
    """
    # Check if database exists, if not initialize it
    if not os.path.exists(DB_PATH):
        logger.info("Database not found, initializing...")
        try:
            from Database import initialize_database
            initialize_database()
        except ImportError:
            logger.error("Could not import database module")
            return

    # Create files directory if it doesn't exist
    os.makedirs("files", exist_ok=True)

    # Start the server
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(MAX_CONNECTIONS)

        logger.info(f"Server started on {HOST}:{PORT}")

        while True:
            client_socket, addr = server_socket.accept()
            logger.info(f"New connection from {addr}")
            thread_pool.submit(handle_client, client_socket, addr)
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        if 'server_socket' in locals():
            server_socket.close()
        thread_pool.shutdown()


if __name__ == "__main__":
    main()
