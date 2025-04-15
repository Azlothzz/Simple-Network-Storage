# This file simulates the phone


import socket
import json
import threading
import os
import time
import sys
from datetime import datetime

# Server settings
PHONE_HOST = 'localhost'
PHONE_PORT = 8888   # listening to port 8888 same as in api_user.py

# OTP storage
otp_storage = {}
new_otp_received = threading.Event()

def log_message(message):
    """Log message with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def receive_otp():
    """Start server to listen for OTP from clients"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((PHONE_HOST, PHONE_PORT))
        server.listen(5)
        log_message(f"OTP receiver started, listening on port: {PHONE_PORT}")
        log_message("Waiting for OTP codes...")
        
        while True:
            client, addr = server.accept()
            # Create new thread to handle connection
            threading.Thread(target=handle_client, args=(client, addr)).start()
            
    except Exception as e:
        log_message(f"Server error: {e}")
    finally:
        server.close()

def handle_client(client_socket, addr):
    """Handle client connection and OTP receiving"""
    try:
        # Receive message
        data = client_socket.recv(1024).decode()
        if data:
            try:
                # Parse JSON message
                message = json.loads(data)
                if 'username' in message and 'otp_secret' in message:
                    username = message['username']
                    otp = message['otp_secret']
                    
                    # Store OTP
                    otp_storage[username] = {
                        'otp_secret': otp,
                        'timestamp': time.time()
                    }
                    
                    # Send success response
                    response = {'status': 'success', 'message': 'OTP received'}
                    client_socket.send(json.dumps(response).encode())
                    
                    # Display received OTP
                    log_message(f"Received OTP for user {username}: {otp}")
                    log_message(f"OTP valid for: 5 mins")
                    new_otp_received.set()
                else:
                    response = {'status': 'error', 'message': 'Invalid message format'}
                    client_socket.send(json.dumps(response).encode())
            except json.JSONDecodeError:
                response = {'status': 'error', 'message': 'Invalid JSON format'}
                client_socket.send(json.dumps(response).encode())
    except Exception as e:
        log_message(f"Error handling client connection: {e}")
    finally:
        client_socket.close()

def send_sample_otp():
    """Client test function to manually send test OTP"""
    try:
        username = input("Enter username: ")
        otp = input("Enter OTP to send: ")
        
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((PHONE_HOST, PHONE_PORT))
        
        message = {'username': username, 'otp': otp}
        client.send(json.dumps(message).encode())
        
        response = client.recv(1024).decode()
        log_message(f"Server response: {response}")
        client.close()
    except Exception as e:
        log_message(f"Failed to send OTP: {e}")

def main():
    """Start OTP receiver listener"""
    try:
        # Create thread to listen for OTP
        otp_receiver = threading.Thread(target=receive_otp, daemon=True)
        otp_receiver.start()
        
        # Main thread wait, display waiting message
        log_message("OTP receiver started, waiting for verification codes...")
        log_message("Type 'exit', 'quit', or 'stop' to shut down the receiver")
        
        # Check for exit command
        while True:
            try:
                # Set small timeout to avoid blocking indefinitely
                user_input = input()
                if user_input.lower() in ['exit', 'quit', 'stop']:
                    log_message("Shutting down OTP receiver...")
                    break
            except EOFError:
                # Handle case when running in non-interactive environment
                time.sleep(10)
            
    except KeyboardInterrupt:
        pass
    finally:
        log_message("OTP receiver closed")
        sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        # Test mode: send test OTP
        send_sample_otp()
    else:
        # Normal mode: start OTP receiver
        main()