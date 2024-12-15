from flask import Flask, render_template, request, send_file, redirect, url_for
import wave
import os
from io import BytesIO
import logging
from werkzeug.utils import secure_filename
import traceback
import hashlib
import time
from datetime import datetime
import json
from collections import deque
import threading
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['LOG_FOLDER'] = 'logs'
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setup logging
if not os.path.exists(app.config['LOG_FOLDER']):
    os.makedirs(app.config['LOG_FOLDER'])

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(app.config['LOG_FOLDER'], 'steganography.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Use thread-safe deque to store last 100 operations
history_lock = threading.Lock()
operation_history = deque(maxlen=100)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

def add_to_history(operation_type, filename, message_length, success, error=None):
    """Add an operation to history with thread safety"""
    with history_lock:
        operation_history.append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'operation': operation_type,
            'filename': filename,
            'message_length': message_length,
            'success': success,
            'error': error
        })

def generate_seed(key):
    """Generate a deterministic seed from the key"""
    if not key:
        return None
    hash_object = hashlib.sha256(key.encode())
    return int(hash_object.hexdigest(), 16)

def scramble_message(message, key):
    """Scramble message using the key"""
    if not key:
        return message
    
    # Generate a repeatable sequence based on the key
    seed = generate_seed(key)
    if not seed:
        return message
    
    import random
    random.seed(seed)
    
    # Convert message to list
    chars = list(message)
    n = len(chars)
    
    # Simple substitution cipher using key-based shifts
    scrambled = []
    for i, char in enumerate(chars):
        # Generate a shift value based on position and key
        shift = random.randint(1, 25)  # Generate consistent shift for each position
        # Apply shift to ASCII value
        ascii_val = ord(char)
        if 32 <= ascii_val <= 126:  # Printable ASCII range
            # Shift within printable ASCII range
            shifted = ((ascii_val - 32 + shift) % (127 - 32)) + 32
            scrambled.append(chr(shifted))
        else:
            # Keep non-printable characters as is
            scrambled.append(char)
    
    logger.info(f"Message scrambled with key, length: {len(message)}")
    return ''.join(scrambled)

def unscramble_message(message, key):
    """Unscramble message using the key"""
    if not key:
        return message
    
    # Use the same seed for unscrambling
    seed = generate_seed(key)
    if not seed:
        return message
    
    import random
    random.seed(seed)
    
    # Convert message to list
    chars = list(message)
    n = len(chars)
    
    # Reverse the substitution cipher
    unscrambled = []
    for i, char in enumerate(chars):
        # Generate the same shift value based on position and key
        shift = random.randint(1, 25)  # Must generate same sequence as scramble
        # Reverse the shift
        ascii_val = ord(char)
        if 32 <= ascii_val <= 126:  # Printable ASCII range
            # Reverse shift within printable ASCII range
            unshifted = ((ascii_val - 32 - shift) % (127 - 32)) + 32
            unscrambled.append(chr(unshifted))
        else:
            # Keep non-printable characters as is
            unscrambled.append(char)
    
    logger.info(f"Message unscrambled with key, length: {len(message)}")
    return ''.join(unscrambled)

def encode_audio(audio_path, message, key=None):
    start_time = time.time()
    logger.info(f"Starting encoding process for file: {audio_path}")
    song = None
    
    try:
        # Validate message length
        if not message:
            raise ValueError("Message cannot be empty")
        
        # Only scramble if key is provided
        if key:
            logger.info(f"Applying encryption with key length: {len(key)}")
            message = scramble_message(message, key)
            # Add key indicator to message
            message = "ENCRYPTED:" + message
            logger.info("Message encrypted and marked as encrypted")
        else:
            logger.info("No encryption key provided, storing message as plaintext")
            message = "PLAIN:" + message
        
        # Open and validate audio file
        try:
            song = wave.open(audio_path, mode='rb')
        except Exception as e:
            raise ValueError(f"Invalid or corrupted WAV file: {str(e)}")
            
        frame_bytes = bytearray(list(song.readframes(song.getnframes())))
        
        # Calculate maximum message length
        max_bytes = len(frame_bytes) // 8
        logger.info(f"Maximum message length: {max_bytes} characters")
        
        # Convert message to binary
        message = message + '*****'  # Add delimiter
        bits = ''.join([format(ord(i), '08b') for i in message])
        
        logger.info(f"Message length: {len(message)} characters")
        logger.info(f"Binary length: {len(bits)} bits")
        
        # Check if message fits
        if len(bits) > len(frame_bytes):
            raise ValueError(f"Message too long. Maximum length is {max_bytes} characters")
        
        # Replace LSB of each byte of the audio data by one bit from the message
        modified_count = 0
        for i, bit in enumerate(bits):
            if i < len(frame_bytes):
                frame_bytes[i] = (frame_bytes[i] & 254) | int(bit)
                modified_count += 1
        
        frame_modified = bytes(frame_bytes)
        
        # Write the modified frames to a new file
        output = BytesIO()
        try:
            with wave.open(output, 'wb') as fd:
                fd.setparams(song.getparams())
                fd.writeframes(frame_modified)
        except Exception as e:
            raise ValueError(f"Failed to create encoded audio: {str(e)}")
        
        output.seek(0)
        return output
    
    finally:
        if song:
            song.close()

def decode_audio(audio_path, key=None):
    start_time = time.time()
    logger.info(f"Starting decoding process for file: {audio_path}")
    song = None
    
    try:
        # Open and validate audio file
        try:
            song = wave.open(audio_path, mode='rb')
        except Exception as e:
            raise ValueError(f"Invalid or corrupted WAV file: {str(e)}")
            
        frame_bytes = bytearray(list(song.readframes(song.getnframes())))
        
        # Extract LSB of each byte
        extracted = [frame_bytes[i] & 1 for i in range(len(frame_bytes))]
        logger.info(f"Extracted {len(extracted)} bits")
        
        # Convert bits to string
        message = ""
        delimiter_found = False
        
        # Process 8 bits at a time
        for i in range(0, len(extracted), 8):
            if i + 8 <= len(extracted):
                # Convert 8 bits to character
                byte = extracted[i:i+8]
                char = chr(int(''.join(map(str, byte)), 2))
                
                # Check for delimiter
                if char == '*':
                    if message.endswith('****'):
                        delimiter_found = True
                        message = message[:-4]  # Remove the **** part
                        break
                message += char
        
        if not delimiter_found:
            raise ValueError("No valid message found (missing delimiter)")
        
        if not message:
            raise ValueError("No hidden message found in the audio file")
        
        logger.info(f"Raw decoded message: {message}")
        
        # Handle encryption prefix
        if message.startswith("ENCRYPTED:"):
            if not key:
                logger.info("Encrypted message found but no key provided")
                return message, True  # Return raw message and flag as encrypted
            # Remove prefix and decrypt
            encrypted_message = message[len("ENCRYPTED:"):]
            logger.info(f"Attempting to decrypt message with key length: {len(key)}")
            try:
                decrypted_message = unscramble_message(encrypted_message, key)
                logger.info("Message successfully decrypted")
                return decrypted_message, False
            except Exception as e:
                logger.error(f"Decryption failed: {str(e)}")
                raise ValueError("Failed to decrypt message with provided key")
        elif message.startswith("PLAIN:"):
            # Remove prefix for plaintext messages
            plain_message = message[len("PLAIN:"):]
            logger.info("Plain message successfully decoded")
            return plain_message, False
        else:
            logger.info("Legacy message format detected")
            return message, False
    
    except Exception as e:
        logger.error(f"Error during decoding: {str(e)}")
        raise
    
    finally:
        if song:
            song.close()

@app.route('/encode', methods=['POST'])
def encode():
    temp_path = None
    try:
        logger.info("Starting encode request")
        
        if 'audio' not in request.files:
            logger.warning("No audio file in request")
            add_to_history('encode', None, 0, False, 'No audio file provided')
            return {'error': 'No audio file provided'}, 400
        
        audio_file = request.files['audio']
        if not audio_file.filename:
            logger.warning("Empty filename provided")
            add_to_history('encode', None, 0, False, 'No file selected')
            return {'error': 'No file selected'}, 400
            
        message = request.form.get('message', '')
        key = request.form.get('key', '')  # Key is optional
        
        if not message:
            logger.warning("No message provided")
            add_to_history('encode', audio_file.filename, 0, False, 'No message provided')
            return {'error': 'No message provided'}, 400
        
        # Only validate key if it's provided
        if key and len(key) < 4:
            logger.warning("Key too short")
            add_to_history('encode', audio_file.filename, len(message), False, 
                         'If using encryption, key must be at least 4 characters long')
            return {'error': 'If using encryption, key must be at least 4 characters long'}, 400
        
        if not audio_file.filename.endswith('.wav'):
            logger.warning(f"Invalid file type: {audio_file.filename}")
            add_to_history('encode', audio_file.filename, len(message), False, 
                         f"Invalid file type: {audio_file.filename}")
            return {'error': 'Only WAV files are supported'}, 400
        
        # Use secure filename with timestamp to avoid conflicts
        timestamp = int(time.time())
        filename = f"temp_{timestamp}_{secure_filename(audio_file.filename)}"
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        logger.info(f"Saving file to {temp_path}")
        audio_file.save(temp_path)
        
        try:
            logger.info("Starting encoding process")
            if key:
                logger.info("Using encryption with provided key")
            else:
                logger.info("No encryption key provided, encoding without encryption")
                
            output = encode_audio(temp_path, message, key)
            
            # Log successful operation
            add_to_history('encode', audio_file.filename, len(message), True)
            
            logger.info("Encoding successful")
            return send_file(
                output,
                mimetype='audio/wav',
                as_attachment=True,
                download_name='encoded.wav'
            )
        finally:
            # Ensure the file handle is closed before attempting deletion
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                    logger.info(f"Cleaned up temporary file {temp_path}")
                except Exception as e:
                    logger.warning(f"Failed to clean up temporary file {temp_path}: {str(e)}")
    
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error in encode: {error_msg}")
        logger.error(traceback.format_exc())
        add_to_history('encode', audio_file.filename if audio_file else None, 
                      len(message) if message else 0, False, error_msg)
        return {'error': error_msg}, 500

@app.route('/decode', methods=['POST'])
def decode():
    temp_path = None
    try:
        logger.info("Starting decode request")
        
        if 'audio' not in request.files:
            logger.warning("No audio file in request")
            add_to_history('decode', None, 0, False, 'No audio file provided')
            return {'error': 'No audio file provided'}, 400
        
        audio_file = request.files['audio']
        key = request.form.get('key', '')
        
        if not audio_file.filename:
            logger.warning("Empty filename provided")
            add_to_history('decode', None, 0, False, 'No file selected')
            return {'error': 'No file selected'}, 400
        
        if not audio_file.filename.endswith('.wav'):
            logger.warning(f"Invalid file type: {audio_file.filename}")
            add_to_history('decode', audio_file.filename, 0, False, 
                         f"Invalid file type: {audio_file.filename}")
            return {'error': 'Only WAV files are supported'}, 400
        
        # Use secure filename with timestamp
        timestamp = int(time.time())
        filename = f"temp_{timestamp}_{secure_filename(audio_file.filename)}"
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        logger.info(f"Saving file to {temp_path}")
        audio_file.save(temp_path)
        
        try:
            message, is_encrypted = decode_audio(temp_path, key)
            
            if is_encrypted and not key:
                logger.info("Encrypted message detected, key required")
                add_to_history('decode', audio_file.filename, 0, False, 
                             'Message is encrypted, key required')
                return {
                    'needs_key': True,
                    'error': 'This message is encrypted and requires a key to decode'
                }, 200
            
            logger.info(f"Successfully decoded message: {message[:50]}...")
            add_to_history('decode', audio_file.filename, len(message), True)
            
            return {
                'message': message,
                'is_encrypted': is_encrypted,
                'needs_key': False
            }
            
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
                logger.info(f"Cleaned up temporary file {temp_path}")
    
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error in decode: {error_msg}")
        logger.error(traceback.format_exc())
        add_to_history('decode', audio_file.filename if audio_file else None, 
                      0, False, error_msg)
        return {'error': error_msg}, 500

@app.route('/history')
@login_required
def history():
    with history_lock:
        # Convert deque to list for template rendering
        history_list = list(operation_history)
    return render_template('history.html', history=history_list)

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        
        return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            return render_template('signup.html', error='Username already exists')
        
        if User.query.filter_by(email=email).first():
            return render_template('signup.html', error='Email already registered')
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        return redirect(url_for('index'))
    
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True) 