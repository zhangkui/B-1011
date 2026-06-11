import os
import uuid
import logging
import magic
from logging.handlers import RotatingFileHandler
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import segno
from PIL import Image
import cv2
import numpy as np
from flask_cors import CORS

# Initialize App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///memory_qr.db'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['QR_FOLDER'] = os.path.join('static', 'qrcodes')
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64MB max limit

# Constants for Validation
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}
ALLOWED_MIME_TYPES = {
    'image/png', 'image/jpeg', 'image/gif', 
    'video/mp4', 'video/quicktime', 'video/x-msvideo'
}
MAX_TITLE_LENGTH = 100
MAX_TEXT_LENGTH = 2000

def allowed_file(filename, file_stream=None):
    # Check extension
    if '.' not in filename or filename.rsplit('.', 1)[1].lower() not in ALLOWED_EXTENSIONS:
        return False
    
    # Check MIME type if stream provided
    if file_stream:
        header = file_stream.read(2048)
        file_stream.seek(0)
        mime = magic.from_buffer(header, mime=True)
        if mime not in ALLOWED_MIME_TYPES:
            app.logger.warning(f"File content mismatch: {filename} has MIME {mime}")
            return False
            
    return True

# Logging Configuration
if not os.path.exists('logs'):
    os.makedirs('logs')

formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s [%(pathname)s:%(lineno)d]: %(message)s'
)

file_handler = RotatingFileHandler('logs/memory_qr.log', maxBytes=10240000, backupCount=10)
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)

app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Memory QR startup')

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['QR_FOLDER'], exist_ok=True)

# Extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
CORS(app, supports_credentials=True) # Enable CORS for frontend proxy

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    memories = db.relationship('Memory', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Memory(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    text_content = db.Column(db.Text, nullable=True)
    media_filename = db.Column(db.String(200), nullable=True)
    media_type = db.Column(db.String(20), nullable=True) # 'image', 'video'
    qr_filename = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'text_content': self.text_content,
            'media_url': f'/static/uploads/{self.media_filename}' if self.media_filename else None,
            'media_type': self.media_type,
            'qr_url': f'/static/qrcodes/{self.qr_filename}' if self.qr_filename else None,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M'),
            'author': self.author.username
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({'error': 'Unauthorized', 'message': 'Please login first'}), 401

# Routes

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    response = None
    if current_user.is_authenticated:
        response = jsonify({'authenticated': True, 'username': current_user.username})
    else:
        response = jsonify({'authenticated': False})
    
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        login_user(user)
        app.logger.info(f"User logged in: {username}")
        return jsonify({'success': True, 'username': user.username})
    app.logger.warning(f"Failed login attempt for user: {username}")
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400
        
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username already exists'}), 400
    
    try:
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        app.logger.info(f"New user registered: {username}")
        return jsonify({'success': True, 'username': user.username})
    except Exception as e:
        app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    username = current_user.username
    logout_user()
    app.logger.info(f"User logged out: {username}")
    return jsonify({'success': True})

@app.route('/api/memories', methods=['GET'])
@login_required
def get_memories():
    memories = Memory.query.filter_by(user_id=current_user.id).order_by(Memory.created_at.desc()).all()
    return jsonify([m.to_dict() for m in memories])

@app.route('/api/memories', methods=['POST'])
@login_required
def create_memory():
    title = request.form.get('title', '').strip()
    text = request.form.get('text', '').strip()
    file = request.files.get('file')
    
    # Validation: Length Limits
    if not title:
        return jsonify({'success': False, 'message': 'Title is required'}), 400
    if len(title) > MAX_TITLE_LENGTH:
        return jsonify({'success': False, 'message': f'Title too long (max {MAX_TITLE_LENGTH})'}), 400
    if text and len(text) > MAX_TEXT_LENGTH:
        return jsonify({'success': False, 'message': f'Content too long (max {MAX_TEXT_LENGTH})'}), 400
        
    media_filename = None
    media_type = None
    
    if file and file.filename:
        if not allowed_file(file.filename, file):
            return jsonify({'success': False, 'message': 'Invalid file type or content'}), 400
            
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        media_filename = unique_filename
        
        ext = filename.rsplit('.', 1)[1].lower()
        if ext in ['jpg', 'jpeg', 'png', 'gif']:
            media_type = 'image'
        elif ext in ['mp4', 'mov', 'avi']:
            media_type = 'video'
    
    try:
        memory = Memory(
            title=title,
            text_content=text,
            media_filename=media_filename,
            media_type=media_type,
            author=current_user
        )
        db.session.add(memory)
        db.session.commit()
        app.logger.info(f"Memory created: {memory.id} by user {current_user.username}")
        return jsonify({'success': True, 'id': memory.id})
    except Exception as e:
        app.logger.error(f"Error creating memory: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/memories/<memory_id>', methods=['GET'])
@login_required
def get_memory(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    # Check if user is author OR has permission (for now just author, or if decrypted)
    # Since this is "Double Encryption", we assume if they hit this endpoint with auth, they can view it
    # But strictly, only author should view UNLESS they decoded it.
    # For MVP, we allow author to view directly.
    # If decoding, the decoder will return the data.
    return jsonify(memory.to_dict())

@app.route('/api/memories/<memory_id>', methods=['DELETE'])
@login_required
def delete_memory(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    if memory.user_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403
    
    db.session.delete(memory)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/memories/<memory_id>/design', methods=['POST'])
@login_required
def design_qr(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    if memory.user_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403
        
    color = request.form.get('color', '#000000')
    bg_color = request.form.get('bg_color', '#ffffff')
    bg_file = request.files.get('bg_image')
    logo_file = request.files.get('logo_image')
    
    qr_content = memory.id 
    qr = segno.make_qr(qr_content, error='h')
    qr_filename = f"qr_{memory.id}.png"
    qr_path = os.path.join(app.config['QR_FOLDER'], qr_filename)
    
    try:
        # 1. 生成基础二维码
        temp_qr_path = os.path.join(app.config['QR_FOLDER'], f"temp_{qr_filename}")
        # 如果有背景图，二维码背景设为透明以便叠加
        qr_bg = None if (bg_file and bg_file.filename) else bg_color
        qr.save(temp_qr_path, scale=10, dark=color, light=qr_bg)
        
        qrcode_img = Image.open(temp_qr_path).convert("RGBA")
        
        # 2. 如果有 Logo，先嵌入到二维码中心
        if logo_file and logo_file.filename:
            logo_temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_logo_{memory.id}.png")
            logo_file.save(logo_temp_path)
            logo = Image.open(logo_temp_path).convert("RGBA")
            
            # 计算 Logo 大小 (二维码大小的 1/4)
            logo_size = qrcode_img.width // 4
            logo = logo.resize((logo_size, logo_size), Image.Resampling.LANCZOS)
            
            # 计算位置
            pos = ((qrcode_img.width - logo_size) // 2, (qrcode_img.height - logo_size) // 2)
            
            # 创建一个带圆角的 Logo 背景 (可选，让 Logo 更清晰)
            # 这里简单处理，直接粘贴
            qrcode_img.paste(logo, pos, logo)
            
            if os.path.exists(logo_temp_path): os.remove(logo_temp_path)

        # 3. 如果有背景图，将带 Logo 的二维码叠加到背景上
        if bg_file and bg_file.filename:
            bg_temp_name = f"temp_bg_{memory.id}.png"
            bg_temp_path = os.path.join(app.config['UPLOAD_FOLDER'], bg_temp_name)
            bg_file.save(bg_temp_path)
            
            background = Image.open(bg_temp_path).convert("RGBA")
            
            # 背景图比二维码稍大一些
            target_size = (qrcode_img.width + 100, qrcode_img.height + 100)
            background = background.resize(target_size, Image.Resampling.LANCZOS)
            
            pos = ((background.width - qrcode_img.width) // 2, (background.height - qrcode_img.height) // 2)
            background.paste(qrcode_img, pos, qrcode_img)
            background.save(qr_path)
            
            if os.path.exists(bg_temp_path): os.remove(bg_temp_path)
        else:
            # 没有背景图，直接保存带 Logo 的二维码
            qrcode_img.save(qr_path)
            
        if os.path.exists(temp_qr_path): os.remove(temp_qr_path)
            
        memory.qr_filename = qr_filename
        db.session.commit()
        return jsonify({'success': True, 'qr_url': f'/static/qrcodes/{qr_filename}'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/decode', methods=['POST'])
def decode_qr():
    file = request.files.get('qr_image')
    if not file:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
    filename = secure_filename(file.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_decode_{filename}")
    file.save(path)
    
    try:
        image = cv2.imread(path)
        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(image)
    finally:
        if os.path.exists(path):
            os.remove(path)
    
    if data:
        memory = Memory.query.get(data)
        if memory:
            if not current_user.is_authenticated:
                return jsonify({'success': False, 'error': 'auth_required', 'memory_id': memory.id}), 401
            return jsonify({'success': True, 'memory_id': memory.id})
        else:
            return jsonify({'success': False, 'message': 'Invalid QR Code'}), 404
    
    return jsonify({'success': False, 'message': 'No QR code detected'}), 400

# Static file serving for Backend (images)
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

# Initialize DB
with app.app_context():
    db.create_all()
    # Create test user if not exists
    if not User.query.filter_by(username='admin').first():
        test_user = User(username='admin')
        test_user.set_password('password')
        db.session.add(test_user)
        db.session.commit()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
