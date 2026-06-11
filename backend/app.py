import os
import uuid
import logging
import magic
import re
import json
from logging.handlers import RotatingFileHandler
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, abort, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
import cv2
import numpy as np
from flask_cors import CORS

from qr_generator import (
    QR_TEMPLATES, EXPORT_SIZES, generate_qr_full,
    generate_export_variants, assess_qr_readability,
    validate_hex_color
)

# Initialize App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///memory_qr.db'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['QR_FOLDER'] = os.path.join('static', 'qrcodes')
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64MB max limit
app.config['MEMORY_VIEW_URL'] = '/view_memory.html'
app.config['BASE_URL'] = os.environ.get('BASE_URL', '')

# Constants for Validation
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}
ALLOWED_MIME_TYPES = {
    'image/png', 'image/jpeg', 'image/gif',
    'video/mp4', 'video/quicktime', 'video/x-msvideo'
}
IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi'}
MAX_TITLE_LENGTH = 100
MAX_TEXT_LENGTH = 2000
MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10MB for images
MAX_VIDEO_SIZE = 64 * 1024 * 1024  # 64MB for videos

# Status constants
MEMORY_STATUS_ACTIVE = 'active'
MEMORY_STATUS_ARCHIVED = 'archived'
MEMORY_STATUS_DRAFT = 'draft'

# Dangerous file patterns
DANGEROUS_EXTENSIONS = {'exe', 'bat', 'cmd', 'sh', 'php', 'js', 'html', 'htm', 'svg', 'pdf', 'zip', 'rar', '7z'}
DANGEROUS_MIME_PREFIXES = {'application/', 'text/html', 'text/javascript'}

def allowed_file(filename, file_stream=None, file_size=0):
    if not filename:
        return False, 'No filename provided'

    filename_lower = filename.lower()

    # Check for dangerous extensions first
    if '.' in filename_lower:
        ext = filename_lower.rsplit('.', 1)[1].lower()
        if ext in DANGEROUS_EXTENSIONS:
            return False, f'File type .{ext} is not allowed'
        if ext not in ALLOWED_EXTENSIONS:
            return False, f'File type .{ext} is not supported'
    else:
        return False, 'File has no extension'

    # Check for path traversal or malicious filenames
    if '..' in filename or '/' in filename or '\\' in filename:
        return False, 'Invalid filename'

    # Double extension check (e.g., image.jpg.exe)
    parts = filename_lower.split('.')
    if len(parts) > 2:
        last_ext = parts[-1]
        second_last_ext = parts[-2]
        if second_last_ext not in ALLOWED_EXTENSIONS and last_ext in ALLOWED_EXTENSIONS:
            # Suspicious double extension
            pass

    # Check MIME type if stream provided
    if file_stream:
        try:
            header = file_stream.read(4096)
            file_stream.seek(0)
            mime = magic.from_buffer(header, mime=True)

            # Check dangerous MIME types
            for prefix in DANGEROUS_MIME_PREFIXES:
                if mime.startswith(prefix) and mime not in ALLOWED_MIME_TYPES:
                    app.logger.warning(f"Blocked dangerous MIME type: {filename} has MIME {mime}")
                    return False, 'File content type not allowed'

            if mime not in ALLOWED_MIME_TYPES:
                app.logger.warning(f"File content mismatch: {filename} has MIME {mime}, but will allow based on extension")
                # If MIME detection fails or is inconclusive, fall back to extension check
                # This handles cases where python-magic is not properly configured on Windows
        except Exception as e:
            app.logger.warning(f"MIME detection error for {filename}: {str(e)}, falling back to extension check")
            # MIME detection failed, fall back to extension check which was already done above

    # Size validation based on type
    if file_size > 0:
        ext = filename_lower.rsplit('.', 1)[1].lower()
        if ext in IMAGE_EXTENSIONS and file_size > MAX_IMAGE_SIZE:
            return False, f'Image too large (max {MAX_IMAGE_SIZE // 1024 // 1024}MB)'
        if ext in VIDEO_EXTENSIONS and file_size > MAX_VIDEO_SIZE:
            return False, f'Video too large (max {MAX_VIDEO_SIZE // 1024 // 1024}MB)'

    return True, 'OK'

def sanitize_filename(filename):
    filename = secure_filename(filename)
    if not filename:
        filename = 'upload_' + uuid.uuid4().hex[:8]
    return filename

def is_safe_redirect_url(target):
    if not target:
        return False
    # Only allow relative URLs (same origin)
    if target.startswith('/') and not target.startswith('//'):
        return True
    return False

def get_base_url():
    base_url = app.config.get('BASE_URL', '')
    if base_url:
        return base_url.rstrip('/')
    return request.host_url.rstrip('/')

def build_view_url(memory_id):
    return get_base_url() + app.config['MEMORY_VIEW_URL'] + '?id=' + memory_id

def safe_json_loads(s, default=None):
    if not s:
        return default or {}
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return default or {}

def log_operation(action, detail='', user_id=None, memory_id=None, ip=None):
    try:
        log = OperationLog(
            action=action,
            detail=detail[:500] if detail else '',
            user_id=user_id or (current_user.id if current_user.is_authenticated else None),
            memory_id=memory_id,
            ip=ip or request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Failed to write operation log: {str(e)}")

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
    operation_logs = db.relationship('OperationLog', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

VISIBILITY_PRIVATE = 'private'
VISIBILITY_PUBLIC = 'public'

class Memory(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    text_content = db.Column(db.Text, nullable=True)
    media_filename = db.Column(db.String(200), nullable=True)
    media_type = db.Column(db.String(20), nullable=True)
    qr_filename = db.Column(db.String(200), nullable=True)
    qr_quality_score = db.Column(db.Integer, default=0)
    design_config = db.Column(db.Text, nullable=True)
    logo_filename = db.Column(db.String(200), nullable=True)
    bg_filename = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(20), default=MEMORY_STATUS_ACTIVE, nullable=False)
    unlock_time = db.Column(db.DateTime, nullable=True)
    visibility = db.Column(db.String(20), default=VISIBILITY_PRIVATE, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def get_design_config(self):
        return safe_json_loads(self.design_config, {})

    def set_design_config(self, config):
        self.design_config = json.dumps(config)

    def is_locked(self):
        if not self.unlock_time:
            return False
        return datetime.utcnow() < self.unlock_time

    def can_view(self, user=None):
        if self.visibility == VISIBILITY_PUBLIC:
            return True
        if user and user.is_authenticated and user.id == self.user_id:
            return True
        return False

    def to_dict(self, viewer=None):
        design_config = self.get_design_config()
        locked = self.is_locked()
        can_view = self.can_view(viewer)

        result = {
            'id': self.id,
            'title': self.title,
            'status': self.status,
            'visibility': self.visibility,
            'unlock_time': self.unlock_time.strftime('%Y-%m-%d %H:%M:%S') if self.unlock_time else None,
            'is_locked': locked,
            'can_view': can_view,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M') if self.updated_at else None,
            'author': self.author.username,
            'author_id': self.user_id,
            'view_url': f'{app.config["MEMORY_VIEW_URL"]}?id={self.id}',
            'full_view_url': build_view_url(self.id)
        }

        if not locked and can_view:
            result['text_content'] = self.text_content
            result['media_url'] = f'/static/uploads/{self.media_filename}' if self.media_filename else None
            result['media_type'] = self.media_type
            result['qr_url'] = f'/static/qrcodes/{self.qr_filename}' if self.qr_filename else None
            result['qr_quality_score'] = self.qr_quality_score or 0
            result['design_config'] = design_config
            result['logo_url'] = f'/static/qrcodes/{self.logo_filename}' if self.logo_filename else None
            result['bg_url'] = f'/static/qrcodes/{self.bg_filename}' if self.bg_filename else None
        else:
            result['text_content'] = None
            result['media_url'] = None
            result['media_type'] = None
            result['qr_url'] = None
            result['qr_quality_score'] = 0
            result['design_config'] = {}
            result['logo_url'] = None
            result['bg_url'] = None

        return result

class OperationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    memory_id = db.Column(db.String(36), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    detail = db.Column(db.String(500), nullable=True)
    ip = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'detail': self.detail,
            'memory_id': self.memory_id,
            'ip': self.ip,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
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
    username = data.get('username', '').strip()
    password = data.get('password', '')
    redirect_url = data.get('redirect', '')

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        login_user(user)
        app.logger.info(f"User logged in: {username}")
        log_operation('login', f'User {username} logged in', user_id=user.id)

        result = {'success': True, 'username': user.username}
        if redirect_url and is_safe_redirect_url(redirect_url):
            result['redirect'] = redirect_url
        return jsonify(result)

    app.logger.warning(f"Failed login attempt for user: {username}")
    log_operation('login_failed', f'Failed login for username: {username}', ip=request.remote_addr)
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    redirect_url = data.get('redirect', '')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400

    if len(username) < 3 or len(username) > 50:
        return jsonify({'success': False, 'message': 'Username must be between 3 and 50 characters'}), 400

    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username already exists'}), 400

    try:
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        app.logger.info(f"New user registered: {username}")
        log_operation('register', f'New user registered: {username}', user_id=user.id)

        result = {'success': True, 'username': user.username}
        if redirect_url and is_safe_redirect_url(redirect_url):
            result['redirect'] = redirect_url
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    username = current_user.username
    user_id = current_user.id
    logout_user()
    app.logger.info(f"User logged out: {username}")
    log_operation('logout', f'User {username} logged out', user_id=user_id)
    return jsonify({'success': True})

@app.route('/api/memories', methods=['GET'])
@login_required
def get_memories():
    status_filter = request.args.get('status', '')
    query = Memory.query.filter_by(user_id=current_user.id)
    if status_filter:
        query = query.filter_by(status=status_filter)
    memories = query.order_by(Memory.created_at.desc()).all()
    log_operation('list_memories', f'Listed {len(memories)} memories')
    return jsonify([m.to_dict(viewer=current_user) for m in memories])

def parse_unlock_time(time_str):
    if not time_str:
        return None
    try:
        for fmt in ['%Y-%m-%dT%H:%M', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M']:
            try:
                return datetime.strptime(time_str, fmt)
            except ValueError:
                continue
        return None
    except Exception:
        return None

@app.route('/api/memories', methods=['POST'])
@login_required
def create_memory():
    title = request.form.get('title', '').strip()
    text = request.form.get('text', '').strip()
    file = request.files.get('file')
    status = request.form.get('status', MEMORY_STATUS_ACTIVE)
    unlock_time_str = request.form.get('unlock_time', '')
    visibility = request.form.get('visibility', VISIBILITY_PRIVATE)

    if status not in [MEMORY_STATUS_ACTIVE, MEMORY_STATUS_DRAFT, MEMORY_STATUS_ARCHIVED]:
        status = MEMORY_STATUS_ACTIVE

    if visibility not in [VISIBILITY_PRIVATE, VISIBILITY_PUBLIC]:
        visibility = VISIBILITY_PRIVATE

    unlock_time = parse_unlock_time(unlock_time_str)

    if not title:
        return jsonify({'success': False, 'message': 'Title is required'}), 400
    if len(title) > MAX_TITLE_LENGTH:
        return jsonify({'success': False, 'message': f'Title too long (max {MAX_TITLE_LENGTH} characters)'}), 400
    if text and len(text) > MAX_TEXT_LENGTH:
        return jsonify({'success': False, 'message': f'Content too long (max {MAX_TEXT_LENGTH} characters)'}), 400

    media_filename = None
    media_type = None

    if file and file.filename:
        is_valid, error_msg = allowed_file(file.filename, file, request.content_length or 0)
        if not is_valid:
            app.logger.warning(f"Blocked file upload: {file.filename}, reason: {error_msg}")
            log_operation('upload_blocked', f'Blocked file: {file.filename}, reason: {error_msg}')
            return jsonify({'success': False, 'message': error_msg}), 400

        safe_filename = sanitize_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{safe_filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        media_filename = unique_filename

        ext = safe_filename.rsplit('.', 1)[1].lower()
        if ext in IMAGE_EXTENSIONS:
            media_type = 'image'
        elif ext in VIDEO_EXTENSIONS:
            media_type = 'video'

    try:
        memory = Memory(
            title=title,
            text_content=text,
            media_filename=media_filename,
            media_type=media_type,
            status=status,
            unlock_time=unlock_time,
            visibility=visibility,
            author=current_user
        )
        db.session.add(memory)
        db.session.commit()
        app.logger.info(f"Memory created: {memory.id} by user {current_user.username}")
        log_operation('create_memory', f'Created memory: {title}', memory_id=memory.id)
        return jsonify({'success': True, 'id': memory.id, 'view_url': memory.to_dict()['view_url']})
    except Exception as e:
        app.logger.error(f"Error creating memory: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/memories/<memory_id>', methods=['GET'])
def get_memory(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    
    if memory.is_locked():
        log_operation('view_locked_memory', f'Attempted to view locked memory: {memory.title}', memory_id=memory.id)
        return jsonify(memory.to_dict(viewer=current_user if current_user.is_authenticated else None))
    
    if not memory.can_view(current_user if current_user.is_authenticated else None):
        if not current_user.is_authenticated:
            return jsonify({'error': 'auth_required', 'message': 'Please login'}), 401
        app.logger.warning(f"Unauthorized access attempt to memory {memory_id} by user {current_user.username}")
        log_operation('unauthorized_access', f'Attempted to access memory {memory_id}', memory_id=memory_id)
        return jsonify({'error': 'Forbidden'}), 403

    log_operation('view_memory', f'Viewed memory: {memory.title}', memory_id=memory.id)
    return jsonify(memory.to_dict(viewer=current_user if current_user.is_authenticated else None))

@app.route('/api/memories/<memory_id>', methods=['PUT'])
@login_required
def update_memory(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    if memory.user_id != current_user.id:
        log_operation('unauthorized_edit', f'Attempted to edit memory {memory_id}', memory_id=memory_id)
        return jsonify({'error': 'Forbidden'}), 403

    title = request.form.get('title', '').strip()
    text = request.form.get('text', '').strip()
    file = request.files.get('file')
    remove_media = request.form.get('remove_media', 'false').lower() == 'true'
    new_status = request.form.get('status', '')
    unlock_time_str = request.form.get('unlock_time', '')
    visibility = request.form.get('visibility', '')

    if title:
        if len(title) > MAX_TITLE_LENGTH:
            return jsonify({'success': False, 'message': f'Title too long (max {MAX_TITLE_LENGTH} characters)'}), 400
        memory.title = title

    if text is not None:
        if len(text) > MAX_TEXT_LENGTH:
            return jsonify({'success': False, 'message': f'Content too long (max {MAX_TEXT_LENGTH} characters)'}), 400
        memory.text_content = text

    if new_status and new_status in [MEMORY_STATUS_ACTIVE, MEMORY_STATUS_DRAFT, MEMORY_STATUS_ARCHIVED]:
        memory.status = new_status

    if unlock_time_str is not None:
        if unlock_time_str == '':
            memory.unlock_time = None
        else:
            parsed = parse_unlock_time(unlock_time_str)
            if parsed:
                memory.unlock_time = parsed

    if visibility and visibility in [VISIBILITY_PRIVATE, VISIBILITY_PUBLIC]:
        memory.visibility = visibility

    if remove_media and memory.media_filename:
        old_file = os.path.join(app.config['UPLOAD_FOLDER'], memory.media_filename)
        if os.path.exists(old_file):
            os.remove(old_file)
        memory.media_filename = None
        memory.media_type = None

    if file and file.filename:
        is_valid, error_msg = allowed_file(file.filename, file, request.content_length or 0)
        if not is_valid:
            log_operation('upload_blocked', f'Blocked file: {file.filename}, reason: {error_msg}')
            return jsonify({'success': False, 'message': error_msg}), 400

        if memory.media_filename:
            old_file = os.path.join(app.config['UPLOAD_FOLDER'], memory.media_filename)
            if os.path.exists(old_file):
                os.remove(old_file)

        safe_filename = sanitize_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{safe_filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        memory.media_filename = unique_filename

        ext = safe_filename.rsplit('.', 1)[1].lower()
        if ext in IMAGE_EXTENSIONS:
            memory.media_type = 'image'
        elif ext in VIDEO_EXTENSIONS:
            memory.media_type = 'video'

    try:
        memory.updated_at = datetime.utcnow()
        db.session.commit()
        app.logger.info(f"Memory updated: {memory.id} by user {current_user.username}")
        log_operation('update_memory', f'Updated memory: {memory.title}', memory_id=memory.id)
        return jsonify({'success': True, 'memory': memory.to_dict(viewer=current_user)})
    except Exception as e:
        app.logger.error(f"Error updating memory: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/memories/<memory_id>/status', methods=['PATCH'])
@login_required
def update_memory_status(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    if memory.user_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403

    data = request.json or {}
    new_status = data.get('status', '')

    if new_status not in [MEMORY_STATUS_ACTIVE, MEMORY_STATUS_DRAFT, MEMORY_STATUS_ARCHIVED]:
        return jsonify({'success': False, 'message': 'Invalid status'}), 400

    old_status = memory.status
    memory.status = new_status
    memory.updated_at = datetime.utcnow()
    db.session.commit()

    log_operation('status_change', f'Status changed from {old_status} to {new_status}', memory_id=memory.id)
    return jsonify({'success': True, 'status': new_status})

@app.route('/api/capsules', methods=['GET'])
def get_capsules():
    query = Memory.query.filter(
        Memory.status == MEMORY_STATUS_ACTIVE,
        Memory.unlock_time.isnot(None)
    )
    
    capsules = query.order_by(Memory.unlock_time.asc()).all()
    
    viewer = current_user if current_user.is_authenticated else None
    result = []
    for c in capsules:
        if c.visibility == VISIBILITY_PUBLIC or (viewer and viewer.id == c.user_id):
            result.append(c.to_dict(viewer=viewer))
    
    return jsonify(result)

@app.route('/api/memories/<memory_id>', methods=['DELETE'])
@login_required
def delete_memory(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    if memory.user_id != current_user.id:
        log_operation('unauthorized_delete', f'Attempted to delete memory {memory_id}', memory_id=memory_id)
        return jsonify({'error': 'Forbidden'}), 403

    memory_title = memory.title

    try:
        if memory.media_filename:
            media_path = os.path.join(app.config['UPLOAD_FOLDER'], memory.media_filename)
            if os.path.exists(media_path):
                os.remove(media_path)

        if memory.qr_filename:
            qr_path = os.path.join(app.config['QR_FOLDER'], memory.qr_filename)
            if os.path.exists(qr_path):
                os.remove(qr_path)

        OperationLog.query.filter_by(memory_id=memory_id).update({'memory_id': None})

        db.session.delete(memory)
        db.session.commit()
        app.logger.info(f"Memory deleted: {memory_id} by user {current_user.username}")
        log_operation('delete_memory', f'Deleted memory: {memory_title}')
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error deleting memory: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/qr/templates', methods=['GET'])
def get_qr_templates():
    templates = []
    for key, tpl in QR_TEMPLATES.items():
        templates.append({
            'id': key,
            'name': tpl['name'],
            'dark': tpl['dark'],
            'light': tpl['light'],
            'finder_dark': tpl.get('finder_dark', tpl['dark']),
            'finder_light': tpl.get('finder_light', tpl['light']),
            'corner_style': tpl.get('corner_style', 'square'),
            'dot_style': tpl.get('dot_style', 'square'),
        })
    return jsonify({'success': True, 'templates': templates})

@app.route('/api/qr/export-sizes', methods=['GET'])
def get_export_sizes():
    sizes = []
    for key, sz in EXPORT_SIZES.items():
        sizes.append({
            'id': key,
            'name': sz['name'],
            'scale': sz['scale'],
            'margin': sz['margin'],
        })
    return jsonify({'success': True, 'sizes': sizes})

@app.route('/api/memories/<memory_id>/design', methods=['POST'])
@login_required
def design_qr(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    if memory.user_id != current_user.id:
        log_operation('unauthorized_qr_design', f'Attempted to design QR for memory {memory_id}', memory_id=memory_id)
        return jsonify({'error': 'Forbidden'}), 403

    template = request.form.get('template', 'classic')
    dark_color = request.form.get('dark_color', '')
    light_color = request.form.get('light_color', '')
    finder_dark = request.form.get('finder_dark', '')
    finder_light = request.form.get('finder_light', '')
    dot_style = request.form.get('dot_style', '')
    corner_style = request.form.get('corner_style', '')
    size_type = request.form.get('size_type', 'standard')

    logo_shape = request.form.get('logo_shape', 'square')
    logo_radius = int(request.form.get('logo_radius', 0) or 0)
    logo_border_width = int(request.form.get('logo_border_width', 0) or 0)
    logo_border_color = request.form.get('logo_border_color', '#ffffff')
    logo_opacity = int(request.form.get('logo_opacity', 100) or 100)
    logo_padding = int(request.form.get('logo_padding', 8) or 8)

    bg_file = request.files.get('bg_image')
    logo_file = request.files.get('logo_image')

    if template not in QR_TEMPLATES:
        template = 'classic'

    tpl = QR_TEMPLATES[template]
    if not dark_color:
        dark_color = tpl['dark']
    if not light_color:
        light_color = tpl['light']
    if not finder_dark:
        finder_dark = tpl.get('finder_dark', tpl['dark'])
    if not finder_light:
        finder_light = tpl.get('finder_light', tpl['light'])
    if not dot_style:
        dot_style = tpl.get('dot_style', 'square')
    if not corner_style:
        corner_style = tpl.get('corner_style', 'square')

    if not validate_hex_color(dark_color):
        return jsonify({'success': False, 'message': 'Invalid dark color format'}), 400
    if not validate_hex_color(light_color):
        return jsonify({'success': False, 'message': 'Invalid light color format'}), 400
    if finder_dark and not validate_hex_color(finder_dark):
        return jsonify({'success': False, 'message': 'Invalid finder dark color format'}), 400
    if finder_light and not validate_hex_color(finder_light):
        return jsonify({'success': False, 'message': 'Invalid finder light color format'}), 400
    if logo_border_color and not validate_hex_color(logo_border_color):
        return jsonify({'success': False, 'message': 'Invalid logo border color format'}), 400

    if dot_style not in ['square', 'rounded', 'circle']:
        dot_style = 'square'
    if corner_style not in ['square', 'rounded']:
        corner_style = 'square'
    if logo_shape not in ['square', 'rounded', 'circle']:
        logo_shape = 'square'

    logo_radius = max(0, min(logo_radius, 100))
    logo_border_width = max(0, min(logo_border_width, 20))
    logo_opacity = max(0, min(logo_opacity, 100))
    logo_padding = max(0, min(logo_padding, 50))

    if bg_file and bg_file.filename:
        is_valid, err_msg = allowed_file(bg_file.filename, bg_file)
        if not is_valid:
            return jsonify({'success': False, 'message': f'Background image: {err_msg}'}), 400

    if logo_file and logo_file.filename:
        is_valid, err_msg = allowed_file(logo_file.filename, logo_file)
        if not is_valid:
            return jsonify({'success': False, 'message': f'Logo image: {err_msg}'}), 400

    design_config = {
        'template': template,
        'dark_color': dark_color,
        'light_color': light_color,
        'finder_dark': finder_dark,
        'finder_light': finder_light,
        'dot_style': dot_style,
        'corner_style': corner_style,
        'size_type': size_type,
        'logo_shape': logo_shape,
        'logo_radius': logo_radius,
        'logo_border_width': logo_border_width,
        'logo_border_color': logo_border_color,
        'logo_opacity': logo_opacity,
        'logo_padding': logo_padding,
    }

    bg_image_file = None
    if bg_file and bg_file.filename:
        bg_image_file = Image.open(bg_file).convert("RGBA")
        design_config['has_bg_image'] = True
        bg_filename = f"bg_{memory.id}.png"
        bg_path = os.path.join(app.config['QR_FOLDER'], bg_filename)
        bg_image_file.save(bg_path, 'PNG')
        memory.bg_filename = bg_filename
        app.logger.info(f"Saved background image for memory {memory.id}: {bg_filename}")
    else:
        design_config['has_bg_image'] = False
        if memory.bg_filename:
            bg_path = os.path.join(app.config['QR_FOLDER'], memory.bg_filename)
            if os.path.exists(bg_path):
                bg_image_file = Image.open(bg_path).convert("RGBA")
                design_config['has_bg_image'] = True
                app.logger.info(f"Loaded existing background image for memory {memory.id}: {memory.bg_filename}")

    logo_image_file = None
    if logo_file and logo_file.filename:
        logo_image_file = Image.open(logo_file).convert("RGBA")
        design_config['has_logo'] = True
        logo_filename = f"logo_{memory.id}.png"
        logo_path = os.path.join(app.config['QR_FOLDER'], logo_filename)
        logo_image_file.save(logo_path, 'PNG')
        memory.logo_filename = logo_filename
        app.logger.info(f"Saved logo image for memory {memory.id}: {logo_filename}")
    else:
        design_config['has_logo'] = False
        if memory.logo_filename:
            logo_path = os.path.join(app.config['QR_FOLDER'], memory.logo_filename)
            if os.path.exists(logo_path):
                logo_image_file = Image.open(logo_path).convert("RGBA")
                design_config['has_logo'] = True
                app.logger.info(f"Loaded existing logo image for memory {memory.id}: {memory.logo_filename}")

    design_config['_bg_image_file'] = bg_image_file
    design_config['_logo_image_file'] = logo_image_file

    try:
        view_url = build_view_url(memory.id)
        qr_filename, qr_img, quality_score = generate_qr_full(
            view_url, design_config, app.config['QR_FOLDER'], memory.id
        )

        memory.qr_filename = qr_filename
        memory.qr_quality_score = quality_score['score']

        stored_config = {k: v for k, v in design_config.items() if not k.startswith('_')}
        memory.set_design_config(stored_config)

        memory.updated_at = datetime.utcnow()
        db.session.commit()

        log_operation('design_qr', f'Designed QR code for memory: {memory.title}', memory_id=memory.id)

        return jsonify({
            'success': True,
            'qr_url': f'/static/qrcodes/{qr_filename}',
            'quality_score': quality_score,
            'design_config': stored_config,
            'logo_url': f'/static/qrcodes/{memory.logo_filename}' if memory.logo_filename else None,
            'bg_url': f'/static/qrcodes/{memory.bg_filename}' if memory.bg_filename else None,
        })

    except Exception as e:
        app.logger.error(f"QR design error: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/memories/<memory_id>/export', methods=['GET'])
@login_required
def export_qr(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    if memory.user_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403

    if not memory.qr_filename:
        return jsonify({'success': False, 'message': 'No QR code found'}), 400

    qr_path = os.path.join(app.config['QR_FOLDER'], memory.qr_filename)
    if not os.path.exists(qr_path):
        return jsonify({'success': False, 'message': 'QR file not found'}), 404

    try:
        qr_img = Image.open(qr_path).convert("RGBA")
        variants = generate_export_variants(
            qr_img, app.config['QR_FOLDER'], memory.id, memory.qr_filename
        )
        log_operation('export_qr', f'Exported QR variants for memory: {memory.title}', memory_id=memory.id)
        return jsonify({'success': True, 'variants': variants})
    except Exception as e:
        app.logger.error(f"QR export error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/memories/<memory_id>/quality', methods=['GET'])
@login_required
def get_qr_quality(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    if memory.user_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403

    if not memory.qr_filename:
        return jsonify({'success': False, 'message': 'No QR code found'}), 400

    qr_path = os.path.join(app.config['QR_FOLDER'], memory.qr_filename)
    if not os.path.exists(qr_path):
        return jsonify({'success': False, 'message': 'QR file not found'}), 404

    try:
        qr_img = Image.open(qr_path).convert("RGBA")
        quality_score = assess_qr_readability(qr_img)
        memory.qr_quality_score = quality_score['score']
        db.session.commit()
        return jsonify({'success': True, 'quality': quality_score})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/decode', methods=['POST'])
def decode_qr():
    file = request.files.get('qr_image')
    if not file:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400

    safe_filename = sanitize_filename(file.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_decode_{uuid.uuid4().hex}_{safe_filename}")
    file.save(path)

    memory_id = None
    try:
        image = cv2.imread(path)
        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(image)

        if data:
            if data.startswith('http://') or data.startswith('https://') or data.startswith('/'):
                if 'id=' in data:
                    import urllib.parse
                    if '?' in data:
                        query_part = data.split('?', 1)[1]
                        params = urllib.parse.parse_qs(query_part)
                        memory_id = params.get('id', [None])[0]
            else:
                memory_id = data
    finally:
        if os.path.exists(path):
            os.remove(path)

    if memory_id:
        memory = Memory.query.get(memory_id)
        if memory:
            if memory.status != MEMORY_STATUS_ACTIVE:
                log_operation('decode_inactive', f'Decoded inactive memory: {memory_id}', memory_id=memory_id, ip=request.remote_addr)
                return jsonify({'success': False, 'message': 'This memory is not available'}), 404

            log_operation('decode_success', f'Successfully decoded memory: {memory.title}', memory_id=memory_id, ip=request.remote_addr)

            view_url = app.config['MEMORY_VIEW_URL'] + '?id=' + memory.id
            return jsonify({
                'success': True,
                'memory_id': memory.id,
                'view_url': view_url,
                'is_locked': memory.is_locked()
            })
        else:
            log_operation('decode_invalid', f'Decoded invalid memory ID: {memory_id}', ip=request.remote_addr)
            return jsonify({'success': False, 'message': 'Invalid QR Code'}), 404

    log_operation('decode_failed', 'No QR code detected', ip=request.remote_addr)
    return jsonify({'success': False, 'message': 'No QR code detected'}), 400

@app.route('/api/memories/<memory_id>/scan', methods=['POST'])
def scan_memory(memory_id):
    memory = Memory.query.get_or_404(memory_id)

    if memory.status != MEMORY_STATUS_ACTIVE:
        return jsonify({'success': False, 'message': 'This memory is not available'}), 404

    log_operation('qr_scan', f'QR code scanned for memory: {memory.title}', memory_id=memory_id, ip=request.remote_addr)

    view_url = app.config['MEMORY_VIEW_URL'] + '?id=' + memory.id
    return jsonify({
        'success': True,
        'memory_id': memory.id,
        'view_url': view_url,
        'is_locked': memory.is_locked()
    })

_FRONTEND_DIR = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'src')

def serve_frontend_file(filepath):
    full_path = os.path.join(_FRONTEND_DIR, filepath)
    if os.path.exists(full_path):
        return send_from_directory(_FRONTEND_DIR, filepath)
    return None

@app.route('/static/<path:filename>')
def serve_static(filename):
    backend_path = os.path.join('static', filename)
    if os.path.exists(backend_path):
        return send_from_directory('static', filename)
    frontend_file = serve_frontend_file(os.path.join('static', filename))
    if frontend_file is not None:
        return frontend_file
    abort(404)

@app.route('/')
def index_page():
    return send_from_directory(_FRONTEND_DIR, 'index.html')

@app.route('/<path:filename>')
def serve_frontend(filename):
    if filename.startswith('api/'):
        abort(404)
    if '.' not in filename:
        html_file = filename + '.html'
        full_path = os.path.join(_FRONTEND_DIR, html_file)
        if os.path.exists(full_path):
            return send_from_directory(_FRONTEND_DIR, html_file)
    full_path = os.path.join(_FRONTEND_DIR, filename)
    if os.path.exists(full_path):
        return send_from_directory(_FRONTEND_DIR, filename)
    abort(404)

# Initialize DB
def init_db():
    db.create_all()

    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)

    # Add columns to memory table if missing
    if 'memory' in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('memory')]
        if 'status' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text(f"ALTER TABLE memory ADD COLUMN status VARCHAR(20) DEFAULT '{MEMORY_STATUS_ACTIVE}' NOT NULL"))
                    conn.commit()
                app.logger.info("Added 'status' column to memory table")
            except Exception as e:
                app.logger.warning(f"Could not add status column: {e}")

        if 'updated_at' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE memory ADD COLUMN updated_at DATETIME"))
                    conn.commit()
                app.logger.info("Added 'updated_at' column to memory table")
            except Exception as e:
                app.logger.warning(f"Could not add updated_at column: {e}")

        if 'qr_quality_score' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE memory ADD COLUMN qr_quality_score INTEGER DEFAULT 0"))
                    conn.commit()
                app.logger.info("Added 'qr_quality_score' column to memory table")
            except Exception as e:
                app.logger.warning(f"Could not add qr_quality_score column: {e}")

        if 'design_config' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE memory ADD COLUMN design_config TEXT"))
                    conn.commit()
                app.logger.info("Added 'design_config' column to memory table")
            except Exception as e:
                app.logger.warning(f"Could not add design_config column: {e}")

        if 'logo_filename' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE memory ADD COLUMN logo_filename VARCHAR(200)"))
                    conn.commit()
                app.logger.info("Added 'logo_filename' column to memory table")
            except Exception as e:
                app.logger.warning(f"Could not add logo_filename column: {e}")

        if 'bg_filename' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE memory ADD COLUMN bg_filename VARCHAR(200)"))
                    conn.commit()
                app.logger.info("Added 'bg_filename' column to memory table")
            except Exception as e:
                app.logger.warning(f"Could not add bg_filename column: {e}")

        if 'unlock_time' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE memory ADD COLUMN unlock_time DATETIME"))
                    conn.commit()
                app.logger.info("Added 'unlock_time' column to memory table")
            except Exception as e:
                app.logger.warning(f"Could not add unlock_time column: {e}")

        if 'visibility' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE memory ADD COLUMN visibility VARCHAR(20) DEFAULT 'private' NOT NULL"))
                    conn.commit()
                app.logger.info("Added 'visibility' column to memory table")
            except Exception as e:
                app.logger.warning(f"Could not add visibility column: {e}")

    # Create test user if not exists
    if not User.query.filter_by(username='admin').first():
        test_user = User(username='admin')
        test_user.set_password('password')
        db.session.add(test_user)
        db.session.commit()
        app.logger.info("Created default admin user")

with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
