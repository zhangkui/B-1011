import os
import uuid
import logging
import magic
import re
import json
import string
import random
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

UNLOCK_TYPE_NORMAL = 'normal'
UNLOCK_TYPE_GEO = 'geo'
UNLOCK_TYPE_GROUP = 'group'
UNLOCK_TYPE_COMBINED = 'combined'
VALID_UNLOCK_TYPES = [UNLOCK_TYPE_NORMAL, UNLOCK_TYPE_GEO, UNLOCK_TYPE_GROUP, UNLOCK_TYPE_COMBINED]

GEO_RADIUS_OPTIONS = [
    {'value': 100, 'label': '100米'},
    {'value': 500, 'label': '500米'},
    {'value': 1000, 'label': '1000米'},
    {'value': 2000, 'label': '2000米'},
    {'value': 5000, 'label': '5000米'},
]

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
    unlock_type = db.Column(db.String(20), default=UNLOCK_TYPE_NORMAL, nullable=False)
    geo_latitude = db.Column(db.Float, nullable=True)
    geo_longitude = db.Column(db.Float, nullable=True)
    geo_radius = db.Column(db.Integer, nullable=True)
    geo_address = db.Column(db.String(200), nullable=True)
    group_unlock_enabled = db.Column(db.Boolean, default=False, nullable=False)
    group_unlock_count = db.Column(db.Integer, default=2, nullable=False)
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

    def has_geo_lock(self):
        return self.unlock_type in [UNLOCK_TYPE_GEO, UNLOCK_TYPE_COMBINED] and \
               self.geo_latitude is not None and self.geo_longitude is not None and self.geo_radius is not None

    def has_group_lock(self):
        return self.unlock_type in [UNLOCK_TYPE_GROUP, UNLOCK_TYPE_COMBINED] and \
               self.group_unlock_enabled and self.group_unlock_count > 1

    def check_geo_unlock(self, user_lat, user_lon):
        if not self.has_geo_lock():
            return True, None
        if user_lat is None or user_lon is None:
            return False, '需要获取您的位置信息才能查看'
        distance = calculate_distance(self.geo_latitude, self.geo_longitude, user_lat, user_lon)
        if distance <= self.geo_radius:
            return True, None
        return False, f'您当前位置距离解锁地点还有 {distance:.0f} 米，需在 {self.geo_radius} 米范围内才能查看'

    def check_group_unlock(self, user_id):
        if not self.has_group_lock():
            return True, None, None
        if user_id is None:
            return False, '需要登录后才能参与联合解锁', None
        session = UnlockSession.query.filter_by(
            memory_id=self.id, status='active'
        ).order_by(UnlockSession.created_at.desc()).first()
        if session and session.is_unlocked():
            participant = UnlockParticipant.query.filter_by(
                session_id=session.id, user_id=user_id
            ).first()
            if participant:
                return True, None, session
        current_count = 0
        if session:
            current_count = session.current_count
        if not session:
            return False, '尚未有人发起联合解锁，请先发起解锁', session
        if session.current_count >= self.group_unlock_count:
            participant = UnlockParticipant.query.filter_by(
                session_id=session.id, user_id=user_id
            ).first()
            if participant:
                return True, None, session
            return False, '本轮联合解锁已完成，但您未参与，请发起新一轮解锁', session
        participant = UnlockParticipant.query.filter_by(
            session_id=session.id, user_id=user_id
        ).first()
        if participant:
            return False, f'您已参与本轮解锁，还需 {self.group_unlock_count - current_count} 人参与', session
        return False, f'还需 {self.group_unlock_count - current_count} 人参与解锁', session

    def can_view(self, user=None, user_lat=None, user_lon=None, skip_geo=False, skip_group=False):
        if self.visibility == VISIBILITY_PUBLIC:
            return True
        if user and user.is_authenticated and user.id == self.user_id:
            return True
        if user and user.is_authenticated:
            collab = Collaborator.query.filter_by(
                memory_id=self.id, user_id=user.id, status='active'
            ).first()
            if collab:
                return True
            if self.has_group_lock():
                participant = UnlockParticipant.query.join(UnlockSession).filter(
                    UnlockSession.memory_id == self.id,
                    UnlockSession.status == 'active',
                    UnlockParticipant.user_id == user.id
                ).first()
                if participant:
                    session = participant.session
                    if session and session.is_unlocked():
                        return True
        return False

    def to_dict(self, viewer=None, user_lat=None, user_lon=None):
        design_config = self.get_design_config()
        time_locked = self.is_locked()
        base_can_view = self.can_view(viewer)

        geo_locked = False
        geo_message = None
        if self.has_geo_lock() and not (viewer and viewer.is_authenticated and viewer.id == self.user_id):
            geo_unlocked, geo_msg = self.check_geo_unlock(user_lat, user_lon)
            if not geo_unlocked:
                geo_locked = True
                geo_message = geo_msg

        group_locked = False
        group_message = None
        group_session = None
        viewer_id = viewer.id if viewer and viewer.is_authenticated else None
        if self.has_group_lock() and not (viewer and viewer.is_authenticated and viewer.id == self.user_id):
            group_unlocked, group_msg, session = self.check_group_unlock(viewer_id)
            group_session = session
            if not group_unlocked:
                group_locked = True
                group_message = group_msg

        is_locked = time_locked or geo_locked or group_locked
        can_view = base_can_view and not is_locked

        collab_count = Collaborator.query.filter_by(memory_id=self.id, status='active').count()

        result = {
            'id': self.id,
            'title': self.title,
            'status': self.status,
            'visibility': self.visibility,
            'unlock_time': self.unlock_time.strftime('%Y-%m-%d %H:%M:%S') if self.unlock_time else None,
            'is_locked': is_locked,
            'time_locked': time_locked,
            'can_view': can_view,
            'unlock_type': self.unlock_type,
            'geo_locked': geo_locked,
            'geo_message': geo_message,
            'geo_latitude': self.geo_latitude,
            'geo_longitude': self.geo_longitude,
            'geo_radius': self.geo_radius,
            'geo_address': self.geo_address,
            'group_locked': group_locked,
            'group_message': group_message,
            'group_unlock_enabled': self.group_unlock_enabled,
            'group_unlock_count': self.group_unlock_count,
            'group_current_count': group_session.current_count if group_session else 0,
            'group_session_id': group_session.id if group_session else None,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M') if self.updated_at else None,
            'author': self.author.username,
            'author_id': self.user_id,
            'view_url': f'{app.config["MEMORY_VIEW_URL"]}?id={self.id}',
            'full_view_url': build_view_url(self.id),
            'collaborator_count': collab_count
        }

        if not is_locked and can_view:
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

COLLAB_ROLE_OWNER = 'owner'
COLLAB_ROLE_EDITOR = 'editor'
COLLAB_ROLE_VIEWER = 'viewer'
COLLAB_ROLE_COMMENTER = 'commenter'
VALID_COLLAB_ROLES = [COLLAB_ROLE_OWNER, COLLAB_ROLE_EDITOR, COLLAB_ROLE_VIEWER, COLLAB_ROLE_COMMENTER]

COLLAB_ROLE_LABELS = {
    COLLAB_ROLE_OWNER: '创建者',
    COLLAB_ROLE_EDITOR: '编辑者',
    COLLAB_ROLE_VIEWER: '查看者',
    COLLAB_ROLE_COMMENTER: '留言者'
}

class Collaborator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    memory_id = db.Column(db.String(36), db.ForeignKey('memory.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(20), default=COLLAB_ROLE_VIEWER, nullable=False)
    status = db.Column(db.String(20), default='active', nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

    memory = db.relationship('Memory', backref='collaborators')
    user = db.relationship('User', backref='collaborations')

    def to_dict(self):
        return {
            'id': self.id,
            'memory_id': self.memory_id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'role': self.role,
            'role_label': COLLAB_ROLE_LABELS.get(self.role, self.role),
            'status': self.status,
            'joined_at': self.joined_at.strftime('%Y-%m-%d %H:%M') if self.joined_at else None
        }

class CollaborationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    memory_id = db.Column(db.String(36), db.ForeignKey('memory.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    detail = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='collab_logs')

    def to_dict(self):
        return {
            'id': self.id,
            'memory_id': self.memory_id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else '未知用户',
            'action': self.action,
            'detail': self.detail,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None
        }

class Invitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    memory_id = db.Column(db.String(36), db.ForeignKey('memory.id'), nullable=False)
    invite_code = db.Column(db.String(8), unique=True, nullable=False)
    invite_link = db.Column(db.String(500), nullable=True)
    role = db.Column(db.String(20), default=COLLAB_ROLE_VIEWER, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    max_uses = db.Column(db.Integer, default=0)
    use_count = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    creator = db.relationship('User', backref='invitations')

    def to_dict(self):
        return {
            'id': self.id,
            'memory_id': self.memory_id,
            'invite_code': self.invite_code,
            'invite_link': self.invite_link,
            'role': self.role,
            'role_label': COLLAB_ROLE_LABELS.get(self.role, self.role),
            'max_uses': self.max_uses,
            'use_count': self.use_count,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None
        }

class JoinRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    memory_id = db.Column(db.String(36), db.ForeignKey('memory.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invitation_id = db.Column(db.Integer, db.ForeignKey('invitation.id'), nullable=True)
    role = db.Column(db.String(20), default=COLLAB_ROLE_VIEWER, nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)
    message = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship('User', backref='join_requests')
    invitation = db.relationship('Invitation', backref='join_requests')

    def to_dict(self):
        return {
            'id': self.id,
            'memory_id': self.memory_id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'invitation_id': self.invitation_id,
            'role': self.role,
            'role_label': COLLAB_ROLE_LABELS.get(self.role, self.role),
            'status': self.status,
            'message': self.message,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
            'reviewed_at': self.reviewed_at.strftime('%Y-%m-%d %H:%M') if self.reviewed_at else None
        }

class MemoryComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    memory_id = db.Column(db.String(36), db.ForeignKey('memory.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='comments')

    def to_dict(self):
        return {
            'id': self.id,
            'memory_id': self.memory_id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'content': self.content,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None
        }

def log_collab_action(memory_id, action, detail='', user_id=None):
    try:
        log = CollaborationLog(
            memory_id=memory_id,
            user_id=user_id or (current_user.id if current_user.is_authenticated else None),
            action=action,
            detail=detail[:500] if detail else ''
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Failed to write collaboration log: {str(e)}")

def get_user_role(memory_id, user_id):
    if not user_id:
        return None
    memory = Memory.query.get(memory_id)
    if not memory:
        return None
    if memory.user_id == user_id:
        return COLLAB_ROLE_OWNER
    collab = Collaborator.query.filter_by(
        memory_id=memory_id, user_id=user_id, status='active'
    ).first()
    return collab.role if collab else None

def can_edit(memory_id, user_id):
    role = get_user_role(memory_id, user_id)
    return role in [COLLAB_ROLE_OWNER, COLLAB_ROLE_EDITOR]

def can_view_collab(memory_id, user_id):
    role = get_user_role(memory_id, user_id)
    return role is not None

def can_comment(memory_id, user_id):
    role = get_user_role(memory_id, user_id)
    return role in [COLLAB_ROLE_OWNER, COLLAB_ROLE_EDITOR, COLLAB_ROLE_COMMENTER]

def calculate_distance(lat1, lon1, lat2, lon2):
    import math
    R = 6371000
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)
    a = math.sin(delta_phi / 2) ** 2 + \
        math.cos(phi1) * math.cos(phi2) * \
        math.sin(delta_lambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

def generate_invite_code(length=6):
    chars = string.ascii_uppercase + string.digits
    while True:
        code = ''.join(random.choices(chars, k=length))
        if not Invitation.query.filter_by(invite_code=code).first():
            return code

def generate_unlock_code(length=8):
    chars = string.ascii_uppercase + string.digits
    while True:
        code = ''.join(random.choices(chars, k=length))
        if not UnlockSession.query.filter_by(unlock_code=code).first():
            return code

class UnlockSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    memory_id = db.Column(db.String(36), db.ForeignKey('memory.id'), nullable=False)
    initiator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    unlock_code = db.Column(db.String(8), unique=True, nullable=False)
    required_count = db.Column(db.Integer, nullable=False, default=2)
    current_count = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(20), default='active', nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    unlocked_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    memory = db.relationship('Memory', backref='unlock_sessions')
    initiator = db.relationship('User', backref='initiated_unlocks')
    participants = db.relationship('UnlockParticipant', backref='session', lazy=True, cascade='all, delete-orphan')

    def is_unlocked(self):
        return self.status == 'unlocked' or self.current_count >= self.required_count

    def get_unlock_link(self):
        base_url = get_base_url()
        return f"{base_url}/view_memory.html?id={self.memory_id}&unlock_code={self.unlock_code}"

    def to_dict(self):
        return {
            'id': self.id,
            'memory_id': self.memory_id,
            'initiator_id': self.initiator_id,
            'initiator_username': self.initiator.username if self.initiator else None,
            'unlock_code': self.unlock_code,
            'unlock_link': self.get_unlock_link(),
            'required_count': self.required_count,
            'current_count': self.current_count,
            'status': self.status,
            'is_unlocked': self.is_unlocked(),
            'expires_at': self.expires_at.strftime('%Y-%m-%d %H:%M:%S') if self.expires_at else None,
            'unlocked_at': self.unlocked_at.strftime('%Y-%m-%d %H:%M:%S') if self.unlocked_at else None,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
            'participants': [p.to_dict() for p in self.participants]
        }

class UnlockParticipant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('unlock_session.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_latitude = db.Column(db.Float, nullable=True)
    user_longitude = db.Column(db.Float, nullable=True)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='unlock_participations')

    def to_dict(self):
        return {
            'id': self.id,
            'session_id': self.session_id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'joined_at': self.joined_at.strftime('%Y-%m-%d %H:%M') if self.joined_at else None
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
    unlock_type = request.form.get('unlock_type', UNLOCK_TYPE_NORMAL)
    geo_latitude = request.form.get('geo_latitude', None)
    geo_longitude = request.form.get('geo_longitude', None)
    geo_radius = request.form.get('geo_radius', None)
    geo_address = request.form.get('geo_address', '')
    group_unlock_enabled = request.form.get('group_unlock_enabled', 'false').lower() == 'true'
    group_unlock_count = request.form.get('group_unlock_count', 2, type=int)

    if status not in [MEMORY_STATUS_ACTIVE, MEMORY_STATUS_DRAFT, MEMORY_STATUS_ARCHIVED]:
        status = MEMORY_STATUS_ACTIVE

    if visibility not in [VISIBILITY_PRIVATE, VISIBILITY_PUBLIC]:
        visibility = VISIBILITY_PRIVATE

    if unlock_type not in VALID_UNLOCK_TYPES:
        unlock_type = UNLOCK_TYPE_NORMAL

    unlock_time = parse_unlock_time(unlock_time_str)

    if not title:
        return jsonify({'success': False, 'message': 'Title is required'}), 400
    if len(title) > MAX_TITLE_LENGTH:
        return jsonify({'success': False, 'message': f'Title too long (max {MAX_TITLE_LENGTH} characters)'}), 400
    if text and len(text) > MAX_TEXT_LENGTH:
        return jsonify({'success': False, 'message': f'Content too long (max {MAX_TEXT_LENGTH} characters)'}), 400

    if unlock_type in [UNLOCK_TYPE_GEO, UNLOCK_TYPE_COMBINED]:
        if geo_latitude is None or geo_longitude is None or geo_radius is None:
            return jsonify({'success': False, 'message': '地理位置解锁需要提供经纬度和范围'}), 400
        try:
            geo_latitude = float(geo_latitude)
            geo_longitude = float(geo_longitude)
            geo_radius = int(geo_radius)
            if not (-90 <= geo_latitude <= 90):
                return jsonify({'success': False, 'message': '纬度必须在 -90 到 90 之间'}), 400
            if not (-180 <= geo_longitude <= 180):
                return jsonify({'success': False, 'message': '经度必须在 -180 到 180 之间'}), 400
            if geo_radius <= 0:
                return jsonify({'success': False, 'message': '范围必须大于0米'}), 400
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': '地理位置参数格式错误'}), 400
    else:
        geo_latitude = None
        geo_longitude = None
        geo_radius = None
        geo_address = None

    if unlock_type in [UNLOCK_TYPE_GROUP, UNLOCK_TYPE_COMBINED]:
        if not group_unlock_enabled:
            group_unlock_enabled = True
        if group_unlock_count < 2:
            group_unlock_count = 2
        if group_unlock_count > 10:
            group_unlock_count = 10
    else:
        group_unlock_enabled = False
        group_unlock_count = 2

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
            unlock_type=unlock_type,
            geo_latitude=geo_latitude,
            geo_longitude=geo_longitude,
            geo_radius=geo_radius,
            geo_address=geo_address,
            group_unlock_enabled=group_unlock_enabled,
            group_unlock_count=group_unlock_count,
            author=current_user
        )
        db.session.add(memory)
        db.session.commit()
        app.logger.info(f"Memory created: {memory.id} by user {current_user.username}")
        log_operation('create_memory', f'Created memory: {title}, unlock_type: {unlock_type}', memory_id=memory.id)
        return jsonify({'success': True, 'id': memory.id, 'view_url': memory.to_dict()['view_url']})
    except Exception as e:
        app.logger.error(f"Error creating memory: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/memories/<memory_id>', methods=['GET'])
def get_memory(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    
    user_lat = request.args.get('lat', None, type=float)
    user_lon = request.args.get('lon', None, type=float)
    
    viewer = current_user if current_user.is_authenticated else None
    
    if memory.is_locked():
        log_operation('view_locked_memory', f'Attempted to view locked memory: {memory.title}', memory_id=memory.id)
        return jsonify(memory.to_dict(viewer=viewer, user_lat=user_lat, user_lon=user_lon))
    
    if not memory.can_view(viewer, user_lat, user_lon):
        if not current_user.is_authenticated:
            return jsonify({'error': 'auth_required', 'message': 'Please login'}), 401
        
        if memory.has_geo_lock():
            geo_unlocked, geo_msg = memory.check_geo_unlock(user_lat, user_lon)
            if not geo_unlocked:
                log_operation('geo_lock_denied', f'Geo location check failed: {geo_msg}', memory_id=memory.id)
                return jsonify(memory.to_dict(viewer=viewer, user_lat=user_lat, user_lon=user_lon))
        
        if memory.has_group_lock():
            viewer_id = viewer.id if viewer else None
            group_unlocked, group_msg, session = memory.check_group_unlock(viewer_id)
            if not group_unlocked:
                log_operation('group_lock_denied', f'Group unlock check failed: {group_msg}', memory_id=memory.id)
                return jsonify(memory.to_dict(viewer=viewer, user_lat=user_lat, user_lon=user_lon))
        
        app.logger.warning(f"Unauthorized access attempt to memory {memory_id} by user {current_user.username}")
        log_operation('unauthorized_access', f'Attempted to access memory {memory_id}', memory_id=memory_id)
        return jsonify({'error': 'Forbidden'}), 403

    log_operation('view_memory', f'Viewed memory: {memory.title}', memory_id=memory.id)
    return jsonify(memory.to_dict(viewer=viewer, user_lat=user_lat, user_lon=user_lon))

@app.route('/api/memories/<memory_id>', methods=['PUT'])
@login_required
def update_memory(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    if not can_edit(memory_id, current_user.id):
        log_operation('unauthorized_edit', f'Attempted to edit memory {memory_id}', memory_id=memory_id)
        return jsonify({'error': 'Forbidden'}), 403

    title = request.form.get('title', '').strip()
    text = request.form.get('text', '').strip()
    file = request.files.get('file')
    remove_media = request.form.get('remove_media', 'false').lower() == 'true'
    new_status = request.form.get('status', '')
    unlock_time_str = request.form.get('unlock_time', '')
    visibility = request.form.get('visibility', '')
    unlock_type = request.form.get('unlock_type', None)
    geo_latitude = request.form.get('geo_latitude', None)
    geo_longitude = request.form.get('geo_longitude', None)
    geo_radius = request.form.get('geo_radius', None)
    geo_address = request.form.get('geo_address', None)
    group_unlock_enabled = request.form.get('group_unlock_enabled', None)
    group_unlock_count = request.form.get('group_unlock_count', None, type=int)

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

    if unlock_type and unlock_type in VALID_UNLOCK_TYPES:
        memory.unlock_type = unlock_type

    if geo_latitude is not None and geo_longitude is not None and geo_radius is not None:
        try:
            lat = float(geo_latitude)
            lon = float(geo_longitude)
            radius = int(geo_radius)
            if not (-90 <= lat <= 90):
                return jsonify({'success': False, 'message': '纬度必须在 -90 到 90 之间'}), 400
            if not (-180 <= lon <= 180):
                return jsonify({'success': False, 'message': '经度必须在 -180 到 180 之间'}), 400
            if radius <= 0:
                return jsonify({'success': False, 'message': '范围必须大于0米'}), 400
            memory.geo_latitude = lat
            memory.geo_longitude = lon
            memory.geo_radius = radius
            if geo_address is not None:
                memory.geo_address = geo_address[:200]
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': '地理位置参数格式错误'}), 400
    elif geo_latitude == '' or geo_latitude == 'null':
        memory.geo_latitude = None
        memory.geo_longitude = None
        memory.geo_radius = None
        memory.geo_address = None

    if group_unlock_enabled is not None:
        memory.group_unlock_enabled = group_unlock_enabled.lower() == 'true'

    if group_unlock_count is not None:
        if group_unlock_count < 2:
            group_unlock_count = 2
        if group_unlock_count > 10:
            group_unlock_count = 10
        memory.group_unlock_count = group_unlock_count

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
        if memory.user_id != current_user.id:
            log_collab_action(memory_id, 'edit_content', f'{current_user.username} 编辑了记忆内容')
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

    data = request.json or {}
    user_lat = data.get('lat', None)
    user_lon = data.get('lon', None)

    if user_lat is not None:
        try:
            user_lat = float(user_lat)
        except (ValueError, TypeError):
            user_lat = None
    if user_lon is not None:
        try:
            user_lon = float(user_lon)
        except (ValueError, TypeError):
            user_lon = None

    log_operation('qr_scan', f'QR code scanned for memory: {memory.title}', memory_id=memory_id, ip=request.remote_addr)

    viewer = current_user if current_user.is_authenticated else None
    memory_dict = memory.to_dict(viewer=viewer, user_lat=user_lat, user_lon=user_lon)

    view_url = app.config['MEMORY_VIEW_URL'] + '?id=' + memory.id
    return jsonify({
        'success': True,
        'memory_id': memory.id,
        'view_url': view_url,
        'is_locked': memory_dict['is_locked'],
        'geo_locked': memory_dict.get('geo_locked', False),
        'geo_message': memory_dict.get('geo_message', None),
        'group_locked': memory_dict.get('group_locked', False),
        'group_message': memory_dict.get('group_message', None),
        'unlock_type': memory_dict.get('unlock_type', 'normal')
    })

@app.route('/api/memories/<memory_id>/unlock/geo-check', methods=['POST'])
@login_required
def check_geo_unlock(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    
    if not memory.has_geo_lock():
        return jsonify({'success': True, 'unlocked': True, 'message': '此记忆没有地理位置限制'})
    
    data = request.json or {}
    user_lat = data.get('lat', None)
    user_lon = data.get('lon', None)
    
    if user_lat is None or user_lon is None:
        return jsonify({'success': False, 'unlocked': False, 'message': '需要提供位置信息'}), 400
    
    try:
        user_lat = float(user_lat)
        user_lon = float(user_lon)
    except (ValueError, TypeError):
        return jsonify({'success': False, 'unlocked': False, 'message': '位置信息格式错误'}), 400
    
    unlocked, message = memory.check_geo_unlock(user_lat, user_lon)
    distance = calculate_distance(memory.geo_latitude, memory.geo_longitude, user_lat, user_lon)
    
    log_operation(
        'geo_check',
        f'Geo check - lat: {user_lat:.6f}, lon: {user_lon:.6f}, distance: {distance:.0f}m, unlocked: {unlocked}',
        memory_id=memory_id
    )
    
    return jsonify({
        'success': True,
        'unlocked': unlocked,
        'message': message,
        'distance': distance,
        'required_radius': memory.geo_radius,
        'target_latitude': memory.geo_latitude,
        'target_longitude': memory.geo_longitude,
        'target_address': memory.geo_address
    })

@app.route('/api/memories/<memory_id>/unlock/group/start', methods=['POST'])
@login_required
def start_group_unlock(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    
    if not memory.has_group_lock():
        return jsonify({'success': False, 'message': '此记忆没有设置多人联合解锁'}), 400
    
    if memory.user_id == current_user.id:
        return jsonify({'success': False, 'message': '创建者无需参与联合解锁'}), 400
    
    existing_session = UnlockSession.query.filter_by(
        memory_id=memory_id, status='active'
    ).order_by(UnlockSession.created_at.desc()).first()
    
    if existing_session and not existing_session.is_unlocked():
        existing_participant = UnlockParticipant.query.filter_by(
            session_id=existing_session.id, user_id=current_user.id
        ).first()
        if existing_participant:
            return jsonify({
                'success': True,
                'session': existing_session.to_dict(),
                'message': '您已在当前解锁会话中'
            })
    
    unlock_code = generate_unlock_code()
    session = UnlockSession(
        memory_id=memory_id,
        initiator_id=current_user.id,
        unlock_code=unlock_code,
        required_count=memory.group_unlock_count
    )
    db.session.add(session)
    db.session.flush()
    
    data = request.json or {}
    user_lat = data.get('lat', None)
    user_lon = data.get('lon', None)
    
    participant = UnlockParticipant(
        session_id=session.id,
        user_id=current_user.id,
        user_latitude=user_lat,
        user_longitude=user_lon
    )
    db.session.add(participant)
    session.current_count = 1
    
    try:
        db.session.commit()
        log_collab_action(
            memory_id,
            'start_group_unlock',
            f'{current_user.username} 发起了多人联合解锁，需要 {memory.group_unlock_count} 人参与'
        )
        log_operation('group_unlock_start', f'Started group unlock session {unlock_code}', memory_id=memory_id)
        
        return jsonify({
            'success': True,
            'session': session.to_dict(),
            'message': f'已发起联合解锁，还需 {memory.group_unlock_count - 1} 人参与'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error starting group unlock: {str(e)}")
        return jsonify({'success': False, 'message': '发起解锁失败，请重试'}), 500

@app.route('/api/memories/<memory_id>/unlock/group/join', methods=['POST'])
@login_required
def join_group_unlock(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    
    if not memory.has_group_lock():
        return jsonify({'success': False, 'message': '此记忆没有设置多人联合解锁'}), 400
    
    if memory.user_id == current_user.id:
        return jsonify({'success': False, 'message': '创建者无需参与联合解锁'}), 400
    
    session = UnlockSession.query.filter_by(
        memory_id=memory_id, status='active'
    ).order_by(UnlockSession.created_at.desc()).first()
    
    if not session:
        return jsonify({'success': False, 'message': '当前没有进行中的解锁会话，请先发起解锁'}), 400
    
    if session.is_unlocked():
        participant = UnlockParticipant.query.filter_by(
            session_id=session.id, user_id=current_user.id
        ).first()
        if participant:
            return jsonify({
                'success': True,
                'session': session.to_dict(),
                'unlocked': True,
                'message': '记忆已解锁'
            })
        return jsonify({
            'success': False,
            'message': '本轮解锁已完成，但您未参与。请发起新一轮解锁。'
        }), 400
    
    existing_participant = UnlockParticipant.query.filter_by(
        session_id=session.id, user_id=current_user.id
    ).first()
    if existing_participant:
        return jsonify({
            'success': True,
            'session': session.to_dict(),
            'message': f'您已参与本轮解锁，还需 {session.required_count - session.current_count} 人'
        })
    
    data = request.json or {}
    user_lat = data.get('lat', None)
    user_lon = data.get('lon', None)
    
    participant = UnlockParticipant(
        session_id=session.id,
        user_id=current_user.id,
        user_latitude=user_lat,
        user_longitude=user_lon
    )
    db.session.add(participant)
    session.current_count += 1
    
    if session.current_count >= session.required_count:
        session.status = 'unlocked'
        session.unlocked_at = datetime.utcnow()
        unlocked = True
        message = '解锁成功！记忆内容现在可以查看了'
    else:
        unlocked = False
        message = f'参与成功！还需 {session.required_count - session.current_count} 人参与解锁'
    
    try:
        db.session.commit()
        log_collab_action(
            memory_id,
            'join_group_unlock',
            f'{current_user.username} 参与了联合解锁，当前 {session.current_count}/{session.required_count} 人'
        )
        log_operation('group_unlock_join', f'Joined unlock session {session.unlock_code}', memory_id=memory_id)
        
        return jsonify({
            'success': True,
            'session': session.to_dict(),
            'unlocked': unlocked,
            'message': message
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error joining group unlock: {str(e)}")
        return jsonify({'success': False, 'message': '参与解锁失败，请重试'}), 500

@app.route('/api/memories/<memory_id>/unlock/group/status', methods=['GET'])
@login_required
def get_group_unlock_status(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    
    session = UnlockSession.query.filter_by(
        memory_id=memory_id
    ).order_by(UnlockSession.created_at.desc()).first()
    
    if not session:
        return jsonify({
            'success': True,
            'has_session': False,
            'session': None,
            'required_count': memory.group_unlock_count,
            'current_count': 0,
            'unlocked': False
        })
    
    participant = None
    if current_user.is_authenticated:
        participant = UnlockParticipant.query.filter_by(
            session_id=session.id, user_id=current_user.id
        ).first()
    
    return jsonify({
        'success': True,
        'has_session': True,
        'session': session.to_dict(),
        'required_count': memory.group_unlock_count,
        'current_count': session.current_count,
        'unlocked': session.is_unlocked(),
        'is_participant': participant is not None
    })

@app.route('/api/unlock/session/<unlock_code>', methods=['GET'])
@login_required
def get_unlock_session_by_code(unlock_code):
    session = UnlockSession.query.filter_by(unlock_code=unlock_code).first()
    if not session:
        return jsonify({'success': False, 'message': '无效的解锁链接'}), 404
    
    memory = Memory.query.get(session.memory_id)
    if not memory:
        return jsonify({'success': False, 'message': '关联的记忆不存在'}), 404
    
    participant = None
    if current_user.is_authenticated:
        participant = UnlockParticipant.query.filter_by(
            session_id=session.id, user_id=current_user.id
        ).first()
    
    return jsonify({
        'success': True,
        'session': session.to_dict(),
        'memory': {
            'id': memory.id,
            'title': memory.title,
            'author': memory.author.username if memory.author else None,
            'unlock_type': memory.unlock_type,
            'has_geo_lock': memory.has_geo_lock(),
            'geo_address': memory.geo_address
        },
        'is_participant': participant is not None,
        'is_owner': memory.user_id == current_user.id
    })

_FRONTEND_DIR = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'src')

@app.route('/api/collab/<memory_id>/invite', methods=['POST'])
@login_required
def create_invitation(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    if memory.user_id != current_user.id:
        return jsonify({'error': 'Forbidden', 'message': '只有创建者可以生成邀请'}), 403

    data = request.json or {}
    role = data.get('role', COLLAB_ROLE_VIEWER)
    if role not in VALID_COLLAB_ROLES or role == COLLAB_ROLE_OWNER:
        role = COLLAB_ROLE_VIEWER

    invite_code = generate_invite_code()
    base_url = get_base_url()
    invite_link = f"{base_url}/join.html?code={invite_code}"

    invitation = Invitation(
        memory_id=memory_id,
        invite_code=invite_code,
        invite_link=invite_link,
        role=role,
        created_by=current_user.id,
        max_uses=data.get('max_uses', 0)
    )
    db.session.add(invitation)
    db.session.commit()

    log_collab_action(memory_id, 'create_invitation', f'创建邀请码 {invite_code}，角色：{COLLAB_ROLE_LABELS.get(role, role)}')
    return jsonify({'success': True, 'invitation': invitation.to_dict()})

@app.route('/api/collab/<memory_id>/invitations', methods=['GET'])
@login_required
def list_invitations(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    if memory.user_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403

    invitations = Invitation.query.filter_by(memory_id=memory_id).order_by(Invitation.created_at.desc()).all()
    return jsonify({'success': True, 'invitations': [inv.to_dict() for inv in invitations]})

@app.route('/api/collab/invitation/<invite_code>', methods=['GET'])
def get_invitation_info(invite_code):
    invitation = Invitation.query.filter_by(invite_code=invite_code).first()
    if not invitation:
        return jsonify({'success': False, 'message': '邀请码不存在'}), 404

    if not invitation.is_active:
        return jsonify({'success': False, 'message': '邀请已失效'}), 400

    if invitation.max_uses > 0 and invitation.use_count >= invitation.max_uses:
        return jsonify({'success': False, 'message': '邀请已达到使用上限'}), 400

    memory = Memory.query.get(invitation.memory_id)
    if not memory:
        return jsonify({'success': False, 'message': '关联的记忆不存在'}), 404

    has_pending = False
    if current_user.is_authenticated:
        existing = JoinRequest.query.filter_by(
            memory_id=invitation.memory_id,
            user_id=current_user.id,
            status='pending'
        ).first()
        has_pending = existing is not None

        already_member = Collaborator.query.filter_by(
            memory_id=invitation.memory_id,
            user_id=current_user.id,
            status='active'
        ).first()
        if already_member:
            return jsonify({
                'success': True,
                'already_member': True,
                'memory': {'id': memory.id, 'title': memory.title},
                'role': already_member.role,
                'invite_code': invite_code
            })

    return jsonify({
        'success': True,
        'already_member': False,
        'has_pending_request': has_pending,
        'memory': {'id': memory.id, 'title': memory.title},
        'role': invitation.role,
        'role_label': COLLAB_ROLE_LABELS.get(invitation.role, invitation.role),
        'invite_code': invite_code
    })

@app.route('/api/collab/join', methods=['POST'])
@login_required
def join_collaboration():
    data = request.json or {}
    invite_code = data.get('invite_code', '').strip()
    message = data.get('message', '').strip()

    if not invite_code:
        return jsonify({'success': False, 'message': '请提供邀请码'}), 400

    invitation = Invitation.query.filter_by(invite_code=invite_code).first()
    if not invitation:
        return jsonify({'success': False, 'message': '邀请码不存在'}), 404

    if not invitation.is_active:
        return jsonify({'success': False, 'message': '邀请已失效'}), 400

    if invitation.max_uses > 0 and invitation.use_count >= invitation.max_uses:
        return jsonify({'success': False, 'message': '邀请已达到使用上限'}), 400

    memory = Memory.query.get(invitation.memory_id)
    if not memory:
        return jsonify({'success': False, 'message': '关联的记忆不存在'}), 404

    if memory.user_id == current_user.id:
        return jsonify({'success': False, 'message': '您是该记忆的创建者'}), 400

    existing_collab = Collaborator.query.filter_by(
        memory_id=invitation.memory_id,
        user_id=current_user.id,
        status='active'
    ).first()
    if existing_collab:
        return jsonify({'success': False, 'message': '您已是该记忆的协作者'}), 400

    existing_request = JoinRequest.query.filter_by(
        memory_id=invitation.memory_id,
        user_id=current_user.id,
        status='pending'
    ).first()
    if existing_request:
        return jsonify({'success': False, 'message': '您已提交申请，请等待创建者审核'}), 400

    join_req = JoinRequest(
        memory_id=invitation.memory_id,
        user_id=current_user.id,
        invitation_id=invitation.id,
        role=invitation.role,
        status='pending',
        message=message[:200] if message else None
    )
    db.session.add(join_req)
    db.session.commit()

    log_collab_action(invitation.memory_id, 'join_request', f'{current_user.username} 申请加入协作，角色：{COLLAB_ROLE_LABELS.get(invitation.role, invitation.role)}')
    return jsonify({'success': True, 'message': '申请已提交，请等待创建者审核', 'request_id': join_req.id})

@app.route('/api/collab/<memory_id>/requests', methods=['GET'])
@login_required
def list_join_requests(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    if memory.user_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403

    requests = JoinRequest.query.filter_by(
        memory_id=memory_id, status='pending'
    ).order_by(JoinRequest.created_at.desc()).all()
    return jsonify({'success': True, 'requests': [r.to_dict() for r in requests]})

@app.route('/api/collab/requests/<request_id>/approve', methods=['POST'])
@login_required
def approve_join_request(request_id):
    join_req = JoinRequest.query.get_or_404(request_id)
    memory = Memory.query.get_or_404(join_req.memory_id)

    if memory.user_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403

    if join_req.status != 'pending':
        return jsonify({'success': False, 'message': '该申请已处理'}), 400

    existing = Collaborator.query.filter_by(
        memory_id=join_req.memory_id,
        user_id=join_req.user_id,
        status='active'
    ).first()
    if existing:
        join_req.status = 'rejected'
        join_req.reviewed_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': False, 'message': '该用户已是协作者'}), 400

    collab = Collaborator(
        memory_id=join_req.memory_id,
        user_id=join_req.user_id,
        role=join_req.role,
        status='active'
    )
    db.session.add(collab)

    join_req.status = 'approved'
    join_req.reviewed_at = datetime.utcnow()

    if join_req.invitation_id:
        inv = Invitation.query.get(join_req.invitation_id)
        if inv:
            inv.use_count += 1

    db.session.commit()

    username = join_req.user.username if join_req.user else '未知用户'
    log_collab_action(join_req.memory_id, 'approve_join', f'批准 {username} 加入协作，角色：{COLLAB_ROLE_LABELS.get(join_req.role, join_req.role)}')
    return jsonify({'success': True, 'message': f'已批准 {username} 加入协作'})

@app.route('/api/collab/requests/<request_id>/reject', methods=['POST'])
@login_required
def reject_join_request(request_id):
    join_req = JoinRequest.query.get_or_404(request_id)
    memory = Memory.query.get_or_404(join_req.memory_id)

    if memory.user_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403

    if join_req.status != 'pending':
        return jsonify({'success': False, 'message': '该申请已处理'}), 400

    join_req.status = 'rejected'
    join_req.reviewed_at = datetime.utcnow()
    db.session.commit()

    username = join_req.user.username if join_req.user else '未知用户'
    log_collab_action(join_req.memory_id, 'reject_join', f'拒绝 {username} 的协作申请')
    return jsonify({'success': True, 'message': f'已拒绝 {username} 的申请'})

@app.route('/api/collab/<memory_id>/members', methods=['GET'])
@login_required
def list_collaborators(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    role = get_user_role(memory_id, current_user.id)
    if role is None:
        return jsonify({'error': 'Forbidden'}), 403

    owner_info = {
        'id': None,
        'memory_id': memory_id,
        'user_id': memory.user_id,
        'username': memory.author.username if memory.author else None,
        'role': COLLAB_ROLE_OWNER,
        'role_label': COLLAB_ROLE_LABELS[COLLAB_ROLE_OWNER],
        'status': 'active',
        'joined_at': memory.created_at.strftime('%Y-%m-%d %H:%M') if memory.created_at else None
    }

    collabs = Collaborator.query.filter_by(memory_id=memory_id, status='active').all()
    members = [owner_info] + [c.to_dict() for c in collabs]
    return jsonify({'success': True, 'members': members})

@app.route('/api/collab/<memory_id>/members/<collab_id>/role', methods=['PUT'])
@login_required
def update_member_role(memory_id, collab_id):
    memory = Memory.query.get_or_404(memory_id)
    if memory.user_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403

    collab = Collaborator.query.get_or_404(collab_id)
    if collab.memory_id != memory_id:
        return jsonify({'error': 'Invalid collaborator'}), 400

    data = request.json or {}
    new_role = data.get('role', '')
    if new_role not in VALID_COLLAB_ROLES or new_role == COLLAB_ROLE_OWNER:
        return jsonify({'success': False, 'message': '无效的角色'}), 400

    old_role = collab.role
    collab.role = new_role
    db.session.commit()

    username = collab.user.username if collab.user else '未知用户'
    log_collab_action(memory_id, 'role_change', f'{username} 角色从 {COLLAB_ROLE_LABELS.get(old_role, old_role)} 变更为 {COLLAB_ROLE_LABELS.get(new_role, new_role)}')
    return jsonify({'success': True, 'member': collab.to_dict()})

@app.route('/api/collab/<memory_id>/members/<collab_id>', methods=['DELETE'])
@login_required
def remove_member(memory_id, collab_id):
    memory = Memory.query.get_or_404(memory_id)
    if memory.user_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403

    collab = Collaborator.query.get_or_404(collab_id)
    if collab.memory_id != memory_id:
        return jsonify({'error': 'Invalid collaborator'}), 400

    username = collab.user.username if collab.user else '未知用户'
    collab.status = 'removed'
    db.session.commit()

    log_collab_action(memory_id, 'remove_member', f'移除协作者 {username}')
    return jsonify({'success': True, 'message': f'已移除 {username}'})

@app.route('/api/collab/<memory_id>/leave', methods=['POST'])
@login_required
def leave_collaboration(memory_id):
    collab = Collaborator.query.filter_by(
        memory_id=memory_id, user_id=current_user.id, status='active'
    ).first()
    if not collab:
        return jsonify({'success': False, 'message': '您不是该记忆的协作者'}), 400

    collab.status = 'left'
    db.session.commit()

    log_collab_action(memory_id, 'leave_collab', f'{current_user.username} 退出协作')
    return jsonify({'success': True, 'message': '已退出协作'})

@app.route('/api/collab/<memory_id>/logs', methods=['GET'])
@login_required
def get_collab_logs(memory_id):
    role = get_user_role(memory_id, current_user.id)
    if role is None:
        return jsonify({'error': 'Forbidden'}), 403

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    per_page = min(per_page, 100)

    pagination = CollaborationLog.query.filter_by(memory_id=memory_id).order_by(
        CollaborationLog.created_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'success': True,
        'logs': [log.to_dict() for log in pagination.items],
        'total': pagination.total,
        'page': page,
        'per_page': per_page,
        'has_next': pagination.has_next
    })

@app.route('/api/collab/<memory_id>/comments', methods=['GET'])
@login_required
def get_comments(memory_id):
    role = get_user_role(memory_id, current_user.id)
    if role is None:
        return jsonify({'error': 'Forbidden'}), 403

    comments = MemoryComment.query.filter_by(memory_id=memory_id).order_by(
        MemoryComment.created_at.desc()
    ).all()
    return jsonify({'success': True, 'comments': [c.to_dict() for c in comments]})

@app.route('/api/collab/<memory_id>/comments', methods=['POST'])
@login_required
def add_comment(memory_id):
    if not can_comment(memory_id, current_user.id):
        return jsonify({'error': 'Forbidden', 'message': '您没有留言权限'}), 403

    data = request.json or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'success': False, 'message': '留言内容不能为空'}), 400
    if len(content) > 500:
        return jsonify({'success': False, 'message': '留言内容不能超过500字'}), 400

    comment = MemoryComment(
        memory_id=memory_id,
        user_id=current_user.id,
        content=content
    )
    db.session.add(comment)
    db.session.commit()

    log_collab_action(memory_id, 'add_comment', f'{current_user.username} 添加了留言', user_id=current_user.id)
    return jsonify({'success': True, 'comment': comment.to_dict()})

@app.route('/api/memories/collaborated', methods=['GET'])
@login_required
def get_collaborated_memories():
    collabs = Collaborator.query.filter_by(user_id=current_user.id, status='active').all()
    memories = []
    for c in collabs:
        memory = Memory.query.get(c.memory_id)
        if memory:
            d = memory.to_dict(viewer=current_user)
            d['collab_role'] = c.role
            d['collab_role_label'] = COLLAB_ROLE_LABELS.get(c.role, c.role)
            memories.append(d)
    return jsonify(memories)

@app.route('/api/collab/<memory_id>/my-role', methods=['GET'])
@login_required
def get_my_role(memory_id):
    role = get_user_role(memory_id, current_user.id)
    return jsonify({
        'success': True,
        'role': role,
        'role_label': COLLAB_ROLE_LABELS.get(role, role) if role else None,
        'is_owner': role == COLLAB_ROLE_OWNER,
        'can_edit': can_edit(memory_id, current_user.id),
        'can_comment': can_comment(memory_id, current_user.id)
    })

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

    existing_tables = inspector.get_table_names()
    for table_name in ['collaborator', 'collaboration_log', 'invitation', 'join_request', 'memory_comment', 'unlock_session', 'unlock_participant']:
        if table_name not in existing_tables:
            app.logger.info(f"Table '{table_name}' will be created by db.create_all()")

    db.create_all()

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

        if 'unlock_type' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE memory ADD COLUMN unlock_type VARCHAR(20) DEFAULT 'normal' NOT NULL"))
                    conn.commit()
                app.logger.info("Added 'unlock_type' column to memory table")
            except Exception as e:
                app.logger.warning(f"Could not add unlock_type column: {e}")

        if 'geo_latitude' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE memory ADD COLUMN geo_latitude FLOAT"))
                    conn.commit()
                app.logger.info("Added 'geo_latitude' column to memory table")
            except Exception as e:
                app.logger.warning(f"Could not add geo_latitude column: {e}")

        if 'geo_longitude' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE memory ADD COLUMN geo_longitude FLOAT"))
                    conn.commit()
                app.logger.info("Added 'geo_longitude' column to memory table")
            except Exception as e:
                app.logger.warning(f"Could not add geo_longitude column: {e}")

        if 'geo_radius' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE memory ADD COLUMN geo_radius INTEGER"))
                    conn.commit()
                app.logger.info("Added 'geo_radius' column to memory table")
            except Exception as e:
                app.logger.warning(f"Could not add geo_radius column: {e}")

        if 'geo_address' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE memory ADD COLUMN geo_address VARCHAR(200)"))
                    conn.commit()
                app.logger.info("Added 'geo_address' column to memory table")
            except Exception as e:
                app.logger.warning(f"Could not add geo_address column: {e}")

        if 'group_unlock_enabled' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE memory ADD COLUMN group_unlock_enabled BOOLEAN DEFAULT 0 NOT NULL"))
                    conn.commit()
                app.logger.info("Added 'group_unlock_enabled' column to memory table")
            except Exception as e:
                app.logger.warning(f"Could not add group_unlock_enabled column: {e}")

        if 'group_unlock_count' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE memory ADD COLUMN group_unlock_count INTEGER DEFAULT 2 NOT NULL"))
                    conn.commit()
                app.logger.info("Added 'group_unlock_count' column to memory table")
            except Exception as e:
                app.logger.warning(f"Could not add group_unlock_count column: {e}")

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
