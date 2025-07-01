from flask import Flask, render_template, request, redirect, session, url_for, flash, send_file, Response, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt
import os
import base64
import json
import time
import hashlib
import shutil
import random
import threading
import unicodedata
import sqlite3
import difflib
import requests
import csv
import io
import string
import secrets
import urllib.parse
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import uuid
import logging
from datetime import date, datetime, timedelta
from uuid import uuid4
from markupsafe import Markup
from werkzeug.utils import secure_filename
from PIL import Image as PILImage
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import zipfile

try:
    from wand.image import Image
except ImportError:
    pass  # Sẽ xử lý trong upload_avatar() nếu cần

try:
    from PIL import Image as PILImage
except ImportError:
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "Pillow"])
    from PIL import Image as PILImage
    

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eiki_tomobe.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads', 'evernote')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

app.config['TASK_UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads', 'task')
os.makedirs(app.config['TASK_UPLOAD_FOLDER'], exist_ok=True)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Set up logging
logging.basicConfig(level=logging.DEBUG)

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Tạo key từ master password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def get_master_password():
    """Lấy master password từ user"""
    # Trong production, có thể lưu trong session hoặc cache tạm thời
    return getpass.getpass("Enter master password: ")

class PasswordEncryption:
    def __init__(self):
        self.salt = None
        self.fernet = None
        
    def initialize(self, master_password: str):
        """Khởi tạo với master password"""
        # Load salt từ file hoặc tạo mới
        salt_file = 'password_salt.key'
        if os.path.exists(salt_file):
            with open(salt_file, 'rb') as f:
                self.salt = f.read()
        else:
            self.salt = os.urandom(16)
            with open(salt_file, 'wb') as f:
                f.write(self.salt)
        
        # Tạo key từ master password
        key = derive_key_from_password(master_password, self.salt)
        self.fernet = Fernet(key)
    
    def encrypt_password(self, password: str) -> str:
        """Mã hóa password"""
        if not self.fernet:
            raise ValueError("Encryption not initialized")
        encrypted = self.fernet.encrypt(password.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_password(self, encrypted_password: str) -> str:
        """Giải mã password"""
        if not self.fernet:
            raise ValueError("Encryption not initialized")
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_password.encode())
        decrypted = self.fernet.decrypt(encrypted_bytes)
        return decrypted.decode()

# Global instance
password_encryption = PasswordEncryption()

def get_theme():
    """Get theme from UserSettings"""
    settings = get_user_settings()
    return settings.theme_preference or 'light'

def get_user_info():
    """Get user info from UserSettings"""
    settings = get_user_settings()
    return settings.user_name, settings.user_birthday



def verify_password(password):
    """Verify password from UserSettings"""
    try:
        app.logger.info(f"🔍 DEBUG: verify_password() called with password: {'*' * len(password) if password else 'None'}")
        
        settings = get_user_settings()
        app.logger.info(f"🔍 DEBUG: UserSettings loaded - ID: {settings.id if settings else 'None'}")
        
        hash_str = settings.user_password_hash if settings else None
        app.logger.info(f"🔍 DEBUG: hash_str from UserSettings.user_password_hash: {'EXISTS' if hash_str else 'NULL'}")
        
        if not hash_str:
            app.logger.warning(f"⚠️  DEBUG: No password hash found in UserSettings!")
            return False
        
        # Debug: Show first 20 chars of hash for identification
        hash_preview = hash_str[:20] + "..." if len(hash_str) > 20 else hash_str
        app.logger.info(f"🔍 DEBUG: Hash preview: {hash_preview}")
        
        # Verify password
        result = bcrypt.checkpw(password.encode('utf-8'), hash_str.encode('utf-8'))
        app.logger.info(f"🔍 DEBUG: bcrypt.checkpw() result: {result}")
        
        return result
        
    except Exception as e:
        app.logger.error(f"❌ DEBUG: Exception in verify_password(): {str(e)}")
        app.logger.error(f"❌ DEBUG: Exception type: {type(e).__name__}")
        return False

# User model
class User(UserMixin):
    def __init__(self):
        self.id = 'default'

# Category model
class TaskCategory(db.Model):
    __tablename__ = 'task_category' 
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    color = db.Column(db.String(7), nullable=True)  # HEX color, e.g., #FF0000

# Note model
# Trong class Note
class Task(db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('task_category.id'), nullable=True)
    due_date = db.Column(db.DateTime, nullable=True)
    share_id = db.Column(db.String(36), nullable=True)
    is_completed = db.Column(db.Boolean, default=False)
    images = db.Column(db.Text, nullable=True)  # Lưu JSON chứa danh sách ảnh (base64)
    category = db.relationship('TaskCategory', backref='Task')


class Diary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    color = db.Column(db.String(7), nullable=False)

class Slogan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)

# Quote Category model
class QuoteCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    quotes = db.relationship('Quote', backref='category', lazy=True)

class Quote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('quote_category.id'), nullable=False)


# Thêm model mới cho Folder
class EvernoteFolder(db.Model):
    __tablename__ = 'evernote_folder'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('evernote_folder.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Self-referential relationship for nested folders
    children = db.relationship('EvernoteFolder', backref=db.backref('parent', remote_side=[id]))
    notes = db.relationship('EvernoteNote', backref='folder', lazy=True)

# Cập nhật EvernoteNote model - thêm folder_id
class EvernoteNote(db.Model):
    __tablename__ = 'evernote_note'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('evernote_folder.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    share_id = db.Column(db.String(36), nullable=True, unique=True)
    
    # Thay đổi: lưu danh sách tên file thay vì base64
    image_files = db.Column(db.Text, nullable=True)  # JSON array of filenames
    
    def get_image_files(self):
        if self.image_files:
            return json.loads(self.image_files)
        return []
    
    def set_image_files(self, filenames):
        self.image_files = json.dumps(filenames) if filenames else None
    
    def add_image_file(self, filename):
        files = self.get_image_files()
        if filename not in files:
            files.append(filename)
            self.set_image_files(files)
    
    def remove_image_file(self, filename):
        files = self.get_image_files()
        if filename in files:
            files.remove(filename)
            self.set_image_files(files)
            # Xóa file khỏi disk
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    app.logger.info(f"Deleted file: {filename}")
                except Exception as e:
                    app.logger.error(f"Error deleting file {filename}: {e}")

    
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    date = db.Column(db.Date, nullable=False)
    priority = db.Column(db.String(10), nullable=False, default='medium')  # low, medium, high
    repeat_type = db.Column(db.String(20), nullable=True)  # none, daily, weekly, monthly, custom
    repeat_interval = db.Column(db.Integer, nullable=True)  # cho custom repeat
    repeat_unit = db.Column(db.String(10), nullable=True)  # days, weeks, months
    end_date = db.Column(db.Date, nullable=True)
    completed = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    parent_id = db.Column(db.Integer, db.ForeignKey('todo.id'), nullable=True)  # Cho repeat todos
    
    # Relationship cho parent-child todos
    children = db.relationship('Todo', backref=db.backref('parent', remote_side=[id]))

class Password(db.Model):
    __tablename__ = 'passwords'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    website_url = db.Column(db.String(500), nullable=True)
    username = db.Column(db.String(200), nullable=True)
    password_encrypted = db.Column(db.Text, nullable=False)  # ✅ Lưu password đã mã hóa
    note = db.Column(db.Text, nullable=True)
    category_id = db.Column(db.Integer, db.ForeignKey('password_categories.id'), nullable=True)
    category = db.relationship('PasswordCategory', backref='passwords')
    favorite = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    @property
    def password(self):
        """Giải mã password khi truy cập"""
        try:
            if password_encryption.fernet:
                return password_encryption.decrypt_password(self.password_encrypted)
            else:
                return "[Encrypted - Master password required]"
        except:
            return "[Encrypted - Cannot decrypt]"
    
    @password.setter
    def password(self, value):
        """Mã hóa password khi set"""
        if value and password_encryption.fernet:
            self.password_encrypted = password_encryption.encrypt_password(value)
        else:
            # ✅ SỬA: Store as-is if encryption not available (for migration)
            self.password_encrypted = value
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'website_url': self.website_url or '',
            'username': self.username or '',
            'password': self.password,  # Sử dụng property để auto-decrypt
            'note': self.note or '',
            'category_id': self.category_id,
            'category_name': self.category.name if self.category else 'General',
            'category_color': self.category.color if self.category else '#6c757d',
            'favorite': self.favorite,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
class PasswordCategory(db.Model):
    __tablename__ = 'password_categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    color = db.Column(db.String(7), nullable=True, default='#007bff')  # HEX color
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Unique constraint để tránh duplicate categories cho cùng user
    __table_args__ = (db.UniqueConstraint('name', name='unique_password_category_per_user'),)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'color': self.color,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Contact(db.Model):
    __tablename__ = 'contacts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    relation = db.Column(db.String(100))
    phone = db.Column(db.String(50))
    email = db.Column(db.String(100))
    address = db.Column(db.String(200))
    company = db.Column(db.String(200))
    position = db.Column(db.String(100))
    group = db.Column(db.String(100))
    birthday = db.Column(db.String(10))  # YYYY-MM-DD
    website = db.Column(db.String(200))
    anniv1_text = db.Column(db.String(100))
    anniv1_date = db.Column(db.String(10))  # YYYY-MM-DD
    anniv2_text = db.Column(db.String(100))
    anniv2_date = db.Column(db.String(10))
    anniv3_text = db.Column(db.String(100))
    anniv3_date = db.Column(db.String(10))
    dependents = db.Column(db.String(200))  # comma separated or text
    note = db.Column(db.Text)
    
class UserSettings(db.Model):
    __tablename__ = 'user_settings'
    id = db.Column(db.Integer, primary_key=True)
    
    # Password Manager settings
    master_password_hint = db.Column(db.String(200), nullable=True)
    
    # Theme và UI settings
    theme_preference = db.Column(db.String(10), default='light')
    show_bg_image = db.Column(db.Boolean, default=True)
    show_quote = db.Column(db.Boolean, default=True)
    
    # User profile info
    user_name = db.Column(db.String(100), nullable=True)
    user_birthday = db.Column(db.String(20), nullable=True)  # Store as string YYYY-MM-DD
    user_password_hash = db.Column(db.Text, nullable=True)
    
    # JSON fields
    card_info = db.Column(db.Text, nullable=True)  # JSON string for card data
    links_tree = db.Column(db.Text, nullable=True)  # JSON string for links
    breath_settings = db.Column(db.Text, nullable=True)  # JSON string
    
    # AI settings
    ai_question_template = db.Column(db.Text, nullable=True)
    vocabulary_query_template = db.Column(db.Text, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)


# Mindmap Models
class MindMap(db.Model):
    __tablename__ = 'mindmap'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=False, default='personal')
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    shared = db.Column(db.Boolean, default=False)
    share_password = db.Column(db.String(100), nullable=True)
    
    # Relationships
    nodes = db.relationship('MindMapNode', backref='mindmap', lazy=True, cascade='all, delete-orphan')
    connections = db.relationship('MindMapConnection', backref='mindmap', lazy=True, cascade='all, delete-orphan')

class MindMapNode(db.Model):
    __tablename__ = 'mindmap_node'
    id = db.Column(db.String(50), primary_key=True)  # node_1, node_2, etc.
    mindmap_id = db.Column(db.Integer, db.ForeignKey('mindmap.id'), nullable=False)
    text = db.Column(db.String(500), nullable=False)
    x = db.Column(db.Float, nullable=False)
    y = db.Column(db.Float, nullable=False)
    color = db.Column(db.String(7), nullable=False, default='#ffffff')
    font_size = db.Column(db.String(10), nullable=False, default='14px')
    is_root = db.Column(db.Boolean, default=False)
    parent_id = db.Column(db.String(50), db.ForeignKey('mindmap_node.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # Self-referential relationship for parent-child
    children = db.relationship(
                                'MindMapNode',
                                backref=db.backref('parent', remote_side=[id]),
                                lazy=True,
                                foreign_keys='MindMapNode.parent_id'
                            )

class MindMapConnection(db.Model):
    __tablename__ = 'mindmap_connection'
    id = db.Column(db.Integer, primary_key=True)
    mindmap_id = db.Column(db.Integer, db.ForeignKey('mindmap.id'), nullable=False)
    from_node_id = db.Column(db.String(50), nullable=False)
    to_node_id = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

class MindMapShare(db.Model):
    __tablename__ = 'mindmap_share'
    id = db.Column(db.Integer, primary_key=True)
    mindmap_id = db.Column(db.Integer, db.ForeignKey('mindmap.id'), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)  # Generated password for shared access
    permission = db.Column(db.String(20), nullable=False, default='view')  # view, edit
    created_at = db.Column(db.DateTime, default=datetime.now)
    expires_at = db.Column(db.DateTime, nullable=True)
    
    mindmap = db.relationship('MindMap', backref='shares')
    
    
def get_card_info(self):
    """Get card info as dict"""
    if self.card_info:
        try:
            return json.loads(self.card_info)
        except:
            return {}
    return {}

def set_card_info(self, data):
    """Set card info from dict"""
    if data:
        self.card_info = json.dumps(data, ensure_ascii=False)
    else:
        self.card_info = None

def get_links_tree(self):
    """Get links tree as list"""
    if self.links_tree:
        try:
            return json.loads(self.links_tree)
        except:
            return []
    return []

def set_links_tree(self, data):
    """Set links tree from list"""
    if data:
        self.links_tree = json.dumps(data, ensure_ascii=False)
    else:
        self.links_tree = None

def get_breath_settings(self):
    """Get breath settings as dict"""
    if self.breath_settings:
        try:
            return json.loads(self.breath_settings)
        except:
            return {}
    return {}

def set_breath_settings(self, data):
    """Set breath settings from dict"""
    if data:
        self.breath_settings = json.dumps(data, ensure_ascii=False)
    else:
        self.breath_settings = None

def to_dict(self):
    return {
        'id': self.id,
        'master_password_hint': self.master_password_hint,
        'theme_preference': self.theme_preference,
        'show_bg_image': self.show_bg_image,
        'show_quote': self.show_quote,
        'user_name': self.user_name,
        'user_birthday': self.user_birthday,
        'card_info': self.get_card_info(),
        'links_tree': self.get_links_tree(),
        'breath_settings': self.get_breath_settings(),
        'ai_question_template': self.ai_question_template,
        'vocabulary_query_template': self.vocabulary_query_template,
        'created_at': self.created_at.isoformat() if self.created_at else None,
        'updated_at': self.updated_at.isoformat() if self.updated_at else None
    }
    
def get_user_settings():
    """Get or create user settings - always default for single user"""
    settings = UserSettings.query.filter_by().first()
    if not settings:
        settings = UserSettings()
        db.session.add(settings)
        db.session.commit()
    return settings

def update_user_setting(**kwargs):
    """Update specific user settings - single user system"""
    settings = get_user_settings()
    
    for key, value in kwargs.items():
        if hasattr(settings, key):
            setattr(settings, key, value)
    
    settings.updated_at = datetime.now()
    db.session.commit()
    return settings

def get_user_setting(setting_name=None, default=None):
    """Get specific user setting"""
    settings = get_user_settings()
    if setting_name:
        return getattr(settings, setting_name, default)
    return settings

def get_keywords_file_path():
    """Get path to keywords progress file"""
    return os.path.join(app.root_path, 'keywords.txt')

def get_kw_file_path():
    """Get path to kw.txt file"""
    file_path = os.path.join(app.root_path, 'kw.txt')
    app.logger.info(f"kw.txt path: {file_path}")
    return file_path

def get_method_file_path():
    """Get path to method.txt file"""
    return os.path.join(app.root_path, 'method.txt')

    
def load_knowledge_categories():
    """Load knowledge categories from kw.txt"""
    file_path = get_kw_file_path()
    default_categories = {
        "science": ["Machine Learning", "Quantum Physics", "Biotechnology"],
        "history": ["World War II", "Ancient Civilizations", "Industrial Revolution"],
        "business": ["Digital Marketing", "Entrepreneurship", "Financial Analysis"]
    }
    
    try:
        app.logger.info(f"Loading knowledge categories from: {file_path}")
        
        if os.path.exists(file_path):
            app.logger.info(f"File exists, reading content...")
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                
                if not content:
                    return default_categories                
                data = json.loads(content)
                
                if isinstance(data, dict) and data:
                    return data
                else:
                    return default_categories
        else:
            app.logger.info("File doesn't exist, creating with default categories")
            # Create default kw.txt file
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_categories, f, ensure_ascii=False, indent=2)
            app.logger.info(f"Created default kw.txt at: {file_path}")
            return default_categories
    except json.JSONDecodeError as e:
        app.logger.error(f"JSON decode error in kw.txt: {str(e)}")
        return default_categories
    except Exception as e:
        app.logger.error(f"Error loading kw.txt: {str(e)}")
        return default_categories
    
def get_ai_file_path():
    """Get path to AI.txt file"""
    return os.path.join(app.root_path, 'AI.txt')

def load_ai_settings():
    """Load AI settings from AI.txt"""
    file_path = get_ai_file_path()
    default_settings = {
        "chatgpt_url": "https://chat.openai.com/?q={query}",
        "grok_url": "https://x.com/i/grok?q={query}",
        "perplexity_url": "https://www.perplexity.ai/?q={query}",
        "you_url": "https://you.com/search?q={query}",
        "copilot_url": "https://copilot.microsoft.com/?q={query}",
        "chatgpt_enabled": True,
        "grok_enabled": True,
        "perplexity_enabled": False,
        "you_enabled": False,
        "copilot_enabled": False
    }
    
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Merge with defaults, but keep custom URLs if they exist
                settings = default_settings.copy()
                settings.update(data)  # This will override defaults with saved data
                return settings
        else:
            # Create default AI.txt file
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_settings, f, ensure_ascii=False, indent=2)
            return default_settings
    except Exception as e:
        app.logger.error(f"Error loading AI.txt: {str(e)}")
        return default_settings
    
def save_ai_settings(settings):
    """Save AI settings to AI.txt"""
    file_path = get_ai_file_path()
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        app.logger.error(f"Error saving AI.txt: {str(e)}")
        return False

@app.route('/ai_settings', methods=['GET', 'POST'])
@login_required
def ai_settings():
    if request.method == 'POST':
        try:
            data = request.get_json()
            app.logger.info(f"Received AI settings data: {data}")
            
            # Validate only URL fields that contain {query}
            url_fields = ['chatgpt_url', 'grok_url', 'perplexity_url', 'you_url', 'copilot_url']
            
            for key, value in data.items():
                # Only validate URL fields, skip enabled fields
                if key in url_fields and value and value.strip():
                    if '{query}' not in value:
                        app.logger.warning(f"Invalid URL for {key}: {value}")
                        return jsonify({
                            'status': 'error', 
                            'message': f'{key.replace("_url", "").title()} URL must contain {{query}} placeholder'
                        }), 400
            
            app.logger.info("Validation passed, saving settings...")
            if save_ai_settings(data):
                app.logger.info("AI settings saved successfully")
                return jsonify({'status': 'success'})
            else:
                app.logger.error("Failed to save AI settings")
                return jsonify({'status': 'error', 'message': 'Failed to save AI settings'}), 500
                
        except Exception as e:
            app.logger.error(f"Error in ai_settings route: {str(e)}")
            return jsonify({'status': 'error', 'message': f'Server error: {str(e)}'}), 500
    else:
        return jsonify(load_ai_settings())
    
def load_criteria_methods():
    """Load criteria methods from method.txt"""
    file_path = get_method_file_path()
    default_methods = {
        "science": ["Hiểu được khái niệm cơ bản", "Biết ứng dụng thực tế", "Có thể giải thích cho người khác"],
        "history": ["Nhớ được thời gian sự kiện", "Hiểu nguyên nhân kết quả", "Liên kết với hiện tại"],
        "business": ["Nắm được lý thuyết", "Biết cách áp dụng", "Có thể phân tích case study"]
    }
    
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data if isinstance(data, dict) else default_methods
        else:
            # Create default method.txt file
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_methods, f, ensure_ascii=False, indent=2)
            return default_methods
    except Exception as e:
        app.logger.error(f"Error loading method.txt: {str(e)}")
        return default_methods
    
    
def initialize_keywords_file():
    """Initialize keywords.txt file if it doesn't exist"""
    file_path = get_keywords_file_path()
    
    if not os.path.exists(file_path):
        # Load categories dynamically from kw.txt
        knowledge_categories = load_knowledge_categories()
        
        default_data = {
            "completed_keywords": [],
            "criteria_progress": {},  # New: track criteria completion
            "last_updated": datetime.now().isoformat(),
            "stats": {
                "total_completed": 0,
                "categories_progress": {category: 0 for category in knowledge_categories.keys()}
            }
        }
        
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_data, f, ensure_ascii=False, indent=2)
            app.logger.info(f"Created keywords.txt file at {file_path}")
        except Exception as e:
            app.logger.error(f"Error creating keywords.txt: {str(e)}")
            
# Initialize database and user.txt
with app.app_context():
    initialize_keywords_file()
    load_knowledge_categories()
    load_criteria_methods()
    db.create_all()

    # ✅ SỬA: Tạo default password categories thay vì categories chung
    default_password_categories = [
        ('General', '#6c757d'),
        ('SNS', '#007bff'),
        ('Banking', '#28a745'),
        ('Work', '#ffc107'),
        ('Shopping', '#fd7e14'),
        ('Email', '#6f42c1')
    ]
    
    for name, color in default_password_categories:
        if not PasswordCategory.query.filter_by(name=name).first():
            category = PasswordCategory(name=name, color=color)
            db.session.add(category)
    
    # Tạo default folder cho Evernote
    if not EvernoteFolder.query.first():
        default_folder = EvernoteFolder(name="General Notes")
        db.session.add(default_folder)
        db.session.commit()
        app.logger.info("Created default folder: General Notes")
    
    # Tạo default categories cho Notes/Tasks (giữ nguyên)
    for name, color in [('Work', '#FF9999'), ('Personal', '#99FF99'), ('Ideas', '#9999FF')]:
        if not TaskCategory.query.filter_by(name=name).first():
            db.session.add(TaskCategory(name=name, color=color))
    
    if not Slogan.query.filter_by().first():
        default_slogan = Slogan(text="Write your story, live your journey.")
        db.session.add(default_slogan)
        db.session.commit()
    
    if not QuoteCategory.query.first():
        db.session.add(QuoteCategory(name="General"))
        db.session.commit()
        
    db.session.commit()
            


def nl2br(value):
    return Markup(value.replace('\n', '<br>'))

app.jinja_env.filters['nl2br'] = nl2br

    
@app.route('/set_theme', methods=['POST'])
@login_required
def set_theme():
    theme = request.json.get('theme')
    update_user_setting(theme_preference=theme)
    
    return jsonify({'status': 'success'})

    
@login_manager.user_loader
def load_user(user_id):
    return User()



# Register font for Vietnamese support
try:
    pdfmetrics.registerFont(TTFont('DejaVuSans', 'DejaVuSans.ttf'))
except Exception as e:
    app.logger.error(f"Failed to register font: {str(e)}")
    pdfmetrics.registerFont(TTFont('DejaVuSans', 'Helvetica'))  # Fallback to Helvetica


@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/task')
@login_required
def task():
    search_query = request.args.get('search', '').strip()
    category_id = request.args.get('category_id', type=int)
    show_completed = request.args.get('show_completed', default=0, type=int)
    show_incomplete = request.args.get('show_incomplete', default=1, type=int)

    # Lấy danh sách category
    categories = TaskCategory.query.order_by(TaskCategory.id).all()

    # Query notes theo user
    notes_query = Task.query

    # Lọc theo category nếu có
    if category_id:
        notes_query = notes_query.filter_by(category_id=category_id)

    # Lọc completed/incomplete
    if show_completed and not show_incomplete:
        notes_query = notes_query.filter_by(is_completed=True)
    elif show_incomplete and not show_completed:
        notes_query = notes_query.filter_by(is_completed=False)
    # Nếu cả hai đều bật hoặc đều tắt thì không lọc gì thêm

    # Lọc theo search
    if search_query:
        notes_query = notes_query.filter(
            (Task.title.ilike(f'%{search_query}%')) |
            (Task.content.ilike(f'%{search_query}%'))
        )

    # Sắp xếp theo due_date tăng dần, nulls_last để note không có due_date xuống cuối
    notes_query = notes_query.order_by(Task.due_date.asc().nulls_last())

    notes = notes_query.all()

    # Group notes by category_id đã sort
    notes_by_category = {}
    for note in notes:
        notes_by_category.setdefault(note.category_id, []).append(note)

    # Chuẩn bị dữ liệu cho JS (nếu cần)
    notes_data = [
        {
            "id": n.id,
            "title": n.title,
            "content": n.content,
            "due_date": n.due_date.isoformat() if n.due_date else None,
            "category_id": n.category_id,
            "is_completed": n.is_completed,
            "share_id": getattr(n, 'share_id', None),
            "images": [
            {
                "filename": img.get("filename"),
                "data": img.get("data")
            } for img in (json.loads(n.images) if n.images else [])
        ]
        }
        for n in notes
    ]
    categories_data = [
        {
            "id": c.id,
            "name": c.name,
            "color": c.color
        }
        for c in categories
    ]

    now = datetime.now()

    return render_template(
        'Memo/task.html',
        notes=notes,
        notes_by_category=notes_by_category,
        notes_data=notes_data,
        search_query=search_query,
        categories=categories_data,
        selected_category=category_id,
        show_completed=show_completed,
        show_incomplete=show_incomplete,
        now=now
    )

def normalize_filename(filename):
    if not filename or not isinstance(filename, str):
        return 'image.jpg'
    # Chuẩn hóa Unicode về dạng NFKC để xử lý ký tự tiếng Nhật
    normalized = unicodedata.normalize('NFKC', filename)
    # Thay thế ký tự không an toàn
    safe_name = ''.join(c if c.isalnum() or c in '._-\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FAF' else '_' for c in normalized)
    # Loại bỏ nhiều dấu chấm và dấu chấm cuối
    safe_name = safe_name.replace('..', '.').rstrip('.')
    return safe_name or 'image.jpg'

@app.route('/add_note', methods=['POST'])
@login_required
def add_note():
    try:
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        category_id = request.form.get('category_id')
        due_date = request.form.get('due_date')
        
        if not title:
            return jsonify({'status': 'error', 'message': 'Title is required'})
        
        # ✅ SỬA: Parse due_date với format datetime-local
        due_date_parsed = None
        if due_date:
            try:
                # Xử lý cả 2 format: datetime-local (YYYY-MM-DDTHH:MM) và date (YYYY-MM-DD)
                if 'T' in due_date:
                    due_date_parsed = datetime.strptime(due_date, '%Y-%m-%dT%H:%M')
                else:
                    # Nếu chỉ có ngày, set time mặc định là 23:59
                    date_part = datetime.strptime(due_date, '%Y-%m-%d')
                    due_date_parsed = date_part.replace(hour=23, minute=59)
            except ValueError as e:
                logging.error(f"Invalid due date format: {due_date}, error: {str(e)}")
                return jsonify({'status': 'error', 'message': 'Invalid due date format'})
        
        # Process images
        images = request.files.getlist('images')
        images_data = []
        
        for image in images:
            if image and image.filename:
                try:
                    # Generate unique filename
                    timestamp = int(time.time() * 1000)
                    original_filename = secure_filename(image.filename)
                    name, ext = os.path.splitext(original_filename)
                    unique_filename = f"{name}_{timestamp}_{uuid4().hex[:8]}{ext}"
                    
                    # Save file to disk
                    filepath = os.path.join(app.config['TASK_UPLOAD_FOLDER'], unique_filename)
                    
                    # Process image like in upload_task_images
                    if image.filename.lower().endswith('.heic'):
                        try:
                            with Image(blob=image.read()) as img:
                                img.format = 'jpeg'
                                img.compression_quality = 85
                                img.save(filename=filepath.replace('.heic', '.jpg').replace('.HEIC', '.jpg'))
                                unique_filename = unique_filename.replace('.heic', '.jpg').replace('.HEIC', '.jpg')
                        except:
                            image.save(filepath)
                    else:
                        pil_image = PILImage.open(image)
                        max_size = (1920, 1080)
                        if pil_image.size[0] > max_size[0] or pil_image.size[1] > max_size[1]:
                            pil_image.thumbnail(max_size, PILImage.Resampling.LANCZOS)
                        
                        if pil_image.mode in ('RGBA', 'P'):
                            pil_image = pil_image.convert('RGB')
                        
                        pil_image.save(filepath, 'JPEG', quality=85, optimize=True)
                    
                    images_data.append({
                        'filename': unique_filename,
                        'original_name': original_filename,
                        'path': f'/static/uploads/task/{unique_filename}',
                        'upload_time': datetime.now().isoformat(),
                        'size': os.path.getsize(filepath) if os.path.exists(filepath) else 0
                    })
                    
                except Exception as e:
                    logging.error(f"Error processing image {image.filename}: {str(e)}")
                    continue
        
        # Create note
        note = Task(
            title=title,
            content=content,
            category_id=int(category_id) if category_id and category_id.isdigit() else None,
            due_date=due_date_parsed,  # ✅ SỬA: Sử dụng due_date_parsed thay vì due_date.strptime()
            images=json.dumps(images_data) if images_data else None
        )
        
        db.session.add(note)
        db.session.commit()
        
        # Return note data
        note_data = {
            'id': note.id,
            'title': note.title,
            'content': note.content,
            'category': note.category.name if note.category else 'Uncategorized',
            'due_date': note.due_date.strftime('%Y-%m-%d %H:%M') if note.due_date else None,  # ✅ SỬA: Format đầy đủ
            'images': images_data,
        }
        
        return jsonify({'status': 'success', 'note': note_data})
        
    except Exception as e:
        logging.error(f"Add note error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/edit_note/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_note(id):
    note = Task.query.get_or_404(id)

    if request.method == 'POST':
        try:
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()
            category_id = request.form.get('category_id')
            due_date = request.form.get('due_date')
            
            # Validate required fields
            if not title:
                return jsonify({'status': 'error', 'message': 'Title is required'}), 400

            if not content:
                return jsonify({'status': 'error', 'message': 'Content is required'}), 400

            # Parse due_date
            due_date_parsed = None
            if due_date:
                try:
                    if 'T' in due_date:
                        due_date_parsed = datetime.strptime(due_date, '%Y-%m-%dT%H:%M')
                    else:
                        date_part = datetime.strptime(due_date, '%Y-%m-%d')
                        due_date_parsed = date_part.replace(hour=23, minute=59)
                except ValueError as e:
                    app.logger.error(f"Invalid due date format: {due_date}")
                    return jsonify({'status': 'error', 'message': 'Invalid due date format'}), 400

            # Process new images
            new_images = request.files.getlist('images')
            existing_images = json.loads(note.images) if note.images else []
            
            for image in new_images:
                if image and image.filename:
                    try:
                        # Generate unique filename
                        timestamp = int(time.time() * 1000)
                        original_filename = secure_filename(image.filename)
                        name, ext = os.path.splitext(original_filename)
                        unique_filename = f"{name}_{timestamp}_{uuid4().hex[:8]}{ext}"
                        
                        # Save file to disk
                        filepath = os.path.join(app.config['TASK_UPLOAD_FOLDER'], unique_filename)
                        
                        # Process image
                        if image.filename.lower().endswith('.heic'):
                            try:
                                with Image(blob=image.read()) as img:
                                    img.format = 'jpeg'
                                    img.compression_quality = 85
                                    img.save(filename=filepath.replace('.heic', '.jpg').replace('.HEIC', '.jpg'))
                                    unique_filename = unique_filename.replace('.heic', '.jpg').replace('.HEIC', '.jpg')
                            except:
                                image.save(filepath)
                        else:
                            pil_image = PILImage.open(image)
                            max_size = (1920, 1080)
                            if pil_image.size[0] > max_size[0] or pil_image.size[1] > max_size[1]:
                                pil_image.thumbnail(max_size, PILImage.Resampling.LANCZOS)
                            
                            if pil_image.mode in ('RGBA', 'P'):
                                pil_image = pil_image.convert('RGB')
                            
                            pil_image.save(filepath, 'JPEG', quality=85, optimize=True)
                        
                        # Add to existing images
                        existing_images.append({
                            'filename': unique_filename,
                            'original_name': original_filename,
                            'path': f'/static/uploads/task/{unique_filename}',
                            'upload_time': datetime.now().isoformat(),
                            'size': os.path.getsize(filepath) if os.path.exists(filepath) else 0
                        })
                        
                    except Exception as e:
                        app.logger.error(f"Error processing image {image.filename}: {str(e)}")
                        continue

            # Update note
            note.title = title
            note.content = content
            note.category_id = int(category_id) if category_id and category_id.isdigit() else None
            note.due_date = due_date_parsed
            note.images = json.dumps(existing_images) if existing_images else None

            db.session.commit()

            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'status': 'success',
                    'message': 'Note updated successfully!',
                    'note': {
                        'id': note.id,
                        'title': note.title,
                        'content': note.content,
                        'category_id': note.category_id,
                        'category_name': note.category.name if note.category else 'Uncategorized',
                        'due_date': note.due_date.strftime('%Y-%m-%dT%H:%M') if note.due_date else '',
                        'is_completed': bool(note.is_completed),
                        'images': existing_images
                    }
                })
            return redirect(url_for('task'))

        except Exception as e:
            app.logger.error(f"Error in edit_note: {str(e)}")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': f'Server error: {str(e)}'}), 500
            return redirect(url_for('task'))

    # GET request - Load note data for editing
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        images = json.loads(note.images) if note.images else []
        
        # ✅ SỬA: Format due_date cho datetime-local input
        due_date_formatted = ''
        if note.due_date:
            # Format: YYYY-MM-DDTHH:MM (không có seconds)
            due_date_formatted = note.due_date.strftime('%Y-%m-%dT%H:%M')
        
        return jsonify({
            'status': 'success',
            'message': 'Note loaded successfully.',
            'note': {
                'id': note.id,
                'title': note.title,
                'content': note.content,
                'category_id': note.category_id,
                'category_name': note.category.name if note.category else 'Uncategorized',
                'due_date': due_date_formatted,  # ✅ SỬA: Format đúng cho datetime-local
                'is_completed': bool(note.is_completed),
                'images': images
            }
        })

    return redirect(url_for('task'))

# Route hiển thị note được chia sẻ (không cần login)
@app.route('/shared/evernote/<share_id>')
def view_shared_evernote(share_id):
    try:
        note = EvernoteNote.query.filter_by(share_id=share_id).first_or_404()
        
        # ✅ SỬA: Get images từ image_files field (không phải images field)
        image_files = note.get_image_files() if hasattr(note, 'get_image_files') else []
        images = []
        
        for filename in image_files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                images.append({
                    'filename': filename,
                    'url': url_for('get_shared_evernote_image_file', share_id=share_id, filename=filename)
                })
        
        app.logger.info(f"Shared note {share_id} has {len(images)} images")
        
        return render_template('Memo/shared_evernote.html', 
                             note=note, 
                             images=images)
        
    except Exception as e:
        app.logger.error(f"Error viewing shared note: {str(e)}")
        return render_template('error.html', 
                             error_message="Note not found or has been deleted"), 404

@app.route('/shared/evernote/<share_id>/image/<filename>')
def get_shared_evernote_image_file(share_id, filename):
    """Serve image files for shared notes (không cần login)"""
    try:
        # Verify share_id exists
        note = EvernoteNote.query.filter_by(share_id=share_id).first_or_404()
        
        # Verify image belongs to this note
        image_files = note.get_image_files() if hasattr(note, 'get_image_files') else []
        
        if filename not in image_files:
            app.logger.warning(f"Image {filename} not found in note {share_id}")
            return "Image not found", 404
        
        # Serve the image file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(file_path):
            app.logger.warning(f"Image file {filename} not found on disk")
            return "Image file not found", 404
            
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
        
    except Exception as e:
        app.logger.error(f"Error serving shared image {filename}: {e}")
        return "Error serving image", 500
    
@app.route('/toggle_complete/<int:note_id>', methods=['POST'])
def toggle_complete(note_id):
    try:
        note = Task.query.get_or_404(note_id)
        note.is_completed = not note.is_completed
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Completion status updated',
            'is_completed': note.is_completed
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/delete_note/<int:id>', methods=['POST'])
@login_required
def delete_note(id):
    note = Task.query.get_or_404(id)
    try:
        db.session.delete(note)
        db.session.commit()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'success'})
        else:
            flash('Note deleted successfully.', 'success')
            return redirect(url_for('task'))
    except Exception as e:
        db.session.rollback()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'message': str(e)}), 500
        else:
            flash('Failed to delete note.', 'danger')
            return redirect(url_for('task'))

@app.route('/export/<int:id>')
@login_required
def export_note(id):
    note = Task.query.get_or_404(id)

    file_content = f"Title: {note.title}\n\n{note.content}\n\nCategory: {note.category.name if note.category else 'None'}"
    file = BytesIO(file_content.encode('utf-8'))
    return send_file(file, download_name=f"{note.title}.txt", as_attachment=True)

@app.route('/export_pdf/<int:id>')
@login_required
def export_pdf(id):
    note = Task.query.get_or_404(id)

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    try:
        p.setFont('DejaVuSans', 12)
    except:
        p.setFont('Helvetica', 12)  # Fallback font
    p.drawString(100, 750, note.title)
    y = 700
    for line in note.content.split('\n'):
        p.drawString(100, y, line)
        y -= 20
    p.drawString(100, y, f"Category: {note.category.name if note.category else 'None'}")
    y -= 30

    # Thêm ảnh vào PDF
    images = json.loads(note.images) if note.images else []
    for img in images:
        try:
            img_data = base64.b64decode(img['data'])
            img_buffer = BytesIO(img_data)
            # Chèn ảnh, resize cho phù hợp trang
            from reportlab.lib.utils import ImageReader
            image = ImageReader(img_buffer)
            iw, ih = image.getSize()
            max_width = 400
            max_height = 300
            scale = min(max_width / iw, max_height / ih, 1)
            draw_width = iw * scale
            draw_height = ih * scale
            if y - draw_height < 50:
                p.showPage()
                y = 750
            p.drawImage(image, 100, y - draw_height, width=draw_width, height=draw_height)
            y -= draw_height + 20
        except Exception as e:
            # Nếu lỗi ảnh, bỏ qua ảnh đó
            continue

    p.showPage()
    p.save()
    buffer.seek(0)
    return send_file(buffer, download_name=f"{note.title}.pdf", as_attachment=True)

@app.route('/Card')
@login_required
def card():
    return render_template('Card/Card1.html')

@app.route('/card_list')
@login_required
def card_list():
    card_dir = os.path.join(app.template_folder, 'Card')
    files = []
    for fname in os.listdir(card_dir):
        if fname.endswith('.html'):
            files.append(fname)
    return jsonify({'files': files})


import os

@app.route('/card_view/<filename>')
@login_required
def card_view(filename):
    if not filename.endswith('.html'):
        return "Invalid file", 400
    card_dir = os.path.join('Card', filename)
    settings = get_user_settings()
    card_info = settings.get_card_info()
    avatar_dir = os.path.join(app.static_folder, 'avatar')
    avatar_file = None
    if os.path.exists(avatar_dir):
        for fname in os.listdir(avatar_dir):
            if fname.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp', '.heic')):
                avatar_file = f'avatar/{fname}'
                break
    card_info['avatar_url'] = url_for('static', filename=avatar_file) if avatar_file else ''
    return render_template(card_dir, **card_info)

@app.route('/calendar')
@login_required
def calendar():
    categories = TaskCategory.query.all()
    # Serialize categories for JavaScript
    categories_data = [{'id': c.id, 'name': c.name, 'color': c.color or '#ffffff'} for c in categories]
    return render_template('Memo/calendar.html', categories=categories, categories_data=categories_data)

@app.route('/notes')
@login_required
def get_notes():
    notes = Task.query.all()
    events = [
        {
            'id': note.id,
            'title': note.title,
            'start': note.due_date.isoformat() if note.due_date else None,
            'backgroundColor': note.category.color if note.category and note.category.color else '#ffffff',
            'is_completed': note.is_completed
        }
        for note in notes if note.due_date
    ]
    return jsonify(events)

@app.route('/manage_categories')
@login_required
def manage_categories():
    categories = TaskCategory.query.all()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'status': 'success',
            'categories': [{'id': c.id, 'name': c.name, 'color': c.color or '#ffffff'} for c in categories]
        })
    return render_template('Memo/manage_categories.html', categories=categories)

@app.route('/add_category', methods=['GET', 'POST'])
@login_required
def add_category():
    if request.method == 'POST':
        name = request.form['name']
        color = request.form['color']
        if TaskCategory.query.filter_by(name=name).first():
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': 'Category already exists!'}), 400
            flash('Category already exists!', 'danger')
        else:
            category = TaskCategory(name=name, color=color)
            db.session.add(category)
            db.session.commit()
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'status': 'success',
                    'category': {'id': category.id, 'name': category.name, 'color': category.color or '#ffffff'}
                })
            flash('Category added successfully!', 'success')
        if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
            return redirect(url_for('manage_categories'))
    return render_template('add_category.html')

@app.route('/edit_category/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_category(id):
    category = TaskCategory.query.get_or_404(id)

    if request.method == 'POST':
        name = request.form['name']
        color = request.form['color']
        if TaskCategory.query.filter_by(name=name).first() and name != category.name:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': 'Category name already exists!'}), 400
            flash('Category name already exists!', 'danger')
        else:
            category.name = name
            category.color = color
            db.session.commit()
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'status': 'success',
                    'category': {'id': category.id, 'name': category.name, 'color': category.color or '#ffffff'}
                })
            flash('Category updated successfully!', 'success')
        if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
            return redirect(url_for('manage_categories'))
    return render_template('edit_category.html', category=category)

@app.route('/delete_category/<int:id>', methods=['POST'])
@login_required
def delete_category(id):
    category = TaskCategory.query.get_or_404(id)
    Task.query.filter_by(category_id=id).update({'category_id': None})
    db.session.delete(category)
    db.session.commit()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'status': 'success'})
    flash('Category deleted successfully!', 'success')

    if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
        return redirect(url_for('manage_categories'))
    return jsonify({'status': 'success'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        if verify_password(password):
            user = User()
            login_user(user)
            # Lấy theme từ config và lưu vào session
            session['theme'] = get_theme()
            return redirect(url_for('home'))
        flash('Invalid password', 'danger')
    return render_template('login.html')

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    new_password = request.form['new_password']
    if new_password:
        hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        
        # ✅ SỬA: Lưu vào UserSettings
        update_user_setting(user_password_hash=hashed.decode('utf-8'))
        
        flash('Password changed successfully!', 'success')
    else:
        flash('Please enter a new password', 'danger')
    return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/sync', methods=['POST'])
@login_required
def sync_notes():
    try:
        data = request.get_json()
        #app.logger.debug(f"Received sync data: {data}")
        for note in data.get('notes', []):
            existing_note = Task.query.get(note.get('id'))
            if existing_note:
                existing_note.title = note['title']
                existing_note.content = note['content']
                existing_note.category_id = note.get('category_id')
                due_date = note.get('due_date')
                existing_note.due_date = datetime.fromisoformat(due_date) if due_date else None
                existing_note.is_completed = note.get('is_completed', False)
            else:
                category = TaskCategory.query.filter_by(id=note.get('category_id')).first()
                new_note = Task(
                    title=note['title'],
                    content=note['content'],
                    category_id=category.id if category else None,
                    due_date=datetime.fromisoformat(due_date) if (due_date := note.get('due_date')) else None,
                    is_completed=note.get('is_completed', False)
                )
                db.session.add(new_note)
        db.session.commit()
        notes = Task.query.all()
        response = {
            'notes': [
                {
                    'id': note.id,
                    'title': note.title,
                    'content': note.content,
                    'category_id': note.category_id if note.category_id else None,
                    'due_date': note.due_date.isoformat() if note.due_date else None,
                    'is_completed': note.is_completed
                } for note in notes
            ]
        }
        #app.logger.debug(f"Sync response: {response}")
        return response
    except Exception as e:
        app.logger.error(f"Sync error: {str(e)}")
        return {'error': str(e)}, 500

import os

@app.route('/db_size')
@login_required
def db_size():
    db_path = os.path.join(app.instance_path, 'eiki_tomobe.db')  # Sửa lại đường dẫn này
    try:
        size_bytes = os.path.getsize(db_path)
        size_kb = round(size_bytes / 1024, 2)
        size_mb = round(size_kb / 1024, 2)
        return jsonify({'size_bytes': size_bytes, 'size_kb': size_kb, 'size_mb': size_mb})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/Diary/new', methods=['GET', 'POST'])
def new_diary():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        color = request.form['color']
        
        diary = Diary(title=title, content=content, color=color)
        db.session.add(diary)
        db.session.commit()
        
        flash('Diary entry saved!', 'success')
        return redirect(url_for('diary_list'))
    return render_template('Diary/new_diary.html')

@app.route('/Diary/edit/<int:id>', methods=['GET', 'POST'])
def edit_diary(id):
    diary = Diary.query.get_or_404(id)
    
    if request.method == 'POST':
        diary.title = request.form['title']
        diary.content = request.form['content']
        diary.color = request.form['color']
        db.session.commit()  # ✅ SỬA: db thay vì db_diary
        flash('Diary entry updated!', 'success')
        return redirect(url_for('diary_grid'))
    return render_template('Diary/edit_diary.html', diary=diary)

def require_diary_master_password():
    """Decorator để check master password - sử dụng password manager auth"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            # ✅ SỬA: Sử dụng session password manager thay vì diary riêng
            if not session.get('master_password_verified'):
                return jsonify({'status': 'error', 'message': 'Master password required'}), 401
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


@app.route('/Diary/grid')
def diary_grid():
    diaries = Diary.query.all()
    return render_template('Diary/diary_grid.html', diaries=diaries)

@app.route('/Diary/list')
def diary_list():
    diaries = Diary.query.order_by(Diary.date.desc()).all()
    return render_template('Diary/diary_list.html', diaries=diaries)

@app.route('/change_slogan', methods=['POST'])
def change_slogan():
    new_slogan_text = request.form['new_slogan']
    if not new_slogan_text or len(new_slogan_text) > 200:
        flash('Slogan must be between 1 and 200 characters.', 'danger')
        return redirect(request.referrer or url_for('Diary/diary_grid'))

    slogan = Slogan.query.first()
    if slogan:
        slogan.text = new_slogan_text
    else:
        slogan = Slogan(text=new_slogan_text)
        db.session.add(slogan)
    db.session.commit()
    flash('Slogan updated successfully!', 'success')
    return redirect(request.referrer or url_for('Diary/diary_grid'))

@app.context_processor
def inject_theme():
    # ✅ SỬA: Lấy theme từ UserSettings thay vì session/config
    theme = 'light'  # default
    
    if current_user.is_authenticated:
        try:
            settings = get_user_settings()
            theme = settings.theme_preference or 'light'
        except:
            theme = session.get('theme', 'light')
    else:
        theme = session.get('theme', 'light')
    
    # ✅ SỬA: Lấy user info từ UserSettings
    try:
        settings = get_user_settings()
        username = settings.user_name or 'Unknown'
        birthday = settings.user_birthday
    except:
        username, birthday = 'Unknown', None
    
    days_alive = 0
    if birthday:
        try:
            dob = datetime.strptime(birthday, '%Y-%m-%d').date()
            days_alive = (date.today() - dob).days
        except Exception:
            pass

    slogan = Slogan.query.first()
    slogan_text = slogan.text if slogan else "Write your story, live your journey."
    
    return dict(
        theme=theme,
        username=username,
        days_alive=days_alive,
        slogan=slogan_text
    )

# Custom Jinja2 filter to format numbers with thousands separators
@app.template_filter('format_thousands')
def format_thousands(number):
    try:
        return "{:,}".format(int(number))
    except (ValueError, TypeError):
        return number


@app.route('/quotes', methods=['GET', 'POST'])
def quotes():
    categories = QuoteCategory.query.order_by(QuoteCategory.name).all()
    quote = None
    selected_category = None

    all_quotes = Quote.query.all()

    if request.method == 'POST':
        if 'category' in request.form and request.form['category']:
            selected_category = request.form['category']
            category = QuoteCategory.query.filter_by(name=selected_category).first()
            quotes_list = Quote.query.filter_by(category=category).all() if category else []
            if quotes_list:
                quote = random.choice(quotes_list)
        else:
            if all_quotes:
                quote = random.choice(all_quotes)

    if not quote and all_quotes:
        quote = random.choice(all_quotes)

    return render_template('Quote/quotes.html', quote=quote, categories=categories,
                            selected_category=selected_category)
        

@app.route('/quotes/manage', methods=['GET', 'POST'])
def manage_quotes():
    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        category_name = request.form.get('category', '').strip()
        # Kiểm tra trùng lặp
        existing_quotes = [q.content for q in Quote.query.all()]
        for existing_content in existing_quotes:
            similarity = difflib.SequenceMatcher(None, content.lower(), existing_content.lower()).ratio()
            if similarity >= 0.8:
                flash("Trích dẫn này quá giống (≥80%) với một trích dẫn đã tồn tại! Vui lòng nhập trích dẫn khác.", "error")
                break
        else:
            if content:
                if category_name:
                    category = QuoteCategory.query.filter_by(name=category_name).first()
                    if not category:
                        category = QuoteCategory(name=category_name)
                        db.session.add(category)
                        db.session.commit()
                else:
                    # Nếu không nhập nguồn, tìm nguồn "St"
                    category = QuoteCategory.query.filter_by(name="St").first()
                    if not category:
                        category = QuoteCategory(name="St")
                        db.session.add(category)
                        db.session.commit()
                db.session.add(Quote(content=content, category=category))
                db.session.commit()
                flash("Trích dẫn đã được thêm thành công!", "success")
    quotes = Quote.query.order_by(Quote.content).all()
    categories = QuoteCategory.query.order_by(QuoteCategory.name).all()
    category_counts = db.session.query(QuoteCategory, db.func.count(Quote.id)).outerjoin(Quote).group_by(QuoteCategory.id).all()
    return render_template('Quote/manage_quotes.html', quotes=quotes, categories=categories, category_counts=category_counts)
    
@app.route('/quotes/edit/<int:id>', methods=['POST'])
def edit_quote(id):
    content = request.form['content']
    category_name = request.form['category']
    quote = Quote.query.get_or_404(id)
    category = QuoteCategory.query.filter_by(name=category_name).first()
    if not category:
        category = QuoteCategory(name=category_name)
        db.session.add(category)
        db.session.commit()
    quote.content = content
    quote.category = category
    db.session.commit()
    flash("Trích dẫn đã được sửa thành công!", "success")
    return redirect(url_for('manage_quotes'))


@app.route('/quotes/delete/<int:id>')
def delete_quote(id):
    quote = Quote.query.get_or_404(id)
    db.session.delete(quote)
    db.session.commit()
    flash("Trích dẫn đã được xóa thành công!", "success")
    return redirect(url_for('manage_quotes'))

@app.route('/quotes/delete_category/<int:category_id>')
def delete_quote_category(category_id):
    category = QuoteCategory.query.get_or_404(category_id)
    quote_count = Quote.query.filter_by(category=category).count()
    if quote_count > 0:
        flash(
            f"Không thể xóa nguồn '{category.name}' vì đang chứa {quote_count} trích dẫn. Vui lòng xóa hết trích dẫn trong nguồn này trước.",
            "error")
    else:
        db.session.delete(category)
        db.session.commit()
        flash(f"Nguồn '{category.name}' đã được xóa thành công.", "success")
    return redirect(url_for('manage_quotes'))

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'photo')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'heic'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def compress_and_resize_image(file_path, max_size_kb=500, max_dimension=1920, quality=85):
    """Compress and resize image to reduce file size"""
    try:
        with PILImage.open(file_path) as img:
            # Convert to RGB if necessary
            if img.mode in ('RGBA', 'LA', 'P'):
                img = img.convert('RGB')
            
            # Resize if too large
            if img.width > max_dimension or img.height > max_dimension:
                img.thumbnail((max_dimension, max_dimension), PILImage.Resampling.LANCZOS)
            
            # Save with compression
            temp_path = file_path + '.tmp'
            img.save(temp_path, format='JPEG', quality=quality, optimize=True)
            
            # Check file size and reduce quality if needed
            while os.path.getsize(temp_path) > max_size_kb * 1024 and quality > 20:
                quality -= 10
                img.save(temp_path, format='JPEG', quality=quality, optimize=True)
            
            # Replace original file
            shutil.move(temp_path, file_path)
            return True
            
    except Exception as e:
        app.logger.error(f"Error compressing image {file_path}: {e}")
        # Clean up temp file if exists
        temp_path = file_path + '.tmp'
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return False
    
@app.route('/upload_bg', methods=['POST'])
@login_required
def upload_bg():
    if 'bg_image' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('home'))
    file = request.files['bg_image']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('home'))
    if file and allowed_file(file.filename):
        # Xóa rỗng thư mục photo
        if os.path.exists(UPLOAD_FOLDER):
            shutil.rmtree(UPLOAD_FOLDER)
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        filename = secure_filename(file.filename)
        save_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(save_path)
        flash('Ảnh nền đã được cập nhật!', 'success')
    else:
        flash('File không hợp lệ!', 'danger')
    return redirect(url_for('home'))


def get_random_quote_from_db():
    """Lấy 1 quote ngẫu nhiên từ bảng quote trong quotes.db"""

    quote = Quote.query.order_by(db.func.random()).first()
    if quote:
        quote_text = quote.content
        quote_author = quote.category.name if quote.category else ""
    else:
        quote_text = "Chưa có trích dẫn nào."
        quote_author = ""
    return quote_text, quote_author
    
@app.route('/home')
@login_required
def home():
    quote_text, quote_author = get_random_quote_from_db()
    
    bg_image_url = None
    photo_dir = os.path.join(app.static_folder, 'photo')
    if os.path.exists(photo_dir):
        files = [f for f in os.listdir(photo_dir) if allowed_file(f)]
        if files:
            bg_image_url = url_for('static', filename=f'photo/{files[0]}')
    
    # ✅ SỬA: Lấy UI settings từ UserSettings
    settings = get_user_settings()
    alerts_today, alerts_tomorrow = get_birthday_alerts()
    
    return render_template(
        'home.html',
        quote_content=quote_text,
        quote_author=quote_author,
        bg_image_url=bg_image_url if settings.show_bg_image else None,
        show_quote=settings.show_quote,
        alerts_today=alerts_today,
        alerts_tomorrow=alerts_tomorrow
    )

@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar_image' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('home'))
    file = request.files['avatar_image']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('home'))
    # Xoá hết ảnh cũ trong static/avatar
    avatar_folder = os.path.join(app.static_folder, 'avatar')
    if os.path.exists(avatar_folder):
        for f in os.listdir(avatar_folder):
            try:
                os.remove(os.path.join(avatar_folder, f))
            except Exception:
                pass
    else:
        os.makedirs(avatar_folder, exist_ok=True)
    filename = secure_filename(file.filename)
    ext = os.path.splitext(filename)[1].lower()
    save_path = os.path.join(avatar_folder, filename)
    # Xử lý HEIC
    if ext == '.heic':
        try:
            from wand.image import Image
            with Image(file=file) as img:
                img.format = 'jpeg'
                img.compression_quality = 30  # Giảm chất lượng/dung lượng còn 30%
                img.save(filename=save_path.replace('.heic', '.jpg'))
            flash('Avatar HEIC đã được chuyển và nén thành công!', 'success')
        except Exception as e:
            flash(f'Lỗi xử lý HEIC: {e}', 'danger')
            return redirect(url_for('home'))
    else:
        file.save(save_path)
        flash('Avatar đã được cập nhật!', 'success')
    return redirect(url_for('home'))

@app.route('/get_card_info')
@login_required
def get_card_info_api():
    settings = get_user_settings()
    card_info = settings.get_card_info()
    return jsonify(card_info)

@app.route('/api/card_info', methods=['GET', 'POST'])
@login_required
def api_card_info():
    """API endpoint for card info management"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # ✅ SỬA: Lưu vào UserSettings
            settings = get_user_settings()
            settings.set_card_info({
                'Name': data.get('Name', ''),
                'Job': data.get('Job', ''),
                'Email': data.get('Email', ''),
                'Phone': data.get('Phone', ''),
                'SNS': data.get('SNS', ''),
                'SubSlogan': data.get('SubSlogan', '')
            })
            settings.updated_at = datetime.now()
            db.session.commit()
            
            app.logger.info(f"Card info saved successfully: {list(data.keys())}")
            return jsonify({'status': 'success'})
        except Exception as e:
            app.logger.error(f"Error updating card info: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
    else:
        try:
            # ✅ SỬA: Lấy từ UserSettings
            settings = get_user_settings()
            card_info = settings.get_card_info()
            return jsonify(card_info)
        except Exception as e:
            app.logger.error(f"Error loading card info: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/card_list')
@login_required
def api_card_list():
    """API endpoint for card list"""
    try:
        card_dir = os.path.join(app.template_folder, 'Card')
        files = []
        if os.path.exists(card_dir):
            for fname in os.listdir(card_dir):
                if fname.endswith('.html'):
                    files.append(fname)
        return jsonify({'files': files})
    except Exception as e:
        app.logger.error(f"Error getting card list: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/ui_settings', methods=['GET', 'POST'])
@login_required
def api_ui_settings():
    """API endpoint for UI settings using UserSettings"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # ✅ SỬA: Cập nhật vào UserSettings
            update_user_setting(
                show_bg_image=bool(data.get('show_bg_image', True)),
                show_quote=bool(data.get('show_quote', True))
            )
            
            return jsonify({'status': 'success'})
        except Exception as e:
            app.logger.error(f"Error saving UI settings: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
    else:
        try:
            # ✅ SỬA: Lấy từ UserSettings
            settings = get_user_settings()
            return jsonify({
                'show_bg_image': settings.show_bg_image,
                'show_quote': settings.show_quote
            })
        except Exception as e:
            app.logger.error(f"Error loading UI settings: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/links_tree', methods=['GET', 'POST'])
@login_required
def api_links_tree():
    """API endpoint for links tree"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # ✅ SỬA: Lưu vào UserSettings
            settings = get_user_settings()
            settings.set_links_tree(data.get('links_tree', []))
            settings.updated_at = datetime.now()
            db.session.commit()
            
            return jsonify({'status': 'success'})
        except Exception as e:
            app.logger.error(f"Error saving links tree: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
    else:
        try:
            # ✅ SỬA: Lấy từ UserSettings
            settings = get_user_settings()
            links_tree = settings.get_links_tree()
            return jsonify({'links_tree': links_tree})
        except Exception as e:
            app.logger.error(f"Error loading links tree: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
        


def encode_card(filename):
    return hashlib.sha256(filename.encode()).hexdigest()[:12]

# Ví dụ ánh xạ tạm thời (nên lưu vào DB nếu dùng thực tế)
CARD_HASH_MAP = {}
def get_card_hash(filename):
    h = encode_card(filename)
    CARD_HASH_MAP[h] = filename
    return h

@app.route('/get_card_hash/<filename>')
def get_card_hash_api(filename):
    # Bảo vệ chỉ cho phép file .html trong thư mục Card
    card_dir = os.path.join(app.template_folder, 'Card')
    if not filename.endswith('.html') or filename not in os.listdir(card_dir):
        return jsonify({'error': 'Invalid file'}), 400
    h = get_card_hash(filename)
    return jsonify({'hash': h})

@app.route('/public_card/<card_hash>')
def public_card(card_hash):
    filename = CARD_HASH_MAP.get(card_hash)
    if not filename or not filename.endswith('.html'):
        return "Invalid or expired link", 404
    card_dir = f'Card/{filename}'  # SỬA Ở ĐÂY
    settings = get_user_settings()
    card_info = settings.get_card_info()
    avatar_dir = os.path.join(app.static_folder, 'avatar')
    avatar_file = None
    if os.path.exists(avatar_dir):
        for fname in os.listdir(avatar_dir):
            if fname.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp', '.heic')):
                avatar_file = f'avatar/{fname}'
                break
    card_info['avatar_url'] = url_for('static', filename=avatar_file) if avatar_file else ''
    return render_template(card_dir, **card_info)

@app.route('/breath')
@login_required
def breath():
    return render_template('breath.html')

@app.route('/breath_settings', methods=['GET', 'POST'])
@login_required
def breath_settings():
    if request.method == 'POST':
        try:
            data = request.json
            
            # ✅ SỬA: Lưu vào UserSettings
            settings = get_user_settings()
            settings.set_breath_settings(data)
            settings.updated_at = datetime.now()
            db.session.commit()
            
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    else:
        try:
            # ✅ SỬA: Lấy từ UserSettings
            settings = get_user_settings()
            return jsonify(settings.get_breath_settings())
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
@app.route('/eye_exercise')
@login_required
def eye_exercise():
    return render_template('eye_exercise.html')

# app.py
@app.route('/game_flip')
def game_flip():
    return render_template('Game/game_memory.html')

@app.route('/game_math')
def game_math():
    return render_template('Game/game_math.html')

# app.py
@app.route('/ever_note')
@login_required
def ever_note():
    return render_template('Memo/ever_note.html')

@app.route('/api/evernote_folders', methods=['GET'])
@login_required
def get_evernote_folders():
    """Get all folders in tree structure"""
    try:
        # Sắp xếp folders theo tên tăng dần
        folders = EvernoteFolder.query.order_by(EvernoteFolder.name.asc()).all()
        
        def build_folder_tree(parent_id=None):
            tree = []
            # Lọc và sắp xếp folders cùng level theo tên
            level_folders = [f for f in folders if f.parent_id == parent_id]
            level_folders.sort(key=lambda x: x.name.lower())  # Case-insensitive sort
            
            for folder in level_folders:
                folder_data = {
                    'id': folder.id,
                    'name': folder.name,
                    'parent_id': folder.parent_id,
                    'created_at': folder.created_at.isoformat() if folder.created_at else None,
                    'children': build_folder_tree(folder.id),
                    'notes_count': len(folder.notes)
                }
                tree.append(folder_data)
            return tree
        
        return jsonify({
            'status': 'success',
            'folders': build_folder_tree()
        })
    except Exception as e:
        app.logger.error(f"Error getting folders: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/evernote_folders', methods=['POST'])
@login_required
def create_evernote_folder():
    """Create new folder"""
    try:
        data = request.json
        name = data.get('name', '').strip()
        parent_id = data.get('parent_id')
        
        if not name:
            return jsonify({'status': 'error', 'message': 'Folder name is required'}), 400
        
        # Check if parent exists (if parent_id provided)
        if parent_id and not EvernoteFolder.query.get(parent_id):
            return jsonify({'status': 'error', 'message': 'Parent folder not found'}), 404
        
        folder = EvernoteFolder(name=name, parent_id=parent_id)
        db.session.add(folder)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'folder': {
                'id': folder.id,
                'name': folder.name,
                'parent_id': folder.parent_id,
                'created_at': folder.created_at.isoformat()
            }
        })
    except Exception as e:
        app.logger.error(f"Error creating folder: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/evernote_folders/<int:folder_id>', methods=['PUT'])
@login_required
def update_evernote_folder(folder_id):
    """Update folder"""
    try:
        folder = EvernoteFolder.query.get_or_404(folder_id)
        data = request.json
        
        name = data.get('name', '').strip()
        if not name:
            return jsonify({'status': 'error', 'message': 'Folder name is required'}), 400
        
        parent_id = data.get('parent_id')
        
        # Prevent making folder its own parent or creating circular reference
        if parent_id == folder_id:
            return jsonify({'status': 'error', 'message': 'Folder cannot be its own parent'}), 400
        
        # Check if parent exists (if parent_id provided)
        if parent_id and not EvernoteFolder.query.get(parent_id):
            return jsonify({'status': 'error', 'message': 'Parent folder not found'}), 404
        
        folder.name = name
        folder.parent_id = parent_id
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'folder': {
                'id': folder.id,
                'name': folder.name,
                'parent_id': folder.parent_id
            }
        })
    except Exception as e:
        app.logger.error(f"Error updating folder: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def delete_note_images(note):
    """Helper function to delete all image files for a note"""
    try:
        image_files = note.get_image_files()
        deleted_count = 0
        
        for filename in image_files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    deleted_count += 1
                    app.logger.info(f"Deleted image file: {filename}")
                except Exception as e:
                    app.logger.error(f"Error deleting image file {filename}: {e}")
        
        app.logger.info(f"Deleted {deleted_count} image files for note {note.id}")
        return deleted_count
        
    except Exception as e:
        app.logger.error(f"Error deleting images for note {note.id}: {e}")
        return 0
    
@app.route('/api/evernote_folders/<int:folder_id>', methods=['DELETE'])
@login_required  
def delete_evernote_folder(folder_id):
    try:
        folder = EvernoteFolder.query.get_or_404(folder_id)
        data = request.json or {}
        action = data.get('action', 'move_to_parent')
        
        app.logger.info(f"Deleting folder {folder_id} with action: {action}")
        
        if action == 'delete_all':
            # Delete all notes and subfolders recursively WITH IMAGE CLEANUP
            def delete_folder_recursive(f):
                app.logger.info(f"Recursively deleting folder: {f.id}")
                
                # Delete all image files from notes in this folder FIRST
                notes_in_folder = EvernoteNote.query.filter_by(folder_id=f.id).all()
                for note in notes_in_folder:
                    delete_note_images(note)
                
                # Then delete all notes in this folder from database
                notes_deleted = EvernoteNote.query.filter_by(folder_id=f.id).delete()
                app.logger.info(f"Deleted {notes_deleted} notes from folder {f.id}")
                
                # Delete all subfolders recursively
                children = EvernoteFolder.query.filter_by(parent_id=f.id).all()
                for child in children:
                    delete_folder_recursive(child)
                
                # Delete the folder itself
                db.session.delete(f)
            
            delete_folder_recursive(folder)
            
        else:  # move_to_parent (default)
            app.logger.info(f"Moving contents of folder {folder_id} to parent")
            
            # Move all notes to parent folder (no image deletion needed)
            notes = EvernoteNote.query.filter_by(folder_id=folder.id).all()
            for note in notes:
                note.folder_id = folder.parent_id
                app.logger.info(f"Moved note {note.id} to parent folder {folder.parent_id}")
            
            # Move all subfolders to parent folder  
            subfolders = EvernoteFolder.query.filter_by(parent_id=folder.id).all()
            for subfolder in subfolders:
                subfolder.parent_id = folder.parent_id
                app.logger.info(f"Moved subfolder {subfolder.id} to parent folder {folder.parent_id}")
            
            # Delete the folder (but keep notes and their images)
            db.session.delete(folder)
        
        db.session.commit()
        app.logger.info(f"Successfully deleted folder {folder_id}")
        
        return jsonify({
            'status': 'success', 
            'message': 'Folder deleted successfully',
            'action': action
        })
        
    except Exception as e:
        app.logger.error(f"Error deleting folder {folder_id}: {str(e)}")
        db.session.rollback()
        return jsonify({
            'status': 'error', 
            'message': f'Failed to delete folder: {str(e)}'
        }), 500

@app.route('/api/evernote_folders/<int:folder_id>/notes', methods=['GET'])
@login_required
def get_folder_notes(folder_id):
    """Get all notes in a specific folder"""
    try:
        folder = EvernoteFolder.query.get_or_404(folder_id)
        # Sắp xếp notes theo title tăng dần
        notes = EvernoteNote.query.filter_by(folder_id=folder_id).order_by(EvernoteNote.title.asc()).all()
        
        return jsonify({
            'status': 'success',
            'folder': {
                'id': folder.id,
                'name': folder.name
            },
            'notes': [
                {
                    'id': n.id,
                    'title': n.title,
                    'content': n.content,
                    'folder_id': n.folder_id,
                    'created_at': n.created_at.isoformat() if n.created_at else None,
                    'updated_at': n.updated_at.isoformat() if n.updated_at else None,
                    'images': json.loads(n.images) if n.images else []
                } for n in notes
            ]
        })
    except Exception as e:
        app.logger.error(f"Error getting folder notes: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# Cập nhật API tạo note để hỗ trợ folder_id
@app.route('/api/evernote_notes', methods=['POST'])
@login_required
def add_evernote_note():
    try:
        data = request.json
        folder_id = data.get('folder_id')
        
        # Validate folder exists if provided
        if folder_id and not EvernoteFolder.query.get(folder_id):
            return jsonify({'status': 'error', 'message': 'Folder not found'}), 404
        
        app.logger.debug(f"Creating note with folder id: {folder_id}")
        note = EvernoteNote(
            title=data.get('title', ''),
            content=data.get('content', ''),
            folder_id=folder_id
            # Bỏ dòng images=data.get('images') vì model mới không có field này
        )
        db.session.add(note)
        db.session.commit()
        
        return jsonify({
            'status': 'success', 
            'id': note.id,
            'folder_id': note.folder_id,
            'created_at': note.created_at.isoformat() if note.created_at else None,
            'updated_at': note.updated_at.isoformat() if note.updated_at else None
        })
    except Exception as e:
        app.logger.error(f"Error creating note: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
@app.route('/share/<share_id>')
def share_note(share_id):
    note = Task.query.filter_by(share_id=share_id).first_or_404()
    return render_template('Memo/share_note.html', note=note)


@app.route('/api/evernote_notes/<int:note_id>/share', methods=['POST'])
@login_required
def create_evernote_share_link(note_id):
    app.logger.info(f"Creating share link for note_id: {note_id}")
    
    try:
        # Check if note exists
        note = EvernoteNote.query.get(note_id)
        if not note:
            app.logger.error(f"Note {note_id} not found")
            return jsonify({'status': 'error', 'message': 'Note not found'}), 404
        
        app.logger.info(f"Found note: {note.title}")
        
        # ✅ FORCE generate new share_id (luôn tạo mới)
        from uuid import uuid4
        note.share_id = str(uuid4())
        app.logger.info(f"Generated NEW share_id: {note.share_id}")
        
        try:
            db.session.commit()
            app.logger.info("Database commit successful")
        except Exception as db_error:
            app.logger.error(f"Database commit failed: {db_error}")
            db.session.rollback()
            raise db_error
        
        # Tạo URL chia sẻ
        share_url = url_for('view_shared_evernote', share_id=note.share_id, _external=True)
        app.logger.info(f"Generated share URL: {share_url}")
        
        return jsonify({
            'status': 'success',
            'share_url': share_url,
            'share_id': note.share_id
        })
        
    except Exception as e:
        app.logger.error(f"Error creating share link for note {note_id}: {str(e)}")
        app.logger.error(f"Exception type: {type(e).__name__}")
        return jsonify({
            'status': 'error', 
            'message': f'Failed to create share link: {str(e)}'
        }), 500
    
# Cập nhật API update note để hỗ trợ folder_id
@app.route('/api/evernote_notes/<int:note_id>', methods=['PUT'])
@login_required
def update_evernote_note(note_id):
    try:
        note = EvernoteNote.query.get_or_404(note_id)
        data = request.json
        
        note.title = data.get('title', note.title)
        note.content = data.get('content', note.content)
        
        # Update folder if provided
        if 'folder_id' in data:
            folder_id = data['folder_id']
            if folder_id and not EvernoteFolder.query.get(folder_id):
                return jsonify({'status': 'error', 'message': 'Folder not found'}), 404
            note.folder_id = folder_id
        
        if 'images' in data:
            note.images = data['images']
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'folder_id': note.folder_id,
            'updated_at': note.updated_at.isoformat() if note.updated_at else None
        })
    except Exception as e:
        app.logger.error(f"Error updating note: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/evernote_notes/<int:note_id>', methods=['DELETE'])
@login_required
def delete_evernote_note(note_id):
    try:
        note = EvernoteNote.query.get_or_404(note_id)
        
        # Delete all image files using helper function
        deleted_images_count = delete_note_images(note)
        
        # Delete note from database
        db.session.delete(note)
        db.session.commit()
        
        app.logger.info(f"Deleted note {note_id} and {deleted_images_count} image files")
        
        return jsonify({
            'status': 'success',
            'message': f'Note and {deleted_images_count} image files deleted successfully'
        })
        
    except Exception as e:
        app.logger.error(f"Error deleting note {note_id}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/cleanup_orphaned_images', methods=['POST'])
@login_required
def cleanup_orphaned_images():
    """Clean up image files that are no longer referenced by any note"""
    try:
        # Get all image files in upload folder
        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
            return jsonify({
                'status': 'success',
                'message': 'Upload folder does not exist',
                'deleted_count': 0
            })
        
        all_files = set(os.listdir(upload_folder))
        
        # Get all image files referenced by notes
        referenced_files = set()
        notes = EvernoteNote.query.all()
        
        for note in notes:
            image_files = note.get_image_files()
            referenced_files.update(image_files)
        
        # Find orphaned files
        orphaned_files = all_files - referenced_files
        deleted_count = 0
        
        for filename in orphaned_files:
            file_path = os.path.join(upload_folder, filename)
            try:
                if os.path.isfile(file_path):  # Only delete files, not directories
                    os.remove(file_path)
                    deleted_count += 1
                    app.logger.info(f"Deleted orphaned file: {filename}")
            except Exception as e:
                app.logger.error(f"Error deleting orphaned file {filename}: {e}")
        
        return jsonify({
            'status': 'success',
            'message': f'Cleaned up {deleted_count} orphaned image files',
            'deleted_count': deleted_count,
            'orphaned_files': list(orphaned_files)
        })
        
    except Exception as e:
        app.logger.error(f"Error cleaning up orphaned images: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
# Cập nhật API get notes để include folder info
@app.route('/api/evernote_notes', methods=['GET'])
@login_required
def get_evernote_notes():
    try:
        folder_id = request.args.get('folder_id', type=int)
        
        if folder_id:
            # Sắp xếp notes theo title tăng dần
            notes = EvernoteNote.query.filter_by(folder_id=folder_id).order_by(EvernoteNote.title.asc()).all()
        else:
            # Sắp xếp tất cả notes theo title tăng dần
            notes = EvernoteNote.query.order_by(EvernoteNote.title.asc()).all()
        
        notes_data = []
        for note in notes:
            # Get image URLs instead of base64 data
            image_files = note.get_image_files()
            images = []
            for filename in image_files:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.exists(file_path):
                    images.append({
                        'filename': filename,
                        'url': url_for('get_evernote_image_file', filename=filename),
                        'size': os.path.getsize(file_path)
                    })
            
            notes_data.append({
                'id': note.id,
                'title': note.title,
                'content': note.content,
                'folder_id': note.folder_id,
                'folder_name': note.folder.name if note.folder else None,
                'created_at': note.created_at.isoformat() if note.created_at else None,
                'updated_at': note.updated_at.isoformat() if note.updated_at else None,
                'images': images
            })
        
        return jsonify(notes_data)
        
    except Exception as e:
        app.logger.error(f"Error getting notes: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/uploads/evernote/<filename>')
def get_evernote_image_file(filename):
    """Serve image files"""
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        app.logger.error(f"Error serving image {filename}: {e}")
        return jsonify({'status': 'error', 'message': 'Image not found'}), 404

@app.route('/api/evernote_notes/<int:note_id>/delete_image/<string:filename>', methods=['DELETE'])
@login_required
def delete_evernote_image_file(note_id, filename):
    """Delete image file"""
    try:
        note = EvernoteNote.query.get_or_404(note_id)
        
        # Remove from database
        note.remove_image_file(filename)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Image deleted successfully'})
        
    except Exception as e:
        app.logger.error(f"Error deleting image {filename}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/evernote_notes/<int:note_id>/images', methods=['GET'])
@login_required
def get_evernote_note_images(note_id):
    """Get all images for a note"""
    try:
        note = EvernoteNote.query.get_or_404(note_id)
        image_files = note.get_image_files()
        
        images = []
        for filename in image_files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                images.append({
                    'filename': filename,
                    'url': url_for('get_evernote_image_file', filename=filename),
                    'size': os.path.getsize(file_path)
                })
            else:
                # Remove non-existent file from database
                note.remove_image_file(filename)
        
        # Commit any cleanup changes
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'images': images
        })
        
    except Exception as e:
        app.logger.error(f"Error getting images for note {note_id}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# app.py - Thêm route này
@app.route('/api/evernote_notes/<int:note_id>', methods=['GET'])
@login_required
def get_single_evernote_note(note_id):
    """Get a single note by ID"""
    try:
        note = EvernoteNote.query.get_or_404(note_id)
        
        # Get folder info if exists
        folder_name = note.folder.name if note.folder else None
        
        # Get image URLs - check if method exists
        image_files = []
        if hasattr(note, 'get_image_files'):
            try:
                image_files = note.get_image_files() or []
            except Exception as e:
                app.logger.warning(f"Error getting image files: {e}")
                image_files = []
        
        images = []
        for filename in image_files:
            try:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.exists(file_path):
                    images.append({
                        'filename': filename,
                        'url': url_for('get_evernote_image_file', filename=filename),
                        'size': os.path.getsize(file_path)
                    })
            except Exception as e:
                app.logger.warning(f"Error processing image {filename}: {e}")
                continue
        
        return jsonify({
            'status': 'success',
            'note': {
                'id': note.id,
                'title': note.title,
                'content': note.content,
                'folder_id': note.folder_id,
                'folder_name': folder_name,
                'created_at': note.created_at.isoformat() if note.created_at else None,
                'updated_at': note.updated_at.isoformat() if note.updated_at else None,
                'images': images
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error getting single note {note_id}: {str(e)}")
        app.logger.error(f"Exception type: {type(e).__name__}")
        
        # ✅ Return detailed error for debugging
        return jsonify({
            'status': 'error', 
            'message': f'Failed to get note: {str(e)}',
            'error_type': type(e).__name__
        }), 500
    
@app.route('/api/evernote_notes/<int:note_id>/upload_images', methods=['POST'])
@login_required
def upload_evernote_images(note_id):
    try:
        note = EvernoteNote.query.get_or_404(note_id)
        files = request.files.getlist('images')
        
        if not files or not any(file.filename for file in files):
            return jsonify({'status': 'error', 'message': 'No files uploaded'}), 400
        
        uploaded_files = []
        processed_count = 0
        
        for file in files:
            if file and file.filename and allowed_file(file.filename):
                try:
                    # Tạo unique filename: note name + timestamp + tên gốc
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]  # milliseconds
                    note_name = secure_filename(note.title) if note.title else f'note_{note_id}'
                    filename = f"{note_name}_{timestamp}"
                    
                    # Ensure .jpg extension for consistency
                    name, ext = os.path.splitext(filename)
                    if ext.lower() in ['.heic', '.png', '.gif', '.webp']:
                        filename = name + '.jpg'
                    
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    
                    # Handle HEIC files
                    if file.filename.lower().endswith('.heic'):
                        try:
                            from wand.image import Image as WandImage
                            with WandImage(file=file) as img:
                                img.format = 'jpeg'
                                img.save(filename=file_path)
                        except ImportError:
                            app.logger.error("Wand not available for HEIC conversion")
                            continue
                    else:
                        # Save file normally
                        file.save(file_path)
                    
                    # Compress and resize
                    if compress_and_resize_image(file_path):
                        note.add_image_file(filename)
                        uploaded_files.append({
                            'filename': filename,
                            'url': url_for('get_evernote_image_file', filename=filename),
                            'size': os.path.getsize(file_path)
                        })
                        processed_count += 1
                    else:
                        # Remove file if compression failed
                        if os.path.exists(file_path):
                            os.remove(file_path)
                        app.logger.error(f"Failed to process image: {filename}")
                        
                except Exception as e:
                    app.logger.error(f"Error processing file {file.filename}: {str(e)}")
        
        # Commit changes to database
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Uploaded {processed_count} images successfully',
            'uploaded_files': uploaded_files,
            'processed_count': processed_count
        })
        
    except Exception as e:
        app.logger.error(f"Error in upload_evernote_images: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# API để lấy ảnh từ Evernote note
@app.route('/api/evernote_notes/<int:note_id>/image/<string:image_id>')
def get_evernote_image(note_id, image_id):
    try:
        note = EvernoteNote.query.get_or_404(note_id)
        images = json.loads(note.images) if note.images else []
        
        image = next((img for img in images if img.get('id') == image_id), None)
        if not image:
            return jsonify({'status': 'error', 'message': 'Image not found'}), 404
            
        image_data = base64.b64decode(image['data'])
        return send_file(
            BytesIO(image_data), 
            mimetype='image/jpeg',
            as_attachment=False,
            download_name=image['filename']
        )
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# API xóa ảnh khỏi note
@app.route('/api/evernote_notes/<int:note_id>/delete_image/<string:image_id>', methods=['DELETE'])
@login_required
def delete_evernote_image(note_id, image_id):
    try:
        note = EvernoteNote.query.get_or_404(note_id)
        images = json.loads(note.images) if note.images else []
        
        # Lọc bỏ ảnh cần xóa
        new_images = [img for img in images if img.get('id') != image_id]
        
        note.images = json.dumps(new_images) if new_images else None
        db.session.commit()
        
        return jsonify({'status': 'success'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
    
def contrast_text_color(hex_color):
    if not hex_color:
        return "#000"
    hex_color = hex_color.lstrip('#')
    if len(hex_color) != 6:
        return "#000"
    r = int(hex_color[0:2], 16)
    g = int(hex_color[2:4], 16)
    b = int(hex_color[4:6], 16)
    luminance = 0.299 * r + 0.587 * g + 0.114 * b
    return "#000" if luminance > 186 else "#fff"

app.jinja_env.filters['contrast_text_color'] = contrast_text_color

@app.route('/todo')
@login_required
def todo():
    return render_template('Memo/todo.html')

# API endpoints cho TODO
@app.route('/api/todos', methods=['GET'])
@login_required
def get_todos():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = Todo.query
    
    if start_date and end_date:
        try:
            start = datetime.strptime(start_date, '%Y-%m-%d').date()
            end = datetime.strptime(end_date, '%Y-%m-%d').date()
            query = query.filter(Todo.date >= start, Todo.date <= end)
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400
    
    todos = query.all()
    
    return jsonify([{
        'id': todo.id,
        'title': todo.title,
        'date': todo.date.isoformat(),
        'priority': todo.priority,
        'repeat_type': todo.repeat_type,
        'repeat_interval': todo.repeat_interval,
        'repeat_unit': todo.repeat_unit,
        'end_date': todo.end_date.isoformat() if todo.end_date else None,
        'completed': todo.completed,
        'parent_id': todo.parent_id
    } for todo in todos])

@app.route('/api/todos', methods=['POST'])
@login_required
def add_todo():
    try:
        data = request.json
        
        # Validate required fields
        if not data.get('title') or not data.get('date'):
            return jsonify({'error': 'Title and date are required'}), 400
        
        # Parse date
        try:
            todo_date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400
        
        # Create main todo
        todo = Todo(
            title=data['title'],
            date=todo_date,
            priority=data.get('priority', 'medium'),
            repeat_type=data.get('repeat_type', 'none'),
            repeat_interval=data.get('repeat_interval'),
            repeat_unit=data.get('repeat_unit'),
            end_date=datetime.strptime(data['end_date'], '%Y-%m-%d').date() if data.get('end_date') else None,
            completed=False
        )
        
        db.session.add(todo)
        db.session.commit()
        
        # Generate repeat todos if needed
        if data.get('repeat_type') != 'none':
            generate_repeat_todos(todo)
        
        return jsonify({
            'id': todo.id,
            'title': todo.title,
            'date': todo.date.isoformat(),
            'priority': todo.priority,
            'repeat_type': todo.repeat_type,
            'completed': todo.completed
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding todo: {str(e)}")
        return jsonify({'error': 'Failed to add todo'}), 500

@app.route('/api/todos/<int:todo_id>', methods=['PUT'])
@login_required
def update_todo(todo_id):
    try:
        todo = Todo.query.get_or_404(todo_id)
        
        
        data = request.json
        update_all = data.get('update_all', False)
        
        if update_all:
            # Update all related todos (same parent or children)
            related_todos = []
            
            if todo.parent_id:
                # This is a child todo, get parent and all siblings
                parent = Todo.query.get(todo.parent_id)
                if parent:
                    related_todos.append(parent)
                    related_todos.extend(Todo.query.filter_by(parent_id=todo.parent_id).all())
            else:
                # This is a parent todo, get all children
                related_todos.append(todo)
                related_todos.extend(Todo.query.filter_by(parent_id=todo.id).all())
            
            # Update all related todos (except completed status and date)
            for related_todo in related_todos:
                if 'title' in data:
                    related_todo.title = data['title']
                if 'priority' in data:
                    related_todo.priority = data['priority']
                # Don't update repeat settings for existing todos
                # Don't update completed status or date for other todos
        else:
            # Update only this todo
            if 'completed' in data:
                todo.completed = data['completed']
            if 'title' in data:
                todo.title = data['title']
            if 'priority' in data:
                todo.priority = data['priority']
            if 'date' in data:
                try:
                    todo.date = datetime.strptime(data['date'], '%Y-%m-%d').date()
                except ValueError:
                    return jsonify({'error': 'Invalid date format'}), 400
        
        db.session.commit()
        
        return jsonify({
            'id': todo.id,
            'title': todo.title,
            'date': todo.date.isoformat(),
            'priority': todo.priority,
            'completed': todo.completed,
            'updated_count': len(related_todos) if update_all else 1
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating todo: {str(e)}")
        return jsonify({'error': 'Failed to update todo'}), 500

@app.route('/api/todos/<int:todo_id>', methods=['DELETE'])
@login_required
def delete_todo(todo_id):
    try:
        todo = Todo.query.get_or_404(todo_id)
        
        delete_all = request.args.get('delete_all') == 'true'
        app.logger.info(f"Deleting todo {todo_id}, delete_all={delete_all}, parent_id={todo.parent_id}")
        
        deleted_count = 1
        
        if delete_all:
            # Delete all related todos
            if todo.parent_id:
                # This is a child todo, delete parent and all siblings
                parent = Todo.query.get(todo.parent_id)
                if parent:
                    # Count siblings before deleting
                    sibling_count = Todo.query.filter_by(parent_id=todo.parent_id).count()
                    app.logger.info(f"Found {sibling_count} siblings to delete")
                    deleted_count = sibling_count + 1  # siblings + parent
                    
                    # Delete all siblings
                    Todo.query.filter_by(parent_id=todo.parent_id).delete()
                    # Delete parent
                    db.session.delete(parent)
                    app.logger.info(f"Deleted parent and {sibling_count} siblings")
                else:
                    # If no parent found, just delete this todo
                    db.session.delete(todo)
                    deleted_count = 1
                    app.logger.info("No parent found, deleted only current todo")
            else:
                # This is a parent todo, delete all children
                children_count = Todo.query.filter_by(parent_id=todo.id).count()
                app.logger.info(f"Found {children_count} children to delete")
                deleted_count = children_count + 1  # children + parent
                
                # Delete all children
                Todo.query.filter_by(parent_id=todo.id).delete()
                # Delete parent (this todo)
                db.session.delete(todo)
                app.logger.info(f"Deleted parent and {children_count} children")
        else:
            # Delete only this todo
            db.session.delete(todo)
            deleted_count = 1
            app.logger.info("Deleted single todo")
        
        db.session.commit()
        app.logger.info(f"Successfully deleted {deleted_count} todos")
        
        return jsonify({
            'message': f'Deleted {deleted_count} todo(s) successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting todo: {str(e)}")
        return jsonify({'error': 'Failed to delete todo'}), 500

def generate_repeat_todos(base_todo):
    """Generate repeat todos based on base todo settings"""
    if base_todo.repeat_type == 'none':
        return
    
    current_date = base_todo.date
    end_date = base_todo.end_date or (current_date + timedelta(days=365))  # Default 1 year
    
    while True:
        # Calculate next date
        if base_todo.repeat_type == 'daily':
            current_date += timedelta(days=1)
        elif base_todo.repeat_type == 'weekly':
            current_date += timedelta(weeks=1)
        elif base_todo.repeat_type == 'monthly':
            # Add one month (approximate)
            if current_date.month == 12:
                current_date = current_date.replace(year=current_date.year + 1, month=1)
            else:
                current_date = current_date.replace(month=current_date.month + 1)
        elif base_todo.repeat_type == 'custom':
            if base_todo.repeat_unit == 'days':
                current_date += timedelta(days=base_todo.repeat_interval)
            elif base_todo.repeat_unit == 'weeks':
                current_date += timedelta(weeks=base_todo.repeat_interval)
            elif base_todo.repeat_unit == 'months':
                for _ in range(base_todo.repeat_interval):
                    if current_date.month == 12:
                        current_date = current_date.replace(year=current_date.year + 1, month=1)
                    else:
                        current_date = current_date.replace(month=current_date.month + 1)
        
        # Stop if we exceed end date
        if current_date > end_date:
            break
        
        # Create repeat todo
        repeat_todo = Todo(
            title=base_todo.title,
            date=current_date,
            priority=base_todo.priority,
            repeat_type=base_todo.repeat_type,
            repeat_interval=base_todo.repeat_interval,
            repeat_unit=base_todo.repeat_unit,
            end_date=base_todo.end_date,
            completed=False,
            parent_id=base_todo.id
        )
        
        db.session.add(repeat_todo)
    
    db.session.commit()

# Thêm API endpoint cho auto-save diary
@app.route('/api/diary/auto_save', methods=['POST'])
@login_required
def auto_save_diary():
    try:
        data = request.get_json()
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        color = data.get('color', '#ffffff')
        draft_id = data.get('draft_id')

        if not title or not content:
            return jsonify({'status': 'skipped', 'message': 'Title and content required'}), 200

        diary = None
        if draft_id:
            diary = Diary.query.filter_by(id=draft_id).first()
        if diary:
            # Update existing draft regardless of title change
            diary.title = title
            diary.content = content
            diary.color = color
            diary.date = datetime.now()
            db.session.commit()
            return jsonify({
                'status': 'updated',
                'message': 'Draft updated successfully',
                'diary_id': diary.id
            })
        else:
            # Create new draft
            diary = Diary(title=title, content=content, color=color)
            db.session.add(diary)
            db.session.commit()
            return jsonify({
                'status': 'created',
                'message': 'Draft created successfully',
                'diary_id': diary.id
            })
    except Exception as e:
        app.logger.error(f"Error in auto_save_diary: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
@app.route('/api/diary/auto_save_edit/<int:diary_id>', methods=['PUT'])
@login_required
def auto_save_edit_diary(diary_id):
    try:
        data = request.get_json()
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        color = data.get('color', '#ffffff')
        
        # Chỉ lưu khi cả title và content đều có dữ liệu
        if not title or not content:
            return jsonify({
                'status': 'skipped',
                'message': 'Both title and content are required for auto-save'
            })
        
        diary = Diary.query.get_or_404(diary_id)
        
        # Cập nhật diary
        diary.title = title
        diary.content = content
        diary.color = color
        diary.date = datetime.now()  # Cập nhật thời gian chỉnh sửa
        db.session.commit()
        
        return jsonify({
            'status': 'updated',
            'message': 'Diary auto-saved successfully',
            'diary_id': diary.id
        })
                
    except Exception as e:
        app.logger.error(f"Error in auto_save_edit_diary: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to auto-save: {str(e)}'
        }), 500
        

@app.route('/knowledge')
def knowledge():
    return render_template('learning/knowledge.html') 



@app.route('/api/config', methods=['GET', 'POST'])
@login_required
def api_config():
    """API endpoint for config management"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            settings = get_user_settings()
            
            # Update specific fields from request
            if 'ai_question_template' in data:
                settings.ai_question_template = data['ai_question_template']
            
            if 'vocabulary_query_template' in data:
                settings.vocabulary_query_template = data['vocabulary_query_template']
            
            settings.updated_at = datetime.now()
            db.session.commit()
            
            app.logger.info(f"Config saved successfully: {list(data.keys())}")
            return jsonify({'status': 'success'})
        except Exception as e:
            app.logger.error(f"Error updating config: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
    else:
        try:
            settings = get_user_settings()
            return jsonify({
                'ai_question_template': settings.ai_question_template,
                'vocabulary_query_template': settings.vocabulary_query_template
            })
        except Exception as e:
            app.logger.error(f"Error loading config: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
        
def generate_knowledge_links(keyword):
    import urllib.parse
    encoded_keyword = urllib.parse.quote(keyword)
    
    # Load AI settings
    ai_settings = load_ai_settings()
    
    # Load question template from UserSettings - SỬA LẠI DÒNG NÀY
    settings = get_user_settings()
    question_template = settings.ai_question_template or "1.hãy nêu tổng quan và các khía cạnh chi tiết về {keyword} bằng các bản dịch tiếng anh, tiếng việt và tiếng nhật (những từ vựng jlpt N1 thì thêm furigana). 2.sao cho sau khi đọc xong thì có đủ kiến thức để trình bày lại cho người khác. 3.hãy cho bảng từ vựn (đầy đủ phiên âm, âm hán việt) liên quan đến chủ đề này. 4.nêu 1 số link nguồn để tìm hiểu sâu hơn về chủ đề này."
    
    # Replace {keyword} with actual keyword
    question = question_template.replace('{keyword}', keyword)
    sources = []
    
    # Use URLs from settings - these can now be customized
    ai_services = {
        'chatgpt': {
            'url': ai_settings.get('chatgpt_url', "https://chat.openai.com/?q={query}"),
            'title': 'ChatGPT AI',
            'icon': 'bi-robot',
            'description': 'Hỏi ChatGPT về từ khóa này',
            'color': 'success'
        },
        'grok': {
            'url': ai_settings.get('grok_url', "https://x.com/i/grok?q={query}"),
            'title': 'Grok AI',
            'icon': 'bi-lightning',
            'description': 'Hỏi Grok AI của X (Twitter)',
            'color': 'dark'
        },
        'perplexity': {
            'url': ai_settings.get('perplexity_url', "https://www.perplexity.ai/?q={query}"),
            'title': 'Perplexity AI',
            'icon': 'bi-search',
            'description': 'Tìm kiếm Perplexity AI về từ khóa này',
            'color': 'info'
        },
        'you': {
            'url': ai_settings.get('you_url', "https://you.com/search?q={query}"),
            'title': 'You.com Search',
            'icon': 'bi-globe',
            'description': 'Tìm kiếm You.com về từ khóa này',
            'color': 'warning'
        },
        'copilot': {
            'url': ai_settings.get('copilot_url', "https://copilot.microsoft.com/?q={query}"),
            'title': 'Copilot AI',
            'icon': 'bi-microsoft',
            'description': 'Hỏi Microsoft Copilot về từ khóa này',
            'color': 'secondary'
        }
    }
    
    # Add enabled AI services
    for service_name, service_info in ai_services.items():
        if ai_settings.get(f'{service_name}_enabled'):
            service_url = service_info['url'].replace('{query}', urllib.parse.quote(question))
            sources.append({
                'title': service_info['title'],
                'url': service_url,
                'language': 'Multi',
                'icon': service_info['icon'],
                'description': service_info['description'],
                'color': service_info['color']
            })
    
    
    return sources



def load_keywords_progress():
    """Load keywords progress from file"""
    file_path = get_keywords_file_path()
    knowledge_categories = load_knowledge_categories()
    
    default_progress = {
        'completed_keywords': [],
        'criteria_progress': {},  # Format: {"category:keyword": [true, false, true]}
        'last_updated': datetime.now().isoformat(),
        'stats': {
            'total_completed': 0,
            'categories_progress': {category: 0 for category in knowledge_categories.keys()}
        }
    }
    
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Validate and merge with default structure
                if not isinstance(data, dict):
                    raise ValueError("Invalid file format")
                
                # Ensure all required keys exist
                for key in default_progress:
                    if key not in data:
                        data[key] = default_progress[key]
                
                # Ensure criteria_progress exists
                if 'criteria_progress' not in data:
                    data['criteria_progress'] = {}
                
                # Ensure all categories exist in stats
                if 'categories_progress' not in data['stats']:
                    data['stats']['categories_progress'] = default_progress['stats']['categories_progress']
                else:
                    for category in knowledge_categories.keys():
                        if category not in data['stats']['categories_progress']:
                            data['stats']['categories_progress'][category] = 0
                
                return data
        else:
            # File doesn't exist, create it
            initialize_keywords_file()
            return default_progress
            
    except Exception as e:
        app.logger.error(f"Error loading keywords progress: {str(e)}")
        
        # Try to backup corrupted file
        try:
            backup_path = file_path + '.backup'
            if os.path.exists(file_path):
                os.rename(file_path, backup_path)
                app.logger.info(f"Corrupted file backed up to {backup_path}")
        except:
            pass
        
        # Create new default file
        initialize_keywords_file()
        return default_progress

def save_keywords_progress(progress_data):
    """Save keywords progress to file"""
    file_path = get_keywords_file_path()
    try:
        progress_data['last_updated'] = datetime.now().isoformat()
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(progress_data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        app.logger.error(f"Error saving keywords progress: {str(e)}")
        return False


def get_daily_keyword():
    """Get daily keyword from available (non-completed) keywords"""
    available_keywords = get_available_keywords()
    knowledge_categories = load_knowledge_categories()
    
    # Flatten all available keywords
    all_available = []
    for category, keywords in available_keywords.items():
        for keyword in keywords:
            all_available.append((keyword, category))
    
    if not all_available:
        # If all keywords are completed, reset or return random from all
        all_available = []
        for category, keywords in knowledge_categories.items():
            for keyword in keywords:
                all_available.append((keyword, category))
    
    # Use today's date as seed for consistent daily keyword
    today = date.today()
    import random
    random.seed(today.toordinal())
    
    keyword, category = random.choice(all_available)
    return keyword, category

@app.route('/api/daily_keyword')
def get_daily_keyword_api():
    """API endpoint to get daily keyword"""
    try:
        keyword, category = get_daily_keyword()
        links = generate_knowledge_links(keyword)
        progress = load_keywords_progress()
        criteria_methods = load_criteria_methods()
        ai_settings = load_ai_settings()  # Add this line
        
        # Check if current keyword is completed
        is_completed = keyword in progress.get('completed_keywords', [])
        
        # Get criteria for this category
        criteria = criteria_methods.get(category, [])
        
        # Get criteria progress for this keyword
        criteria_key = f"{category}:{keyword}"
        criteria_progress = progress.get('criteria_progress', {}).get(criteria_key, [False] * len(criteria))
        
        # Ensure criteria_progress has correct length
        if len(criteria_progress) != len(criteria):
            criteria_progress = [False] * len(criteria)
        
        return jsonify({
            'status': 'success',
            'keyword': keyword,
            'category': category,
            'links': links,
            'is_completed': is_completed,
            'criteria': criteria,
            'criteria_progress': criteria_progress,
            'ai_settings': ai_settings,  # Add this line
            'date': datetime.now().strftime('%Y-%m-%d'),
            'stats': progress.get('stats', {})
        })
    except Exception as e:
        app.logger.error(f"Error getting daily keyword: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/complete_keyword', methods=['POST'])
@login_required
def complete_keyword():
    """Mark a keyword as completed"""
    try:
        data = request.get_json()
        keyword = data.get('keyword')
        category = data.get('category')
        
        if not keyword:
            return jsonify({
                'status': 'error',
                'message': 'Keyword is required'
            }), 400
        
        progress = load_keywords_progress()
        
        # Add keyword to completed list if not already there
        if keyword not in progress['completed_keywords']:
            progress['completed_keywords'].append(keyword)
            progress['stats']['total_completed'] = len(progress['completed_keywords'])
            
            # Update category progress
            if 'categories_progress' not in progress['stats']:
                progress['stats']['categories_progress'] = {}
            
            if category:
                if category not in progress['stats']['categories_progress']:
                    progress['stats']['categories_progress'][category] = 0
                progress['stats']['categories_progress'][category] += 1
        
        # Save progress
        if save_keywords_progress(progress):
            return jsonify({
                'status': 'success',
                'message': f'Đã đánh dấu hoàn thành: {keyword}',
                'stats': progress['stats']
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Không thể lưu tiến độ'
            }), 500
            
    except Exception as e:
        app.logger.error(f"Error completing keyword: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/uncomplete_keyword', methods=['POST'])
@login_required
def uncomplete_keyword():
    """Remove a keyword from completed list"""
    try:
        data = request.get_json()
        keyword = data.get('keyword')
        category = data.get('category')
        
        if not keyword:
            return jsonify({
                'status': 'error',
                'message': 'Keyword is required'
            }), 400
        
        progress = load_keywords_progress()
        
        # Remove keyword from completed list
        if keyword in progress['completed_keywords']:
            progress['completed_keywords'].remove(keyword)
            progress['stats']['total_completed'] = len(progress['completed_keywords'])
            
            # Update category progress
            if category and 'categories_progress' in progress['stats']:
                if category in progress['stats']['categories_progress']:
                    progress['stats']['categories_progress'][category] = max(0, 
                        progress['stats']['categories_progress'][category] - 1)
        
        # Save progress
        if save_keywords_progress(progress):
            return jsonify({
                'status': 'success',
                'message': f'Đã bỏ đánh dấu: {keyword}',
                'stats': progress['stats']
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Không thể lưu tiến độ'
            }), 500
            
    except Exception as e:
        app.logger.error(f"Error uncompleting keyword: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/keywords_stats')
def get_keywords_stats():
    """Get keywords completion statistics"""
    try:
        progress = load_keywords_progress()
        knowledge_categories = load_knowledge_categories()
        
        total_keywords = sum(len(keywords) for keywords in knowledge_categories.values())
        completed_count = len(progress.get('completed_keywords', []))
        
        # Calculate category stats
        category_stats = {}
        for category, keywords in knowledge_categories.items():
            total_in_category = len(keywords)
            completed_in_category = progress.get('stats', {}).get('categories_progress', {}).get(category, 0)
            category_stats[category] = {
                'total': total_in_category,
                'completed': completed_in_category,
                'percentage': round((completed_in_category / total_in_category) * 100, 1) if total_in_category > 0 else 0
            }
        
        return jsonify({
            'status': 'success',
            'stats': {
                'total_keywords': total_keywords,
                'completed_keywords': completed_count,
                'remaining_keywords': total_keywords - completed_count,
                'completion_percentage': round((completed_count / total_keywords) * 100, 1) if total_keywords > 0 else 0,
                'category_stats': category_stats,
                'last_updated': progress.get('last_updated')
            }
        })
    except Exception as e:
        app.logger.error(f"Error getting keywords stats: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/keywords/<category>')
def get_keywords(category):
    """Get keywords for a specific category (excluding completed ones)"""
    try:
        available_keywords = get_available_keywords()
        knowledge_categories = load_knowledge_categories()
        
        keywords = available_keywords.get(category, [])
        
        progress = load_keywords_progress()
        completed_keywords = set(progress.get('completed_keywords', []))
        
        # Add completion status to each keyword
        keywords_with_status = []
        for keyword in knowledge_categories.get(category, []):
            keywords_with_status.append({
                'keyword': keyword,
                'completed': keyword in completed_keywords
            })
        
        return jsonify({
            'status': 'success',
            'keywords': keywords,
            'keywords_with_status': keywords_with_status,
            'category': category
        })
    except Exception as e:
        app.logger.error(f"Error getting keywords for category {category}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Thêm function get_available_keywords() vào phần knowledge system (sau function load_keywords_progress):

def get_available_keywords():
    """Get keywords that haven't been completed yet"""
    progress = load_keywords_progress()
    completed_keywords = set(progress.get('completed_keywords', []))
    knowledge_categories = load_knowledge_categories()
    
    available_keywords = {}
    for category, keywords in knowledge_categories.items():
        # Lọc ra những keywords chưa hoàn thành
        available_in_category = [kw for kw in keywords if kw not in completed_keywords]
        if available_in_category:  # Chỉ thêm category nếu còn keywords available
            available_keywords[category] = available_in_category
    
    return available_keywords

# Cũng thêm route /api/random_keyword nếu chưa có:
@app.route('/api/random_keyword')
def get_random_keyword_api():
    """API endpoint to get random keyword (not daily)"""
    try:
        available_keywords = get_available_keywords()
        knowledge_categories = load_knowledge_categories()
        criteria_methods = load_criteria_methods()
        
        # Flatten all available keywords
        all_available = []
        for category, keywords in available_keywords.items():
            for keyword in keywords:
                all_available.append((keyword, category))
        
        if not all_available:
            return jsonify({
                'status': 'info',
                'message': 'Bạn đã hoàn thành tất cả keywords! Chúc mừng!',
                'all_completed': True
            })
        
        # Use current timestamp + random seed for better randomness
        import random
        import time
        random.seed(int(time.time() * 1000000) % 1000000)  # Use microseconds for better randomness
        
        keyword, category = random.choice(all_available)
        links = generate_knowledge_links(keyword)
        progress = load_keywords_progress()
        
        # Get criteria for this category
        criteria = criteria_methods.get(category, [])
        
        # Get criteria progress for this keyword
        criteria_key = f"{category}:{keyword}"
        criteria_progress = progress.get('criteria_progress', {}).get(criteria_key, [False] * len(criteria))
        
        # Ensure criteria_progress has correct length
        if len(criteria_progress) != len(criteria):
            criteria_progress = [False] * len(criteria)
        
        app.logger.info(f"Random keyword selected: {keyword} from category: {category}")
        
        return jsonify({
            'status': 'success',
            'keyword': keyword,
            'category': category,
            'links': links,
            'is_completed': False,
            'criteria': criteria,
            'criteria_progress': criteria_progress,
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'stats': progress.get('stats', {}),
            'is_random': True  # Flag to indicate this is random
        })
    except Exception as e:
        app.logger.error(f"Error getting random keyword: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
        
@app.route('/api/update_criteria', methods=['POST'])
@login_required
def update_criteria():
    """Update criteria completion for a keyword"""
    try:
        data = request.get_json()
        keyword = data.get('keyword')
        category = data.get('category')
        criteria_progress = data.get('criteria_progress', [])
        
        if not keyword or not category:
            return jsonify({
                'status': 'error',
                'message': 'Keyword and category are required'
            }), 400
        
        progress = load_keywords_progress()
        criteria_key = f"{category}:{keyword}"
        
        # Update criteria progress
        if 'criteria_progress' not in progress:
            progress['criteria_progress'] = {}
        
        progress['criteria_progress'][criteria_key] = criteria_progress
        
        # Check if all criteria are completed
        all_completed = all(criteria_progress) if criteria_progress else False
        
        # Update keyword completion status based on criteria
        if all_completed and keyword not in progress['completed_keywords']:
            progress['completed_keywords'].append(keyword)
            progress['stats']['total_completed'] = len(progress['completed_keywords'])
            
            # Update category progress
            if 'categories_progress' not in progress['stats']:
                progress['stats']['categories_progress'] = {}
            if category not in progress['stats']['categories_progress']:
                progress['stats']['categories_progress'][category] = 0
            progress['stats']['categories_progress'][category] += 1
            
        elif not all_completed and keyword in progress['completed_keywords']:
            progress['completed_keywords'].remove(keyword)
            progress['stats']['total_completed'] = len(progress['completed_keywords'])
            
            # Update category progress
            if category in progress['stats'].get('categories_progress', {}):
                progress['stats']['categories_progress'][category] = max(0,
                    progress['stats']['categories_progress'][category] - 1)
        
        # Save progress
        if save_keywords_progress(progress):
            return jsonify({
                'status': 'success',
                'message': 'Tiến độ đã được cập nhật',
                'is_completed': all_completed,
                'stats': progress['stats']
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Không thể lưu tiến độ'
            }), 500
            
    except Exception as e:
        app.logger.error(f"Error updating criteria: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def get_vocabulary_file_path():
    """Get path to vocabulary progress file"""
    return os.path.join(app.root_path, 'vocabulary_progress.txt')

def load_vocabulary_data():
    """Load vocabulary from Word.txt"""
    file_path = os.path.join(app.root_path, 'Word.txt')
    
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        else:
            app.logger.error(f"Word.txt file not found at {file_path}")
            return {}
    except Exception as e:
        app.logger.error(f"Error loading Word.txt: {str(e)}")
        return {}

def initialize_vocabulary_progress():
    """Initialize vocabulary progress file if it doesn't exist"""
    file_path = get_vocabulary_file_path()
    
    if not os.path.exists(file_path):
        vocabulary_data = load_vocabulary_data()
        
        default_data = {
            "completed_words": [],
            "last_updated": datetime.now().isoformat(),
            "stats": {
                "total_completed": 0,
                "level_progress": {level: 0 for level in vocabulary_data.keys()}
            }
        }
        
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_data, f, ensure_ascii=False, indent=2)
            app.logger.info(f"Created vocabulary_progress.txt file at {file_path}")
        except Exception as e:
            app.logger.error(f"Error creating vocabulary_progress.txt: {str(e)}")

def load_vocabulary_progress():
    """Load vocabulary progress from file"""
    file_path = get_vocabulary_file_path()
    vocabulary_data = load_vocabulary_data()
    
    default_progress = {
        'completed_words': [],
        'last_updated': datetime.now().isoformat(),
        'stats': {
            'total_completed': 0,
            'level_progress': {level: 0 for level in vocabulary_data.keys()}
        }
    }
    
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                if not isinstance(data, dict):
                    raise ValueError("Invalid file format")
                
                # Ensure all required keys exist
                for key in default_progress:
                    if key not in data:
                        data[key] = default_progress[key]
                
                # Ensure all levels exist in stats
                if 'level_progress' not in data['stats']:
                    data['stats']['level_progress'] = default_progress['stats']['level_progress']
                else:
                    for level in vocabulary_data.keys():
                        if level not in data['stats']['level_progress']:
                            data['stats']['level_progress'][level] = 0
                
                return data
        else:
            initialize_vocabulary_progress()
            return default_progress
            
    except Exception as e:
        app.logger.error(f"Error loading vocabulary progress: {str(e)}")
        
        try:
            backup_path = file_path + '.backup'
            if os.path.exists(file_path):
                os.rename(file_path, backup_path)
                app.logger.info(f"Corrupted file backed up to {backup_path}")
        except:
            pass
        
        initialize_vocabulary_progress()
        return default_progress

def save_vocabulary_progress(progress_data):
    """Save vocabulary progress to file"""
    file_path = get_vocabulary_file_path()
    try:
        progress_data['last_updated'] = datetime.now().isoformat()
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(progress_data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        app.logger.error(f"Error saving vocabulary progress: {str(e)}")
        return False

def get_daily_vocabulary():
    """Get daily vocabulary word from available (non-completed) words"""
    available_words = get_available_vocabulary()
    vocabulary_data = load_vocabulary_data()
    
    # Flatten all available words
    all_available = []
    for level, words in available_words.items():
        for word in words.keys():
            japanese_meaning = words[word].get('Japanese', '')
            vietnamese_meaning = words[word].get('Vietnamese', '')
            all_available.append((word, level, japanese_meaning, vietnamese_meaning))
    
    if not all_available:
        # If all words are completed, reset or return random from all
        all_available = []
        for level, words in vocabulary_data.items():
            for word, details in words.items():
                japanese_meaning = details.get('Japanese', '')
                vietnamese_meaning = details.get('Vietnamese', '')
                all_available.append((word, level, japanese_meaning, vietnamese_meaning))
    
    # Use today's date as seed for consistent daily word
    today = date.today()
    random.seed(today.toordinal())
    
    word, level, japanese_meaning, vietnamese_meaning = random.choice(all_available)
    return word, level, japanese_meaning, vietnamese_meaning

def get_available_vocabulary():
    """Get vocabulary words that haven't been completed yet"""
    progress = load_vocabulary_progress()
    completed_words = set(progress.get('completed_words', []))
    vocabulary_data = load_vocabulary_data()
    
    available_words = {}
    for level, words in vocabulary_data.items():
        available_in_level = {word: details for word, details in words.items() 
                            if word not in completed_words}
        if available_in_level:
            available_words[level] = available_in_level
    
    return available_words

def generate_vocabulary_links(word):
    """Generate AI search links for vocabulary with custom query"""
    encoded_word = urllib.parse.quote(word)
    
    # Load AI settings
    ai_settings = load_ai_settings()
    
    # Load vocabulary query template from UserSettings - SỬA LẠI DÒNG NÀY
    settings = get_user_settings()
    vocabulary_template = settings.vocabulary_query_template or "Please explain the word '{word}' in detail including: 1. Definition and meaning, 2. Pronunciation guide, 3. Example sentences with context, 4. Common collocations and phrases, 5. Etymology if interesting, 6. Similar or related words"
    
    # Replace {word} with actual word
    query = vocabulary_template.replace('{word}', word)
    sources = []
    
    
    # Use URLs from settings - these can now be customized
    ai_services = {
        'chatgpt': {
            'url': ai_settings.get('chatgpt_url', "https://chat.openai.com/?q={query}"),
            'title': 'ChatGPT AI',
            'icon': 'bi-robot',
            'description': f'Ask ChatGPT about "{word}"',
            'color': 'success'
        },
        'grok': {
            'url': ai_settings.get('grok_url', "https://x.com/i/grok?q={query}"),
            'title': 'Grok AI',
            'icon': 'bi-lightning',
            'description': f'Ask Grok AI about "{word}"',
            'color': 'dark'
        },
        'perplexity': {
            'url': ai_settings.get('perplexity_url', "https://www.perplexity.ai/?q={query}"),
            'title': 'Perplexity AI',
            'icon': 'bi-search',
            'description': f'Search Perplexity AI for "{word}"',
            'color': 'info'
        },
        'you': {
            'url': ai_settings.get('you_url', "https://you.com/search?q={query}"),
            'title': 'You.com Search',
            'icon': 'bi-globe',
            'description': f'Search You.com for "{word}"',
            'color': 'warning'
        },
        'copilot': {
            'url': ai_settings.get('copilot_url', "https://copilot.microsoft.com/?q={query}"),
            'title': 'Copilot AI',
            'icon': 'bi-microsoft',
            'description': f'Ask Microsoft Copilot about "{word}"',
            'color': 'secondary'
        }
    }
    
    # Add enabled AI services
    for service_name, service_info in ai_services.items():
        if ai_settings.get(f'{service_name}_enabled'):
            # Get the URL template from settings
            url_template = service_info['url']
            
            # Replace {query} with the full query template (for detailed explanation)
            # And also support {word} for simple word lookup
            if '{word}' in url_template:
                # If URL template has {word}, use just the word
                service_url = url_template.replace('{word}', encoded_word)
            else:
                # If URL template has {query}, use the full query
                service_url = url_template.replace('{query}', urllib.parse.quote(query))
            
            sources.append({
                'title': service_info['title'],
                'url': service_url,
                'icon': service_info['icon'],
                'description': service_info['description'],
                'color': service_info['color']
            })
    
    return sources


# Add vocabulary routes
@app.route('/vocabulary')
@login_required
def vocabulary():
    return render_template('learning/vocabulary.html')

@app.route('/api/daily_vocabulary')
def get_daily_vocabulary_api():
    """API endpoint to get daily vocabulary"""
    try:
        word, level, japanese_meaning, vietnamese_meaning = get_daily_vocabulary()
        progress = load_vocabulary_progress()
        
        # Check if current word is completed
        is_completed = word in progress.get('completed_words', [])
        
        # Generate AI links for vocabulary
        ai_links = generate_vocabulary_links(word)
        
        return jsonify({
            'status': 'success',
            'word': word,
            'level': level,
            'japanese_meaning': japanese_meaning,
            'vietnamese_meaning': vietnamese_meaning,
            'is_completed': is_completed,
            'ai_links': ai_links,  # Add AI links
            'date': datetime.now().strftime('%Y-%m-%d'),
            'stats': progress.get('stats', {})
        })
    except Exception as e:
        app.logger.error(f"Error getting daily vocabulary: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/random_vocabulary')
def get_random_vocabulary_api():
    """API endpoint to get random vocabulary (not daily)"""
    try:
        available_words = get_available_vocabulary()
        vocabulary_data = load_vocabulary_data()
        
        # Flatten all available words
        all_available = []
        for level, words in available_words.items():
            for word, details in words.items():
                japanese_meaning = details.get('Japanese', '')
                vietnamese_meaning = details.get('Vietnamese', '')
                all_available.append((word, level, japanese_meaning, vietnamese_meaning))
        
        if not all_available:
            return jsonify({
                'status': 'info',
                'message': 'You have learned all vocabulary words! Congratulations!',
                'all_completed': True
            })
        
        # Use current timestamp for better randomness
        random.seed(int(time.time() * 1000000) % 1000000)
        
        word, level, japanese_meaning, vietnamese_meaning = random.choice(all_available)
        progress = load_vocabulary_progress()
        
        # Generate AI links for vocabulary
        ai_links = generate_vocabulary_links(word)
        
        app.logger.info(f"Random vocabulary selected: {word} from level: {level}")
        
        return jsonify({
            'status': 'success',
            'word': word,
            'level': level,
            'japanese_meaning': japanese_meaning,
            'vietnamese_meaning': vietnamese_meaning,
            'is_completed': False,
            'ai_links': ai_links,  # Add AI links
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'stats': progress.get('stats', {}),
            'is_random': True
        })
    except Exception as e:
        app.logger.error(f"Error getting random vocabulary: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
        

@app.route('/api/complete_vocabulary', methods=['POST'])
@login_required
def complete_vocabulary():
    """Mark a vocabulary word as completed"""
    try:
        data = request.get_json()
        word = data.get('word')
        level = data.get('level')
        
        if not word:
            return jsonify({
                'status': 'error',
                'message': 'Word is required'
            }), 400
        
        progress = load_vocabulary_progress()
        
        # Add word to completed list if not already there
        if word not in progress['completed_words']:
            progress['completed_words'].append(word)
            progress['stats']['total_completed'] = len(progress['completed_words'])
            
            # Update level progress
            if 'level_progress' not in progress['stats']:
                progress['stats']['level_progress'] = {}
            
            if level:
                if level not in progress['stats']['level_progress']:
                    progress['stats']['level_progress'][level] = 0
                progress['stats']['level_progress'][level] += 1
        
        # Save progress
        if save_vocabulary_progress(progress):
            return jsonify({
                'status': 'success',
                'message': f'Learned: {word}',
                'stats': progress['stats']
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Unable to save progress'
            }), 500
            
    except Exception as e:
        app.logger.error(f"Error completing vocabulary: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/uncomplete_vocabulary', methods=['POST'])
@login_required
def uncomplete_vocabulary():
    """Remove a vocabulary word from completed list"""
    try:
        data = request.get_json()
        word = data.get('word')
        level = data.get('level')
        
        if not word:
            return jsonify({
                'status': 'error',
                'message': 'Word is required'
            }), 400
        
        progress = load_vocabulary_progress()
        
        # Remove word from completed list
        if word in progress['completed_words']:
            progress['completed_words'].remove(word)
            progress['stats']['total_completed'] = len(progress['completed_words'])
            
            # Update level progress
            if level and 'level_progress' in progress['stats']:
                if level in progress['stats']['level_progress']:
                    progress['stats']['level_progress'][level] = max(0, 
                        progress['stats']['level_progress'][level] - 1)
        
        # Save progress
        if save_vocabulary_progress(progress):
            return jsonify({
                'status': 'success',
                'message': f'Removed: {word}',
                'stats': progress['stats']
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Unable to save progress'
            }), 500
            
    except Exception as e:
        app.logger.error(f"Error uncompleting vocabulary: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/vocabulary_stats')
def get_vocabulary_stats():
    """Get vocabulary completion statistics"""
    try:
        progress = load_vocabulary_progress()
        vocabulary_data = load_vocabulary_data()
        
        total_words = sum(len(words) for words in vocabulary_data.values())
        completed_count = len(progress.get('completed_words', []))
        
        # Calculate level stats
        level_stats = {}
        for level, words in vocabulary_data.items():
            total_in_level = len(words)
            completed_in_level = progress.get('stats', {}).get('level_progress', {}).get(level, 0)
            level_stats[level] = {
                'total': total_in_level,
                'completed': completed_in_level,
                'percentage': round((completed_in_level / total_in_level) * 100, 1) if total_in_level > 0 else 0
            }
        
        return jsonify({
            'status': 'success',
            'stats': {
                'total_words': total_words,
                'completed_words': completed_count,
                'remaining_words': total_words - completed_count,
                'completion_percentage': round((completed_count / total_words) * 100, 1) if total_words > 0 else 0,
                'level_stats': level_stats,
                'last_updated': progress.get('last_updated')
            }
        })
    except Exception as e:
        app.logger.error(f"Error getting vocabulary stats: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Initialize vocabulary progress on app start
with app.app_context():
    initialize_vocabulary_progress()
    
@app.route('/api/evernote_notes/<int:note_id>/move', methods=['PUT'])
@login_required
def move_evernote_note(note_id):
    """Move note to different folder"""
    try:
        note = EvernoteNote.query.get_or_404(note_id)
        data = request.json
        
        new_folder_id = data.get('folder_id')
        
        # Validate folder exists if provided
        if new_folder_id and not EvernoteFolder.query.get(new_folder_id):
            return jsonify({'status': 'error', 'message': 'Target folder not found'}), 404
        
        old_folder_id = note.folder_id
        note.folder_id = new_folder_id
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Note moved successfully',
            'old_folder_id': old_folder_id,
            'new_folder_id': new_folder_id
        })
        
    except Exception as e:
        app.logger.error(f"Error moving note: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
# Password Manager Routes
@app.route('/password_manager')
@login_required
def password_manager():
    return render_template('Password/password_manager.html')

@app.route('/api/passwords', methods=['GET'])
@login_required
def get_passwords():
    try:
        # Check if this is a test request
        if request.args.get('test'):
            if not session.get('master_password_verified'):
                return jsonify({'status': 'error', 'message': 'Master password required'}), 401
            return jsonify({'status': 'success', 'test': True})
        
        # Normal password request - require master password
        if not session.get('master_password_verified'):
            return jsonify({'status': 'error', 'message': 'Master password required'}), 401
            
        search = request.args.get('search', '').strip()
        category_id = request.args.get('category_id', type=int)
        
        query = Password.query
        
        if search:
            query = query.filter(
                db.or_(
                    Password.title.contains(search),
                    Password.website_url.contains(search),
                    Password.username.contains(search),
                    Password.note.contains(search)
                )
            )
        
        if category_id:
            query = query.filter_by(category_id=category_id)
        
        passwords = query.order_by(Password.favorite.desc(), Password.title.asc()).all()
        
        return jsonify({
            'status': 'success',
            'passwords': [p.to_dict() for p in passwords] if passwords else []
        })
    except Exception as e:
        app.logger.error(f"Error in get_passwords: {str(e)}")
        return jsonify({
            'status': 'success', 
            'passwords': []
        })
        
def require_master_password():
    """Decorator để check master password"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            # Check if master password was verified recently (trong 1 giờ)
            if not session.get('master_password_verified'):
                return jsonify({'status': 'error', 'message': 'Master password required'}), 401
            
            verify_time = session.get('master_password_time', 0)
            if time.time() - verify_time > 3600:  # 1 hour timeout
                session.pop('master_password_verified', None)
                session.pop('master_password_time', None)
                return jsonify({'status': 'error', 'message': 'Master password expired'}), 401
                
            # ✅ THÊM: Initialize encryption với master password nếu chưa có
            if not password_encryption.fernet:
                return jsonify({'status': 'error', 'message': 'Master password required'}), 401
            
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

@app.route('/api/passwords', methods=['POST'])
@login_required
@require_master_password()
def add_password():
    try:
        data = request.json
        
        # Password sẽ tự động được encrypt khi set
        password = Password(
            title=data['title'],
            website_url=data.get('website_url', ''),
            username=data.get('username', ''),
            password=data['password'],  # Sẽ tự động encrypt
            note=data.get('note', ''),
            category_id=data.get('category_id'),
            favorite=data.get('favorite', False)
        )
        
        db.session.add(password)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'password': password.to_dict()  # Sẽ tự động decrypt khi trả về
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding password: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/passwords/<int:password_id>', methods=['PUT'])
@login_required
def update_password(password_id):
    try:
        password = Password.query.get_or_404(password_id)
        
        data = request.json
        
        # Validate category if provided
        category_id = data.get('category_id')
        if category_id:
            category = PasswordCategory.query.filter_by(id=category_id).first()
            if not category:
                return jsonify({'status': 'error', 'message': 'Invalid category'}), 400
        
        password.title = data['title']
        password.website_url = data.get('website_url', '')
        password.username = data.get('username', '')
        password.password = data['password']
        password.note = data.get('note', '')
        password.category_id = category_id
        password.favorite = data.get('favorite', False)
        password.updated_at = datetime.now()
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'password': password.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating password: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/passwords/<int:password_id>', methods=['DELETE'])
@login_required
def delete_password(password_id):
    try:
        password = Password.query.get_or_404(password_id)
        
        db.session.delete(password)
        db.session.commit()
        
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/passwords/import', methods=['POST'])
@login_required
def import_passwords():
    try:
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No file selected'}), 400
        
        # Read CSV file
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_input = csv.DictReader(stream)
        
        imported_count = 0
        for row in csv_input:
            # ✅ SỬA: Find or create category
            category_name = row.get('Category', row.get('category', 'Imported'))
            category = None
            if category_name and category_name != 'Imported':
                category = PasswordCategory.query.filter_by(
                    name=category_name
                ).first()
                
                if not category:
                    # Create new category
                    category = PasswordCategory(
                        name=category_name,
                        color='#6c757d'
                    )
                    db.session.add(category)
                    db.session.flush()  # Get the ID
            
            password = Password(
                title=row.get('Title', row.get('title', '')),
                website_url=row.get('Website', row.get('URL', row.get('url', ''))),
                username=row.get('Username', row.get('username', '')),
                password=row.get('Password', row.get('password', '')),
                note=row.get('Notes', row.get('note', '')),
                category_id=category.id if category else None
            )
            db.session.add(password)
            imported_count += 1
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Imported {imported_count} passwords successfully'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error importing passwords: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/passwords/categories', methods=['GET'])
@login_required
def get_password_categories():
    try:
        categories = PasswordCategory.query.order_by(PasswordCategory.name.asc()).all()
        
        return jsonify({
            'status': 'success',
            'categories': [cat.to_dict() for cat in categories]
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/passwords/generate', methods=['POST'])
@login_required
def generate_password():
    try:
        data = request.json
        length = data.get('length', 12)
        include_upper = data.get('include_upper', True)
        include_lower = data.get('include_lower', True)
        include_numbers = data.get('include_numbers', True)
        include_symbols = data.get('include_symbols', True)
        
        import string
        import secrets
        
        chars = ''
        if include_lower:
            chars += string.ascii_lowercase
        if include_upper:
            chars += string.ascii_uppercase
        if include_numbers:
            chars += string.digits
        if include_symbols:
            chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        if not chars:
            return jsonify({'status': 'error', 'message': 'At least one character type must be selected'}), 400
        
        password = ''.join(secrets.choice(chars) for _ in range(length))
        
        return jsonify({
            'status': 'success',
            'password': password
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
@app.route('/api/categories', methods=['GET'])
@login_required
def get_categories():
    try:
        # Get password categories with password counts
        categories = db.session.query(
        PasswordCategory.id,
        PasswordCategory.name,
        PasswordCategory.color,
        db.func.count(Password.id).label('password_count')
    ).outerjoin(Password).group_by(PasswordCategory.id).order_by(PasswordCategory.name.asc()).all()
        
        return jsonify({
            'status': 'success',
            'categories': [{
                'id': cat.id,
                'name': cat.name,
                'color': cat.color,
                'password_count': cat.password_count
            } for cat in categories]
        })
    except Exception as e:
        app.logger.error(f"Error getting password categories: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/categories', methods=['POST'])
@login_required
def create_category():
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        color = data.get('color', '#007bff')
        
        if not name:
            return jsonify({'status': 'error', 'message': 'Category name is required'}), 400
        
        if len(name) > 50:
            return jsonify({'status': 'error', 'message': 'Category name must be 50 characters or less'}), 400
        
        # Check if category already exists
        existing = PasswordCategory.query.filter_by(name=name).first()
        if existing:
            return jsonify({'status': 'error', 'message': 'Category already exists'}), 400
        
        category = PasswordCategory(name=name, color=color)
        db.session.add(category)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'category': {
                'id': category.id,
                'name': category.name,
                'color': category.color,
                'password_count': 0
            }
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating password category: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/categories/<int:category_id>', methods=['PUT'])
@login_required
def update_category(category_id):
    try:
        category = PasswordCategory.query.filter_by(id=category_id).first()
        if not category:
            return jsonify({'status': 'error', 'message': 'Category not found'}), 404
        
        data = request.get_json()
        new_name = data.get('name', '').strip()
        new_color = data.get('color', category.color)
        
        if not new_name:
            return jsonify({'status': 'error', 'message': 'Category name is required'}), 400
        
        if len(new_name) > 50:
            return jsonify({'status': 'error', 'message': 'Category name must be 50 characters or less'}), 400
        
        # Check if new name conflicts with existing categories
        existing = PasswordCategory.query.filter_by(name=new_name).filter(PasswordCategory.id != category_id).first()
        if existing:
            return jsonify({'status': 'error', 'message': 'Category name already exists'}), 400
        
        category.name = new_name
        category.color = new_color
        category.updated_at = datetime.now()
        
        db.session.commit()
        
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating password category: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
@login_required
def delete_password_category(category_id): 
    try:
        category = PasswordCategory.query.filter_by(id=category_id).first()
        if not category:
            return jsonify({'status': 'error', 'message': 'Category not found'}), 404
        
        # Move all passwords in this category to null (General)
        Password.query.filter_by(category_id=category_id).update({'category_id': None})
        
        db.session.delete(category)
        db.session.commit()
        
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting password category: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/auth/master_password', methods=['POST'])
@login_required
def authenticate_master_password():
    """Xác thực master password"""
    try:
        data = request.get_json()
        master_password = data.get('master_password')
        
        if not master_password:
            return jsonify({'status': 'error', 'message': 'Master password required'}), 400
        
        # Test encryption với một password mẫu
        try:
            password_encryption.initialize(master_password)
            
            # Test encrypt/decrypt để verify master password
            test_password = "test123"
            encrypted = password_encryption.encrypt_password(test_password)
            decrypted = password_encryption.decrypt_password(encrypted)
            
            if decrypted == test_password:
                # Lưu vào session (chỉ trong thời gian ngắn)
                session['master_password_verified'] = True
                session['master_password_time'] = time.time()
                
                return jsonify({
                    'status': 'success',
                    'message': 'Master password verified'
                })
            else:
                return jsonify({'status': 'error', 'message': 'Invalid master password'}), 401
                
        except Exception as e:
            app.logger.error(f"Master password verification failed: {e}")
            return jsonify({'status': 'error', 'message': 'Invalid master password'}), 401
            
    except Exception as e:
        app.logger.error(f"Error in master password auth: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/auth/master_password_status', methods=['GET'])
@login_required
def master_password_status():
    """Check master password authentication status"""
    try:
        if session.get('master_password_verified'):
            # Check if session hasn't expired (1 hour timeout)
            verify_time = session.get('master_password_time', 0)
            if time.time() - verify_time <= 3600:  # 1 hour
                return jsonify({
                    'status': 'success',
                    'authenticated': True,
                    'message': 'Master password verified'
                })
            else:
                # Session expired, clear it
                session.pop('master_password_verified', None)
                session.pop('master_password_time', None)
                return jsonify({
                    'status': 'error',
                    'authenticated': False,
                    'message': 'Master password session expired'
                }), 401
        else:
            return jsonify({
                'status': 'error',
                'authenticated': False,
                'message': 'Master password not verified'
            }), 401
            
    except Exception as e:
        app.logger.error(f"Error checking master password status: {str(e)}")
        return jsonify({
            'status': 'error',
            'authenticated': False,
            'message': 'Server error'
        }), 500
        
@app.route('/api/auth/change_master_password', methods=['POST'])
@login_required
def change_master_password():
    """Thay đổi master password"""
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        new_hint = data.get('new_hint', '').strip()
        
        if not current_password or not new_password:
            return jsonify({'status': 'error', 'message': 'Both passwords are required'}), 400
        
        # Verify current master password
        try:
            password_encryption.initialize(current_password)
            
            # Test with existing password
            test_password = "test123"
            encrypted = password_encryption.encrypt_password(test_password)
            decrypted = password_encryption.decrypt_password(encrypted)
            
            if decrypted != test_password:
                return jsonify({'status': 'error', 'message': 'Current master password is incorrect'}), 401
                
        except Exception as e:
            app.logger.error(f"Current master password verification failed: {e}")
            return jsonify({'status': 'error', 'message': 'Current master password is incorrect'}), 401
        
        # Get all passwords for re-encryption
        passwords = Password.query.all()
        
        # Decrypt all passwords with current master password
        decrypted_passwords = []
        for pwd in passwords:
            try:
                decrypted_pwd = password_encryption.decrypt_password(pwd.password_encrypted)
                decrypted_passwords.append({
                    'id': pwd.id,
                    'password': decrypted_pwd
                })
            except Exception as e:
                app.logger.error(f"Failed to decrypt password {pwd.id}: {e}")
                return jsonify({'status': 'error', 'message': f'Failed to decrypt existing passwords'}), 500
        
        # Initialize encryption with new master password
        try:
            password_encryption.initialize(new_password)
        except Exception as e:
            app.logger.error(f"Failed to initialize new encryption: {e}")
            return jsonify({'status': 'error', 'message': 'Failed to initialize new encryption'}), 500
        
        # Re-encrypt all passwords with new master password
        try:
            for pwd_data in decrypted_passwords:
                password_obj = Password.query.get(pwd_data['id'])
                if password_obj:
                    new_encrypted = password_encryption.encrypt_password(pwd_data['password'])
                    password_obj.password_encrypted = new_encrypted
            
            # Update hint if provided
            if new_hint or new_hint == '':  # Allow clearing hint
                settings = UserSettings.query.first()
                if not settings:
                    settings = UserSettings()
                    db.session.add(settings)
                
                settings.master_password_hint = new_hint if new_hint else None
                settings.updated_at = datetime.now()
            
            db.session.commit()
            
            # Update session
            session['master_password_verified'] = True
            session['master_password_time'] = time.time()
            
            return jsonify({
                'status': 'success',
                'message': f'Master password changed successfully. Re-encrypted {len(decrypted_passwords)} passwords.'
            })
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Failed to re-encrypt passwords: {e}")
            return jsonify({'status': 'error', 'message': 'Failed to re-encrypt passwords'}), 500
            
    except Exception as e:
        app.logger.error(f"Error changing master password: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/auth/master_password_hint', methods=['GET'])
@login_required
def get_master_password_hint():
    """Lấy hint cho master password"""
    try:
        settings = UserSettings.query.first()
        hint = settings.master_password_hint if settings else None
        
        return jsonify({
            'status': 'success',
            'hint': hint
        })
    except Exception as e:
        app.logger.error(f"Error getting master password hint: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/auth/master_password_hint', methods=['POST'])
@login_required
def set_master_password_hint():
    """Set hint cho master password"""
    try:
        data = request.get_json()
        hint = data.get('hint', '').strip()
        
        if len(hint) > 200:
            return jsonify({'status': 'error', 'message': 'Hint must be 200 characters or less'}), 400
        
        settings = UserSettings.query.first()
        if not settings:
            settings = UserSettings()
            db.session.add(settings)
        
        settings.master_password_hint = hint if hint else None
        settings.updated_at = datetime.now()
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Hint saved successfully'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error setting master password hint: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
@app.route('/api/auth/lock_master_password', methods=['POST'])
@login_required
def lock_master_password():
    """Khóa master password session ngay lập tức"""
    try:
        # Xóa session master password
        session.pop('master_password_verified', None)
        session.pop('master_password_time', None)
        
        # Reset password encryption instance
        global password_encryption
        password_encryption.fernet = None
        
        app.logger.info(f"Master password session locked for user {current_user.id}")
        
        return jsonify({
            'status': 'success',
            'message': 'Password manager locked successfully'
        })
        
    except Exception as e:
        app.logger.error(f"Error locking master password: {str(e)}")
        return jsonify({
            'status': 'error', 
            'message': str(e)
        }), 500
        
@app.route('/upload_task_images', methods=['POST'])
@login_required
def upload_task_images():
    try:
        note_id = request.form.get('note_id')
        if not note_id:
            return jsonify({'status': 'error', 'message': 'Note ID required'})
        
        note = Task.query.get_or_404(note_id)
        images = request.files.getlist('images')
        
        if not images:
            return jsonify({'status': 'success', 'images': []})
        
        # Get existing images
        existing_images = json.loads(note.images) if note.images else []
        uploaded_images = []
        
        # Process new images
        for image in images:
            if image and image.filename:
                try:
                    # Generate unique filename
                    timestamp = int(time.time() * 1000)
                    original_filename = secure_filename(image.filename)
                    name, ext = os.path.splitext(original_filename)
                    unique_filename = f"{name}_{timestamp}_{uuid4().hex[:8]}{ext}"
                    
                    # Save file to disk
                    filepath = os.path.join(app.config['TASK_UPLOAD_FOLDER'], unique_filename)
                    
                    # Process and save image
                    if image.filename.lower().endswith('.heic'):
                        # Handle HEIC files
                        try:
                            with Image(blob=image.read()) as img:
                                img.format = 'jpeg'
                                img.compression_quality = 85
                                img.save(filename=filepath.replace('.heic', '.jpg').replace('.HEIC', '.jpg'))
                                unique_filename = unique_filename.replace('.heic', '.jpg').replace('.HEIC', '.jpg')
                                filepath = filepath.replace('.heic', '.jpg').replace('.HEIC', '.jpg')
                        except:
                            # Fallback: save as is
                            image.save(filepath)
                    else:
                        # Regular image processing
                        pil_image = PILImage.open(image)
                        
                        # Resize if too large
                        max_size = (1920, 1080)
                        if pil_image.size[0] > max_size[0] or pil_image.size[1] > max_size[1]:
                            pil_image.thumbnail(max_size, PILImage.Resampling.LANCZOS)
                        
                        # Convert to RGB if necessary
                        if pil_image.mode in ('RGBA', 'P'):
                            pil_image = pil_image.convert('RGB')
                        
                        # Save with compression
                        pil_image.save(filepath, 'JPEG', quality=85, optimize=True)
                    
                    # Create image info
                    image_info = {
                        'filename': unique_filename,
                        'original_name': original_filename,
                        'path': f'/static/uploads/task/{unique_filename}',
                        'upload_time': datetime.now().isoformat(),
                        'size': os.path.getsize(filepath) if os.path.exists(filepath) else 0
                    }
                    
                    existing_images.append(image_info)
                    uploaded_images.append(image_info)
                    
                except Exception as e:
                    logging.error(f"Error processing image {image.filename}: {str(e)}")
                    continue
        
        # Update note with new images
        note.images = json.dumps(existing_images) if existing_images else None
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'images': uploaded_images,
            'total_images': len(existing_images),
            'message': f'{len(uploaded_images)} image(s) uploaded successfully'
        })
        
    except Exception as e:
        logging.error(f"Upload task images error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

# Route xóa ảnh task
@app.route('/delete_task_image', methods=['POST'])
@login_required
def delete_task_image():
    try:
        data = request.get_json()
        note_id = data.get('note_id')
        image_filename = data.get('filename')
        
        if not note_id or not image_filename:
            return jsonify({'status': 'error', 'message': 'Missing parameters'})
        
        note = Task.query.get_or_404(note_id)
        images = json.loads(note.images) if note.images else []
        
        # Find and remove image
        updated_images = []
        deleted_file = None
        
        for img in images:
            if img.get('filename') == image_filename:
                deleted_file = img
                # Delete physical file
                try:
                    filepath = os.path.join(app.config['TASK_UPLOAD_FOLDER'], image_filename)
                    if os.path.exists(filepath):
                        os.remove(filepath)
                except Exception as e:
                    logging.error(f"Error deleting file {filepath}: {str(e)}")
            else:
                updated_images.append(img)
        
        # Update database
        note.images = json.dumps(updated_images) if updated_images else None
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Image deleted successfully',
            'deleted_file': deleted_file
        })
        
    except Exception as e:
        logging.error(f"Delete task image error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})
    
@app.route('/static/uploads/task/<filename>')
def serve_task_image(filename):
    """Serve task image files"""
    try:
        return send_from_directory(app.config['TASK_UPLOAD_FOLDER'], filename)
    except Exception as e:
        app.logger.error(f"Error serving task image {filename}: {e}")
        return jsonify({'status': 'error', 'message': 'Image not found'}), 404


@app.route('/api/diary/auth/status', methods=['GET'])
@login_required
def check_diary_auth_status():
    """Check diary authentication status"""
    try:
        user_settings = UserSettings.query.first()
        password_count = Password.query.count()
        
        has_hint = bool(user_settings and user_settings.master_password_hint)
        has_master_password = password_count > 0 or has_hint
        
        # ✅ SỬA: Check session từ Password Manager
        is_authenticated = session.get('master_password_verified', False)
        
        if not has_master_password:
            # Chưa có master password → cho phép access
            redirect_to_password_manager = False
            is_authenticated = True
        else:
            # Có master password → check session
            if is_authenticated:
                # Đã authenticated từ Password Manager
                redirect_to_password_manager = False
            else:
                # Chưa authenticated → redirect to Password Manager
                redirect_to_password_manager = True
        
        app.logger.info(f"Diary auth - has_master: {has_master_password}, session_verified: {is_authenticated}, redirect: {redirect_to_password_manager}")
        
        return jsonify({
            'status': 'success',
            'has_master_password': has_master_password,
            'is_authenticated': is_authenticated,
            'redirect_to_password_manager': redirect_to_password_manager
        })
    except Exception as e:
        app.logger.error(f"Error checking diary auth status: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Server error'}), 500

@app.route('/download_db')
@login_required
def download_db():
    db_path = os.path.join(app.instance_path, 'eiki_tomobe.db') 
    if not os.path.isabs(db_path):
        db_path = os.path.join(app.root_path, db_path)
    zip_io = BytesIO()
    with zipfile.ZipFile(zip_io, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(db_path, arcname=os.path.basename(db_path))
    zip_io.seek(0)
    return send_file(zip_io, as_attachment=True, download_name='eiki_tomobe_db.zip')

@app.route('/api/db_tables')
@login_required
def api_db_tables():
    # Lấy đúng đường dẫn file DB
    db_path = os.path.join(app.instance_path, 'eiki_tomobe.db')
    app.logger.info(f"Database path: {db_path}")
    if not os.path.isabs(db_path):
        db_path = os.path.join(app.root_path, db_path)
    # Kiểm tra file tồn tại
    if not os.path.exists(db_path):
        return jsonify({'tables': []})
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # Lấy danh sách table (bỏ qua bảng hệ thống)
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = [row[0] for row in cur.fetchall()]
    app.logger.info(f"Found tables: {tables}")
    table_info = []
    for t in tables:
        try:
            cur.execute(f"SELECT COUNT(*) FROM '{t}'")
            count = cur.fetchone()[0]
        except Exception:
            count = '?'
        table_info.append({'name': t, 'rows': count})
    conn.close()
    return jsonify({'tables': table_info})

@app.route('/api/db_delete_table', methods=['POST'])
@login_required
def api_db_delete_table():
    table = request.json.get('table')
    if not table:
        return jsonify({'status': 'error', 'message': 'No table specified'}), 400
    db_path = os.path.join(app.instance_path, 'eiki_tomobe.db') 
    if not os.path.isabs(db_path):
        db_path = os.path.join(app.root_path, db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    try:
        cur.execute(f'DELETE FROM {table}')
        conn.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/uploads_files')
@login_required
def api_uploads_files():
    folder = os.path.join(app.root_path, 'static', 'uploads')
    files = []
    for root, dirs, filenames in os.walk(folder):
        for fname in filenames:
            path = os.path.relpath(os.path.join(root, fname), folder)
            size = os.path.getsize(os.path.join(root, fname))
            files.append({'name': path.replace("\\", "/"), 'size': size})
    return jsonify({'files': files})

@app.route('/api/delete_upload_file', methods=['POST'])
@login_required
def api_delete_upload_file():
    fname = request.json.get('filename')
    folder = os.path.join(app.root_path, 'static', 'uploads')
    abs_path = os.path.abspath(os.path.join(folder, fname))
    if not abs_path.startswith(folder) or not os.path.isfile(abs_path):
        return jsonify({'status': 'error', 'message': 'Invalid file'}), 400
    try:
        os.remove(abs_path)
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/english_cloze')
@login_required
def english_cloze():
    return render_template('learning/english_cloze.html')

@app.route('/contacts', methods=['GET', 'POST'])
@login_required
def contacts():
    contacts = Contact.query.all()
    today = date.today()
    tomorrow = today + timedelta(days=1)
    alerts_today = []
    alerts_tomorrow = []

    def check_event(dt_str):
        if not dt_str:
            return None
        try:
            d = datetime.strptime(dt_str, "%Y-%m-%d").date()
            return d.replace(year=today.year)
        except Exception:
            return None

    for c in contacts:
        # Birthday
        bday = check_event(c.birthday)
        if bday:
            if bday == today:
                alerts_today.append(f"{c.name} sinh nhật hôm nay!")
            elif bday == tomorrow:
                alerts_tomorrow.append(f"{c.name} sinh nhật ngày mai!")
        # Anniversaries
        for anniv_text, anniv_date in [
            (c.anniv1_text, c.anniv1_date),
            (c.anniv2_text, c.anniv2_date),
            (c.anniv3_text, c.anniv3_date),
        ]:
            if anniv_text and anniv_date:
                anniv = check_event(anniv_date)
                if anniv:
                    if anniv == today:
                        alerts_today.append(f"{c.name}: {anniv_text} hôm nay!")
                    elif anniv == tomorrow:
                        alerts_tomorrow.append(f"{c.name}: {anniv_text} ngày mai!")

    return render_template(
        "Contact/contacts.html",
        contacts=contacts,
        alerts_today=alerts_today,
        alerts_tomorrow=alerts_tomorrow
    )

@app.route('/contacts/save', methods=['POST'])
@login_required
def save_contact():
    form = request.form
    contact_id = form.get('id')
    if contact_id:
        contact = Contact.query.get(contact_id)
        if not contact:
            flash('Không tìm thấy liên hệ!', 'danger')
            return redirect(url_for('contacts'))
    else:
        contact = Contact()
        db.session.add(contact)
    # Cập nhật các trường
    for field in ['name', 'relation', 'phone', 'email', 'address', 'company', 'position', 'group',
                  'birthday', 'website', 'anniv1_text', 'anniv1_date', 'anniv2_text', 'anniv2_date',
                  'anniv3_text', 'anniv3_date', 'dependents', 'note']:
        setattr(contact, field, form.get(field))
    db.session.commit()
    flash('Đã lưu liên hệ!', 'success')
    return redirect(url_for('contacts'))

@app.route('/contacts/delete/<int:id>')
@login_required
def delete_contact(id):
    contact = Contact.query.get(id)
    if contact:
        db.session.delete(contact)
        db.session.commit()
        flash('Đã xoá liên hệ!', 'success')
    else:
        flash('Không tìm thấy liên hệ!', 'danger')
    return redirect(url_for('contacts'))

@app.route('/contacts/<int:id>/json')
@login_required
def get_contact_json(id):
    contact = Contact.query.get_or_404(id)
    return jsonify({
        'id': contact.id,
        'name': contact.name,
        'relation': contact.relation,
        'phone': contact.phone,
        'email': contact.email,
        'address': contact.address,
        'company': contact.company,
        'position': contact.position,
        'group': contact.group,
        'birthday': contact.birthday,
        'website': contact.website,
        'anniv1_text': contact.anniv1_text,
        'anniv1_date': contact.anniv1_date,
        'anniv2_text': contact.anniv2_text,
        'anniv2_date': contact.anniv2_date,
        'anniv3_text': contact.anniv3_text,
        'anniv3_date': contact.anniv3_date,
        'dependents': contact.dependents,
        'note': contact.note
    })
    
def get_birthday_alerts():
    today = date.today()
    tomorrow = today + timedelta(days=1)
    now = datetime.now()
    
    alerts_today = []
    alerts_tomorrow = []
    
    # Check contact birthdays and anniversaries
    contacts = Contact.query.all()
    for contact in contacts:
        # Check birthday
        if contact.birthday:
            birthday = datetime.strptime(contact.birthday, '%Y-%m-%d').date()
            if birthday.month == today.month and birthday.day == today.day:
                alerts_today.append(f"Hôm nay là sinh nhật của {contact.name}")
            elif birthday.month == tomorrow.month and birthday.day == tomorrow.day:
                alerts_tomorrow.append(f"Ngày mai là sinh nhật của {contact.name}")
        
        # Check anniversaries (anniv1_date, anniv2_date, anniv3_date)
        for i in [1, 2, 3]:
            anniv_date = getattr(contact, f'anniv{i}_date', None)
            anniv_text = getattr(contact, f'anniv{i}_text', None)
            if anniv_date:
                anniv = datetime.strptime(anniv_date, '%Y-%m-%d').date()
                if anniv.month == today.month and anniv.day == today.day:
                    alerts_today.append(f"Hôm nay là {anniv_text or 'kỷ niệm'} của {contact.name}")
                elif anniv.month == tomorrow.month and anniv.day == tomorrow.day:
                    alerts_tomorrow.append(f"Ngày mai là {anniv_text or 'kỷ niệm'} của {contact.name}")
    
    # Check task deadlines
    tasks = Task.query.filter(Task.is_completed == False).all()
    for task in tasks:
        if task.due_date:
            due_date = task.due_date.date()
            if due_date == today:
                alerts_today.append(f"Task '{task.title}' hết hạn hôm nay")
            elif due_date == tomorrow:
                alerts_tomorrow.append(f"Task '{task.title}' hết hạn ngày mai")
            elif due_date < today:
                alerts_today.append(f"Task '{task.title}' đã quá hạn từ {due_date.strftime('%d/%m/%Y')}")
    
    return alerts_today, alerts_tomorrow


# Mindmap Routes
@app.route('/mindmap')
@login_required
def mindmap():
    return render_template('Mindmap/mindmap.html', theme=get_theme())

@app.route('/api/mindmaps', methods=['GET'])
@login_required
def get_mindmaps():
    mindmaps = MindMap.query.order_by(MindMap.updated_at.desc()).all()
    return jsonify([{
        'id': mm.id,
        'title': mm.title,
        'description': mm.description,
        'category': mm.category,
        'created_at': mm.created_at.isoformat(),
        'updated_at': mm.updated_at.isoformat(),
        'shared': mm.shared
    } for mm in mindmaps])

@app.route('/api/mindmaps', methods=['POST'])
@login_required
def create_mindmap():
    data = request.get_json()
    
    # Create mindmap
    mindmap = MindMap(
        title=data['title'],
        description=data.get('description', ''),
        category=data.get('category', 'personal')
    )
    db.session.add(mindmap)
    db.session.flush()  # Get the ID
    
    # Save nodes
    for node_data in data['nodes']:
        node = MindMapNode(
            id=node_data['id'],
            mindmap_id=mindmap.id,
            text=node_data['text'],
            x=node_data['x'],
            y=node_data['y'],
            color=node_data['color'],
            font_size=node_data['fontSize'],
            is_root=node_data['isRoot'],
            parent_id=node_data.get('parent')
        )
        db.session.add(node)
    
    # Save connections
    for conn_data in data['connections']:
        connection = MindMapConnection(
            mindmap_id=mindmap.id,
            from_node_id=conn_data['from'],
            to_node_id=conn_data['to']
        )
        db.session.add(connection)
    
    db.session.commit()
    
    return jsonify({'id': mindmap.id, 'status': 'success'})

@app.route('/api/mindmaps/<int:mindmap_id>', methods=['GET'])
@login_required
def get_mindmap(mindmap_id):
    mindmap = MindMap.query.get_or_404(mindmap_id)
    for node in mindmap.nodes:
        print(f"Node ID: {node.id}, Text: {node.text}, Parent: {node.parent_id}, children: {node.children}  ")
    
    
    nodes = [{
        'id': node.id,
        'text': node.text,
        'x': node.x,
        'y': node.y,
        'color': node.color,
        'fontSize': node.font_size,
        'isRoot': node.is_root,
        'parent': node.parent_id,
        'children': [child.id for child in (node.children or [])]
    } for node in mindmap.nodes]
    
    connections = [{
        'from': conn.from_node_id,
        'to': conn.to_node_id
    } for conn in mindmap.connections]
    
    return jsonify({
        'id': mindmap.id,
        'title': mindmap.title,
        'description': mindmap.description,
        'category': mindmap.category,
        'nodes': nodes,
        'connections': connections
    })

@app.route('/api/mindmaps/<int:mindmap_id>', methods=['PUT'])
@login_required
def update_mindmap(mindmap_id):
    mindmap = MindMap.query.get_or_404(mindmap_id)
    data = request.get_json()
    
    MindMap.query.filter_by(mindmap_id=id).delete()
    MindMapConnection.query.filter_by(mindmap_id=id).delete()
    db.session.commit()
    
    # Update mindmap info
    mindmap.title = data.get('title', mindmap.title)
    mindmap.description = data.get('description', mindmap.description)
    mindmap.category = data.get('category', mindmap.category)
    mindmap.updated_at = datetime.now()
    
    # Clear existing nodes and connections
    MindMapNode.query.filter_by(mindmap_id=mindmap_id).delete()
    MindMapConnection.query.filter_by(mindmap_id=mindmap_id).delete()
    
    # Add updated nodes
    for node_data in data['nodes']:
        node = MindMapNode(
            id=node_data['id'],
            mindmap_id=mindmap.id,
            text=node_data['text'],
            x=node_data['x'],
            y=node_data['y'],
            color=node_data['color'],
            font_size=node_data['fontSize'],
            is_root=node_data['isRoot'],
            parent_id=node_data.get('parent')
        )
        db.session.add(node)
    
    # Add updated connections
    for conn_data in data['connections']:
        connection = MindMapConnection(
            mindmap_id=mindmap.id,
            from_node_id=conn_data['from'],
            to_node_id=conn_data['to']
        )
        db.session.add(connection)
    
    db.session.commit()
    
    return jsonify({'status': 'success'})

@app.route('/api/mindmaps/<int:mindmap_id>', methods=['DELETE'])
@login_required
def delete_mindmap(mindmap_id):
    mindmap = MindMap.query.get_or_404(mindmap_id)
    db.session.delete(mindmap)
    db.session.commit()
    
    return jsonify({'status': 'success'})

@app.route('/api/mindmaps/<int:mindmap_id>/share', methods=['POST'])
@login_required
def share_mindmap(mindmap_id):
    mindmap = MindMap.query.get_or_404(mindmap_id)
    data = request.get_json()
    
    # Generate share password
    import secrets
    import string
    share_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
    
    # Create share entry
    share = MindMapShare(
        mindmap_id=mindmap_id,
        email=data['email'],
        password=share_password,
        permission=data.get('permission', 'view'),
        expires_at=datetime.now() + timedelta(days=data.get('expire_days', 30))
    )
    
    db.session.add(share)
    mindmap.shared = True
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'share_password': share_password,
        'share_url': f'/mindmap/shared/{mindmap_id}'
    })

@app.route('/mindmap/shared/<int:mindmap_id>')
def shared_mindmap(mindmap_id):
    email = request.args.get('email')
    password = request.args.get('password')
    
    if not email or not password:
        return render_template('error.html', message='Missing email or password')
    
    # Verify share access
    share = MindMapShare.query.filter_by(
        mindmap_id=mindmap_id,
        email=email,
        password=password
    ).first()
    
    if not share or (share.expires_at and share.expires_at < datetime.now()):
        return render_template('error.html', message='Invalid or expired share link')
    
    mindmap = MindMap.query.get_or_404(mindmap_id)
    
    return render_template('Mindmap/shared_mindmap.html', 
                         mindmap=mindmap, 
                         permission=share.permission,
                         theme=get_theme())


if __name__ == '__main__':
    app.run(debug=True)