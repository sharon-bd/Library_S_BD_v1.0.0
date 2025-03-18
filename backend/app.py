# app.py

from datetime import date, datetime, timedelta, timezone
from functools import wraps
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from sqlalchemy import inspect
from flask import (
    Flask, jsonify, make_response, request, g, send_from_directory, redirect,
    send_file, render_template, session, abort  
)
import coloredlogs
import jwt
from sqlalchemy import create_engine, event
from sqlalchemy.orm import scoped_session, sessionmaker, Session
from database_init import initialize_database, create_initial_data
# Local imports
from database import db
from models import Book, BookType, Customer, Loan
from models.loan import Loan, loan_blueprint
import random

# Basic Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'library.db')}"
HTML_DIR = os.path.join(PROJECT_DIR, "frontend", "html")

app = Flask(
    __name__,
    static_folder=os.path.join(PROJECT_DIR, "frontend/static")
)
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "supersecret")

# Initialize database
db.init_app(app)
app.register_blueprint(loan_blueprint, url_prefix="/api")

# Logging Configuration
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "app.log")

logging.basicConfig(
    level=logging.DEBUG,
    filename=LOG_FILE,
    filemode="a",
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
coloredlogs.install(
    level="DEBUG",
    fmt="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    isatty=True,   
)

# Check if DB exists and create if needed
db_path = os.path.join(BASE_DIR, 'library.db')
logging.info(f"Checking for database at {db_path}")
initialize_database(app, db_path)

# Database engine and session factory
engine = create_engine(DATABASE_URI)
session_factory = sessionmaker(bind=engine)
SessionLocal = scoped_session(session_factory)


# Utility Functions (moved up to be defined before use)
def log_message(level, message):
    """Log messages at various levels."""
    levels = {"info": logging.info, "warn": logging.warning, "error": logging.error}
    log_func = levels.get(level.lower(), logging.debug)
    log_func(message)

def calculate_age(birth_date):
    """Calculate age from birth date."""
    today = datetime.today()
    return today.year - birth_date.year - (
        (today.month, today.day) < (birth_date.month, birth_date.day)
    )

def update_all_customer_ages():
    """Update all customer ages during startup."""
    with app.app_context():
        try:
            customers = db.session.query(Customer).all()
            today = date.today()
            updated_count = 0

            for customer in customers:
                if customer.birth_date:
                    new_age = today.year - customer.birth_date.year - (
                        (today.month, today.day) < (customer.birth_date.month, customer.birth_date.day)
                    )
                    if customer.age != new_age:
                        logging.info(
                            f"Age update at startup - Customer ID {customer.id}: "
                            f"current age = {customer.age}, new age = {new_age}"
                        )
                        customer.age = new_age
                        updated_count += 1

            if updated_count > 0:
                db.session.commit()
                logging.info(f"Updated ages for {updated_count} customers during startup")
            else:
                logging.info("No customer ages needed updating during startup")
        except Exception as e:
            logging.error(f"Error updating customer ages during startup: {str(e)}")
            db.session.rollback()

# Event Listeners (moved up to be defined before use)
@event.listens_for(Customer.age, "set")
def age_change_listener(target, value, oldvalue, initiator):
    """Log changes to customer age."""
    customer_id = getattr(target, "id", "New")
    if value != oldvalue:
        print(f"[INFO] The age of customer ID {customer_id} changed from {oldvalue} to {value}")

# Initial logging messages (now after function definitions)
logging.info("Logging system initialized with DEBUG level")
logging.info("Flask application starting")
logging.info("Database connection established")
logging.info("Authentication system ready")
logging.info("Library management system ready to serve requests")
logging.info("Updating customer ages during startup...")
update_all_customer_ages()

# Example Users
USERS = {
    "librarian": {"password": "LibPass123", "role": "librarian"},
    "customer": {"password": "CustPass456", "role": "customer"},
    "developer": {"password": "DevPass789", "role": "developer"}
}

# Request Lifecycle Handlers
@app.before_request
def before_request():
    """Ensure each request has a dedicated database session."""
    if "db_session" not in g:
        g.db_session = SessionLocal()

@app.teardown_request
def teardown_request(exception):
    """Close the database session after each request."""
    session = g.pop("db_session", None)
    if session:
        session.close()

@app.after_request
def add_no_cache_headers(response):
    """Add headers to prevent caching of sensitive data."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# Ensure auth-utils.js is properly cached
@app.after_request
def add_header(response):
    if request.path.endswith(".js"):
        response.headers["Cache-Control"] = "no-store"
    return response

# Helper function to extract username from token for logging purposes
def get_token_username(token):
    """Extract username or customer info from token for logging purposes without validation."""
    try:
        # Just decode without verification for logging purposes
        payload = jwt.decode(token, options={"verify_signature": False})
        if "username" in payload:
            return payload.get('username', 'unknown')
        elif "email" in payload:
            return payload.get('email', 'unknown')
        elif "customer_id" in payload:
            return f"Customer ID: {payload.get('customer_id', 'unknown')}"
        return "unknown-user"
    except:
        return 'invalid-token-format'

# Token Utility Functions
def get_token():
    """Retrieve JWT token from cookies or Authorization header with improved logging."""
    token = request.cookies.get("access_token")
    
    # If not in cookies, check Authorization header
    if not token:
        auth_header = request.headers.get("Authorization")
        if (auth_header and auth_header.startswith("Bearer ")):
            token = auth_header.split(" ")[1]
            if token == "undefined" or token == "null":
                token = None
    
    # Log token extraction for debugging (careful not to log the actual token)
    if token:
        logging.debug(f"Token found in {'cookies' if request.cookies.get('access_token') else 'Authorization header'}")
    else:
        logging.debug("No token found in cookies or Authorization header")
        
    return token

def decode_token(token):
    """Decode and validate JWT token, returning payload or None if invalid."""
    if not token:
        return None
        
    try:
        # Decode token with 5-second tolerance for clock differences
        return jwt.decode(
            token, 
            app.config["SECRET_KEY"], 
            algorithms=["HS256"],
            options={"leeway": 5}
        )
    except jwt.ExpiredSignatureError:
        endpoint = request.path
        user_info = get_token_username(token)
        expiry_message = f"TOKEN EXPIRED: User '{user_info}' attempted to access '{endpoint}'"
        # Log to both file and terminal
        logging.error(expiry_message)
        print(f"\033[91m[ERROR] {expiry_message}\033[0m")  # Red text in terminal
        return None
    except jwt.InvalidTokenError:
        endpoint = request.path
        invalid_message = f"INVALID TOKEN: Attempted access to '{endpoint}'"
        # Log to both file and terminal
        logging.error(invalid_message)
        print(f"\033[91m[ERROR] {invalid_message}\033[0m")  # Red text in terminal
        return None

# Authentication Decorators
def token_required(f):
    """Ensure a valid token is present for the request."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("access_token")
        endpoint = request.path
        if not token:
            missing_message = f"MISSING TOKEN: Attempted access to '{endpoint}'"
            logging.warning(missing_message)
            print(f"\033[93m[WARNING] {missing_message}\033[0m")  # Yellow text in terminal
            return jsonify({"success": False, "message": "Missing access token in cookies"}), 401
        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            request.user = payload
        except jwt.ExpiredSignatureError:
            user_info = get_token_username(token)
            expiry_message = f"TOKEN EXPIRED: User '{user_info}' attempted to access '{endpoint}'"
            # Log to both file and terminal
            logging.error(expiry_message)
            print(f"\033[91m[ERROR] {expiry_message}\033[0m")  # Red text in terminal
            return jsonify({"success": False, "message": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            invalid_message = f"INVALID TOKEN: Attempted access to '{endpoint}'"
            logging.error(invalid_message)
            print(f"\033[91m[ERROR] {invalid_message}\033[0m")  # Red text in terminal
            return jsonify({"success": False, "message": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

def librarian_token_required(f):
    """Restrict access to librarians only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("access_token")
        endpoint = request.path
        if not token:
            missing_message = f"MISSING LIBRARIAN TOKEN: Attempted access to '{endpoint}'"
            logging.warning(missing_message)
            print(f"\033[93m[WARNING] {missing_message}\033[0m")
            return jsonify({"success": False, "message": "Missing access token in cookies"}), 401
        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            if payload.get("role") != "librarian":
                unauthorized_message = f"UNAUTHORIZED: Non-librarian access to '{endpoint}' - Role: {payload.get('role')}"
                logging.warning(unauthorized_message)
                print(f"\033[93m[WARNING] {unauthorized_message}\033[0m")
                return jsonify({"success": False, "message": "Unauthorized access: Librarians only"}), 403
        except jwt.ExpiredSignatureError:
            user_info = get_token_username(token)
            expiry_message = f"LIBRARIAN TOKEN EXPIRED: User '{user_info}' attempted to access '{endpoint}'"
            logging.error(expiry_message)
            print(f"\033[91m[ERROR] {expiry_message}\033[0m")
            return jsonify({"success": False, "message": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            invalid_message = f"INVALID LIBRARIAN TOKEN: Attempted access to '{endpoint}'"
            logging.error(invalid_message)
            print(f"\033[91m[ERROR] {invalid_message}\033[0m")
            return jsonify({"success": False, "message": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

def customer_token_required(f):
    """Restrict access to customers only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token()
        endpoint = request.path
        if not token:
            missing_message = f"MISSING CUSTOMER TOKEN: Attempted access to '{endpoint}'"
            logging.warning(missing_message)
            print(f"\033[93m[WARNING] {missing_message}\033[0m")
            return jsonify({"success": False, "message": "Missing access token"}), 401
        
        payload = decode_token(token)
        if not payload:
            # Error already logged in decode_token function
            return jsonify({"success": False, "message": "Invalid or expired token"}), 401
            
        if payload.get("role") != "customer":
            unauthorized_message = f"UNAUTHORIZED: Non-customer access to '{endpoint}' - Role: {payload.get('role')}"
            logging.warning(unauthorized_message)
            print(f"\033[93m[WARNING] {unauthorized_message}\033[0m")
            return jsonify({"success": False, "message": "Unauthorized access"}), 403
            
        g.customer = payload
        return f(*args, **kwargs)
    return decorated

def customer_or_librarian_token_required(f):
    """Allow access to customers or librarians."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token()
        endpoint = request.path
        if not token:
            missing_message = f"MISSING TOKEN: Attempted access to '{endpoint}'"
            logging.warning(missing_message)
            print(f"\033[93m[WARNING] {missing_message}\033[0m")
            return jsonify({"success": False, "message": "Missing access token"}), 401
            
        payload = decode_token(token)
        if not payload:
            # Error already logged in decode_token function
            return jsonify({"success": False, "message": "Invalid or expired token"}), 401
            
        if payload.get("role") not in ["customer", "librarian"]:
            unauthorized_message = f"UNAUTHORIZED: Invalid role access to '{endpoint}' - Role: {payload.get('role')}"
            logging.warning(unauthorized_message)
            print(f"\033[93m[WARNING] {unauthorized_message}\033[0m")
            return jsonify({"success": False, "message": "Unauthorized access"}), 403
            
        g.user = payload
        return f(*args, **kwargs)
    return decorated

def developer_token_required(f):
    """Restrict access to developers only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("access_token")
        endpoint = request.path
        if not token:
            missing_message = f"MISSING DEVELOPER TOKEN: Attempted access to '{endpoint}'"
            logging.warning(missing_message)
            print(f"\033[93m[WARNING] {missing_message}\033[0m")
            return jsonify({"success": False, "message": "Missing access token in cookies"}), 401
        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            if payload.get("role") != "developer":
                unauthorized_message = f"UNAUTHORIZED: Non-developer access to '{endpoint}' - Role: {payload.get('role')}"
                logging.warning(unauthorized_message)
                print(f"\033[93m[WARNING] {unauthorized_message}\033[0m")
                return jsonify({"success": False, "message": "Unauthorized access: Developers only"}), 403
        except jwt.ExpiredSignatureError:
            user_info = get_token_username(token)
            expiry_message = f"DEVELOPER TOKEN EXPIRED: User '{user_info}' attempted to access '{endpoint}'"
            logging.error(expiry_message)
            print(f"\033[91m[ERROR] {expiry_message}\033[0m")
            return jsonify({"success": False, "message": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            invalid_message = f"INVALID DEVELOPER TOKEN: Attempted access to '{endpoint}'"
            logging.error(invalid_message)
            print(f"\033[91m[ERROR] {invalid_message}\033[0m")
            return jsonify({"success": False, "message": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

# General Routes
@app.route("/")
def homepage():
    """Serve the main homepage HTML."""
    return send_from_directory(HTML_DIR, "homepage.html")

@app.route("/about")
def about_page():
    """Serve the public 'about.html' page."""
    return send_from_directory(HTML_DIR, "about.html")

# Function to check token role
def check_token_role(allowed_roles=None):
    """Check if token exists and has one of the allowed roles."""
    if allowed_roles is None:
        allowed_roles = []
    
    token = request.cookies.get("access_token")
    if not token:
        return None
        
    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        if payload.get("role") in allowed_roles:
            return payload.get("role")
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        pass
        
    return None

 

def librarian_protected_serve_html(filename):
    """Serve HTML files that require librarian authentication."""
    token = request.cookies.get("access_token")
    directory = HTML_DIR
    
    if not token:
        logging.warning(f"MISSING TOKEN: Attempted access to protected page '{filename}'")
        return jsonify({"success": False, "message": "Authentication required"}), 401
        
    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        if payload.get("role") != "librarian":
            unauthorized_message = f"UNAUTHORIZED: Non-librarian access to '{filename}' - Role: {payload.get('role')}"
            logging.warning(unauthorized_message)
            print(f"\033[93m[WARNING] {unauthorized_message}\033[0m")
            return jsonify({"success": False, "message": "Unauthorized"}), 403
            
        # Librarian authenticated, serve the file
        return send_from_directory(directory, filename)
        
    except jwt.ExpiredSignatureError:
        logging.error(f"TOKEN EXPIRED: Attempted access to protected page '{filename}'")
        return jsonify({"success": False, "message": "Token expired"}), 401
    except jwt.InvalidTokenError:
        logging.error(f"INVALID TOKEN: Attempted access to protected page '{filename}'")
        return jsonify({"success": False, "message": "Invalid token"}), 401

# Modify the existing route
@app.route("/frontend/html/<path:filename>")
def serve_html(filename):
    """Serve HTML files, applying authentication where required."""
    public_pages = {"about.html", "contact_us.html", "homepage.html"}
    developer_pages = {"developers.html"}
    directory = HTML_DIR
    full_path = os.path.join(directory, filename)

    if not os.path.exists(full_path):
        logging.error(f"File not found: {full_path}")
        return jsonify({"success": False, "message": "File not found"}), 404

    if filename in public_pages:
        return send_from_directory(directory, filename)
    
    if filename in developer_pages:
        # Check for dev_mode parameter
        if request.args.get("dev_mode") == "true":
            logging.info(f"Developer access granted via dev_mode to {filename}")
            return send_from_directory(directory, filename)
        
        # Developer token check from cookies
        token = request.cookies.get("access_token")
        if token:
            try:
                payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
                if payload.get("role") == "developer":
                    logging.info(f"Developer access granted via token to {filename}")
                    return send_from_directory(directory, filename)
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                pass
                
        # Check for developer authentication cookie
        dev_token_cookie = request.cookies.get("developer_token")
        if dev_token_cookie:
            logging.info(f"Developer access granted via cookie to {filename}")
            return send_from_directory(directory, filename)
               
        # If code reaches here, not authorized
        logging.warning(f"UNAUTHORIZED: Access to '{filename}' - Role: Unknown or Unauthorized")
        return redirect("/frontend/html/homepage.html")
    
    # Use librarian authentication for all non-public pages
    return librarian_protected_serve_html(filename)

# Serve static files from the frontend directory
@app.route('/frontend/static/<path:path>')
def serve_frontend_static(path):
    """Serve static files from the frontend/static directory."""
    return send_from_directory(os.path.join(app.root_path, '..', 'frontend', 'static'), path)

# Authentication Routes
@app.route("/api/login", methods=["POST"])
def login():
    """Handle librarian login and set JWT token in cookie with consistent logging."""
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    
    logging.info(f"Librarian login attempt with username: {username}")
    
    user = USERS.get(username)

    if not user or user["password"] != password:
        logging.warning(f"Failed librarian login attempt for username: {username}")
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    # Set the librarian token expiration time
    hours = 8
    local_now = datetime.now()
    expiration_time = local_now + timedelta(hours=hours)
    
    token_payload = {
        "username": username,
        "role": user["role"],
        "exp": int(expiration_time.timestamp())
    }
    token = jwt.encode(token_payload, app.config["SECRET_KEY"], algorithm="HS256")
    
    # Standardized login success log with expiration time
    logging.info(f"User login successful: {username} (role: {user['role']}) (expires: {expiration_time.strftime('%Y-%m-%d %H:%M:%S')} local server time)")
    
    # Create response with token as cookie
    response = make_response(jsonify({
        "success": True, 
        "message": "Login successful",
        "role": user["role"],
        "tokenDuration": f"{hours} hours"
    }))
    
    response.set_cookie(
        "access_token",
        token,
        httponly=True,
        max_age=int(hours * 3600),
        path="/",
        samesite="Lax"
    )
    
    return response

@app.route("/api/customer_login", methods=["POST"])
def customer_login():
    """Customer login route with consistent logging of token expiration"""
    try:
        logging.info("Customer login attempt")
        data = request.get_json()
        email = data.get("email", "").lower()
        password = data.get("password", "")
        
        logging.info(f"Login attempt with email: {email}")
        
        if not email or not password:
            logging.warning(f"Missing email or password for customer login")
            return jsonify({"success": False, "message": "Missing email or password"}), 400
            
        # Check customer credentials against database
        customer = Customer.query.filter_by(email=email).first()
        
        if not customer:
            logging.warning(f"Customer not found with email: {email}")
            return jsonify({"success": False, "message": "Invalid credentials"}), 401
            
        # Simple password check (replace with better authentication in production)
        if password != "CustPass456":
            logging.warning(f"Invalid password attempt for customer: {email}")
            return jsonify({"success": False, "message": "Invalid credentials"}), 401
            
        # Set token duration
        hours = 2  # Customer tokens: 2 hours
        
        # Generate token with local server time expiration
        local_now = datetime.now()
        expiration_time = local_now + timedelta(hours=hours)
        
        token_data = {
            "id": customer.id,
            "email": customer.email,
            "role": "customer",
            "exp": int(expiration_time.timestamp()),
        }
        
        token = jwt.encode(token_data, app.config["SECRET_KEY"], algorithm="HS256")
        
        # Standardized login success log with expiration time
        logging.info(f"User login successful: {customer.email} (ID: {customer.id}, role: customer) (expires: {expiration_time.strftime('%Y-%m-%d %H:%M:%S')} local server time)")
        
        # Create response with token as cookie
        response = make_response(jsonify({
            "success": True, 
            "customer_id": customer.id,
            "tokenDuration": f"{hours} hours"
        }))
        
        response.set_cookie(
            "access_token",
            token,
            httponly=True,
            max_age=int(hours * 3600),
            path="/",
            samesite="Lax"
        )
        
        return response
        
    except Exception as e:
        logging.error(f"Error during customer login: {str(e)}")
        return jsonify({"success": False, "message": "Server error during login"}), 500

@app.route('/api/developer_login', methods=['POST'])
def developer_login():
    """Handle developer login requests with consistent logging"""
    try:
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')
        
        logging.info(f"Developer login attempt with username: {username}")
        
        # Verify developer credentials
        valid_user = verify_developer_credentials(username, password)
        
        if valid_user:
            # Create a JWT token with developer role
            hours = 8.5  # Developer tokens: 8.5 hours
            
            # Use local server time
            local_now = datetime.now()
            expiration_time = local_now + timedelta(hours=hours)
            
            token_payload = {
                'username': username,
                'role': 'developer',
                'exp': int(expiration_time.timestamp())
            }
            token = jwt.encode(token_payload, app.config["SECRET_KEY"], algorithm="HS256")
            
            # Standardized login success log with expiration time
            logging.info(f"User login successful: {username} (role: developer) (expires: {expiration_time.strftime('%Y-%m-%d %H:%M:%S')} local server time)")
            
            # Create response with success message and token
            response = jsonify({
                'success': True, 
                'message': 'Developer login successful',
                'token': token,
                'tokenDuration': f'{hours} hours',
                'expiresAt': expiration_time.strftime("%Y-%m-%d %H:%M:%S")
            })
            
            # Set secure HTTP-only cookie with the token
            response.set_cookie(
                'access_token', 
                token, 
                httponly=True, 
                secure=app.config.get('COOKIE_SECURE', False),
                max_age=int(hours * 3600)
            )
            
            # Also set a dev_mode_session cookie for additional verification
            response.set_cookie(
                'dev_mode_session',
                'true',
                max_age=int(hours * 3600),
                path="/"
            )
            
            return response
        else:
            logging.warning(f"Failed developer login attempt for username: {username}")
            return jsonify({'success': False, 'message': 'Invalid developer credentials'}), 401
            
    except Exception as e:
        logging.error(f"Error during developer login: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/logout", methods=["POST"])
def logout():
    """Handle logout by clearing authentication cookies."""
    try:
        # Get request data to check if we should preserve developer access
        data = request.get_json() or {}
        preserve_developer = data.get("preserveDeveloperAccess", False)
        
        # Get user info for logging
        token = request.cookies.get("access_token")
        user_info = "Unknown"
        if token:
            try:
                payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"], options={"verify_signature": False})
                if payload.get("role") == "customer" and payload.get("id"):
                    user_info = f"Customer:{payload.get('id')}"
                elif payload.get("username"):
                    user_info = f"{payload.get('role')}:{payload.get('username')}"
            except:
                pass
        
        logging.info(f"User {user_info} logged out (preserve_developer={preserve_developer})")
        
        # Create response that clears ALL authentication cookies
        response = make_response(jsonify({"success": True, "message": "Logged out successfully"}))
        
        # Determine which cookies to clear based on preserve_developer flag
        cookies_to_clear = ["access_token", "customer_token"]
        
        # Only clear developer cookies if not preserving developer access
        if not preserve_developer:
            cookies_to_clear.extend(["developer_token", "developer_access", "dev_mode_session"])
        
        for cookie_name in cookies_to_clear:
            response.delete_cookie(cookie_name, path="/")
            # Also try with different paths to ensure complete cleanup
            response.delete_cookie(cookie_name, path="/frontend/")
            response.delete_cookie(cookie_name, path="/frontend/html/")
            response.delete_cookie(cookie_name, path="/frontend/user_pages/")
            response.delete_cookie(cookie_name, path="/api/")
            
            # Explicitly set to empty with expired time
            response.set_cookie(cookie_name, "", expires=0, path="/")
        
        return response
    except Exception as e:
        logging.error(f"Error during logout: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/refresh_session', methods=['POST'])
def refresh_session():
    """Refresh the user's session without requiring full re-authentication."""
    token = request.cookies.get("access_token")
    if not token:
        return jsonify({"success": False, "message": "No token provided"}), 401
        
    try:
        # Verify the token but don't check expiration
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"], 
                           options={"verify_exp": False})
        
        # Get token details
        user_id = payload.get("id")
        role = payload.get("role")
        email = payload.get("email")
        username = payload.get("username")
        
        # Set token duration based on role
        if role == "customer":
            hours = 2  # Customer tokens: 2 hours
        elif role == "librarian":
            hours = 8  # Librarian tokens: 8 hours
        elif role == "developer":
            hours = 8.5  # Developer tokens: 8.5 hours
        else:
            hours = 2  # Default to 2 hours for unknown roles
        
        # Calculate token expiration time based on user role
        expiration_time = datetime.now(timezone.utc) + timedelta(hours=hours)
        token_data = {
            "id": user_id,
            "email": email,
            "username": username,
            "role": role,
            "exp": int(expiration_time.timestamp()),
        }
        
        token = jwt.encode(token_data, app.config["SECRET_KEY"], algorithm="HS256")
        
        # Create response with refreshed token
        response = make_response(jsonify({
            "success": True,
            "tokenDuration": f"{hours} hours"  # Include duration in response
        }))
        response.set_cookie(
            "access_token",
            token,
            httponly=True,
            max_age=int(hours * 3600),  # Convert hours to seconds
            path="/",
            samesite="Lax"
        )
        
        return response
        
    except Exception as e:
        logging.error(f"Error during session refresh: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

# Customer Routes
@app.route("/api/customer_data")
def get_customer_data():
    """Get customer data based on authentication token with human-readable expiration time"""
    try:
        logging.info(f"Customer data request received from {request.remote_addr}")
        
        # Log content type at debug level only
        logging.debug(f"Request content type: {request.headers.get('Content-Type')}")
        
        # Get token and verify it
        token = get_token()
        logging.debug(f"Token found in cookies")
        
        if not token:
            logging.warning("No token provided for customer data request")
            return jsonify({"success": False, "message": "No token provided"}), 401
            
        try:
            # Decode and verify the token
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            logging.debug(f"Token decoded successfully: {payload}")
            
            # Convert expiration timestamp to human-readable format
            exp_timestamp = payload.get("exp")
            expiration_time = datetime.fromtimestamp(exp_timestamp)
            human_readable_expiration = expiration_time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Get customer data based on token
            if payload.get("role") == "customer" and payload.get("id"):
                customer_id = payload.get("id")
                customer = db.session.get(Customer, customer_id)
                
                if not customer:
                    logging.warning(f"Customer not found with ID: {customer_id}")
                    return jsonify({"success": False, "message": "Customer not found"}), 404
                    
                logging.info(f"Returning data for customer {customer_id} ({customer.name}) (expires: {human_readable_expiration} local server time)")
                
                # Return customer data with human-readable expiration time
                return jsonify({
                    "customer": {
                        "id": customer.id,
                        "name": customer.name,
                        "email": customer.email,
                        "city": customer.city,
                        "age": customer.age,
                        "birth_date": customer.birth_date.isoformat() if customer.birth_date else None
                    },
                    "session": {
                        "role": "customer",
                        "expires": f"{human_readable_expiration} local server time"
                    }
                })
            else:
                logging.warning(f"Invalid token role for customer data: {payload.get('role')}")
                return jsonify({"success": False, "message": "Invalid token role"}), 403
                
        except jwt.ExpiredSignatureError:
            logging.warning("Token expired in customer data request")
            return jsonify({"success": False, "message": "Token expired"}), 401
            
        except jwt.InvalidTokenError as e:
            logging.warning(f"Invalid token in customer data request: {str(e)}")
            return jsonify({"success": False, "message": "Invalid token"}), 401
            
    except Exception as e:
        logging.error(f"Error in get_customer_data: {str(e)}")
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500

@app.route("/frontend/user_pages/<path:filename>")
def serve_user_pages(filename):
    """Serve user pages based on file type and authentication requirements."""
    # Log the request in more detail
    logging.info(f"User page request: {filename} - Cookies: {list(request.cookies.keys())}")
    
    # Check for developer access cookie - allows bypassing for development
    developer_access = request.cookies.get("developer_access") == "true"
    
    # Check for authentication token in cookie or query parameter
    has_token = False
    token = request.cookies.get("access_token") or request.args.get("token")
    
    if token:
        logging.info(f"Token found for user page request: {filename}")
        try:
            # Decode token using HS256 algorithm
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            
            # After successful decode, check if token is for a customer
            if payload.get("role") == "customer":
                has_token = True
                logging.info(f"Valid customer token for: {filename}")
            else:
                logging.warning(f"Token has wrong role ({payload.get('role')}) for: {filename}")
        except Exception as e:
            # Log the error with token data (without the signature)
            try:
                # Extract token contents for logging without signature check
                raw_payload = jwt.decode(token, options={"verify_signature": False})
                logging.error(f"Token validation error for {filename}: {str(e)}")
                logging.error(f"Token raw data: {raw_payload}")
            except:
                logging.error(f"Token validation error for {filename}: {str(e)}")
    else:
        logging.info(f"No token found for user page request: {filename}")
    
    # For development only - log when developer access is used
    if developer_access and not has_token:
        logging.info(f"Developer access used to bypass authentication for: {filename}")
        has_token = True  # Allow access with developer cookie
    
    # Enforce authentication unless developer access is enabled
    if not has_token and not developer_access:
        logging.warning(f"UNAUTHORIZED ACCESS ATTEMPT: IP {request.remote_addr} tried to access {filename}")
        return redirect('/frontend/html/homepage.html')
        
    # Proceed with serving the file
    file_path = os.path.join(app.root_path, "..", "frontend", "user_pages", filename)
    if not os.path.isfile(file_path):
        logging.error(f"File not found: {file_path}")
        return jsonify({"success": False, "message": "File not found"}), 404
    
    return send_file(file_path)

# Book Routes
def fetch_all(query):
    """Safely fetch all results from a SQLAlchemy query with error logging."""
    try:
        return query.all()
    except Exception as e:
        logging.error(f"Error during database fetch: {e}")
        return None

def get_session():
    """Context manager for database session handling."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

@app.route("/api/books/<int:book_id>", methods=["GET"])
def get_book(book_id):
    """Fetch a specific book and its loan history by ID."""
    try:
        with get_session() as session:
            book = session.get(Book, book_id)
            if not book:
                return jsonify({"success": False, "message": "Book not found"}), 404

            loans = session.query(Loan).filter_by(book_id=book_id).all()
            loan_data = [
                {
                    "loan_date": loan.loan_date.strftime("%Y-%m-%d"),
                    "return_date": (
                        loan.return_date.strftime("%Y-%m-%d") if loan.return_date else None
                    ),
                    "customer_name": (
                        session.get(Customer, loan.cust_id).name if session.get(Customer, loan.cust_id)
                        else "Unknown Customer"
                    ),
                    "book_title": book.title,
                    "book_author": book.author
                }
                for loan in loans
            ]
            return jsonify({
                "success": True,
                "book": {
                    "id": book.id,
                    "title": book.title,
                    "author": book.author,
                    "year_published": book.year_published,
                    "loan_period": book.loan_period,
                    "loans": loan_data
                }
            })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/books", methods=["GET"])
def get_books():
    """Fetch books with optional filters: title, author, year, loan_period, id."""
    try:
        query = g.db_session.query(Book)
        title = request.args.get("title", "")
        author = request.args.get("author", "")
        year = request.args.get("year", "")
        loan_period = request.args.get("loan_period", "")
        book_id = request.args.get("id", "")

        # Get user info for logging
        user_role = "anonymous"
        user_id = "unknown"
        token = request.cookies.get("access_token")
        
        if token:
            try:
                payload = jwt.decode(token, options={"verify_signature": False})
                user_role = payload.get("role", "unknown")
                user_id = payload.get("id") or payload.get("username", "unknown")
            except:
                pass

        # Build search criteria log
        search_criteria = {}
        if title:
            query = query.filter(Book.title.ilike(f"%{title}%"))
            search_criteria["title"] = title
        if author:
            query = query.filter(Book.author.ilike(f"%{author}%"))
            search_criteria["author"] = author
        if year:
            query = query.filter(Book.year_published.like(f"%{year}%"))
            search_criteria["year"] = year
        if loan_period:
            query = query.filter(Book.loan_period == loan_period)
            search_criteria["loan_period"] = loan_period
        if book_id:
            try:
                query = query.filter(Book.id == int(book_id))
                search_criteria["id"] = book_id
            except ValueError:
                return jsonify({"error": "ID must be an integer"}), 400

        books = query.all()
        
        # Format search criteria for log
        criteria_text = ", ".join([f"{k}:{v}" for k, v in search_criteria.items()]) if search_criteria else "None"
        
        # Log the search with criteria and result count
        logging.info(f"BOOKS SEARCH: User[{user_role}] searched books - CRITERIA: {criteria_text} - RESULTS: {len(books)}/{Book.query.count()} records")
        
        return jsonify([
            {
                "id": book.id,
                "title": book.title,
                "author": book.author,
                "year_published": book.year_published,
                "loan_period": book.loan_period,
                "is_active": book.is_active,
                "is_loaned": book.is_loaned
            }
            for book in books
        ]), 200
    except Exception as e:
        logging.error(f"Error fetching books: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Modify your existing add_book endpoint
@app.route("/api/add_book", methods=["POST"])
def add_book():
    """Add a new book to the library."""
    try:
        data = request.get_json()
        title = data.get("title")
        author = data.get("author")
        year_published = data.get("year_published")
        book_type = data.get("type")
        
        # Convert book_type to integer
        if book_type:
            try:
                book_type = int(book_type)
            except (TypeError, ValueError):
                logging.warning(f"Invalid book type: {book_type}")
                return jsonify({"success": False, "message": "Invalid book type"}), 400
        
        # Map book types to their standard loan periods in days
        loan_period = None
        if book_type == 1:
            loan_period = 10
        elif book_type == 2:
            loan_period = 5
        elif book_type == 3:
            loan_period = 2
        
        # Define loan duration based on book type
        loan_period = None
        if book_type == 1:
            loan_period = 10
        elif book_type == 2:
            loan_period = 5
        elif book_type == 3:
            loan_period = 2
            
        # Log the determined values
        logging.info(f"Book type: {book_type}, calculated loan period: {loan_period}")
        
        # Validate input
        if not all([title, author, year_published, book_type]):
            return jsonify({"success": False, "message": "Missing required fields"}), 400
            
        # Create new book
        new_book = Book(
            title=title,
            author=author,
            year_published=year_published,
            type=book_type,
            loan_period=loan_period  # Set this explicitly
        )
        
        # Add to database and force flush to ensure loan_period is saved
        db.session.add(new_book)
        db.session.flush()  # This forces the INSERT without committing
        
        # Verify loan_period was set correctly
        logging.info(f"Book saved with loan period: {new_book.loan_period}")
        
        # Now commit the transaction
        db.session.commit()
        
        return jsonify({
            "success": True, 
            "message": "Book added successfully", 
            "book_id": new_book.id,
            "loan_period": new_book.loan_period  # Return the actual loan period
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"ERROR ADDING BOOK: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/books/<int:book_id>", methods=["PATCH"])
def update_book(book_id):
    """Update a book's is_active status."""
    session = g.db_session
    book = session.query(Book).filter(Book.id == book_id).first()
    if not book:
        logging.error(f"Book update failed: Book ID {book_id} not found")
        return jsonify({"error": "Book not found"}), 404

    data = request.get_json()
    if data is None or "is_active" not in data:
        logging.error(f"Book update failed: Invalid request for Book ID {book_id} - missing is_active field")
        return jsonify({"error": "Invalid request"}), 400

    # Get the old and new status for logging
    old_status = "active" if book.is_active else "inactive"
    new_status = "active" if data["is_active"] else "inactive"
    
    # Update the book status
    book.is_active = data["is_active"]
    session.commit()
    
    # Log the status change with detailed information
    action = "Activation" if data["is_active"] else "Deactivation"
    log_message = f"Book Status Change: {action} of Book ID {book_id} ({book.title}) - Changed from {old_status} to {new_status}"
    
    # Use different log levels based on the action
    if data["is_active"]:
        # For activation, use DEBUG level (typically displayed in blue/green in colored logs)
        logging.debug(log_message)
    else:
        # For deactivation, use ERROR level (typically displayed in red in colored logs)
        logging.error(log_message)
    
    return jsonify({"message": "Book status updated successfully", "is_active": book.is_active}), 200

# Loan Routes
@app.route("/api/loan_book", methods=["POST"])
def loan_book():
    """Create a new loan for a book."""
    session = None
    try:
        data = request.get_json()
        book_id = data.get("book_id")
        cust_id = int(data.get("cust_id"))

        session = session_factory()
        book = session.get(Book, book_id)
        customer = session.get(Customer, cust_id)

        if not book or not customer:
            return jsonify({"success": False, "message": "Book or customer not found"}), 404

        logging.info(f"Loan request: book_id={book_id} ({book.title}), cust_id={cust_id} ({customer.name})")
        if book.is_loaned:
            return jsonify({"success": False, "message": "Book is already loaned"}), 400

        loan = Loan(book_id=book_id, cust_id=cust_id)
        loan.customer_name = customer.name
        loan.book_name = book.title
        if book.loan_period:
            loan.return_date = datetime.now(timezone.utc) + timedelta(days=book.loan_period)

        session.add(loan)
        book.is_loaned = True
        session.commit()
        return jsonify({
            "success": True,
            "message": "Loan created successfully",
            "return_date": (
                loan.return_date.strftime("%Y-%m-%d") if book.loan_period else None
            )
        })
    except Exception as e:
        logging.error(f"Error while processing loan: {str(e)}")
        return jsonify({"message": str(e), "success": False}), 500
    finally:
        if session:
            session.close()

@app.route("/api/late_loans", methods=["GET"])
def late_loans():
    """Fetch overdue loans with optional filters."""
    today = datetime.now().date()
    query = Loan.query.filter(Loan.return_date < today)

    # Log search parameters
    search_params = {k: v for k, v in request.args.items() if v}
    if search_params:
        logging.info(f"LATE LOANS SEARCH: Parameters: {search_params}")
    
    # Customer name filter
    customer_name = request.args.get("customer_name")
    if customer_name:
        query = query.filter(Loan.customer.has(Customer.name.ilike(f"%{customer_name}%")))
    
    # Book name filter
    book_name = request.args.get("book_name")
    if book_name:
        query = query.filter(Loan.book.has(Book.title.ilike(f"%{book_name}%")))
    
    # Author name filter
    author_name = request.args.get("author_name")
    if author_name:
        query = query.filter(Loan.book.has(Book.author.ilike(f"%{author_name}%")))
    
    # Loan date filter with flexible format
    loan_date_str = request.args.get("loan_date")
    if loan_date_str:
        loan_date = parse_flexible_date(loan_date_str)
        if loan_date:
            query = query.filter(Loan.loan_date == loan_date)
        else:
            # Only return error if it's not a partial date search (single digit)
            if len(loan_date_str) > 2 and "." not in loan_date_str:
                return jsonify({"error": f"Invalid loan_date format. Use DD.MM.YYYY"}), 400
    
    # Return date filter with flexible format
    return_date_str = request.args.get("return_date")
    if return_date_str:
        return_date = parse_flexible_date(return_date_str)
        if return_date:
            query = query.filter(Loan.return_date == return_date)
        else:
            # Only return error if it's not a partial date search (single digit)
            if len(return_date_str) > 2 and "." not in return_date_str:
                return jsonify({"error": f"Invalid return_date format. Use DD.MM.YYYY"}), 400
    
    # Book ID filter with logging
    book_id = request.args.get("book_id")
    if book_id:
        try:
            query = query.filter(Loan.book_id == int(book_id))
            logging.info(f"BOOK ID SEARCH: Filtering for Book ID: {book_id}")
        except ValueError:
            return jsonify({"error": "Invalid book_id value"}), 400
    
    # Get results and log findings
    late_loans_data = query.all()
    logging.info(f"LATE LOANS SEARCH RESULT: Found {len(late_loans_data)} late loans")
    
    return jsonify([
        {
            "id": loan.id,
            "customer_name": loan.customer.name,
            "book_name": loan.book.title,
            "book_author": loan.book.author,
            "loan_date": loan.loan_date.strftime("%Y-%m-%d"),
            "return_date": (
                loan.return_date.strftime("%Y-%m-%d") if loan.return_date else None
            ),
            "book_id": loan.book.id
        }
        for loan in late_loans_data
    ]), 200

@app.route("/api/returnBook/<int:loan_id>", methods=["POST"])
def return_book(loan_id):
    """Return a book by deleting its loan record with detailed logging."""
    try:
        loan = db.session.query(Loan).filter(Loan.id == loan_id).first()
        if not loan:
            logging.error(f"BOOK RETURN FAILED: Loan record {loan_id} not found")
            return jsonify({"message": "Loan record not found", "success": False}), 404

        # Get book and customer details for logging
        book_id = loan.book_id
        cust_id = loan.cust_id
        
        book = db.session.get(Book, book_id) if book_id else None
        customer = db.session.get(Customer, cust_id) if cust_id else None
        
        book_title = book.title if book else "Unknown book"
        book_author = book.author if book else ""
        customer_name = customer.name if customer else "Unknown customer"
        
        # Calculate days on loan
        loan_date = loan.loan_date
        return_date = loan.return_date
        today = datetime.now(timezone.utc)
        
        # Extract date component for calculation
        if loan_date:
            # Get just the date part for consistent comparison
            loan_date_for_calc = loan_date.date() if hasattr(loan_date, 'date') else loan_date
            today_date = today.date()
            days_on_loan = (today_date - loan_date_for_calc).days
        else:
            days_on_loan = 0
        
        # Check if return is late
        is_late = False
        days_overdue = 0
        if return_date:
            # Standardize return_date to datetime format with timezone
            if isinstance(return_date, date) and not isinstance(return_date, datetime):
                # Convert plain date to datetime at midnight
                return_datetime = datetime.combine(return_date, datetime.min.time(), tzinfo=timezone.utc)
            else:
                # Use existing datetime and ensure timezone is set
                return_datetime = return_date
                if return_datetime.tzinfo is None:
                    return_datetime = return_datetime.replace(tzinfo=timezone.utc)
            
            is_late = today > return_datetime
            if is_late:
                # Use date objects for calculating days
                return_date_for_calc = return_datetime.date()
                today_date = today.date()
                days_overdue = (today_date - return_date_for_calc).days
        
        # Update book status before deleting loan
        if book:
            book.is_loaned = False
        
        # Get user info for logging
        user_role = "anonymous"
        user_id = "unknown"
        token = request.cookies.get("access_token")
        
        if token:
            try:
                payload = jwt.decode(token, options={"verify_signature": False})
                user_role = payload.get("role", "unknown")
                user_id = payload.get("id") or payload.get("username", "unknown")
            except:
                pass
        
        # Delete the loan
        db.session.delete(loan)
        db.session.commit()
        
        # Log the return with all details
        if is_late:
            log_message = (
                f"BOOK RETURNED LATE: User[{user_role}] processed return - "
                f"Book ID {book_id} '{book_title}' by {book_author} - "
                f"Customer: {customer_name} (ID:{cust_id}) - "
                f"Days on loan: {days_on_loan} - Days overdue: {days_overdue}"
            )
            logging.warning(log_message)
        else:
            log_message = (
                f"BOOK RETURNED: User[{user_role}] processed return - "
                f"Book ID {book_id} '{book_title}' by {book_author} - "
                f"Customer: {customer_name} (ID:{cust_id}) - "
                f"Days on loan: {days_on_loan}"
            )
            logging.info(log_message)
        
        return jsonify({
            "message": "Book returned successfully",
            "success": True,
            "is_late": is_late,
            "days_on_loan": days_on_loan,
            "days_overdue": days_overdue if is_late else 0
        })
    except Exception as e:
        logging.error(f"Error while returning book: {str(e)}")
        db.session.rollback()
        return jsonify({"message": str(e), "success": False}), 500

# Logging Route
@app.route("/api/log_disable_attempt", methods=["POST"])
def log_disable_attempt():
    """Log attempt to disable a customer who has active loans."""
    data = request.get_json()
    customer_id = data.get("customer_id")
    customer_name = data.get("customer_name", "Unknown")
    book_title = data.get("book_title", "Unknown")
    
    # Log in red using ERROR level (appears red in coloredlogs)
    error_message = f"DISABLE ATTEMPT REJECTED: Customer ID {customer_id} ({customer_name}) has active loans - borrowing: {book_title}"
    logging.error(error_message)
    
    return jsonify({"success": True, "message": "Disable attempt logged"}), 200

# Customer Management Routes
@app.route("/api/add_customer", methods=["POST"])
def add_customer():
    """Add a new customer to the library."""
    try:
        data = request.json
        name = data.get("name")
        city = data.get("city")
        birth_date_str = data.get("birth_date")
        email = data.get("email")
        
        # Validate input
        if not all([name, city, birth_date_str]):
            logging.warning(f"CUSTOMER VALIDATION ERROR: Missing required fields")
            return jsonify({"success": False, "message": "Missing required fields"}), 400
        
        # Convert birth date string to date object
        try:
            birth_date = datetime.strptime(birth_date_str, "%Y-%m-%d").date()
        except ValueError:
            error_msg = f"Invalid date format: {birth_date_str}"
            logging.error(f"CUSTOMER VALIDATION ERROR: {error_msg}")
            return jsonify({"success": False, "message": error_msg}), 400
        
        # Calculate age
        today = datetime.now().date()
        age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
        
        # Check if age is less than 3
        if age < 3:
            error_msg = "Customer must be at least 3 years old"
            logging.warning(f"CUSTOMER VALIDATION ERROR: {error_msg}")
            return jsonify({"success": False, "message": error_msg}), 400
        
        # Create new customer with age field explicitly set
        new_customer = Customer(
            name=name,
            city=city,
            birth_date=birth_date,
            email=email,
            age=age  # Explicitly set the age field
        )
        
        # Get user role if available
        user_role = "anonymous"
        token = request.cookies.get("access_token")
        if token:
            try:
                payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
                user_role = payload.get("role", "unknown")
            except:
                pass
        
        # Add to database
        db.session.add(new_customer)
        db.session.commit()
        
        logging.info(f"CUSTOMER ADDED: User[{user_role}] added customer '{name}' (ID: {new_customer.id}), Age: {age}, from {city}, Email: {email}")
        
        return jsonify({
            "success": True, 
            "message": "Customer added successfully", 
            "customer_id": new_customer.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        error_msg = str(e)
        logging.error(f"ERROR ADDING CUSTOMER: {error_msg}")
        return jsonify({"success": False, "message": error_msg}), 500

@app.route("/api/customers", methods=["GET"])
def get_customers():
    """Fetch customers with optional filters: id, name, city, age."""
    # Build dictionary of search parameters for logging
    search_params = {key: value for key, value in request.args.items() if value}
    
    # Get user info for logging
    user_role = "anonymous"
    user_id = "unknown"
    token = request.cookies.get("access_token")
    
    if token:
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            user_role = payload.get("role", "unknown")
            user_id = payload.get("id") or payload.get("username", "unknown")
        except:
            pass
    
    # Format search criteria for log
    criteria_text = ", ".join([f"{k}:{v}" for k, v in search_params.items()]) if search_params else "None"
    
    query = g.db_session.query(Customer)
    filters = {
        "id": lambda q, v: q.filter(Customer.id == int(v)),
        "name": lambda q, v: q.filter(Customer.name.ilike(f"%{v}%")),
        "city": lambda q, v: q.filter(Customer.city.ilike(f"%{v}%")),
        "age": lambda q, v: q.filter(Customer.age == int(v)),
        "is_active": lambda q, v: q.filter(Customer.is_active == (v.lower() == 'true'))
    }

    for param, apply_filter in filters.items():
        value = request.args.get(param)
        if value:
            try:
                query = apply_filter(query, value)
            except ValueError:
                logging.error(f"Invalid {param} value: {value}")
                return jsonify({"error": f"Invalid {param} value"}), 400

    customers = query.all()
    
    # Log with detailed search information
    logging.info(f"CUSTOMERS SEARCH: User[{user_role}] searched customers - CRITERIA: {criteria_text} - RESULTS: {len(customers)}/{Customer.query.count()} records")
    
    return jsonify([
        {
            "id": cust.id,
            "name": cust.name,
            "city": cust.city,
            "age": cust.age,
            "birth_date": cust.birth_date.isoformat() if cust.birth_date else None,
            "is_active": cust.is_active,
            "email": cust.email
        }
        for cust in customers
    ])

@app.route("/api/customers/<int:id>", methods=["GET"])
def get_customer_by_id(id):
    """Fetch a customer by ID."""
    customer = g.db_session.query(Customer).filter(Customer.id == id).first()
    if not customer:
        return jsonify({"error": "Customer not found"}), 404
    return jsonify({
        "id": customer.id,
        "name": customer.name,
        "city": customer.city,
        "age": customer.age,
        "is_active": customer.is_active
    })

@app.route("/api/customers/<int:id>", methods=["PATCH"])
def update_customer(id):
    """Update a customer's is_active status with loan validation."""
    session = g.db_session
    data = request.get_json()
    is_active = data.get("is_active")

    try:
        # Lock the customer record for update
        customer = session.query(Customer).filter(Customer.id == id).with_for_update().first()
        if not customer:
            return jsonify({"message": "Customer not found", "success": False}), 404

        # Check for active loans only when trying to disable
        if is_active is False:
            active_loans = session.query(Loan).filter(
                Loan.cust_id == id,
                Loan.return_date >= datetime.now()
            ).with_for_update().all()
            
            if active_loans:
                loaned_books = ", ".join(
                    loan.book.title if loan.book and loan.book.title else "Unknown Book"
                    for loan in active_loans
                )
                error_message = f"Cannot disable customer: Active loan(s) exist. Loaned book(s): {loaned_books}"
                log_message("warn", f"Cannot disable customer {id}: {error_message}")
                session.rollback()
                return jsonify({"message": error_message, "success": False}), 400

        # Update customer status
        customer.is_active = is_active
        session.flush()  # Flush changes to DB
        session.commit()  # Commit immediately
        
        # Convert boolean to standardized text and log with appropriate level for color
        status_text = "Active" if is_active else "Inactive"
        
        if is_active:
            # For activation, use DEBUG level (should appear green in coloredlogs)
            logging.debug(f"Customer {id} status updated successfully to {status_text}")
        else:
            # For deactivation, use ERROR level (appears red in coloredlogs)
            logging.error(f"Customer {id} status updated successfully to {status_text}")
        return jsonify({
            "message": "Customer status updated successfully",
            "success": True,
            "is_active": is_active
        }), 200
        
    except Exception as e:
        session.rollback()
        log_message("error", f"Error updating customer {id} status: {str(e)}")
        return jsonify({"message": str(e), "success": False}), 500
    
@app.route("/api/update_email/<int:customer_id>", methods=["PUT"])
def update_email(customer_id):
    """Update a customer's email address."""
    try:
        new_email = request.json.get("email")
        if not new_email:
            return jsonify({"success": False, "message": "Email is required"}), 400

        from flask import current_app
        customer = db.session.get(Customer, customer_id)

        if not customer:
            return jsonify({"success": False, "message": "Customer not found"}), 404

        customer.email = new_email
        db.session.commit()
        return jsonify({
            "success": True,
            "message": f"Email updated for customer {customer_id}"
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/update_customer_age/<int:customer_id>", methods=["POST"])
def update_customer_age(customer_id):
    """Recalculate and update a customer's age."""
    customer = g.db_session.get(Customer, customer_id)
    if not customer:
        return jsonify({"success": False, "message": "Customer not found"}), 404

    if customer.birth_date:
        today = date.today()
        new_age = today.year - customer.birth_date.year - (
            (today.month, today.day) < (customer.birth_date.month, customer.birth_date.day)
        )
        if customer.age != new_age:
            logging.info(
                f"Age difference detected for customer ID {customer_id}: "
                f"current age = {customer.age}, new age = {new_age}"
            )
            customer.age = new_age
            g.db_session.commit()
    return jsonify({"success": True, "message": "Customer age updated successfully"}), 200

# Developer Routes
@app.route("/developers")
def developers():
    """Serve developer-only page with redirects for unauthorized users."""
    token = request.cookies.get("access_token")
    if not token:
        return redirect("/")
        
    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        if payload.get("role") != "developer":
            # Instead of 403, redirect to homepage
            unauthorized_message = f"UNAUTHORIZED: Non-developer access to '/developers' - Role: {payload.get('role')}"
            logging.warning(unauthorized_message)
            print(f"\033[93m[WARNING] {unauthorized_message}\033[0m")
            return redirect("/")
    except jwt.ExpiredSignatureError:
        return redirect("/")
    except jwt.InvalidTokenError:
        return redirect("/")
        
    # User is authenticated as developer, serve the page
    return send_from_directory(os.path.join(PROJECT_DIR, "frontend", "html"), "developers.html")

@app.route('/developers.html')
def developers_redirect():
    """Redirect requests for /developers.html to the correct path"""
    return redirect('/frontend/html/developers.html')

@app.route("/create_test_data", methods=["POST"])
def create_test_data_legacy():
    """Run a script to create test data in the database."""
    try:
        # Use the correct relative path to the script
        script_path = os.path.join(os.path.dirname(__file__), 'test_reset_db.py')
        result = subprocess.run(
            ["python", script_path],
            capture_output=True,
            text=True,
            encoding="utf-8"
        )
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)

        if result.returncode == 0:
            return jsonify({"message": "Test data created successfully!"}), 200
        return jsonify({"message": f"Error creating test data: {result.stderr}"}), 500
    except Exception as e:
        print("Exception:", str(e))
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route("/api/reset_database", methods=["POST"])
def reset_database():
    """Reset the database using test_reset_db.py script"""
    try:
        # Check if request comes from developers page
        referrer = request.headers.get('Referer', '')
        is_from_dev_page = '/developers.html' in referrer
        
        if not is_from_dev_page:
            logging.warning(f"UNAUTHORIZED: Reset database attempt from non-developers page: {referrer}")
            return jsonify({
                "success": False,
                "message": "This operation must be initiated from the developers page"
            }), 403
            
        # Check for developer access token in cookie first
        token = request.cookies.get("access_token")
        dev_mode_session = request.cookies.get("dev_mode_session") == "true"
        
        is_authorized = False
        
        # Verify token has developer role
        if token:
            try:
                payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
                if payload.get("role") == "developer":
                    is_authorized = True
                    logging.info(f"Database reset authorized for developer: {payload.get('username', 'unknown')}")
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                pass
                
        # If no valid token, check for dev_mode_session
        if not is_authorized and dev_mode_session:
            is_authorized = True
            logging.info("Database reset authorized via dev_mode_session")
            
        if not is_authorized:
            logging.warning("UNAUTHORIZED: Reset database attempt without proper authorization")
            return jsonify({
                "success": False,
                "message": "Authorization required for database operations"
            }), 401
            
        # If authorized, proceed with database reset
        from test_reset_db import create_sample_db
        create_sample_db()
        
        return jsonify({
            "success": True,
            "message": "Database reset successfully with test data"
        })
            
    except Exception as e:
        logging.error(f"Error in reset_database: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Server error: {str(e)}"
        }), 500

@app.route("/api/log_search", methods=["POST"])
def log_search():
    """Log search operations performed by users"""
    data = request.json
    page_type = data.get("pageType", "unknown")
    search_params = data.get("searchParams", {})
    result_count = data.get("resultCount", 0)
    total_records = data.get("totalRecords", 0)
    
    # Get user info if available
    user_role = "anonymous"
    user_id = "unknown"
    token = request.cookies.get("access_token")
    if token:
        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"], options={"verify_signature": False})
            user_role = payload.get("role", "unknown")
            user_id = payload.get("id") or payload.get("username", "unknown")
        except:
            pass
    
    # Format search criteria for logging
    criteria_parts = []
    for key, value in search_params.items():
        if value:
            criteria_parts.append(f"{key}:{value}")
    
    criteria_text = ", ".join(criteria_parts) if criteria_parts else "None"
    
    # Set appropriate log level based on search type
    # Use INFO for standard searches, DEBUG for empty searches, WARNING for unsuccessful ones
    log_level = logging.INFO
    
    # Log with formatted criteria and result count
    if page_type == "loan_books":
        message = f"LOAN BOOKS SEARCH: User[{user_role}] searched books - CRITERIA: {criteria_text} - RESULTS: {result_count}/{total_records} records"
    elif page_type == "loan_customers":
        message = f"LOAN CUSTOMERS SEARCH: User[{user_role}] searched customers - CRITERIA: {criteria_text} - RESULTS: {result_count}/{total_records} records"
    elif page_type in ["books", "customers", "loans", "returns", "late_loans"]:
        message = f"{page_type.upper()} SEARCH: User[{user_role}] searched {page_type} - CRITERIA: {criteria_text} - RESULTS: {result_count}/{total_records} records"
    else:
        message = f"SEARCH: User[{user_role}] searched {page_type} - CRITERIA: {criteria_text} - RESULTS: {result_count}/{total_records} records"
    
    # Log at the appropriate level
    logging.log(log_level, message)
    
    return jsonify({"success": True}), 200

# Add this route to log book ID searches
@app.route("/api/log_search", methods=["GET"])
def log_search_api():
    """Log search operations"""
    search_type = request.args.get("type")
    search_value = request.args.get("value")
    
    if search_type == "book_id":
        logging.info(f"BOOK ID SEARCH: User searched for Book ID: {search_value}")
    
    return "", 204  # No content response

#     Helper function 
def parse_flexible_date(date_str):
    """Parse dates in DD.MM.YYYY format and handle partial formats."""
    if not date_str:
        return None
        
    # Try DD.MM.YYYY format (preferred format)
    try:
        if len(date_str.split('.')) == 3:
            day, month, year = date_str.split('.')
            return datetime.strptime(f"{year}-{month}-{day}", "%Y-%m-%d").date()
    except ValueError:
        pass
    
    # Try YYYY-MM-DD format (API format)
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        pass
    
    # For partial searches, return None
    return None

@app.route("/api/log_action", methods=["POST"])
def log_action():
    """Log user actions from the frontend"""
    data = request.json
    
    # Extract action data
    action_type = data.get("action_type", "Unknown")
    action_details = data.get("details", {})
    page = data.get("page", "Unknown")
    
    # Get user info if available
    user_role = "anonymous"
    user_id = "unknown"
    token = request.cookies.get("access_token")
    
    if token:
        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            user_role = payload.get("role", "unknown")
            user_id = payload.get("username", payload.get("customer_id", "unknown"))
        except:
            pass
    
    # Handle specific actions with custom log formatting
    if action_type == "book_addition_attempt":
        book_title = action_details.get("title", "unknown")
        book_author = action_details.get("author", "unknown")
        book_year = action_details.get("year_published", "unknown")
        book_type = action_details.get("type", "unknown")
        log_message = f"BOOK ADDITION ATTEMPT: User[{user_role}] attempted to add book '{book_title}' by {book_author} (Year: {book_year}, Type: {book_type})"
        logging.info(log_message)
        
    elif action_type == "book_added_successfully":
        book_title = action_details.get("title", "unknown")
        book_author = action_details.get("author", "unknown")
        book_id = action_details.get("book_id", "unknown")
        log_message = f"BOOK ADDED SUCCESSFULLY: User[{user_role}] added book '{book_title}' by {book_author} with ID {book_id}"
        logging.info(log_message)
        
    elif action_type == "book_addition_failed":
        book_title = action_details.get("title", "unknown")
        error = action_details.get("error", "unknown error")
        log_message = f"BOOK ADDITION FAILED: User[{user_role}] failed to add book '{book_title}'. Reason: {error}"
        logging.error(log_message)
        
    elif action_type == "book_return":
        book_id = action_details.get("book_id", "unknown")
        title = action_details.get("title", "unknown")
        customer = action_details.get("customer_name", "unknown")
        days = action_details.get("days_on_loan", "unknown")
        log_message = f"BOOK RETURNED (JS): User[{user_role}] returned Book ID {book_id} '{title}' from {customer} after {days} days"
        logging.info(log_message)
        
    elif action_type == "late_book_return":
        book_id = action_details.get("book_id", "unknown")
        title = action_details.get("title", "unknown")
        customer = action_details.get("customer_name", "unknown")
        days = action_details.get("days_on_loan", "unknown")
        days_overdue = action_details.get("days_overdue", "unknown")
        log_message = f"LATE RETURN (JS): User[{user_role}] returned Book ID {book_id} '{title}' from {customer} after {days} days, {days_overdue} DAYS OVERDUE"
        logging.warning(log_message)
    
    elif action_type == "page_load":
        log_message = f"PAGE LOAD: User[{user_role}] loaded {page}"
        logging.info(log_message)
        
    else:
        # Generic action logging
        log_message = f"ACTION: User[{user_role}] performed {action_type} on {page} - Details: {action_details}"
        logging.info(log_message)
    
    return jsonify({"success": True}), 200

@app.route("/api/verify_developer_access", methods=["POST"])
def verify_developer_access():
    """Verify if the current session has developer access."""
    try:
        data = request.get_json()
        dev_mode_requested = data.get("dev_mode", False)
        
        # First check for a valid developer token
        token = request.cookies.get("access_token")
        if token:
            try:
                payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
                if payload.get("role") == "developer":
                    logging.info(f"Developer access verified via valid token")
                    return jsonify({"success": True, "message": "Valid developer token"})
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                pass
        
        # If no valid token, check for authorization to use dev_mode
        if dev_mode_requested:
            # Get the referrer to ensure request is coming from developers.html page
            referrer = request.headers.get('Referer', '')
            is_from_dev_page = '/developers.html' in referrer
            
            # Optional: Check other security criteria like IP address, etc.
            # For this example, we'll just check if it's from the developers page
            if is_from_dev_page:
                # Create a special session marker
                response = jsonify({"success": True, "message": "Developer mode granted"})
                response.set_cookie(
                    "dev_mode_session",
                    "true",
                    max_age=3600,  # 1 hour
                    path="/"
                )
                return response
        
        # If we reach here, no valid developer access
        return jsonify({"success": False, "message": "Developer access denied"})
        
    except Exception as e:
        logging.error(f"Error in verify_developer_access: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

# In your Flask route for the developers page
@app.route('/frontend/html/developers.html')
def developers_page():
    """Serve the developers page with proper authentication checks."""
    # Check for dev_mode parameter
    if request.args.get('dev_mode') == 'true':
        # Check if dev_mode_session cookie is set (from verify_developer_access)
        dev_mode_session = request.cookies.get("dev_mode_session") == "true"
        if dev_mode_session:
            logging.info(f"Developer access granted via dev_mode_session")
            return send_from_directory(HTML_DIR, "developers.html")
    
    # Check for regular developer token
    token = request.cookies.get("access_token")
    if token:
        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            if payload.get("role") == "developer":
                logging.info(f"Developer access granted via token to developers.html")
                return send_from_directory(HTML_DIR, "developers.html")
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            pass
            
    # Log unauthorized attempt
    logging.warning(f"Unauthorized developer access attempt from IP: {request.remote_addr}")
    # Redirect to homepage with error parameter
    return redirect('/?error=unauthorized', code=302)

# Secure logout endpoint
@app.route('/logout', methods=['POST'])
def site_logout():  # Changed function name from logout to site_logout
    # Clear all session data
    session.clear()
    # Set expired auth cookies
    response = redirect('/')
    response.set_cookie('access_token', '', expires=0)
    response.set_cookie('dev_mode_session', '', expires=0)
    return response

def verify_developer_credentials(username, password):
    """Verify developer credentials against predefined values or database."""
    # For simple implementation, check against the USERS dictionary
    if username in USERS and USERS[username]["role"] == "developer" and USERS[username]["password"] == password:
        logging.info(f"Developer credentials verified for: {username}")
        return True
    
    # If you want to check against database instead, use something like:
    # developer = Developer.query.filter_by(username=username).first()
    # if developer and developer.check_password(password):
    #     return True
    
    logging.warning(f"Failed developer login attempt for: {username}")
    return False

@app.route("/api/loans", methods=["GET"])
def get_loans():
    """Get all loans with enhanced logging."""
    try:
        # Get authentication information
        token = request.cookies.get("access_token")
        user_info = "Unknown"
        user_role = "Unknown"
        
        if token:
            try:
                payload = jwt.decode(token, options={"verify_signature": False})
                if payload.get("role") == "customer" and payload.get("id"):
                    user_info = f"Customer:{payload.get('id')}"
                    user_role = "customer"
                elif payload.get("username"):
                    user_info = f"{payload.get('role')}:{payload.get('username')}"
                    user_role = payload.get('role')
            except:
                pass
                
        # Log the request with user info
        logging.info(f"LOANS REQUEST: User[{user_role}] ({user_info}) requested loans data")
        
        # Query the database
        session = SessionLocal()
        try:
            loans = session.query(Loan).all()
            
            # Extract loans data
            loans_data = []
            for loan in loans:
                # Get book and customer data
                book = session.get(Book, loan.book_id) if loan.book_id else None
                customer = session.get(Customer, loan.cust_id) if loan.cust_id else None
                
           
                loans_data.append({
                    "id": loan.id,
                    "book_id": loan.book_id,
                    "cust_id": loan.cust_id,
                    "loan_date": loan.loan_date.strftime("%Y-%m-%d") if loan.loan_date else None,
                    "return_date": loan.return_date.strftime("%Y-%m-%d") if loan.return_date else None,
                    "customer_name": customer.name if customer else "Unknown",
                    "book_title": book.title if book else "Unknown",
                    "book_author": book.author if book else "Unknown"
                })
            
            # Log success with count
            logging.info(f"LOANS DATA: Successfully retrieved {len(loans_data)} loan records")
            
            return jsonify({"loans": loans_data})
        finally:
            session.close()
    except Exception as e:
        logging.error(f"ERROR RETRIEVING LOANS: {str(e)}")
        return jsonify({"error": "Error retrieving loans data", "message": str(e)}), 500

@app.route("/frontend/html/loans.html")
def serve_loans_page():
    """Serve loans.html with enhanced logging."""
    try:
        # Get authentication information
        token = request.cookies.get("access_token")
        user_info = "Unknown"
        user_role = "Unknown"
        
        if token:
            try:
                payload = jwt.decode(token, options={"verify_signature": False})
                if payload.get("role") == "customer" and payload.get("id"):
                    user_info = f"Customer:{payload.get('id')}"
                    user_role = "customer"
                elif payload.get("username"):
                    user_info = f"{payload.get('role')}:{payload.get('username')}"
                    user_role = payload.get('role')
            except:
                pass
        
        # Log page access with user information
        logging.info(f"PAGE ACCESS: User[{user_role}] ({user_info}) accessed loans.html")
        
        # Check if the user should have access to this page
        if user_role not in ["librarian", "developer"]:
            logging.warning(f"UNAUTHORIZED: User[{user_role}] attempted to access loans.html")
            return redirect("/frontend/html/homepage.html")
        
        # Serve the page
        return send_from_directory(HTML_DIR, "loans.html")
    except Exception as e:
        logging.error(f"ERROR SERVING LOANS PAGE: {str(e)}")
        return redirect("/frontend/html/homepage.html")

@app.after_request
def enhance_loan_logs(response):
    """Add enhanced logging for loan-related endpoints."""
    if request.path == '/api/loans':
        # Get authentication information
        token = request.cookies.get("access_token")
        user_info = "Guest"
        
        if token:
            try:
                # Decode without verification for logging
                payload = jwt.decode(token, options={"verify_signature": False})
                if payload.get("role") == "customer":
                    user_info = f"Customer:{payload.get('id')}"
                elif payload.get("username"):
                    user_info = f"{payload.get('role')}:{payload.get('username')}"
            except:
                pass
                
        if response.status_code == 200:
            # Try to parse the response JSON to count loans
            try:
                loans_count = 0
                if response.is_json:
                    data = response.get_json()
                    if isinstance(data, dict) and "loans" in data:
                        loans_count = len(data["loans"])
                        logging.info(f"LOAN AUDIT: User[{user_info}] retrieved {loans_count} loan records via API")
            except:
                logging.info(f"LOAN AUDIT: User[{user_info}] accessed loan data via API")
        else:
            logging.warning(f"LOAN AUDIT: User[{user_info}] got error {response.status_code} accessing loan data")
            
    elif request.path == '/frontend/html/loans.html':
        # Get authentication information
        token = request.cookies.get("access_token")
        user_info = "Guest"
        
        if token:
            try:
                # Decode without verification for logging
                payload = jwt.decode(token, options={"verify_signature": False})
                if payload.get("role") == "customer":
                    user_info = f"Customer:{payload.get('id')}"
                elif payload.get("username"):
                    user_info = f"{payload.get('role')}:{payload.get('username')}"
            except:
                pass
                
        if response.status_code == 200:
            logging.info(f"PAGE AUDIT: User[{user_info}] accessed loans.html")
        else:
            logging.warning(f"PAGE AUDIT: User[{user_info}] got error {response.status_code} accessing loans.html")
    
    return response

@app.route("/api/user_session", methods=["GET"])
def get_user_session():
    """Get current user session information including human-readable expiration time."""
    try:
        # Get token and verify it
        token = get_token()
        
        if not token:
            return jsonify({"success": False, "message": "No active session"}), 401
            
        try:
            # Decode and verify the token
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            
            # Convert expiration timestamp to human-readable format
            exp_timestamp = payload.get("exp")
            expiration_time = datetime.fromtimestamp(exp_timestamp)
            human_readable_expiration = expiration_time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Calculate time remaining in minutes
            now = datetime.now()
            time_remaining_seconds = exp_timestamp - int(now.timestamp())
            time_remaining_minutes = max(0, time_remaining_seconds // 60)
            
            # Get user info based on role
            user_info = {}
            role = payload.get("role")
            
            if role == "customer" and payload.get("id"):
                customer = db.session.get(Customer, payload.get("id"))
                if customer:
                    user_info = {
                        "id": customer.id,
                        "name": customer.name,
                        "email": customer.email
                    }
            elif role == "librarian" or role == "developer":
                user_info = {
                    "username": payload.get("username"),
                }
            
            # Log session information with human-readable expiration
            logging.info(f"Session info requested for {role} (expires: {human_readable_expiration} local server time)")
            
            return jsonify({
                "success": True,
                "session": {
                    "role": role,
                    "user": user_info,
                    "expires": f"{human_readable_expiration} local server time",
                    "time_remaining_minutes": time_remaining_minutes
                }
            })
                
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Session expired"}), 401
            
        except jwt.InvalidTokenError as e:
            return jsonify({"success": False, "message": f"Invalid session: {str(e)}"}), 401
            
    except Exception as e:
        return jsonify({"success": False, "message": f"Error retrieving session: {str(e)}"}), 500

# Main Entry Point
if __name__ == "__main__":
    app.run(debug=True)

