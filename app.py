# app.py
import os
import sqlite3
import hashlib
import datetime
import random
import string
import logging
import json
import time  # For PoW simulation delays
import threading  # For background mining
from functools import wraps
from flask import (Flask, render_template, redirect, url_for, request, session, flash, g, send_from_directory)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from dotenv import load_dotenv
import secrets  # For password reset tokens for regular users

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default_fallback_secret_key')
app.config['DATABASE'] = os.environ.get('DATABASE_URL', 'voting.db')
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# Password Reset Token Configuration (for regular users)
app.config['RESET_TOKEN_MAX_AGE_SECONDS'] = 1800  # 30 minutes

mail = Mail(app)

# ADMIN_USERNAME and ADMIN_PASSWORD_HASH from .env are now primarily for bootstrapping
# the admin account in the database if it doesn't exist.
ADMIN_USERNAME_ENV = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH_ENV = os.environ.get("ADMIN_PASSWORD_HASH")

if not ADMIN_PASSWORD_HASH_ENV:
    # This is still critical for the initial setup if the DB is empty.
    print("CRITICAL: ADMIN_PASSWORD_HASH environment variable is not set! This is needed for initial admin creation.")

VOTING_OPEN = True


# --- Decentralized Blockchain Classes (PoW) ---
# ... (Block, Blockchain, Node classes - UNCHANGED from your provided code) ...
class Block:
    def __init__(self, index, timestamp, data, previous_hash, nonce=0, hash_val=None):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        if hash_val:
            self.hash = hash_val
        else:
            self.hash = self.calculate_hash() if nonce != -1 else None

    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{json.dumps(self.data, sort_keys=True)}{self.previous_hash}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'hash': self.hash
        }

    @classmethod
    def from_dict(cls, block_dict):
        return cls(
            index=block_dict['index'],
            timestamp=block_dict['timestamp'],
            data=block_dict['data'],
            previous_hash=block_dict['previous_hash'],
            nonce=block_dict.get('nonce', 0),
            hash_val=block_dict['hash']
        )


class Blockchain:
    def __init__(self, difficulty=3, node_id=""):
        self.node_id = node_id
        self.chain = [self._create_genesis_block()]
        self.pending_transactions = []
        self.difficulty = difficulty
        app.logger.info(f"Node {self.node_id}: Blockchain initialized with difficulty {self.difficulty}")

    def _create_genesis_block(self):
        genesis_block = Block(0, datetime.datetime.utcnow().isoformat(),
                              {"genesis": True, "message": "Voting System Genesis"}, "0", nonce=0)
        genesis_block.hash = genesis_block.calculate_hash()
        return genesis_block

    def get_latest_block(self):
        return self.chain[-1]

    def proof_of_work(self, block_to_mine):
        app.logger.info(
            f"Node {self.node_id}: Starting PoW for block #{block_to_mine.index} with difficulty {self.difficulty}...")
        block_to_mine.nonce = 0
        computed_hash = block_to_mine.calculate_hash()
        target_prefix = '0' * self.difficulty
        start_time = time.time()
        while not computed_hash.startswith(target_prefix):
            block_to_mine.nonce += 1
            computed_hash = block_to_mine.calculate_hash()
            if block_to_mine.nonce % 100000 == 0:
                app.logger.debug(
                    f"Node {self.node_id}: PoW attempt {block_to_mine.nonce} for block #{block_to_mine.index}...")
        end_time = time.time()
        app.logger.info(
            f"Node {self.node_id}: PoW found for block #{block_to_mine.index}! Nonce: {block_to_mine.nonce}, Hash: {computed_hash[:10]}... Time: {end_time - start_time:.2f}s")
        block_to_mine.hash = computed_hash
        return block_to_mine

    def add_block(self, block):
        latest_block = self.get_latest_block()
        if block.previous_hash != latest_block.hash:
            app.logger.error(
                f"Node {self.node_id}: Failed to add block #{block.index}. Previous hash mismatch. Expected: {latest_block.hash}, Got: {block.previous_hash}")
            return False
        if block.index != latest_block.index + 1:
            app.logger.error(
                f"Node {self.node_id}: Failed to add block #{block.index}. Index mismatch. Expected: {latest_block.index + 1}, Got: {block.index}")
            return False
        if not block.hash or block.hash != block.calculate_hash():
            app.logger.error(f"Node {self.node_id}: Failed to add block #{block.index}. Hash re-calculation mismatch.")
            return False
        if not block.hash.startswith('0' * self.difficulty):
            app.logger.error(
                f"Node {self.node_id}: Failed to add block #{block.index}. Hash does not meet difficulty target.")
            return False
        self.chain.append(block)
        app.logger.info(
            f"Node {self.node_id}: Successfully added block #{block.index} to chain. Chain length: {len(self.chain)}")
        return True

    def add_transaction(self, transaction_data):
        self.pending_transactions.append(transaction_data)
        app.logger.info(
            f"Node {self.node_id}: Transaction {transaction_data} added to mempool. Mempool size: {len(self.pending_transactions)}")
        return self.get_latest_block().index + 1

    def is_chain_valid(self):
        if not self.chain: return False
        genesis = self.chain[0]
        if genesis.index != 0 or genesis.previous_hash != "0" or genesis.hash != genesis.calculate_hash():
            app.logger.warning(f"Node {self.node_id}: Genesis block invalid!")
            return False
        for i in range(1, len(self.chain)):
            current, previous = self.chain[i], self.chain[i - 1]
            if current.hash != current.calculate_hash():
                app.logger.warning(f"Node {self.node_id}: Block #{current.index} hash mismatch.")
                return False
            if current.previous_hash != previous.hash:
                app.logger.warning(f"Node {self.node_id}: Block #{current.index} previous_hash mismatch.")
                return False
            if not current.hash.startswith('0' * self.difficulty):
                app.logger.warning(f"Node {self.node_id}: Block #{current.index} PoW invalid (difficulty).")
                return False
        app.logger.debug(f"Node {self.node_id}: Chain validation passed.")
        return True

    def reset_chain(self):
        self.chain = [self._create_genesis_block()]
        self.pending_transactions = []
        app.logger.info(f"Node {self.node_id}: Blockchain and mempool reset.")


class Node:
    def __init__(self, node_id, network_nodes_ref, difficulty=3):
        self.node_id = node_id
        self.blockchain = Blockchain(difficulty=difficulty, node_id=node_id)
        self.network_nodes_ref = network_nodes_ref
        self.is_mining = False
        self.mining_lock = threading.Lock()

    def add_vote_to_mempool(self, vote_data):
        self.blockchain.add_transaction(vote_data)

    def mine_block_task(self):
        with self.mining_lock:
            if self.is_mining:
                app.logger.info(f"Node {self.node_id}: Already mining.")
                return
            if not self.blockchain.pending_transactions:
                app.logger.info(f"Node {self.node_id}: No transactions to mine.")
                self.is_mining = False
                return
            self.is_mining = True
            app.logger.info(f"Node {self.node_id}: Starting mining operation in background...")
        try:
            latest_block = self.blockchain.get_latest_block()
            transactions_for_block = list(self.blockchain.pending_transactions)
            new_block_data = {"transactions": transactions_for_block, "miner": self.node_id}
            candidate_block = Block(
                index=latest_block.index + 1,
                timestamp=datetime.datetime.utcnow().isoformat(),
                data=new_block_data,
                previous_hash=latest_block.hash,
                nonce=-1
            )
            mined_block = self.blockchain.proof_of_work(candidate_block)
            with self.mining_lock:
                if self.blockchain.get_latest_block().hash == mined_block.previous_hash:
                    if self.blockchain.add_block(mined_block):
                        self.blockchain.pending_transactions = [
                            tx for tx in self.blockchain.pending_transactions if tx not in transactions_for_block
                        ]
                        app.logger.info(
                            f"Node {self.node_id}: Successfully mined and added block #{mined_block.index}. Mempool size: {len(self.blockchain.pending_transactions)}")
                        self.broadcast_block(mined_block)
                    else:
                        app.logger.error(
                            f"Node {self.node_id}: Mined block #{mined_block.index} but failed to add to own chain (validation failed).")
                else:
                    app.logger.warning(
                        f"Node {self.node_id}: Mined block #{mined_block.index} but chain changed (stale block). Discarding.")
        except Exception as e:
            app.logger.error(f"Node {self.node_id}: Error during mining: {e}")
        finally:
            with self.mining_lock:
                self.is_mining = False
            app.logger.info(f"Node {self.node_id}: Mining operation finished.")

    def broadcast_block(self, block):
        app.logger.info(f"Node {self.node_id}: Broadcasting block #{block.index} to other nodes.")
        for node_obj in self.network_nodes_ref:
            if node_obj.node_id != self.node_id:
                node_obj.receive_block(block, self.node_id)

    def receive_block(self, block_obj, from_node_id):
        app.logger.info(f"Node {self.node_id}: Received block #{block_obj.index} from Node {from_node_id}.")
        with self.mining_lock:
            latest_local_block = self.blockchain.get_latest_block()
            if block_obj.index > latest_local_block.index:
                if block_obj.previous_hash == latest_local_block.hash:
                    if self.blockchain.add_block(block_obj):
                        app.logger.info(
                            f"Node {self.node_id}: Accepted and added block #{block_obj.index} from Node {from_node_id}.")
                        if "transactions" in block_obj.data:
                            tx_in_block = block_obj.data["transactions"]
                            self.blockchain.pending_transactions = [
                                tx for tx in self.blockchain.pending_transactions if tx not in tx_in_block
                            ]


SIMULATED_NODES = []
NUM_SIMULATED_NODES = 3
POW_DIFFICULTY = int(os.environ.get("POW_DIFFICULTY", 4))


def initialize_nodes():
    global SIMULATED_NODES
    SIMULATED_NODES.clear()
    for i in range(NUM_SIMULATED_NODES):
        node = Node(node_id=f"Node-{i}", network_nodes_ref=SIMULATED_NODES, difficulty=POW_DIFFICULTY)
        SIMULATED_NODES.append(node)
    app.logger.info(f"Initialized {len(SIMULATED_NODES)} simulated nodes.")


with app.app_context():
    initialize_nodes()


# --- Database Helper Functions ---
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'], detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON;")
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    try:
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
        print("Initialized the database.")
        cursor = db.cursor()
        # Use ADMIN_USERNAME_ENV for bootstrapping username
        admin_exists = cursor.execute('SELECT id FROM admin WHERE username = ?', (ADMIN_USERNAME_ENV,)).fetchone()
        if not admin_exists and ADMIN_PASSWORD_HASH_ENV:
            # Use ADMIN_PASSWORD_HASH_ENV for bootstrapping password
            cursor.execute('INSERT INTO admin (username, password) VALUES (?, ?)',
                           (ADMIN_USERNAME_ENV, ADMIN_PASSWORD_HASH_ENV))
            db.commit()
            print(f"Default admin user '{ADMIN_USERNAME_ENV}' created using environment variables.")
        elif admin_exists:
            print(f"Admin user '{ADMIN_USERNAME_ENV}' already exists in the database.")
        elif not ADMIN_PASSWORD_HASH_ENV:
            print(
                f"Admin user '{ADMIN_USERNAME_ENV}' NOT created because ADMIN_PASSWORD_HASH environment variable is missing.")
    except Exception as e:
        print(f"Error during DB initialization: {e}")
        db.rollback()


@app.cli.command('init-db')
def init_db_command():
    db_path = app.config['DATABASE']
    if os.path.exists(db_path):
        print(f"Removing existing database {db_path}.")
        os.remove(db_path)
    init_db()
    with app.app_context():
        app.logger.info("Resetting simulated blockchain nodes due to init-db.")
        initialize_nodes()


# --- NEW: Admin Password Reset CLI Command (Modifies DB directly) ---
@app.cli.command('reset-admin-password')
def reset_admin_password_command():
    """Resets the admin password in the database."""
    import getpass  # For securely getting password input

    print("--- Admin Password Reset Utility (Database Update) ---")
    # The admin username to target is taken from the ADMIN_USERNAME env var.
    # This user must exist in the 'admin' table.
    target_admin_username = os.environ.get("ADMIN_USERNAME", "admin")  # Default to 'admin' if not set
    print(f"This utility will attempt to reset the password for admin user '{target_admin_username}' in the database.")
    print("-" * 30)

    while True:
        new_password = getpass.getpass(f"Enter new password for admin '{target_admin_username}': ")
        if not new_password:
            print("Password cannot be empty. Please try again.")
            continue
        if len(new_password) < 10:  # Enforce a reasonable minimum length
            print("Admin password should be at least 10 characters long for security. Please try again.")
            continue
        confirm_password = getpass.getpass("Confirm new password: ")
        if new_password == confirm_password:
            break
        else:
            print("Passwords do not match. Please try again.")

    new_password_hash = generate_password_hash(new_password)

    try:
        # We need an app context to use get_db() and other Flask features
        with app.app_context():
            db = get_db()
            cursor = db.execute('UPDATE admin SET password = ? WHERE username = ?',
                                (new_password_hash, target_admin_username))
            db.commit()

            if cursor.rowcount > 0:
                print("\n" + "=" * 40)
                print("SUCCESS: Admin password has been updated in the database.")
                print("=" * 40)
                print(f"Admin Username: {target_admin_username}")
                print(
                    "The password hash in your .env file (ADMIN_PASSWORD_HASH) is now primarily for bootstrapping a new database.")
                print("The active password for login is the one now set in the database.")
                print(
                    "You might need to restart your Flask application if it caches admin credentials (though this app should not).")
                print("=" * 40 + "\n")
            else:
                print("\n" + "=" * 40)
                print(f"ERROR: Could not find admin user '{target_admin_username}' in the database to update.")
                print(
                    "Please ensure the ADMIN_USERNAME in your .env file matches an existing admin user in the database,")
                print("or that the database has been initialized correctly using 'flask init-db'.")
                print(
                    f"If the database is fresh, 'flask init-db' will use ADMIN_USERNAME and ADMIN_PASSWORD_HASH from .env to create the admin.")
                print("No changes were made to the database.")
                print("=" * 40 + "\n")

    except Exception as e:
        print(f"\nERROR: Failed to update admin password in the database: {e}")
        print(
            "Please check your database connection and ensure the 'admin' table exists with a 'username' and 'password' column.")
        print("No changes were made to the database.\n")


# --- File Upload Helper & Decorators ---
# ... (allowed_file, generate_otp, login_required, admin_required - UNCHANGED) ...
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session or not session['admin_logged_in']:
            flash('Admin access required.', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)

    return decorated_function


# --- Password Reset Helper Functions (for regular users) ---
# ... (generate_url_safe_token, hash_token, send_password_reset_email - UNCHANGED) ...
def generate_url_safe_token(num_bytes=32):
    return secrets.token_urlsafe(num_bytes)


def hash_token(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def send_password_reset_email(user_email, user_name, token):
    reset_url = url_for('reset_password_with_token', token_str=token, _external=True)
    subject = "Password Reset Request - Voting System"
    body = f"""Hello {user_name},

Someone (hopefully you) has requested a password reset for your account on the Voting System.
If this was you, please click the link below to reset your password. This link is valid for {app.config['RESET_TOKEN_MAX_AGE_SECONDS'] // 60} minutes.

{reset_url}

If you did not request a password reset, please ignore this email. Your password will remain unchanged.

Regards,
The Voting System Administration
"""
    try:
        msg = Message(subject, recipients=[user_email], body=body)
        mail.send(msg)
        app.logger.info(f"Password reset email sent to {user_email}")
        return True
    except Exception as e:
        app.logger.error(f"Failed to send password reset email to {user_email}: {e}", exc_info=True)
        return False


# --- Routes ---
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = None
    g.admin = None  # For admin context if needed
    if user_id is not None:
        g.user = get_db().execute('SELECT id, name, email FROM voters WHERE id = ?', (user_id,)).fetchone()
    elif session.get('admin_logged_in'):
        # Store the admin username from session if logged in as admin
        g.admin = {'username': session.get('admin_username')}


@app.context_processor
def inject_global_vars():
    return {'current_year': datetime.datetime.utcnow().year, 'voting_open_global': VOTING_OPEN}


@app.route('/')
def home():
    abstraction_details = [
        "Secure Registration: Email OTP verification for new voters.",
        "Secure Voting: One vote per registered user enforced by central DB.",
        "Password Resets (Users): Secure, token-based password reset via email.",
        "Password Resets (Admin): CLI tool to update admin password directly in DB.",  # Updated
        "Data Integrity (Central DB): Vote data is hashed (SHA-256) upon submission.",
        "Decentralized Ledger (Simulated): Votes (transactions) are broadcast to a simulated network of nodes.",
        "Proof-of-Work Consensus (Simulated): Nodes compete to mine blocks and add them to their version of the blockchain.",
        "Admin Control: Admins manage candidates, voting period, and can trigger mining on nodes.",
        "Transparency: Aggregated results (from DB) and simulated blockchain state are viewable.",
    ]
    return render_template('home.html', details=abstraction_details)


# --- User Registration, Login, Logout, Password Reset for users ---
# ... (register, login, logout, forgot_password, reset_password_with_token - UNCHANGED from previous version) ...
@app.route('/register', methods=['GET', 'POST'])
def register():
    otp_verification_in_progress = session.get('registration_otp_sent', False)
    registration_data = session.get('registration_data', {})
    if otp_verification_in_progress:
        otp_timestamp = registration_data.get('otp_timestamp', 0)
        otp_age = datetime.datetime.utcnow().timestamp() - otp_timestamp
        if otp_age > 600:  # 10 minutes
            flash('OTP has expired. Please start registration again.', 'danger')
            session.pop('registration_data', None);
            session.pop('registration_otp_sent', None)
            otp_verification_in_progress = False;
            registration_data = {}
    if request.method == 'POST':
        if otp_verification_in_progress:  # OTP verification stage
            entered_otp = request.form.get('otp')
            if not entered_otp:
                flash('Please enter the OTP you received.', 'warning')
                return render_template('register.html', otp_sent=True, email=registration_data.get('email'))
            if entered_otp == registration_data.get('otp'):
                conn = get_db()
                try:
                    conn.execute("INSERT INTO voters (name, email, phone, password) VALUES (?, ?, ?, ?)",
                                 (registration_data['name'], registration_data['email'], registration_data['phone'],
                                  registration_data['password_hash']))
                    conn.commit()
                    flash('Registration successful! You can now log in.', 'success')
                    session.pop('registration_data', None);
                    session.pop('registration_otp_sent', None)
                    return redirect(url_for('login'))
                except sqlite3.IntegrityError:
                    flash('Email address already registered. Please try logging in or reset your password.', 'danger')
                    conn.rollback();
                    session.pop('registration_data', None);
                    session.pop('registration_otp_sent', None)
                    return redirect(url_for('login'))
                except Exception as e:
                    flash(f'An error occurred: {e}', 'danger')
                    app.logger.error(f"Reg DB Error: {e}");
                    conn.rollback()
                    session.pop('registration_data', None);
                    session.pop('registration_otp_sent', None)
                    return render_template('register.html', otp_sent=False)
            else:
                flash('Invalid OTP. Please try again.', 'danger')
                return render_template('register.html', otp_sent=True, email=registration_data.get('email'))
        else:  # Initial registration data submission
            name = request.form.get('name')
            email = request.form.get('email', '').lower()
            phone = request.form.get('phone')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            if not all([name, email, password, confirm_password]):
                flash('All fields marked * are required.', 'danger')
                return render_template('register.html', otp_sent=False, form_data=request.form)
            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return render_template('register.html', otp_sent=False, form_data=request.form)
            if len(password) < 8:
                flash('Password must be at least 8 characters.', 'danger')
                return render_template('register.html', otp_sent=False, form_data=request.form)

            if get_db().execute('SELECT id FROM voters WHERE email = ?', (email,)).fetchone():
                flash('Email already registered. Please log in or reset your password.', 'danger')
                return redirect(url_for('login'))

            otp = generate_otp()
            hashed_password = generate_password_hash(password)
            session['registration_data'] = {'name': name, 'email': email, 'phone': phone,
                                            'password_hash': hashed_password, 'otp': otp,
                                            'otp_timestamp': datetime.datetime.utcnow().timestamp()}
            session['registration_otp_sent'] = True
            try:
                msg = Message("Your Voting System OTP", recipients=[email])
                msg.body = f"Hello {name},\n\nYour OTP for registration is: {otp}\nThis OTP is valid for 10 minutes."
                mail.send(msg)
                flash('An OTP has been sent to your email address. Please enter it below to complete registration.',
                      'info')
                return render_template('register.html', otp_sent=True, email=email)
            except Exception as e:
                app.logger.error(f"Mail sending failed for {email} during registration: {e}", exc_info=True)
                flash(f'Could not send OTP email. Error: {e}. Please try again later or contact support.', 'danger')
                session.pop('registration_data', None);
                session.pop('registration_otp_sent', None)
                return render_template('register.html', otp_sent=False, form_data=request.form)
    else:  # GET request
        if not otp_verification_in_progress:
            session.pop('registration_data', None);
            session.pop('registration_otp_sent', None)
        return render_template('register.html',
                               otp_sent=otp_verification_in_progress,
                               email=registration_data.get('email') if otp_verification_in_progress else None,
                               form_data=registration_data if otp_verification_in_progress else {})


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email, password = request.form['email'].lower(), request.form['password']
        user = get_db().execute('SELECT * FROM voters WHERE email = ?', (email,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            flash(f'Welcome back, {user["name"]}!', 'success')
            return redirect(url_for('vote'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').lower()
        if not email:
            flash('Please enter your email address.', 'warning')
            return render_template('forgot_password.html')

        conn = get_db()
        user = conn.execute('SELECT id, name, email FROM voters WHERE email = ?', (email,)).fetchone()

        if user:
            conn.execute('DELETE FROM password_reset_tokens WHERE user_id = ?', (user['id'],))
            token = generate_url_safe_token()
            token_hash = hash_token(token)
            expires_at = datetime.datetime.utcnow() + datetime.timedelta(
                seconds=app.config['RESET_TOKEN_MAX_AGE_SECONDS'])
            try:
                conn.execute('INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
                             (user['id'], token_hash, expires_at))
                conn.commit()
                if send_password_reset_email(user['email'], user['name'], token):
                    flash(
                        'A password reset link has been sent to your email address. Please check your inbox (and spam folder).',
                        'info')
                else:
                    flash('Could not send password reset email. Please try again later or contact support.', 'danger')
            except sqlite3.Error as e:
                conn.rollback()
                app.logger.error(f"Database error during password reset token generation for {email}: {e}")
                flash('An error occurred. Please try again.', 'danger')
        else:
            flash('If an account with that email exists, a password reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


@app.route('/reset_password/<token_str>', methods=['GET', 'POST'])
def reset_password_with_token(token_str):
    conn = get_db()
    token_hash_from_url = hash_token(token_str)
    now_utc_str = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')  # For SQL comparison if needed

    token_record = conn.execute(
        'SELECT prt.id, prt.user_id, prt.expires_at, v.email '
        'FROM password_reset_tokens prt JOIN voters v ON prt.user_id = v.id '
        'WHERE prt.token_hash = ?', (token_hash_from_url,)
    ).fetchone()

    if not token_record:
        flash('Invalid or expired password reset link. Please request a new one.', 'danger')
        return redirect(url_for('forgot_password'))

    expires_at_dt = datetime.datetime.fromisoformat(token_record['expires_at'].split('.')[0])
    if datetime.datetime.utcnow() > expires_at_dt:
        flash('Password reset link has expired. Please request a new one.', 'danger')
        try:
            conn.execute('DELETE FROM password_reset_tokens WHERE id = ?', (token_record['id'],))
            conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            app.logger.error(f"Error deleting expired token ID {token_record['id']}: {e}")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not password or not confirm_password:
            flash('Please enter and confirm your new password.', 'warning')
            return render_template('reset_password_form.html', token=token_str)
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password_form.html', token=token_str)
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('reset_password_form.html', token=token_str)

        new_password_hash = generate_password_hash(password)
        try:
            conn.execute('UPDATE voters SET password = ? WHERE id = ?', (new_password_hash, token_record['user_id']))
            conn.execute('DELETE FROM password_reset_tokens WHERE id = ?', (token_record['id'],))
            conn.commit()
            flash('Your password has been successfully reset! You can now log in with your new password.', 'success')
            app.logger.info(
                f"Password reset successfully for user ID {token_record['user_id']} (email: {token_record['email']})")
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            conn.rollback()
            app.logger.error(f"Database error during password update for user ID {token_record['user_id']}: {e}")
            flash('An error occurred while resetting your password. Please try again.', 'danger')
            return render_template('reset_password_form.html', token=token_str)
    return render_template('reset_password_form.html', token=token_str)


@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


# --- Admin Routes ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username_form = request.form['username']
        password_form = request.form['password']

        conn = get_db()
        # The admin username from .env is used to identify the record in the DB
        # This assumes ADMIN_USERNAME_ENV is the canonical username for the admin account.
        admin_record = conn.execute('SELECT * FROM admin WHERE username = ?', (ADMIN_USERNAME_ENV,)).fetchone()

        if admin_record and username_form == admin_record['username'] and check_password_hash(admin_record['password'],
                                                                                              password_form):
            session.clear()
            session['admin_logged_in'] = True
            session['admin_username'] = admin_record['username']  # Store actual username from DB
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            # Fallback check if DB is empty or record not found, and .env vars are set (for initial bootstrap case before DB is fully managed)
            # This fallback might be removed if strict DB-only auth is desired post-bootstrap.
            if not admin_record and ADMIN_USERNAME_ENV == username_form and ADMIN_PASSWORD_HASH_ENV and check_password_hash(
                    ADMIN_PASSWORD_HASH_ENV, password_form):
                session.clear()
                session['admin_logged_in'] = True
                session['admin_username'] = ADMIN_USERNAME_ENV
                flash('Admin login successful (using bootstrap credentials)! Please ensure DB is initialized.',
                      'warning')  # Warning because this means DB might not be primary source yet
                app.logger.warning(
                    "Admin logged in using .env bootstrap credentials. This should typically happen only on first run or if DB admin record is missing.")
                return redirect(url_for('admin_dashboard'))

            flash('Invalid admin username or password.', 'danger')
            app.logger.warning(f"Failed admin login attempt for username: {username_form}")

    return render_template('admin_login.html')


@app.route('/admin/logout')
@admin_required
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('Admin logged out.', 'info')
    return redirect(url_for('home'))


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db()
    candidates = conn.execute('SELECT * FROM candidates ORDER BY name').fetchall()
    voter_count = conn.execute('SELECT COUNT(id) FROM voters').fetchone()[0]
    vote_count = conn.execute('SELECT COUNT(id) FROM votes').fetchone()[0]
    results = conn.execute('''
        SELECT c.id, c.name, c.party, c.image_filename, COUNT(v.id) as vote_count
        FROM candidates c LEFT JOIN votes v ON c.id = v.candidate_id
        GROUP BY c.id ORDER BY vote_count DESC, c.name
    ''').fetchall()
    voters = conn.execute('SELECT id, name, email, registered_at FROM voters ORDER BY registered_at DESC').fetchall()
    node_info = []
    for idx, node_obj in enumerate(SIMULATED_NODES):
        node_info.append({
            "id": node_obj.node_id,
            "chain_length": len(node_obj.blockchain.chain),
            "mempool_size": len(node_obj.blockchain.pending_transactions),
            "is_mining": node_obj.is_mining
        })
    return render_template('admin_dashboard.html',
                           candidates=candidates, voter_count=voter_count,
                           vote_count=vote_count, results=results, voters=voters,
                           voting_open=VOTING_OPEN, node_info=node_info, num_nodes=NUM_SIMULATED_NODES)


# ... (admin_add_candidate, admin_delete_candidate, toggle_voting - UNCHANGED) ...
@app.route('/admin/add_candidate', methods=['GET', 'POST'])
@admin_required
def admin_add_candidate():
    if request.method == 'POST':
        name, party, image = request.form['name'], request.form['party'], request.files.get('image')
        if not name or not party:
            flash('Name and party are required.', 'danger')
            return render_template('admin_add_candidate.html')
        filename = None
        if image and image.filename and allowed_file(image.filename):
            timestamp = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
            base, ext = os.path.splitext(secure_filename(image.filename))
            filename = f"{secure_filename(name.lower().replace(' ', '_'))}_{timestamp}{ext}"
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            try:
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            except Exception as e:
                flash(f"Error saving image: {e}", "danger");
                app.logger.error(f"Img save fail: {e}");
                filename = None
        elif image and image.filename and not allowed_file(image.filename):
            flash(f'Invalid image file type. Allowed: {app.config["ALLOWED_EXTENSIONS"]}', 'warning')
            return render_template('admin_add_candidate.html')
        conn = get_db()
        try:
            conn.execute('INSERT INTO candidates (name, party, image_filename) VALUES (?, ?, ?)',
                         (name, party, filename))
            conn.commit()
            flash('Candidate added!', 'success')
            return redirect(url_for('admin_dashboard'))
        except sqlite3.IntegrityError:
            flash('Candidate name might already exist.', 'danger');
            conn.rollback()
        except Exception as e:
            flash(f'Error adding candidate: {e}', 'danger')
            app.logger.error(f"DB error add cand: {e}");
            conn.rollback()
            if filename and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename)); app.logger.info(
                        f"Cleaned orphan img: {filename}")
                except OSError as unlink_error:
                    app.logger.error(f"Fail remove orphan: {unlink_error}")
    return render_template('admin_add_candidate.html')


@app.route('/admin/delete_candidate/<int:candidate_id>', methods=['POST'])
@admin_required
def admin_delete_candidate(candidate_id):
    conn = get_db()
    try:
        candidate = conn.execute('SELECT name, image_filename FROM candidates WHERE id = ?', (candidate_id,)).fetchone()
        if not candidate: flash('Candidate not found.', 'danger'); return redirect(url_for('admin_dashboard'))
        name, img_file = candidate['name'], candidate['image_filename']
        conn.execute('PRAGMA foreign_keys=ON;')

        has_votes = conn.execute('SELECT 1 FROM votes WHERE candidate_id = ?', (candidate_id,)).fetchone()
        if has_votes:
            flash(
                f'Cannot delete candidate "{name}" as they have existing votes. Please clear votes first or handle this scenario.',
                'danger')
            app.logger.warning(f"Admin attempt to delete candidate {candidate_id} ('{name}') with votes.")
            return redirect(url_for('admin_dashboard'))

        if conn.execute('DELETE FROM candidates WHERE id = ?', (candidate_id,)).rowcount > 0:
            conn.commit()
            flash(f'Candidate "{name}" deleted.', 'success')
            app.logger.info(f"Admin deleted candidate ID {candidate_id} ('{name}')")
            if img_file:
                try:
                    path = os.path.join(app.config['UPLOAD_FOLDER'], img_file)
                    if os.path.exists(path): os.remove(path); app.logger.info(f"Deleted associated image: {img_file}")
                except OSError as e:
                    flash(f'Failed to delete image "{img_file}": {e}', 'warning');
                    app.logger.error(f"Error deleting image: {e}")
        else:
            conn.rollback()
            flash(f'Failed to delete candidate "{name}". Might not exist or another issue.', 'warning')
    except sqlite3.IntegrityError as e:
        conn.rollback()
        flash(f'Cannot delete candidate "{name}" as they likely have votes associated. Error: {e}', 'danger')
        app.logger.warning(
            f"Failed to delete candidate {candidate_id} ('{name}') due to existing votes (IntegrityError): {e}")
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting candidate "{name}": {e}', 'danger')
        app.logger.error(f"Error deleting candidate {candidate_id}: {e}", exc_info=True)
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/toggle_voting', methods=['POST'])
@admin_required
def toggle_voting():
    global VOTING_OPEN
    conn = get_db()
    if not VOTING_OPEN:
        try:
            deleted_votes = conn.execute('DELETE FROM votes').rowcount
            # It's generally better not to delete all voters automatically when toggling voting.
            # If a full reset including voters is needed, it should be a more explicit action.
            # For now, let's keep the voter deletion part commented out or remove it.
            # deleted_voters = conn.execute('DELETE FROM voters').rowcount
            # conn.commit()
            # flash(f'New voting period started. Cleared {deleted_votes} DB votes and {deleted_voters} registered voters.','success')
            # app.logger.info(f"Admin '{session.get('admin_username')}' started new DB voting. Cleared {deleted_votes} votes and {deleted_voters} voters.")
            conn.commit()
            flash(f'New voting period started. Cleared {deleted_votes} DB votes.', 'success')
            app.logger.info(
                f"Admin '{session.get('admin_username')}' started new DB voting period. Cleared {deleted_votes} votes.")

            app.logger.info("Resetting all simulated blockchain nodes for new voting period.")
            for node_obj in SIMULATED_NODES:
                node_obj.blockchain.reset_chain()
            flash('Simulated blockchain nodes have been reset.', 'info')
        except Exception as e:
            conn.rollback()
            flash(f'Error resetting voting data: {e}', 'danger')
            app.logger.error(f"Error resetting voting data by admin: {e}", exc_info=True)
            return redirect(url_for('admin_dashboard'))
    VOTING_OPEN = not VOTING_OPEN
    status = "opened" if VOTING_OPEN else "closed"
    flash(f'Voting has been {status}.', 'info')
    app.logger.info(f"Admin '{session.get('admin_username')}' set voting status to {status.upper()}")
    return redirect(url_for('admin_dashboard'))


# --- Email Sending Helper for Vote Receipt ---
# ... (send_vote_receipt_email - UNCHANGED) ...
def send_vote_receipt_email(voter_name, voter_email, candidate_name, candidate_party, timestamp, vote_hash):
    try:
        receipt_subject = "Your Vote Has Been Recorded!"
        receipt_body = f"""Hello {voter_name},

Thank you for participating in the election. Your vote has been successfully recorded.

Vote Details:
--------------------------------------
Candidate Name: {candidate_name}
Candidate Party: {candidate_party}
Timestamp (UTC): {timestamp}
Your Unique Vote Hash: {vote_hash}
--------------------------------------

This hash is a unique identifier for your vote in our database.
Your vote has also been submitted to our simulated decentralized ledger for additional recording.

Regards,
The Voting System Administration
"""
        msg = Message(receipt_subject, recipients=[voter_email], body=receipt_body)
        app.logger.debug(f"Preparing to send vote receipt to {voter_email} for hash {vote_hash}")
        app.logger.debug(
            f"Mail Config: Server={app.config.get('MAIL_SERVER')}, Port={app.config.get('MAIL_PORT')}, User={app.config.get('MAIL_USERNAME')}")
        mail.send(msg)
        app.logger.info(
            f"Vote receipt email successfully sent (or queued by Flask-Mail) to {voter_email} for vote hash {vote_hash}")
        return True
    except Exception as mail_error:
        app.logger.error(
            f"Failed to send vote receipt email to {voter_email} for vote hash {vote_hash}. Error: {mail_error}",
            exc_info=True)
        return False


# --- Vote and Results Routes ---
# ... (vote, results, uploaded_file - UNCHANGED) ...
@app.route('/vote', methods=['GET', 'POST'])
@login_required
def vote():
    user_id = session['user_id']
    conn = get_db()
    voter_info = g.user
    if not voter_info or not voter_info['email']:
        voter_db_info = conn.execute('SELECT name, email FROM voters WHERE id = ?', (user_id,)).fetchone()
        if not voter_db_info:
            flash('Error: Voter information not found. Cannot proceed.', 'danger');
            return redirect(url_for('home'))
        voter_email, voter_name = voter_db_info['email'], voter_db_info['name']
    else:
        voter_email, voter_name = voter_info['email'], voter_info['name']

    existing_vote_db = conn.execute('SELECT id FROM votes WHERE voter_id = ?', (user_id,)).fetchone()
    candidates = conn.execute('SELECT * FROM candidates ORDER BY name').fetchall()

    if not VOTING_OPEN: flash('Voting is currently closed.', 'warning')

    if request.method == 'POST':
        if not VOTING_OPEN: flash('Cannot vote, voting is closed.', 'danger'); return redirect(url_for('vote'))
        if existing_vote_db: flash('You have already voted (DB). Cannot vote again.', 'danger'); return redirect(
            url_for('vote'))

        candidate_id = request.form.get('candidate')
        if not candidate_id:
            flash('Please select a candidate.', 'warning')
            return render_template('vote.html', candidates=candidates, has_voted=False, voting_open=VOTING_OPEN)

        selected_candidate_info = conn.execute('SELECT name, party FROM candidates WHERE id = ?',
                                               (candidate_id,)).fetchone()
        if not selected_candidate_info:
            flash('Invalid candidate selected.', 'danger')
            return render_template('vote.html', candidates=candidates, has_voted=False, voting_open=VOTING_OPEN)
        try:
            timestamp = datetime.datetime.utcnow().isoformat()
            vote_data_str = f"voter:{user_id}-candidate:{candidate_id}-timestamp:{timestamp}"
            vote_hash = hashlib.sha256(vote_data_str.encode('utf-8')).hexdigest()

            conn.execute('INSERT INTO votes (voter_id, candidate_id, vote_hash, timestamp) VALUES (?, ?, ?, ?)',
                         (user_id, candidate_id, vote_hash, timestamp))
            conn.commit()
            app.logger.info(f"Vote by user ID {user_id} for cand ID {candidate_id} SAVED TO SQLITE DB.")

            transaction_for_blockchain = {
                "type": "vote", "voter_id": user_id, "voter_name": voter_name,
                "candidate_id": int(candidate_id), "timestamp": timestamp, "vote_db_hash": vote_hash
            }
            if SIMULATED_NODES:
                for node_obj in SIMULATED_NODES:
                    node_obj.add_vote_to_mempool(transaction_for_blockchain)
                app.logger.info(f"Vote by user ID {user_id} submitted to mempools of {len(SIMULATED_NODES)} nodes.")

            email_sent_successfully = send_vote_receipt_email(
                voter_name=voter_name, voter_email=voter_email,
                candidate_name=selected_candidate_info['name'], candidate_party=selected_candidate_info['party'],
                timestamp=timestamp, vote_hash=vote_hash
            )
            flash_message = 'Your vote has been cast and submitted to the network!' + \
                            (' A receipt has been sent to your email.' if email_sent_successfully else \
                                 ' However, we could not send an email receipt (check logs).')
            flash_category = 'success' if email_sent_successfully else 'warning'
            flash(flash_message, flash_category)
            return redirect(url_for('results'))
        except sqlite3.IntegrityError:
            flash('DB Integrity Error (already voted?).', 'danger');
            conn.rollback()
        except Exception as e:
            flash(f'An unexpected error occurred during voting: {e}', 'danger');
            app.logger.error(f"Error casting vote for user {user_id}: {e}", exc_info=True);
            conn.rollback()
        return render_template('vote.html', candidates=candidates, has_voted=False, voting_open=VOTING_OPEN)

    return render_template('vote.html', candidates=candidates, has_voted=(existing_vote_db is not None),
                           voting_open=VOTING_OPEN)


@app.route('/results')
def results():
    allow_access = ('admin_logged_in' in session and session['admin_logged_in']) or \
                   ('user_id' in session and not VOTING_OPEN)
    if not allow_access:
        if 'user_id' in session and VOTING_OPEN:
            flash('Results available after voting ends.', 'info');
            return redirect(url_for('vote'))
        else:
            flash('Please log in.', 'warning');
            return redirect(url_for('login'))

    conn = get_db()
    results_data = conn.execute('''
        SELECT c.name, c.party, c.image_filename, COUNT(v.id) as vote_count
        FROM candidates c LEFT JOIN votes v ON c.id = v.candidate_id
        GROUP BY c.id ORDER BY vote_count DESC, c.name
    ''').fetchall()
    user_vote_info = None
    if 'user_id' in session and not ('admin_logged_in' in session and session['admin_logged_in']):
        user_id = session['user_id']
        vote_record = conn.execute('''
            SELECT v.vote_hash, c.name as candidate_name, c.party as candidate_party
            FROM votes v JOIN candidates c ON v.candidate_id = c.id WHERE v.voter_id = ?
        ''', (user_id,)).fetchone()
        if vote_record: user_vote_info = vote_record
    winners = []
    max_votes = 0
    if not VOTING_OPEN and results_data and results_data[0]['vote_count'] > 0:
        max_votes = results_data[0]['vote_count']
        winners = [r for r in results_data if r['vote_count'] == max_votes]
    return render_template('results.html', results=results_data, user_vote=user_vote_info,
                           voting_closed=(not VOTING_OPEN), is_admin=('admin_logged_in' in session),
                           winners=winners, max_votes=max_votes)


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    if '..' in filename or filename.startswith('/'): return "Forbidden", 403
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        try:
            return send_from_directory(os.path.join(app.root_path, 'static', 'images'), 'default_candidate.png')
        except FileNotFoundError:
            return "Image not found", 404


# --- Admin Routes for Decentralized Simulation ---
# ... (admin_view_blockchain_nodes, admin_mine_on_node - UNCHANGED) ...
@app.route('/admin/blockchain_node_view')
@admin_required
def admin_view_blockchain_nodes():
    selected_node_id_str = request.args.get('node_index', '0')
    try:
        selected_node_idx = int(selected_node_id_str)
        if not (0 <= selected_node_idx < len(SIMULATED_NODES)): selected_node_idx = 0
    except ValueError:
        selected_node_idx = 0

    if not SIMULATED_NODES:
        flash("No simulated blockchain nodes are initialized.", "warning")
        return render_template('admin_blockchain_node_view.html', chain=None, node_id_disp="N/A",
                               is_valid=False, mempool=[], num_nodes=0, current_node_idx=0)
    target_node = SIMULATED_NODES[selected_node_idx]
    chain_is_valid = target_node.blockchain.is_chain_valid()
    flash_msg = f"Node {target_node.node_id}'s blockchain integrity check " + (
        "passed." if chain_is_valid else "FAILED!")
    flash_cat = "success" if chain_is_valid else "danger"
    flash(flash_msg, flash_cat)

    display_chain = [block.to_dict() for block in target_node.blockchain.chain]
    for block_dict in display_chain:  # Make data pretty for display
        block_dict['data_str'] = json.dumps(block_dict['data'], indent=2, sort_keys=True)

    return render_template('admin_blockchain_node_view.html',
                           chain=display_chain, node_id_disp=target_node.node_id,
                           is_valid=chain_is_valid, mempool=target_node.blockchain.pending_transactions,
                           current_chain_length=len(target_node.blockchain.chain),
                           difficulty=target_node.blockchain.difficulty,
                           num_nodes=len(SIMULATED_NODES), current_node_idx=selected_node_idx)


@app.route('/admin/mine_on_node/<int:node_idx>', methods=['POST'])
@admin_required
def admin_mine_on_node(node_idx):
    if not (0 <= node_idx < len(SIMULATED_NODES)):
        flash("Invalid node index.", "danger")
    else:
        target_node = SIMULATED_NODES[node_idx]
        if target_node.is_mining:
            flash(f"Node {target_node.node_id} is already mining.", "warning")
        elif not target_node.blockchain.pending_transactions:
            flash(f"Node {target_node.node_id} has no transactions to mine.", "info")
        else:
            mining_thread = threading.Thread(target=target_node.mine_block_task, daemon=True)
            mining_thread.start()
            flash(f"Mining initiated for Node {target_node.node_id}. Refresh to see updates.", "info")
    return redirect(url_for('admin_view_blockchain_nodes', node_index=node_idx))


# --- Main Execution ---
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s (%(module)s:%(lineno)d)')
    app.logger.handlers.clear()  # Avoid duplicate logs if re-running in some environments

    with app.app_context():
        if not os.path.exists(app.config['DATABASE']):
            app.logger.info(f"Database not found. Initializing at {app.config['DATABASE']}...")
            init_db()
        else:
            # Check if admin user exists, if not, try to init (useful if schema changes but db exists)
            db = get_db()
            admin_user_in_db = db.execute('SELECT id FROM admin WHERE username = ?', (ADMIN_USERNAME_ENV,)).fetchone()
            if not admin_user_in_db and ADMIN_PASSWORD_HASH_ENV:
                app.logger.info(
                    f"Admin user '{ADMIN_USERNAME_ENV}' not found in existing DB. Attempting to create from .env.")
                try:
                    db.execute('INSERT INTO admin (username, password) VALUES (?, ?)',
                               (ADMIN_USERNAME_ENV, ADMIN_PASSWORD_HASH_ENV))
                    db.commit()
                    app.logger.info(f"Admin user '{ADMIN_USERNAME_ENV}' created in existing DB.")
                except sqlite3.IntegrityError:
                    app.logger.warning(
                        f"Admin user '{ADMIN_USERNAME_ENV}' could not be inserted (likely already exists due to race or other issue).")
                except Exception as e:
                    app.logger.error(f"Error creating admin user in existing DB: {e}")
            elif not admin_user_in_db and not ADMIN_PASSWORD_HASH_ENV:
                app.logger.critical(
                    f"Admin user '{ADMIN_USERNAME_ENV}' not found in DB, and ADMIN_PASSWORD_HASH env var is NOT SET. Admin login will fail.")

            app.logger.info(f"Database found at {app.config['DATABASE']}.")

    app.logger.info("Starting Voting System Application with Simulated Decentralized PoW Blockchain...")
    app.run(debug=True, use_reloader=False)