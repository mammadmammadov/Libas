import os
import sqlite3
import json
import hashlib
import random
from functools import wraps
from datetime import datetime, date
from itertools import product as cartesian_product
from flask import Flask, render_template, request, jsonify, g, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'libas-dev-secret-key-change-in-production')
DATABASE = 'wardrobe.db'

# Database helpers

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("PRAGMA foreign_keys=OFF")  # Off during migration

    # Create users table first (no migration needed)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.commit()

    # Find admin user id for migrating existing data
    admin_row = db.execute("SELECT id FROM users WHERE is_admin = 1 ORDER BY id LIMIT 1").fetchone()
    admin_id = admin_row[0] if admin_row else 0

    # Migrate tables to per-user schema
    # Check if categories table needs migration by examining actual schema SQL
    # Handles both: (a) no user_id at all, (b) user_id added via ALTER TABLE but old UNIQUE(name) still there
    cat_sql_row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='categories'").fetchone()
    if cat_sql_row is None:
        needs_migration = False  # Table doesn't exist yet, will be created fresh below
    else:
        cat_sql = cat_sql_row[0]
        needs_migration = 'UNIQUE(user_id' not in cat_sql.replace(' ', '')

    if needs_migration:
        # Old tables exist without user_id — rebuild them
        db.executescript(f"""
            ALTER TABLE categories RENAME TO _old_categories;
            CREATE TABLE categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                allow_repeat INTEGER NOT NULL DEFAULT 0,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, name)
            );
            INSERT INTO categories (id, user_id, name, allow_repeat, sort_order, created_at)
                SELECT id, {admin_id}, name, allow_repeat, sort_order, created_at FROM _old_categories;
            DROP TABLE _old_categories;

            ALTER TABLE clothing_items RENAME TO _old_clothing_items;
            CREATE TABLE clothing_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                category_id INTEGER NOT NULL,
                color TEXT DEFAULT '',
                brand TEXT DEFAULT '',
                image_url TEXT DEFAULT '',
                active INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO clothing_items (id, user_id, name, category_id, color, brand, image_url, active, created_at)
                SELECT id, {admin_id}, name, category_id, color, brand, image_url, active, created_at FROM _old_clothing_items;
            DROP TABLE _old_clothing_items;

            ALTER TABLE outfit_history RENAME TO _old_outfit_history;
            CREATE TABLE outfit_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                outfit_hash TEXT NOT NULL,
                outfit_items TEXT NOT NULL,
                worn_date DATE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO outfit_history (id, user_id, outfit_hash, outfit_items, worn_date, created_at)
                SELECT id, {admin_id}, outfit_hash, outfit_items, worn_date, created_at FROM _old_outfit_history;
            DROP TABLE _old_outfit_history;

            ALTER TABLE excluded_outfits RENAME TO _old_excluded_outfits;
            CREATE TABLE excluded_outfits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                outfit_hash TEXT NOT NULL,
                outfit_items TEXT NOT NULL,
                excluded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, outfit_hash)
            );
            INSERT INTO excluded_outfits (id, user_id, outfit_hash, outfit_items, excluded_at)
                SELECT id, {admin_id}, outfit_hash, outfit_items, excluded_at FROM _old_excluded_outfits;
            DROP TABLE _old_excluded_outfits;

            ALTER TABLE pinned_items RENAME TO _old_pinned_items;
            CREATE TABLE pinned_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                item_id INTEGER NOT NULL,
                pin_date DATE NOT NULL,
                UNIQUE(user_id, item_id, pin_date)
            );
            INSERT INTO pinned_items (id, user_id, item_id, pin_date)
                SELECT id, {admin_id}, item_id, pin_date FROM _old_pinned_items;
            DROP TABLE _old_pinned_items;
        """)
    else:
        # Tables already have user_id — just ensure they exist
        db.executescript("""
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                allow_repeat INTEGER NOT NULL DEFAULT 0,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, name)
            );
            CREATE TABLE IF NOT EXISTS clothing_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                category_id INTEGER NOT NULL,
                color TEXT DEFAULT '',
                brand TEXT DEFAULT '',
                image_url TEXT DEFAULT '',
                active INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS outfit_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                outfit_hash TEXT NOT NULL,
                outfit_items TEXT NOT NULL,
                worn_date DATE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS excluded_outfits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                outfit_hash TEXT NOT NULL,
                outfit_items TEXT NOT NULL,
                excluded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, outfit_hash)
            );
            CREATE TABLE IF NOT EXISTS pinned_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                item_id INTEGER NOT NULL,
                pin_date DATE NOT NULL,
                UNIQUE(user_id, item_id, pin_date)
            );
        """)

    db.execute("PRAGMA foreign_keys=ON")
    db.commit()
    db.close()

def seed_default_categories(db, user_id):
    """Seed default wardrobe categories for a new user."""
    cursor = db.execute("SELECT COUNT(*) FROM categories WHERE user_id = ?", (user_id,))
    if cursor.fetchone()[0] == 0:
        defaults = [
            ('Tops', 0, 1), ('Bottoms', 0, 2), ('Shoes', 0, 3),
            ('Belts', 1, 4), ('Accessories', 1, 5), ('Outerwear', 0, 6)
        ]
        for name, allow_repeat, sort_order in defaults:
            db.execute(
                "INSERT INTO categories (user_id, name, allow_repeat, sort_order) VALUES (?, ?, ?, ?)",
                (user_id, name, allow_repeat, sort_order)
            )
        db.commit()

# Outfit generation logic

def compute_outfit_hash(item_ids):
    """Deterministic hash for a set of item IDs."""
    key = ','.join(str(i) for i in sorted(item_ids))
    return hashlib.sha256(key.encode()).hexdigest()[:16]

def generate_outfit(db, user_id, target_date=None, pinned_item_ids=None, skip_hashes=None):
    """
    Generate an outfit for the given date and user.
    - Avoids repeating yesterday's outfit
    - Avoids excluded outfits
    - Respects pinned items
    - Uses deterministic seeding from date for consistency, but allows re-rolls
    """
    if target_date is None:
        target_date = date.today().isoformat()
    if pinned_item_ids is None:
        pinned_item_ids = []
    if skip_hashes is None:
        skip_hashes = set()

    # Get all active categories that have items for this user
    categories = db.execute("""
        SELECT c.id, c.name, c.allow_repeat
        FROM categories c
        WHERE c.user_id = ? AND EXISTS (
            SELECT 1 FROM clothing_items ci
            WHERE ci.category_id = c.id AND ci.active = 1 AND ci.user_id = ?
        )
        ORDER BY c.sort_order
    """, (user_id, user_id)).fetchall()

    if not categories:
        return None

    # Get items per category
    cat_items = {}
    for cat in categories:
        items = db.execute(
            "SELECT id, name, color, brand FROM clothing_items WHERE category_id = ? AND active = 1 AND user_id = ?",
            (cat['id'], user_id)
        ).fetchall()
        if items:
            cat_items[cat['id']] = {
                'name': cat['name'],
                'allow_repeat': cat['allow_repeat'],
                'items': [dict(i) for i in items]
            }

    if not cat_items:
        return None

    # Get pinned items and their categories
    pinned_by_category = {}
    for pid in pinned_item_ids:
        item = db.execute(
            "SELECT id, name, color, brand, category_id FROM clothing_items WHERE id = ? AND active = 1 AND user_id = ?",
            (pid, user_id)
        ).fetchone()
        if item:
            pinned_by_category[item['category_id']] = dict(item)

    # Get yesterday's outfit
    yesterday_hash = None
    yesterday_row = db.execute(
        "SELECT outfit_hash FROM outfit_history WHERE user_id = ? AND worn_date = date(?, '-1 day')",
        (user_id, target_date)
    ).fetchone()
    if yesterday_row:
        yesterday_hash = yesterday_row['outfit_hash']

    # Get all excluded hashes
    excluded = set(r['outfit_hash'] for r in db.execute(
        "SELECT outfit_hash FROM excluded_outfits WHERE user_id = ?", (user_id,)
    ).fetchall())
    excluded.update(skip_hashes)

    # Build item pools per category, respecting pins
    pools = []
    pool_cat_ids = []
    for cat_id, info in sorted(cat_items.items()):
        if cat_id in pinned_by_category:
            pools.append([pinned_by_category[cat_id]])
        else:
            pools.append(info['items'])
        pool_cat_ids.append(cat_id)

    # Generate combinations using shuffled approach for efficiency
    # For small wardrobes, we can enumerate; for large ones, sample randomly
    total_combos = 1
    for p in pools:
        total_combos *= len(p)

    MAX_ENUMERATE = 50000

    if total_combos <= MAX_ENUMERATE:
        # Enumerate all, filter, pick randomly
        all_combos = list(cartesian_product(*pools))
        random.seed(f"{target_date}-{len(skip_hashes)}")
        random.shuffle(all_combos)

        for combo in all_combos:
            ids = [item['id'] for item in combo]
            h = compute_outfit_hash(ids)
            if h == yesterday_hash:
                continue
            if h in excluded:
                continue
            # Build outfit result
            outfit_items = []
            for i, item in enumerate(combo):
                cat_id = pool_cat_ids[i]
                outfit_items.append({
                    'item_id': item['id'],
                    'item_name': item['name'],
                    'item_color': item.get('color', ''),
                    'item_brand': item.get('brand', ''),
                    'category_id': cat_id,
                    'category_name': cat_items[cat_id]['name']
                })
            return {
                'hash': h,
                'items': outfit_items,
                'date': target_date
            }
    else:
        # Random sampling for large wardrobes
        attempts = 0
        random.seed(f"{target_date}-{len(skip_hashes)}")
        while attempts < 10000:
            combo = [random.choice(pool) for pool in pools]
            ids = [item['id'] for item in combo]
            h = compute_outfit_hash(ids)
            if h != yesterday_hash and h not in excluded:
                outfit_items = []
                for i, item in enumerate(combo):
                    cat_id = pool_cat_ids[i]
                    outfit_items.append({
                        'item_id': item['id'],
                        'item_name': item['name'],
                        'item_color': item.get('color', ''),
                        'item_brand': item.get('brand', ''),
                        'category_id': cat_id,
                        'category_name': cat_items[cat_id]['name']
                    })
                return {
                    'hash': h,
                    'items': outfit_items,
                    'date': target_date
                }
            attempts += 1

    return None  # All outfits exhausted

# Auth helpers

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login_page'))
        if not session.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

# Routes: Auth

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/api/auth/register', methods=['POST'])
def register():
    db = get_db()
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    # First user becomes admin
    user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    is_admin = 1 if user_count == 0 else 0

    try:
        db.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), is_admin)
        )
        db.commit()

        user = db.execute("SELECT id, username, is_admin FROM users WHERE username = ?", (username,)).fetchone()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['is_admin'] = bool(user['is_admin'])

        # Seed default categories for the new user
        seed_default_categories(db, user['id'])

        return jsonify({'success': True, 'username': username, 'is_admin': bool(is_admin)})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already taken'}), 400

@app.route('/api/auth/login', methods=['POST'])
def login():
    db = get_db()
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid username or password'}), 401

    session['user_id'] = user['id']
    session['username'] = user['username']
    session['is_admin'] = bool(user['is_admin'])

    return jsonify({'success': True, 'username': user['username'], 'is_admin': bool(user['is_admin'])})

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/auth/me', methods=['GET'])
@login_required
def auth_me():
    return jsonify({
        'user_id': session['user_id'],
        'username': session['username'],
        'is_admin': session.get('is_admin', False)
    })

@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def change_password():
    db = get_db()
    data = request.json
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')

    if not current_password or not new_password:
        return jsonify({'error': 'All fields are required'}), 400
    if len(new_password) < 6:
        return jsonify({'error': 'New password must be at least 6 characters'}), 400
    if current_password == new_password:
        return jsonify({'error': 'New password must be different from the current one'}), 400

    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not check_password_hash(user['password_hash'], current_password):
        return jsonify({'error': 'Current password is incorrect'}), 401

    db.execute('UPDATE users SET password_hash = ? WHERE id = ?',
               (generate_password_hash(new_password), session['user_id']))
    db.commit()
    return jsonify({'success': True})



# Routes: Admin

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_list_users():
    db = get_db()
    rows = db.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY created_at").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/admin/users/<int:user_id>/toggle-admin', methods=['PUT'])
@admin_required
def admin_toggle_admin(user_id):
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot change your own admin status'}), 400
    db = get_db()
    user = db.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    new_status = 0 if user['is_admin'] else 1
    db.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_status, user_id))
    db.commit()
    return jsonify({'success': True, 'is_admin': bool(new_status)})

@app.route('/api/admin/users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def admin_reset_password(user_id):
    data = request.json
    new_password = data.get('new_password', '')
    if not new_password:
        return jsonify({'error': 'New password is required'}), 400
    if len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               (generate_password_hash(new_password), user_id))
    db.commit()
    return jsonify({'success': True})


# Routes: Pages

@app.route('/')
@login_required
def index():
    return render_template('index.html')

# Routes: Categories API

@app.route('/api/categories', methods=['GET'])
@login_required
def get_categories():
    db = get_db()
    uid = session['user_id']
    rows = db.execute("SELECT * FROM categories WHERE user_id = ? ORDER BY sort_order", (uid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/categories', methods=['POST'])
@login_required
def add_category():
    db = get_db()
    uid = session['user_id']
    data = request.json
    name = data.get('name', '').strip()
    allow_repeat = 1 if data.get('allow_repeat', False) else 0
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    try:
        max_order = db.execute("SELECT COALESCE(MAX(sort_order), 0) FROM categories WHERE user_id = ?", (uid,)).fetchone()[0]
        db.execute(
            "INSERT INTO categories (user_id, name, allow_repeat, sort_order) VALUES (?, ?, ?, ?)",
            (uid, name, allow_repeat, max_order + 1)
        )
        db.commit()
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Category already exists'}), 400

@app.route('/api/categories/<int:cat_id>', methods=['PUT'])
@login_required
def update_category(cat_id):
    db = get_db()
    uid = session['user_id']
    data = request.json
    name = data.get('name', '').strip()
    allow_repeat = 1 if data.get('allow_repeat', False) else 0
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    db.execute(
        "UPDATE categories SET name = ?, allow_repeat = ? WHERE id = ? AND user_id = ?",
        (name, allow_repeat, cat_id, uid)
    )
    db.commit()
    return jsonify({'success': True})

@app.route('/api/categories/<int:cat_id>', methods=['DELETE'])
@login_required
def delete_category(cat_id):
    db = get_db()
    uid = session['user_id']
    db.execute("DELETE FROM categories WHERE id = ? AND user_id = ?", (cat_id, uid))
    db.commit()
    return jsonify({'success': True})

# Routes: Clothing Items API

@app.route('/api/items', methods=['GET'])
@login_required
def get_items():
    db = get_db()
    uid = session['user_id']
    rows = db.execute("""
        SELECT ci.*, c.name as category_name
        FROM clothing_items ci
        JOIN categories c ON ci.category_id = c.id
        WHERE ci.active = 1 AND ci.user_id = ?
        ORDER BY c.sort_order, ci.name
    """, (uid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/items', methods=['POST'])
@login_required
def add_item():
    db = get_db()
    uid = session['user_id']
    data = request.json
    name = data.get('name', '').strip()
    category_id = data.get('category_id')
    color = data.get('color', '').strip()
    brand = data.get('brand', '').strip()
    image_url = data.get('image_url', '').strip()
    if not name or not category_id:
        return jsonify({'error': 'Name and category are required'}), 400
    db.execute(
        "INSERT INTO clothing_items (user_id, name, category_id, color, brand, image_url) VALUES (?, ?, ?, ?, ?, ?)",
        (uid, name, category_id, color, brand, image_url)
    )
    db.commit()
    return jsonify({'success': True})

@app.route('/api/items/<int:item_id>', methods=['PUT'])
@login_required
def update_item(item_id):
    db = get_db()
    uid = session['user_id']
    data = request.json
    name = data.get('name', '').strip()
    category_id = data.get('category_id')
    color = data.get('color', '').strip()
    brand = data.get('brand', '').strip()
    image_url = data.get('image_url', '').strip()
    if not name or not category_id:
        return jsonify({'error': 'Name and category are required'}), 400
    db.execute(
        "UPDATE clothing_items SET name = ?, category_id = ?, color = ?, brand = ?, image_url = ? WHERE id = ? AND user_id = ?",
        (name, category_id, color, brand, image_url, item_id, uid)
    )
    db.commit()
    return jsonify({'success': True})

@app.route('/api/items/<int:item_id>', methods=['DELETE'])
@login_required
def delete_item(item_id):
    db = get_db()
    uid = session['user_id']
    db.execute("UPDATE clothing_items SET active = 0 WHERE id = ? AND user_id = ?", (item_id, uid))
    db.commit()
    return jsonify({'success': True})

# Routes: Outfit API

@app.route('/api/outfit/today', methods=['GET'])
@login_required
def get_today_outfit():
    db = get_db()
    uid = session['user_id']
    today = date.today().isoformat()

    # Check if we already have today's outfit in history
    existing = db.execute(
        "SELECT outfit_hash, outfit_items FROM outfit_history WHERE user_id = ? AND worn_date = ?",
        (uid, today)
    ).fetchone()
    if existing:
        items = json.loads(existing['outfit_items'])
        return jsonify({
            'hash': existing['outfit_hash'],
            'items': items,
            'date': today,
            'from_history': True
        })

    # Get pinned items for today
    pinned = db.execute(
        "SELECT item_id FROM pinned_items WHERE user_id = ? AND pin_date = ?", (uid, today)
    ).fetchall()
    pinned_ids = [r['item_id'] for r in pinned]

    outfit = generate_outfit(db, uid, today, pinned_ids)
    if outfit is None:
        return jsonify({'error': 'No valid outfit combinations available. Add more items!'}), 404

    return jsonify(outfit)

@app.route('/api/outfit/regenerate', methods=['POST'])
@login_required
def regenerate_outfit():
    db = get_db()
    uid = session['user_id']
    data = request.json or {}
    today = date.today().isoformat()

    # Remove today's saved outfit if any
    db.execute("DELETE FROM outfit_history WHERE user_id = ? AND worn_date = ?", (uid, today))
    db.commit()

    skip_hashes = set(data.get('skip_hashes', []))

    # Get pinned items
    pinned = db.execute(
        "SELECT item_id FROM pinned_items WHERE user_id = ? AND pin_date = ?", (uid, today)
    ).fetchall()
    pinned_ids = [r['item_id'] for r in pinned]

    outfit = generate_outfit(db, uid, today, pinned_ids, skip_hashes)
    if outfit is None:
        return jsonify({'error': 'All outfit combinations exhausted!'}), 404

    return jsonify(outfit)

@app.route('/api/outfit/accept', methods=['POST'])
@login_required
def accept_outfit():
    """Save the current outfit as today's worn outfit."""
    db = get_db()
    uid = session['user_id']
    data = request.json
    outfit_hash = data.get('hash')
    items = data.get('items')
    today = date.today().isoformat()

    if not outfit_hash or not items:
        return jsonify({'error': 'Invalid outfit data'}), 400

    # Remove any existing entry for today and insert new one
    db.execute("DELETE FROM outfit_history WHERE user_id = ? AND worn_date = ?", (uid, today))
    db.execute(
        "INSERT INTO outfit_history (user_id, outfit_hash, outfit_items, worn_date) VALUES (?, ?, ?, ?)",
        (uid, outfit_hash, json.dumps(items), today)
    )
    db.commit()
    return jsonify({'success': True})

@app.route('/api/outfit/exclude', methods=['POST'])
@login_required
def exclude_outfit():
    """Permanently exclude an outfit combination."""
    db = get_db()
    uid = session['user_id']
    data = request.json
    outfit_hash = data.get('hash')
    items = data.get('items')

    if not outfit_hash:
        return jsonify({'error': 'Hash required'}), 400

    try:
        db.execute(
            "INSERT INTO excluded_outfits (user_id, outfit_hash, outfit_items) VALUES (?, ?, ?)",
            (uid, outfit_hash, json.dumps(items or []))
        )
        db.commit()
    except sqlite3.IntegrityError:
        pass  # Already excluded
    return jsonify({'success': True})

@app.route('/api/outfit/excluded', methods=['GET'])
@login_required
def get_excluded():
    db = get_db()
    uid = session['user_id']
    rows = db.execute("SELECT * FROM excluded_outfits WHERE user_id = ? ORDER BY excluded_at DESC", (uid,)).fetchall()
    result = []
    for r in rows:
        entry = dict(r)
        entry['outfit_items'] = json.loads(entry['outfit_items'])
        result.append(entry)
    return jsonify(result)

@app.route('/api/outfit/excluded/<int:exc_id>', methods=['DELETE'])
@login_required
def remove_excluded(exc_id):
    db = get_db()
    uid = session['user_id']
    db.execute("DELETE FROM excluded_outfits WHERE id = ? AND user_id = ?", (exc_id, uid))
    db.commit()
    return jsonify({'success': True})

# Routes: Pinned Items API

@app.route('/api/pins', methods=['GET'])
@login_required
def get_pins():
    db = get_db()
    uid = session['user_id']
    today = date.today().isoformat()
    rows = db.execute("""
        SELECT p.id, p.item_id, p.pin_date, ci.name as item_name, c.name as category_name
        FROM pinned_items p
        JOIN clothing_items ci ON p.item_id = ci.id
        JOIN categories c ON ci.category_id = c.id
        WHERE p.user_id = ? AND p.pin_date = ?
    """, (uid, today)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/pins', methods=['POST'])
@login_required
def add_pin():
    db = get_db()
    uid = session['user_id']
    data = request.json
    item_id = data.get('item_id')
    today = date.today().isoformat()
    if not item_id:
        return jsonify({'error': 'Item ID required'}), 400
    try:
        db.execute("INSERT INTO pinned_items (user_id, item_id, pin_date) VALUES (?, ?, ?)", (uid, item_id, today))
        db.commit()
    except sqlite3.IntegrityError:
        pass
    return jsonify({'success': True})

@app.route('/api/pins/<int:pin_id>', methods=['DELETE'])
@login_required
def remove_pin(pin_id):
    db = get_db()
    uid = session['user_id']
    db.execute("DELETE FROM pinned_items WHERE id = ? AND user_id = ?", (pin_id, uid))
    db.commit()
    return jsonify({'success': True})

# Routes: History API

@app.route('/api/history', methods=['GET'])
@login_required
def get_history():
    db = get_db()
    uid = session['user_id']
    rows = db.execute(
        "SELECT * FROM outfit_history WHERE user_id = ? ORDER BY worn_date DESC LIMIT 30",
        (uid,)
    ).fetchall()
    result = []
    for r in rows:
        entry = dict(r)
        entry['outfit_items'] = json.loads(entry['outfit_items'])
        result.append(entry)
    return jsonify(result)

# Routes: Stats

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    db = get_db()
    uid = session['user_id']
    total_items = db.execute("SELECT COUNT(*) FROM clothing_items WHERE active = 1 AND user_id = ?", (uid,)).fetchone()[0]
    total_categories = db.execute("SELECT COUNT(*) FROM categories WHERE user_id = ?", (uid,)).fetchone()[0]
    total_outfits_worn = db.execute("SELECT COUNT(*) FROM outfit_history WHERE user_id = ?", (uid,)).fetchone()[0]
    total_excluded = db.execute("SELECT COUNT(*) FROM excluded_outfits WHERE user_id = ?", (uid,)).fetchone()[0]
    return jsonify({
        'total_items': total_items,
        'total_categories': total_categories,
        'total_outfits_worn': total_outfits_worn,
        'total_excluded': total_excluded
    })

#  Startup 

# Always initialise DB (works with both `python app.py` and gunicorn)
with app.app_context():
    init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug, host='0.0.0.0', port=port)
