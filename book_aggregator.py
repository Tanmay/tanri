from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database setup
def init_db():
    with sqlite3.connect('books.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            is_subscribed INTEGER DEFAULT 0
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            image_url TEXT,
            description TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS book_stores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            book_id INTEGER,
            store_name TEXT NOT NULL,
            price REAL,
            url TEXT,
            FOREIGN KEY (book_id) REFERENCES books(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            book_id INTEGER,
            user_id INTEGER,
            rating INTEGER,
            comment TEXT,
            FOREIGN KEY (book_id) REFERENCES books(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        # Insert default admin (username: admin, password: admin123)
        c.execute('INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                 ('admin', generate_password_hash('admin123'), 1))
        # Insert sample books with image and description
        c.execute('INSERT OR IGNORE INTO books (title, author, image_url, description) VALUES (?, ?, ?, ?)',
                 ('Your Book Title 1', 'Your Name', 'https://via.placeholder.com/150', 'A captivating tale of adventure and discovery, perfect for readers of all ages.'))
        c.execute('INSERT OR IGNORE INTO book_stores (book_id, store_name, price, url) VALUES (?, ?, ?, ?)',
                 (1, 'Amazon', 19.99, 'https://www.amazon.com/your-book-url'))
        c.execute('INSERT OR IGNORE INTO book_stores (book_id, store_name, price, url) VALUES (?, ?, ?, ?)',
                 (1, 'Google Books', 14.99, 'https://books.google.com/your-book-url'))
        c.execute('INSERT OR IGNORE INTO book_stores (book_id, store_name, price, url) VALUES (?, ?, ?, ?)',
                 (1, 'Etsy', 24.99, 'https://www.etsy.com/your-book-url'))
        c.execute('INSERT OR IGNORE INTO book_stores (book_id, store_name, price, url) VALUES (?, ?, ?, ?)',
                 (1, 'Pothi.com', 17.99, 'https://www.pothi.com/your-book-url'))
        # Insert more sample books for pagination testing
        for i in range(2, 12):
            c.execute('INSERT OR IGNORE INTO books (title, author, image_url, description) VALUES (?, ?, ?, ?)',
                     (f'Book Title {i}', f'Author {i}', 'https://via.placeholder.com/150', f'Description for Book {i}.'))
            c.execute('INSERT OR IGNORE INTO book_stores (book_id, store_name, price, url) VALUES (?, ?, ?, ?)',
                     (i, 'Amazon', 19.99 + i, f'https://www.amazon.com/book-{i}-url'))
        conn.commit()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in as admin.', 'error')
            return redirect(url_for('login'))
        with sqlite3.connect('books.db') as conn:
            c = conn.cursor()
            c.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],))
            if not c.fetchone()[0]:
                flash('Admin access required.', 'error')
                return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/', methods=['GET', 'POST'])
def index():
    search_query = request.form.get('search', '') if request.method == 'POST' else request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Number of books per page
    offset = (page - 1) * per_page

    with sqlite3.connect('books.db') as conn:
        c = conn.cursor()
        # Count total books for pagination
        if search_query.strip():
            c.execute('SELECT COUNT(*) FROM books WHERE title LIKE ? OR author LIKE ?',
                     (f'%{search_query}%', f'%{search_query}%'))
        else:
            c.execute('SELECT COUNT(*) FROM books')
        total_books = c.fetchone()[0]
        total_pages = (total_books + per_page - 1) // per_page

        # Fetch books for current page
        if search_query.strip():
            c.execute('SELECT * FROM books WHERE title LIKE ? OR author LIKE ? LIMIT ? OFFSET ?',
                     (f'%{search_query}%', f'%{search_query}%', per_page, offset))
        else:
            c.execute('SELECT * FROM books LIMIT ? OFFSET ?', (per_page, offset))
        books = c.fetchall()
        book_data = []
        for book in books:
            c.execute('SELECT * FROM book_stores WHERE book_id = ?', (book[0],))
            stores = c.fetchall()
            c.execute('SELECT r.*, u.username FROM reviews r JOIN users u ON r.user_id = u.id WHERE r.book_id = ?', (book[0],))
            reviews = c.fetchall()
            user_review = None
            if 'user_id' in session:
                c.execute('SELECT id, rating, comment FROM reviews WHERE book_id = ? AND user_id = ?', (book[0], session['user_id']))
                user_review = c.fetchone()
            book_data.append({'book': book, 'stores': stores, 'reviews': reviews, 'user_review': user_review})
    return render_template('index.html', books=book_data, search_query=search_query,
                          page=page, total_pages=total_pages, per_page=per_page, total_books=total_books)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('books.db') as conn:
            c = conn.cursor()
            try:
                c.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                         (username, generate_password_hash(password)))
                conn.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username already exists.', 'error')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('books.db') as conn:
            c = conn.cursor()
            c.execute('SELECT id, password, is_admin FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            if user and check_password_hash(user[1], password):
                session['user_id'] = user[0]
                session['is_admin'] = user[2]
                flash('Logged in successfully!', 'success')
                return redirect(url_for('index'))
            flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/subscribe', methods=['POST'])
@login_required
def subscribe():
    with sqlite3.connect('books.db') as conn:
        c = conn.cursor()
        c.execute('UPDATE users SET is_subscribed = 1 WHERE id = ?', (session['user_id'],))
        conn.commit()
    flash('Subscribed successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/review/<int:book_id>', methods=['POST'])
@login_required
def review(book_id):
    if not session.get('is_subscribed'):
        flash('You must be subscribed to post a review.', 'error')
        return redirect(url_for('index'))
    rating = request.form['rating']
    comment = request.form['comment'].strip()
    # Validate rating and comment
    try:
        rating = int(rating)
        if rating < 1 or rating > 5:
            flash('Rating must be between 1 and 5.', 'error')
            return redirect(url_for('index'))
        if not comment:
            flash('Comment cannot be empty.', 'error')
            return redirect(url_for('index'))
    except ValueError:
        flash('Invalid rating value.', 'error')
        return redirect(url_for('index'))
    with sqlite3.connect('books.db') as conn:
        c = conn.cursor()
        # Check if user already has a review for this book
        c.execute('SELECT id FROM reviews WHERE book_id = ? AND user_id = ?', (book_id, session['user_id']))
        existing_review = c.fetchone()
        if existing_review:
            # Update existing review
            c.execute('UPDATE reviews SET rating = ?, comment = ? WHERE id = ?',
                     (rating, comment, existing_review[0]))
            flash('Review updated successfully!', 'success')
        else:
            # Insert new review
            c.execute('INSERT INTO reviews (book_id, user_id, rating, comment) VALUES (?, ?, ?, ?)',
                     (book_id, session['user_id'], rating, comment))
            flash('Review posted successfully!', 'success')
        conn.commit()
    return redirect(url_for('index'))

@app.route('/delete_review/<int:review_id>', methods=['POST'])
@login_required
def delete_review_user(review_id):
    with sqlite3.connect('books.db') as conn:
        c = conn.cursor()
        c.execute('SELECT user_id FROM reviews WHERE id = ?', (review_id,))
        review = c.fetchone()
        if review and review[0] == session['user_id']:
            c.execute('DELETE FROM reviews WHERE id = ?', (review_id,))
            conn.commit()
            flash('Your review was deleted successfully.', 'success')
        else:
            flash('You can only delete your own reviews.', 'error')
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    if request.method == 'POST':
        if 'add_book' in request.form:
            title = request.form['title']
            author = request.form['author']
            image_url = request.form['image_url']
            description = request.form['description']
            with sqlite3.connect('books.db') as conn:
                c = conn.cursor()
                c.execute('INSERT INTO books (title, author, image_url, description) VALUES (?, ?, ?, ?)',
                         (title, author, image_url, description))
                conn.commit()
            flash('Book added successfully!', 'success')
        elif 'add_store' in request.form:
            book_id = request.form['book_id']
            store_name = request.form['store_name']
            price = request.form['price']
            url = request.form['url']
            try:
                price = float(price)
                if price < 0:
                    flash('Price cannot be negative.', 'error')
                    return redirect(url_for('admin'))
                if not store_name.strip():
                    flash('Store name cannot be empty.', 'error')
                    return redirect(url_for('admin'))
                if not url.strip():
                    flash('URL cannot be empty.', 'error')
                    return redirect(url_for('admin'))
                with sqlite3.connect('books.db') as conn:
                    c = conn.cursor()
                    c.execute('INSERT INTO book_stores (book_id, store_name, price, url) VALUES (?, ?, ?, ?)',
                             (book_id, store_name, price, url))
                    conn.commit()
                flash('Store listing added successfully!', 'success')
            except ValueError:
                flash('Invalid price value.', 'error')
        return redirect(url_for('admin'))
    with sqlite3.connect('books.db') as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users')
        users = c.fetchall()
        c.execute('SELECT * FROM books')
        books = c.fetchall()
        c.execute('SELECT * FROM book_stores')
        stores = c.fetchall()
        c.execute('SELECT r.*, u.username, b.title FROM reviews r JOIN users u ON r.user_id = u.id JOIN books b ON r.book_id = b.id')
        reviews = c.fetchall()
    return render_template('admin.html', users=users, books=books, stores=stores, reviews=reviews)

@app.route('/admin/edit_store/<int:store_id>', methods=['GET', 'POST'])
@admin_required
def edit_store(store_id):
    with sqlite3.connect('books.db') as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM book_stores WHERE id = ?', (store_id,))
        store = c.fetchone()
        c.execute('SELECT * FROM books')
        books = c.fetchall()
        if not store:
            flash('Store listing not found.', 'error')
            return redirect(url_for('admin'))
        if request.method == 'POST':
            book_id = request.form['book_id']
            store_name = request.form['store_name']
            price = request.form['price']
            url = request.form['url']
            try:
                price = float(price)
                if price < 0:
                    flash('Price cannot be negative.', 'error')
                    return redirect(url_for('edit_store', store_id=store_id))
                if not store_name.strip():
                    flash('Store name cannot be empty.', 'error')
                    return redirect(url_for('edit_store', store_id=store_id))
                if not url.strip():
                    flash('URL cannot be empty.', 'error')
                    return redirect(url_for('edit_store', store_id=store_id))
                c.execute('UPDATE book_stores SET book_id = ?, store_name = ?, price = ?, url = ? WHERE id = ?',
                         (book_id, store_name, price, url, store_id))
                conn.commit()
                flash('Store listing updated successfully!', 'success')
                return redirect(url_for('admin'))
            except ValueError:
                flash('Invalid price value.', 'error')
                return redirect(url_for('edit_store', store_id=store_id))
    return render_template('edit_store.html', store=store, books=books)

@app.route('/admin/delete_user/<int:user_id>')
@admin_required
def delete_user(user_id):
    with sqlite3.connect('books.db') as conn:
        c = conn.cursor()
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        c.execute('DELETE FROM reviews WHERE user_id = ?', (user_id,))
        conn.commit()
    flash('User deleted.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete_book/<int:book_id>')
@admin_required
def delete_book(book_id):
    with sqlite3.connect('books.db') as conn:
        c = conn.cursor()
        c.execute('DELETE FROM books WHERE id = ?', (book_id,))
        c.execute('DELETE FROM book_stores WHERE book_id = ?', (book_id,))
        c.execute('DELETE FROM reviews WHERE book_id = ?', (book_id,))
        conn.commit()
    flash('Book deleted.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete_store/<int:store_id>')
@admin_required
def delete_store(store_id):
    with sqlite3.connect('books.db') as conn:
        c = conn.cursor()
        c.execute('DELETE FROM book_stores WHERE id = ?', (store_id,))
        conn.commit()
    flash('Store listing deleted.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete_review/<int:review_id>')
@admin_required
def delete_review(review_id):
    with sqlite3.connect('books.db') as conn:
        c = conn.cursor()
        c.execute('DELETE FROM reviews WHERE id = ?', (review_id,))
        conn.commit()
    flash('Review deleted.', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    init_db()
    #app.run(host='127.0.0.1', port=5000, debug=False)
    app.run(host='https://tanri.onrender.com')