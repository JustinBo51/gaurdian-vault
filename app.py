import os, re, sqlite3, secrets, mimetypes
from datetime import datetime, date
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_from_directory, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get('GUARDIAN_VAULT_DATA', BASE_DIR / 'instance'))
UPLOAD_DIR = DATA_DIR / 'private_uploads'
DB_PATH = DATA_DIR / 'guardian_vault.sqlite3'
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
try:
    os.chmod(DATA_DIR, 0o700)
    os.chmod(UPLOAD_DIR, 0o700)
except OSError:
    pass  # Some hosted filesystems do not support POSIX permission bits.

app = Flask(__name__, instance_path=str(DATA_DIR), instance_relative_config=True)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '0') == '1',
)
ALLOWED_EXTENSIONS = {'pdf','doc','docx','txt','rtf','jpg','jpeg','png','webp','gif','mp3','m4a','wav','ogg','mp4','mov','webm','csv','xlsx'}


def now_iso(): return datetime.now().astimezone().isoformat(timespec='seconds')
def connect_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys = ON')
    db.execute('PRAGMA journal_mode = WAL')
    return db


def init_db():
    with connect_db() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE,
          display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cases (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          title TEXT NOT NULL, jurisdiction TEXT DEFAULT '', case_number TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'Active',
          notes TEXT DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS children (
          id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
          name TEXT NOT NULL, date_of_birth TEXT DEFAULT '', notes TEXT DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS records (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
          record_type TEXT NOT NULL DEFAULT 'Note', title TEXT NOT NULL, event_date TEXT NOT NULL,
          event_time TEXT DEFAULT '', participants TEXT DEFAULT '', location TEXT DEFAULT '', details TEXT DEFAULT '',
          source_label TEXT DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_records_case_date ON records(case_id, event_date DESC, id DESC);
        CREATE INDEX IF NOT EXISTS idx_records_user ON records(user_id);
        CREATE TABLE IF NOT EXISTS attachments (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
          record_id INTEGER REFERENCES records(id) ON DELETE SET NULL,
          original_name TEXT NOT NULL, stored_name TEXT NOT NULL UNIQUE, mime_type TEXT NOT NULL,
          size_bytes INTEGER NOT NULL, description TEXT DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_attachments_case ON attachments(case_id);
        ''')

init_db()

@app.before_request
def setup_request():
    g.db = connect_db()
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)

@app.teardown_request
def close_db(exc):
    db = g.pop('db', None)
    if db is not None: db.close()

@app.context_processor
def inject_globals():
    return {'csrf_token': session.get('csrf_token', ''), 'current_user': get_user(), 'today': date.today().isoformat()}

def get_user():
    uid = session.get('user_id')
    if not uid: return None
    return g.db.execute('SELECT id,email,display_name,created_at FROM users WHERE id=?', (uid,)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please sign in to continue.', 'info')
            return redirect(url_for('login', next=request.path))
        return fn(*args, **kwargs)
    return wrapped

def verify_csrf():
    supplied = request.form.get('csrf_token', '')
    if not supplied or not secrets.compare_digest(supplied, session.get('csrf_token', '')):
        abort(400, description='The form security token is missing or expired. Refresh the page and try again.')

def owned_case(case_id):
    row = g.db.execute('SELECT * FROM cases WHERE id=? AND user_id=?', (case_id, session.get('user_id'))).fetchone()
    if not row: abort(404)
    return row

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def record_types():
    return ['Note','Communication','Visit','Incident','Appointment','Court Hearing','Deadline','Case Plan','Request / Response','Other']

@app.route('/')
def index():
    if not session.get('user_id'): return render_template('landing.html')
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        verify_csrf()
        name = request.form.get('display_name','').strip()[:100]
        email = request.form.get('email','').strip().lower()[:254]
        password = request.form.get('password','')
        if len(password) > 1024:
            flash('Password is too long.', 'error')
            return render_template('auth.html', mode='register')
        if not name or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
            flash('Enter your name and a valid email address.', 'error')
        elif len(password) < 12:
            flash('Use a password with at least 12 characters.', 'error')
        else:
            try:
                cur = g.db.execute('INSERT INTO users(email,display_name,password_hash,created_at) VALUES(?,?,?,?)',
                                   (email,name,generate_password_hash(password),now_iso()))
                g.db.commit()
                session.clear(); session['user_id'] = cur.lastrowid; session['csrf_token'] = secrets.token_urlsafe(32)
                flash('Your private workspace is ready. Add your first case to get started.', 'success')
                return redirect(url_for('dashboard'))
            except sqlite3.IntegrityError:
                flash('An account with that email already exists.', 'error')
    return render_template('auth.html', mode='register')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        verify_csrf()
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        if len(password) > 1024:
            flash('Email or password was not recognized.', 'error')
            return render_template('auth.html', mode='login')
        user = g.db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        if not user or not check_password_hash(user['password_hash'], password):
            flash('Email or password was not recognized.', 'error')
        else:
            session.clear(); session['user_id'] = user['id']; session['csrf_token'] = secrets.token_urlsafe(32)
            return redirect(url_for('dashboard'))
    return render_template('auth.html', mode='login')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    verify_csrf(); session.clear(); return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    cases = g.db.execute('SELECT c.*, (SELECT COUNT(*) FROM records r WHERE r.case_id=c.id) AS record_count, (SELECT COUNT(*) FROM attachments a WHERE a.case_id=c.id) AS file_count FROM cases c WHERE c.user_id=? ORDER BY c.updated_at DESC', (session['user_id'],)).fetchall()
    upcoming = g.db.execute('''SELECT r.*, c.title AS case_title FROM records r JOIN cases c ON c.id=r.case_id
       WHERE r.user_id=? AND r.event_date>=? AND r.record_type IN ('Appointment','Court Hearing','Deadline')
       ORDER BY r.event_date, r.event_time LIMIT 6''', (session['user_id'], date.today().isoformat())).fetchall()
    recent = g.db.execute('''SELECT r.*, c.title AS case_title FROM records r JOIN cases c ON c.id=r.case_id
       WHERE r.user_id=? ORDER BY r.event_date DESC, r.id DESC LIMIT 8''', (session['user_id'],)).fetchall()
    stats = {
      'cases': len(cases),
      'records': g.db.execute('SELECT COUNT(*) FROM records WHERE user_id=?',(session['user_id'],)).fetchone()[0],
      'files': g.db.execute('SELECT COUNT(*) FROM attachments WHERE user_id=?',(session['user_id'],)).fetchone()[0],
      'upcoming': len(upcoming)
    }
    return render_template('dashboard.html', cases=cases, upcoming=upcoming, recent=recent, stats=stats)

@app.route('/cases/new', methods=['GET','POST'])
@login_required
def new_case():
    if request.method == 'POST':
        verify_csrf()
        title = request.form.get('title','').strip()[:180]
        if not title:
            flash('A case name is required.', 'error')
        else:
            stamp=now_iso()
            cur=g.db.execute('INSERT INTO cases(user_id,title,jurisdiction,case_number,status,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',
              (session['user_id'],title,request.form.get('jurisdiction','').strip()[:160],request.form.get('case_number','').strip()[:120],request.form.get('status','Active'),request.form.get('notes','').strip(),stamp,stamp))
            g.db.commit(); flash('Case created.', 'success'); return redirect(url_for('case_detail', case_id=cur.lastrowid))
    return render_template('case_form.html', case=None)

@app.route('/cases/<int:case_id>')
@login_required
def case_detail(case_id):
    case=owned_case(case_id)
    records=g.db.execute('SELECT * FROM records WHERE case_id=? AND user_id=? ORDER BY event_date DESC,event_time DESC,id DESC LIMIT 30',(case_id,session['user_id'])).fetchall()
    files=g.db.execute('SELECT * FROM attachments WHERE case_id=? AND user_id=? ORDER BY created_at DESC LIMIT 12',(case_id,session['user_id'])).fetchall()
    children=g.db.execute('SELECT * FROM children WHERE case_id=? ORDER BY name',(case_id,)).fetchall()
    counts={'records':g.db.execute('SELECT COUNT(*) FROM records WHERE case_id=?',(case_id,)).fetchone()[0], 'files':g.db.execute('SELECT COUNT(*) FROM attachments WHERE case_id=?',(case_id,)).fetchone()[0]}
    return render_template('case_detail.html',case=case,records=records,files=files,children=children,counts=counts)

@app.route('/cases/<int:case_id>/edit', methods=['GET','POST'])
@login_required
def edit_case(case_id):
    case=owned_case(case_id)
    if request.method=='POST':
        verify_csrf(); title=request.form.get('title','').strip()[:180]
        if not title: flash('A case name is required.','error')
        else:
            g.db.execute('UPDATE cases SET title=?,jurisdiction=?,case_number=?,status=?,notes=?,updated_at=? WHERE id=? AND user_id=?',
             (title,request.form.get('jurisdiction','').strip()[:160],request.form.get('case_number','').strip()[:120],request.form.get('status','Active'),request.form.get('notes','').strip(),now_iso(),case_id,session['user_id']))
            g.db.commit(); flash('Case updated.','success'); return redirect(url_for('case_detail',case_id=case_id))
    return render_template('case_form.html',case=case)

@app.route('/cases/<int:case_id>/children/add', methods=['POST'])
@login_required
def add_child(case_id):
    owned_case(case_id); verify_csrf(); name=request.form.get('name','').strip()[:160]
    if name:
        g.db.execute('INSERT INTO children(case_id,name,date_of_birth,notes,created_at) VALUES(?,?,?,?,?)',(case_id,name,request.form.get('date_of_birth','').strip(),request.form.get('notes','').strip(),now_iso())); g.db.commit(); flash('Child record added.','success')
    else: flash('Enter a name.','error')
    return redirect(url_for('case_detail',case_id=case_id))

@app.route('/cases/<int:case_id>/records/new', methods=['GET','POST'])
@login_required
def new_record(case_id):
    case=owned_case(case_id)
    if request.method=='POST':
        verify_csrf(); title=request.form.get('title','').strip()[:200]; rtype=request.form.get('record_type','Note')
        if rtype not in record_types(): rtype='Note'
        event_date=request.form.get('event_date','').strip() or date.today().isoformat()
        if not title: flash('A title is required.','error')
        else:
            stamp=now_iso(); cur=g.db.execute('''INSERT INTO records(user_id,case_id,record_type,title,event_date,event_time,participants,location,details,source_label,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',(session['user_id'],case_id,rtype,title,event_date,request.form.get('event_time','').strip(),request.form.get('participants','').strip(),request.form.get('location','').strip(),request.form.get('details','').strip(),request.form.get('source_label','').strip(),stamp,stamp))
            record_id=cur.lastrowid
            upload=request.files.get('file')
            if upload and upload.filename:
                if not allowed_file(upload.filename):
                    g.db.rollback(); flash('Unsupported file type. The record was not saved with that file.','error'); return redirect(url_for('new_record',case_id=case_id))
                safe=secure_filename(upload.filename) or 'upload'; stored=f'{secrets.token_hex(16)}_{safe}'
                path=UPLOAD_DIR/stored; upload.save(path)
                g.db.execute('INSERT INTO attachments(user_id,case_id,record_id,original_name,stored_name,mime_type,size_bytes,description,created_at) VALUES(?,?,?,?,?,?,?,?,?)',
                  (session['user_id'],case_id,record_id,upload.filename[:255],stored,upload.mimetype or mimetypes.guess_type(safe)[0] or 'application/octet-stream',path.stat().st_size,'',stamp))
            g.db.execute('UPDATE cases SET updated_at=? WHERE id=?',(stamp,case_id)); g.db.commit(); flash('Timeline record saved.','success'); return redirect(url_for('case_detail',case_id=case_id))
    return render_template('record_form.html',case=case,record_types=record_types())

@app.route('/cases/<int:case_id>/files/upload', methods=['POST'])
@login_required
def upload_file(case_id):
    owned_case(case_id); verify_csrf(); upload=request.files.get('file')
    if not upload or not upload.filename: flash('Choose a file first.','error')
    elif not allowed_file(upload.filename): flash('That file type is not supported.','error')
    else:
        safe=secure_filename(upload.filename) or 'upload'; stored=f'{secrets.token_hex(16)}_{safe}'; path=UPLOAD_DIR/stored; upload.save(path)
        g.db.execute('INSERT INTO attachments(user_id,case_id,original_name,stored_name,mime_type,size_bytes,description,created_at) VALUES(?,?,?,?,?,?,?,?)',
          (session['user_id'],case_id,upload.filename[:255],stored,upload.mimetype or mimetypes.guess_type(safe)[0] or 'application/octet-stream',path.stat().st_size,request.form.get('description','').strip()[:500],now_iso()))
        g.db.commit(); flash('File added to the private case library.','success')
    return redirect(url_for('case_detail',case_id=case_id))

@app.route('/files/<int:file_id>')
@login_required
def download_file(file_id):
    item=g.db.execute('SELECT * FROM attachments WHERE id=? AND user_id=?',(file_id,session['user_id'])).fetchone()
    if not item: abort(404)
    # Force download; uploaded HTML/SVG content is never served inline.
    response=send_from_directory(UPLOAD_DIR,item['stored_name'],as_attachment=True,download_name=item['original_name'],mimetype='application/octet-stream')
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Cache-Control']='private, no-store'
    return response

@app.route('/timeline')
@login_required
def timeline():
    cases=g.db.execute('SELECT id,title FROM cases WHERE user_id=? ORDER BY title',(session['user_id'],)).fetchall()
    case_id=request.args.get('case_id','').strip(); q=request.args.get('q','').strip()[:120]; start=request.args.get('start','').strip(); end=request.args.get('end','').strip(); rtype=request.args.get('type','').strip()
    sql='SELECT r.*, c.title AS case_title FROM records r JOIN cases c ON c.id=r.case_id WHERE r.user_id=?'; params=[session['user_id']]
    if case_id.isdigit(): sql+=' AND r.case_id=?'; params.append(int(case_id))
    if q: sql+=' AND (r.title LIKE ? OR r.details LIKE ? OR r.participants LIKE ? OR r.source_label LIKE ?)'; params.extend([f'%{q}%']*4)
    if start: sql+=' AND r.event_date>=?'; params.append(start)
    if end: sql+=' AND r.event_date<=?'; params.append(end)
    if rtype in record_types(): sql+=' AND r.record_type=?'; params.append(rtype)
    sql+=' ORDER BY r.event_date DESC,r.event_time DESC,r.id DESC LIMIT 300'
    rows=g.db.execute(sql,params).fetchall()
    return render_template('timeline.html',rows=rows,cases=cases,filters={'case_id':case_id,'q':q,'start':start,'end':end,'type':rtype},record_types=record_types())

@app.route('/search')
@login_required
def search():
    q=request.args.get('q','').strip()[:120]
    if not q: return render_template('search.html',q='',records=[],files=[])
    like=f'%{q}%'
    records=g.db.execute('SELECT r.*,c.title AS case_title FROM records r JOIN cases c ON c.id=r.case_id WHERE r.user_id=? AND (r.title LIKE ? OR r.details LIKE ? OR r.participants LIKE ? OR r.source_label LIKE ?) ORDER BY r.event_date DESC LIMIT 100',(session['user_id'],like,like,like,like)).fetchall()
    files=g.db.execute('SELECT a.*,c.title AS case_title FROM attachments a JOIN cases c ON c.id=a.case_id WHERE a.user_id=? AND (a.original_name LIKE ? OR a.description LIKE ?) ORDER BY a.created_at DESC LIMIT 100',(session['user_id'],like,like)).fetchall()
    return render_template('search.html',q=q,records=records,files=files)

@app.errorhandler(413)
def too_large(_): return render_template('error.html',code=413,message='That file exceeds the 25 MB upload limit.'),413
@app.errorhandler(400)
def bad_request(error): return render_template('error.html',code=400,message=getattr(error,'description','The request could not be processed.')),400
@app.errorhandler(404)
def not_found(_): return render_template('error.html',code=404,message='The page or record could not be found.'),404

if __name__ == '__main__':
    # Use a production WSGI server for deployment; Flask debug mode is intentionally disabled.
    app.run(host=os.environ.get('HOST','0.0.0.0'), port=int(os.environ.get('PORT','5000')), debug=False)
