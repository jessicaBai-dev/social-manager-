#!/usr/bin/env python3
"""
Social Manager - local approval app.

Run:
    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt
    .venv/bin/python server.py
    # then open http://127.0.0.1:8080
    # for a company server: HOST=0.0.0.0 .venv/bin/python server.py

Python 3.9 compatible. Only dependency is Flask.
No credentials, tokens or API keys are stored in this file.
Settings (including any API key) live only in the local SQLite
database file, are masked in the UI, and are never written to code.
"""
import hashlib
import html
import json
import os
import re
import secrets
import sqlite3
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from functools import wraps
from uuid import uuid4

from flask import (
    Flask, abort, flash, g, redirect, render_template_string,
    request, send_from_directory, session, url_for,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SOCIAL_MANAGER_DB") or os.path.join(BASE_DIR, "social.db")
UPLOAD_DIR = os.environ.get("SOCIAL_MANAGER_UPLOADS") or os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTS = {"jpg", "jpeg", "png", "webp", "gif", "mp4", "mov"}

# Platforms, in the order Aman named them.
# The subtype list is the platform-specific field for each destination.
PLATFORMS = {
    "linkedin": {
        "label": "LinkedIn",
        "subtypes": ["Company Page", "Personal profile"],
        "destination_hint": "e.g. company page name, or personal profile name",
        "publish_note": (
            "Live publishing to LinkedIn needs a LinkedIn API connection and "
            "access token for that company page / profile. No token is assumed "
            "present. An approved post stays Ready to Publish until it is "
            "published externally and its live link is recorded here."
        ),
        "token_key": "linkedin_access_token",
    },
    "instagram": {
        "label": "Instagram",
        "subtypes": ["Feed", "Reel", "Story", "Carousel"],
        "destination_hint": "e.g. Instagram account handle",
        "publish_note": (
            "Live publishing to Instagram via the Meta Graph API needs a "
            "professional / business Instagram account and an access token. "
            "A personal account (for example Aman's linked @onlyamanahmed "
            "in Muse) is not assumed to work for live publishing. No token "
            "is assumed present. An approved post stays Ready to Publish "
            "until it is published externally and its live link is recorded."
        ),
        "token_key": "meta_access_token",
    },
    "facebook": {
        "label": "Facebook",
        "subtypes": ["Page post", "Personal post"],
        "destination_hint": "e.g. Facebook Page name, or personal profile name",
        "publish_note": (
            "Live publishing to Facebook needs a Page access token for the "
            "Page being posted to. No token is assumed present. An approved "
            "post stays Ready to Publish until it is published externally "
            "and its live link is recorded here."
        ),
        "token_key": "meta_access_token",
    },
    "company_portal": {
        "label": "Company Portal",
        "subtypes": ["Portal post"],
        "destination_hint": (
            "Portal name, if different from the portal configured in Settings"
        ),
        "publish_note": (
            "A Company Portal is configurable, not a fixed network. Set the "
            "portal name and endpoint / upload target in Settings (admin "
            "only). Until then, an approved post stays Ready to Publish. "
            "Once configured, an admin can mark it Handed off to Portal "
            "with a reference, instead of claiming an automatic publish."
        ),
        "token_key": "portal_api_key",
    },
}

STATUSES = {
    "pending": "Pending Approval",
    "changes_requested": "Changes Requested",
    "rejected": "Rejected",
    "ready_to_publish": "Ready to Publish",
    "published": "Published",
    "handed_off": "Handed off to Portal",
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024
app.secret_key = os.environ.get("SOCIAL_MANAGER_SECRET") or secrets.token_hex(32)


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'manager', 'viewer')),
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            caption TEXT NOT NULL,
            hashtags TEXT DEFAULT '',
            platform TEXT NOT NULL,
            subtype TEXT DEFAULT '',
            destination TEXT DEFAULT '',
            scheduled_at TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            media_filename TEXT DEFAULT '',
            media_original TEXT DEFAULT '',
            media_mimetype TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            review_comment TEXT DEFAULT '',
            live_url TEXT DEFAULT '',
            publish_note TEXT DEFAULT '',
            created_by TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            post_id INTEGER,
            detail TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
            content TEXT NOT NULL,
            post_id INTEGER,
            created_at TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 salt.encode("utf-8"), 200000).hex()
    return salt + "$" + digest


def verify_password(password, stored):
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               salt.encode("utf-8"), 200000).hex()
    return secrets.compare_digest(calc, digest)


def get_setting(key):
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else ""


def set_setting(key, value):
    conn = get_db()
    conn.execute(
        "INSERT INTO settings(key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()


def mask(value):
    if not value:
        return "Not set"
    if len(value) <= 4:
        return "****"
    return "****" + value[-4:]


def audit(actor, action, post_id, detail=""):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log(actor, action, post_id, detail, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (actor, action, post_id, detail, now_iso()),
    )
    conn.commit()


def user_count():
    conn = get_db()
    row = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
    return row["n"]


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM users WHERE id = ? AND is_active = 1", (uid,)).fetchone()
    return row


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def check_csrf():
    token = request.form.get("csrf_token", "")
    if not token or token != session.get("csrf"):
        abort(400, "Invalid form token. Please go back and try again.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def manager_or_admin(view):
    # Approval actions: manager normally, admin only as a logged override.
    # Server-side: viewers are blocked here, not just hidden in the UI.
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] not in ("admin", "manager"):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


ACTIVITY_ACTIONS = (
    "draft_created", "chat_draft_created", "approve",
    "admin_override_approve", "reject", "request_changes", "edit",
    "resubmit", "mark_published", "hand_off_portal", "user_created",
)


def call_llm(messages):
    """Call the configured OpenAI-compatible endpoint.

    Returns (text, error). error is not None when no key is configured
    or the call fails, so callers never have to fake a reply.
    """
    base_url = get_setting("llm_base_url").strip()
    model = get_setting("llm_model").strip()
    api_key = get_setting("llm_api_key").strip()
    if not base_url or not model or not api_key:
        return None, "No LLM endpoint, model or key is set in Settings."
    endpoint = base_url
    if not endpoint.endswith("/chat/completions"):
        endpoint = endpoint.rstrip("/") + "/chat/completions"
    payload = json.dumps({
        "model": model, "messages": messages, "temperature": 0.7,
    }).encode("utf-8")
    req = urllib.request.Request(
        endpoint, data=payload,
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + api_key},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        return result["choices"][0]["message"]["content"], None
    except Exception as exc:
        return None, "LLM request failed: %s" % exc


def save_chat_message(user, role, content, post_id=None):
    conn = get_db()
    conn.execute(
        "INSERT INTO chat_messages(user_id, username, role, content, post_id, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user["id"], user["username"], role, content, post_id, now_iso()))
    conn.commit()

# ------------------------------------------------------------------- html
CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
 max-width:980px;margin:0 auto;padding:20px;color:#1a1a1a;line-height:1.5}
nav a{margin-right:14px} nav{margin:12px 0 20px}
.card{border:1px solid #ddd;border-radius:10px;padding:14px;margin:12px 0}
label{display:block;margin:10px 0 4px;font-weight:600}
input[type=text],input[type=password],input[type=datetime-local],
select,textarea{width:100%;padding:8px;box-sizing:border-box}
textarea{min-height:110px} button{padding:9px 16px;cursor:pointer}
.flash{border:1px solid #c9a227;background:#fff8dc;padding:10px;border-radius:8px}
table{border-collapse:collapse;width:100%} td,th{border:1px solid #ddd;
 padding:7px;text-align:left;vertical-align:top}
.muted{color:#666} .pill{display:inline-block;background:#eef;padding:2px 8px;
 border-radius:20px;font-size:13px} img,video{max-width:100%}
"""

BASE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} - Social Manager</title><style>""" + CSS + """</style></head>
<body><h1>Social Manager</h1>
{% if user %}
<nav>
<a href="{{ url_for('dashboard') }}">Dashboard</a>
{% if user['role'] == 'admin' %}<a href="{{ url_for('create_post') }}">Create Post</a>{% endif %}
<a href="{{ url_for('queue') }}">Approval Queue</a>
<a href="{{ url_for('activity_page') }}">Activity</a>
<a href="{{ url_for('chat_page') }}">Agent Chat</a>
{% if user['role'] == 'admin' %}<a href="{{ url_for('publish_queue') }}">Publish Queue</a>{% endif %}
<a href="{{ url_for('history') }}">Published / History</a>
{% if user['role'] == 'admin' %}
<a href="{{ url_for('users_page') }}">Team</a>
<a href="{{ url_for('audit_page') }}">Audit Log</a>
<a href="{{ url_for('settings_page') }}">Settings</a>
{% endif %}
<a href="{{ url_for('logout') }}">Logout ({{ user['username'] }} - {{ user['role'] }})</a>
</nav>
{% endif %}
{% with msgs = get_flashed_messages() %}{% if msgs %}
{% for m in msgs %}<div class="flash">{{ m }}</div>{% endfor %}{% endif %}{% endwith %}
{{ body|safe }}
<p class="muted">Local app only. Nothing here publishes automatically.
Approved posts stay Ready to Publish until a live link is recorded
(or, for a Company Portal, a handoff is recorded) by an admin.</p>
</body></html>"""


def page(title, body, user=None):
    return render_template_string(BASE, title=title, body=body, user=user)


def esc(value):
    return html.escape(str(value or ""))


def status_label(status):
    return STATUSES.get(status, status)


def post_card(post, user, show_actions=True):
    media = ""
    if post["media_filename"]:
        url = url_for("uploaded_file", filename=post["media_filename"])
        if (post["media_mimetype"] or "").startswith("video"):
            media = '<video controls src="%s"></video>' % esc(url)
        else:
            media = '<img src="%s" alt="Post media">' % esc(url)
    platform = PLATFORMS.get(post["platform"], {})
    body = '<div class="card"><p><span class="pill">%s</span> ' % esc(status_label(post["status"]))
    body += '<strong>%s</strong>' % esc(platform.get("label", post["platform"]))
    if post["subtype"]:
        body += ' - ' + esc(post["subtype"])
    if post["destination"]:
        body += ' - ' + esc(post["destination"])
    body += '</p><p>%s</p>' % esc(post["caption"]).replace("\n", "<br>")
    if post["hashtags"]:
        body += '<p class="muted">%s</p>' % esc(post["hashtags"])
    if post["scheduled_at"]:
        body += '<p class="muted">Scheduled: %s</p>' % esc(post["scheduled_at"])
    if post["notes"]:
        body += '<p class="muted">Notes: %s</p>' % esc(post["notes"])
    if post["review_comment"]:
        body += '<p><strong>Review comment:</strong> %s</p>' % esc(post["review_comment"])
    if post["live_url"]:
        body += '<p><strong>Live link:</strong> <a href="%s">%s</a></p>' % (
            esc(post["live_url"]), esc(post["live_url"]))
    if post["publish_note"]:
        body += '<p><strong>Publish note:</strong> %s</p>' % esc(post["publish_note"])
    body += '<p class="muted">By %s - created %s - updated %s</p>' % (
        esc(post["created_by"]), esc(post["created_at"]), esc(post["updated_at"]))
    body += media
    if show_actions and post["status"] in ("pending", "changes_requested"):
        body += """
        <form method="post" action="%s">
        <input type="hidden" name="csrf_token" value="%s">
        <label>Review comment (required to reject or request changes)</label>
        <textarea name="comment"></textarea>
        <button type="submit" name="action" value="approve">Approve</button>
        <button type="submit" name="action" value="changes">Request Changes</button>
        <button type="submit" name="action" value="reject">Reject</button>
        </form>""" % (url_for("review_post", post_id=post["id"]), csrf_token())
        if user and user["role"] == "admin":
            body += '<p class="muted">As admin, approving here is recorded in the audit log as an admin override.</p>'
    body += "</div>"
    return body


def publish_explanation(post):
    info = PLATFORMS.get(post["platform"], {})
    token_key = info.get("token_key", "")
    token = get_setting(token_key) if token_key else ""
    note = info.get("publish_note", "")
    if post["platform"] == "company_portal":
        portal_name = get_setting("portal_name")
        portal_endpoint = get_setting("portal_endpoint")
        if portal_name and portal_endpoint:
            note += (" Configured portal: %s (%s). An admin can mark this "
                     "Handed off to Portal with a reference." % (portal_name, portal_endpoint))
        else:
            note += " Portal name / endpoint are not configured in Settings yet."
    elif token:
        note += " A token is stored in Settings, but automatic publishing is NOT implemented in this local build - do not treat the stored token as a live publish. Record a live link only after publishing externally."
    else:
        note += " No publishing token is configured in Settings, so this post stays Ready to Publish."
    return note


# ------------------------------------------------------------------- auth
@app.route("/setup", methods=["GET", "POST"])
def setup():
    if user_count() > 0:
        return redirect(url_for("login"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.")
        else:
            conn = get_db()
            conn.execute(
                "INSERT INTO users(username, password_hash, role, created_at) "
                "VALUES (?, ?, 'admin', ?)",
                (username, hash_password(password), now_iso()),
            )
            conn.commit()
            audit(username, "admin_created", None, "First admin account created on setup")
            flash("Admin account created. Please log in.")
            return redirect(url_for("login"))
    body = """
    <h2>First-time setup - create the Admin account</h2>
    <p>This is Aman (Admin). After this, use Users (admin only) to create the
    social media manager account. The manager gets her own login and password.</p>
    <form method="post">
    <label>Admin username</label><input type="text" name="username" required>
    <label>Admin password</label><input type="password" name="password" required>
    <button type="submit">Create admin account</button></form>"""
    return page("Setup", body, user=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    if user_count() == 0:
        return redirect(url_for("setup"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username,)).fetchone()
        if row and verify_password(password, row["password_hash"]):
            session["user_id"] = row["id"]
            session["csrf"] = secrets.token_hex(16)
            audit(username, "login", None, "Logged in")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
    body = """
    <h2>Log in</h2><form method="post">
    <label>Username</label><input type="text" name="username" required>
    <label>Password</label><input type="password" name="password" required>
    <button type="submit">Log in</button></form>
    <p class="muted">No account yet? If this is a fresh install, visit Setup to create the admin account first.</p>"""
    return page("Log in", body, user=None)


@app.route("/logout")
def logout():
    user = current_user()
    if user:
        audit(user["username"], "logout", None, "Logged out")
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))


# -------------------------------------------------------------- dashboard
@app.route("/")
@login_required
def dashboard():
    user = current_user()
    conn = get_db()
    counts = {}
    for row in conn.execute(
            "SELECT status, COUNT(*) AS n FROM posts GROUP BY status"):
        counts[row["status"]] = row["n"]
    recent = conn.execute(
        "SELECT * FROM posts ORDER BY id DESC LIMIT 5").fetchall()
    body = "<h2>Dashboard</h2><table><tr><th>Status</th><th>Count</th></tr>"
    for key in ("pending", "changes_requested", "rejected",
                "ready_to_publish", "published", "handed_off"):
        body += "<tr><td>%s</td><td>%d</td></tr>" % (
            esc(status_label(key)), counts.get(key, 0))
    body += "</table><h3>Latest posts</h3>"
    for post in recent:
        body += post_card(post, user, show_actions=False)
    if not recent:
        body += "<p>No posts yet.</p>"
    if user["role"] == "manager":
        body += ('<p class="muted">Manager view: approval queue, activity and '
                 'published history. Settings, Team and Audit Log are admin-only.</p>')
    if user["role"] == "viewer":
        body += ('<p class="muted">Viewer view: read-only. You can see activity '
                 'and published posts, but you cannot create, approve, publish '
                 'or change anything.</p>')
    return page("Dashboard", body, user=user)

# ------------------------------------------------------------ create post
@app.route("/create", methods=["GET", "POST"])
@admin_required
def create_post():
    user = current_user()
    llm_url = get_setting("llm_base_url")
    llm_model = get_setting("llm_model")
    llm_key = get_setting("llm_api_key")
    llm_ready = bool(llm_url and llm_model and llm_key)
    if request.method == "POST":
        check_csrf()
        caption = request.form.get("caption", "").strip()
        platform = request.form.get("platform", "")
        if not caption or platform not in PLATFORMS:
            flash("Caption and a valid platform are required.")
        else:
            filename = ""
            original = ""
            mimetype = ""
            upload = request.files.get("media")
            if upload and upload.filename:
                ext = upload.filename.rsplit(".", 1)[-1].lower() if "." in upload.filename else ""
                if ext not in ALLOWED_EXTS:
                    flash("Unsupported media type. Use an image or video file.")
                    return redirect(url_for("create_post"))
                filename = uuid4().hex + "." + ext
                upload.save(os.path.join(UPLOAD_DIR, filename))
                original = upload.filename
                mimetype = upload.mimetype or ""
            conn = get_db()
            cur = conn.execute(
                "INSERT INTO posts(caption, hashtags, platform, subtype, "
                "destination, scheduled_at, notes, media_filename, "
                "media_original, media_mimetype, status, created_by, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                "'pending', ?, ?, ?)",
                (caption, request.form.get("hashtags", "").strip(), platform,
                 request.form.get("subtype", "").strip(),
                 request.form.get("destination", "").strip(),
                 request.form.get("scheduled_at", "").strip(),
                 request.form.get("notes", "").strip(), filename, original,
                 mimetype, user["username"], now_iso(), now_iso()),
            )
            post_id = cur.lastrowid
            conn.commit()
            audit(user["username"], "draft_created", post_id,
                  "Draft created for %s (%s)" % (
                      PLATFORMS[platform]["label"],
                      request.form.get("subtype", "").strip()))
            flash("Draft created and sent to Pending Approval.")
            return redirect(url_for("queue"))
    options = "".join(
        '<option value="%s">%s</option>' % (k, v["label"])
        for k, v in PLATFORMS.items())
    subtype_json = json.dumps(
        {k: v["subtypes"] for k, v in PLATFORMS.items()})
    hint_json = json.dumps(
        {k: v["destination_hint"] for k, v in PLATFORMS.items()})
    llm_block = ""
    if llm_ready:
        llm_block = """
        <div class="card"><h3>Agent / LLM draft help</h3>
        <p>An OpenAI-compatible endpoint, model and key are set in Settings.</p>
        <label>Topic for the draft</label><input type="text" id="llm-topic">
        <button type="button" onclick="generateDraft()">Generate draft text</button>
        <p id="llm-status" class="muted"></p></div>
        <script>
        function generateDraft(){
          var topic=document.getElementById('llm-topic').value;
          var st=document.getElementById('llm-status');
          st.textContent='Generating...';
          fetch('/llm-draft',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({topic:topic,platform:document.getElementById('platform').value})})
          .then(function(r){return r.json();})
          .then(function(d){
            if(d.error){st.textContent=d.error;return;}
            document.getElementById('caption').value=d.caption||'';
            document.getElementById('hashtags').value=d.hashtags||'';
            st.textContent='Draft filled in - check it, edit it, then save. Nothing was published.';
          }).catch(function(){st.textContent='LLM request failed. You can still type the draft manually.';});
        }</script>"""
    else:
        llm_block = """
        <div class="card"><h3>Agent / LLM draft help</h3>
        <p class="muted">No LLM key is set in Settings, so LLM drafting is off.
        Manual draft creation below still works fully - nothing is blocked.</p></div>"""
    body = """
    <h2>Create Post</h2>%s
    <form method="post" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="%s">
    <label>Platform</label>
    <select name="platform" id="platform" onchange="updateSubtypes()">%s</select>
    <label>Platform type</label><select name="subtype" id="subtype"></select>
    <label>Destination</label><input type="text" name="destination" id="destination">
    <p class="muted" id="destination-hint"></p>
    <label>Caption</label><textarea name="caption" id="caption" required></textarea>
    <label>Hashtags</label><input type="text" name="hashtags" id="hashtags">
    <label>Media upload (image or video, optional)</label>
    <input type="file" name="media" accept="image/*,video/*">
    <label>Scheduled time</label><input type="datetime-local" name="scheduled_at">
    <label>Notes for the manager (not published)</label>
    <textarea name="notes"></textarea>
    <button type="submit">Save draft - send to approval</button></form>
    <script>
    var SUBTYPES=%s; var HINTS=%s;
    function updateSubtypes(){
      var p=document.getElementById('platform').value;
      var s=document.getElementById('subtype'); s.innerHTML='';
      SUBTYPES[p].forEach(function(v){var o=document.createElement('option');o.value=v;o.textContent=v;s.appendChild(o);});
      document.getElementById('destination-hint').textContent=HINTS[p]||'';
    }
    updateSubtypes();
    </script>""" % (llm_block, csrf_token(), options, subtype_json, hint_json)
    return page("Create Post", body, user=user)


@app.route("/llm-draft", methods=["POST"])
@admin_required
def llm_draft():
    data = request.get_json(silent=True) or {}
    topic = (data.get("topic") or "").strip()
    platform = data.get("platform") or "instagram"
    base_url = get_setting("llm_base_url").strip()
    model = get_setting("llm_model").strip()
    api_key = get_setting("llm_api_key").strip()
    if not topic:
        return {"error": "Enter a topic first."}, 400
    if not base_url or not model or not api_key:
        return {"error": (
            "No LLM endpoint, model or key is set in Settings. "
            "Type the draft manually - manual creation is not blocked.")}, 400
    endpoint = base_url
    if not endpoint.endswith("/chat/completions"):
        endpoint = endpoint.rstrip("/") + "/chat/completions"
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": (
                "Write a short social media caption for the given platform. "
                "Return the caption, then a line starting with HASHTAGS: "
                "followed by hashtags.")},
            {"role": "user", "content": "Platform: %s. Topic: %s" % (
                PLATFORMS.get(platform, {}).get("label", platform), topic)},
        ],
        "temperature": 0.7,
    }).encode("utf-8")
    req = urllib.request.Request(
        endpoint, data=payload,
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + api_key},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return {"error": "LLM request failed: %s. Type the draft manually." % exc}, 502
    try:
        text = result["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return {"error": "LLM returned an unexpected response. Type the draft manually."}, 502
    caption = text
    hashtags = ""
    if "HASHTAGS:" in text:
        caption, hashtags = text.split("HASHTAGS:", 1)
        hashtags = hashtags.strip()
    return {"caption": caption.strip(), "hashtags": hashtags}


# ------------------------------------------------------------ approval queue
@app.route("/queue")
@login_required
def queue():
    user = current_user()
    conn = get_db()
    posts = conn.execute(
        "SELECT * FROM posts WHERE status IN ('pending', 'changes_requested') "
        "ORDER BY id DESC").fetchall()
    body = "<h2>Approval Queue</h2><p>Only Approved posts move to Ready to Publish. Nothing here publishes automatically.</p>"
    if user["role"] == "viewer":
        body += "<p class='muted'>Viewer view: read-only, no approve / reject buttons.</p>"
    for post in posts:
        body += post_card(post, user, show_actions=(user["role"] != "viewer"))
    if not posts:
        body += "<p>No posts waiting for approval.</p>"
    return page("Approval Queue", body, user=user)


@app.route("/posts/<int:post_id>/review", methods=["POST"])
@manager_or_admin
def review_post(post_id):
    user = current_user()
    check_csrf()
    action = request.form.get("action", "")
    comment = request.form.get("comment", "").strip()
    conn = get_db()
    post = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    if not post:
        abort(404)
    if post["status"] not in ("pending", "changes_requested"):
        flash("That post is not waiting for approval.")
        return redirect(url_for("queue"))
    if action in ("reject", "changes") and not comment:
        flash("A comment is required to reject or request changes.")
        return redirect(url_for("queue"))
    if action == "approve":
        new_status = "ready_to_publish"
        if user["role"] == "admin":
            audit_action = "admin_override_approve"
            detail = "Admin override approval. Comment: " + comment
        else:
            audit_action = "approve"
            detail = "Approved by manager. Comment: " + comment
        flash("Approved. The post is now Ready to Publish - it has NOT been published yet.")
    elif action == "changes":
        new_status = "changes_requested"
        audit_action = "request_changes"
        detail = "Changes requested. Comment: " + comment
        flash("Changes requested. The draft goes back to the agent/admin to revise.")
    elif action == "reject":
        new_status = "rejected"
        audit_action = "reject"
        detail = "Rejected. Comment: " + comment
        flash("Post rejected.")
    else:
        flash("Unknown review action.")
        return redirect(url_for("queue"))
    conn.execute(
        "UPDATE posts SET status = ?, review_comment = ?, updated_at = ? WHERE id = ?",
        (new_status, comment, now_iso(), post_id))
    conn.commit()
    audit(user["username"], audit_action, post_id, detail)
    return redirect(url_for("queue"))


@app.route("/posts/<int:post_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_post(post_id):
    user = current_user()
    conn = get_db()
    post = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    if not post:
        abort(404)
    if request.method == "POST":
        check_csrf()
        old_status = post["status"]
        conn.execute(
            "UPDATE posts SET caption = ?, hashtags = ?, platform = ?, "
            "subtype = ?, destination = ?, scheduled_at = ?, notes = ?, "
            "status = 'pending', updated_at = ? WHERE id = ?",
            (request.form.get("caption", "").strip(),
             request.form.get("hashtags", "").strip(),
             request.form.get("platform", post["platform"]),
             request.form.get("subtype", "").strip(),
             request.form.get("destination", "").strip(),
             request.form.get("scheduled_at", "").strip(),
             request.form.get("notes", "").strip(), now_iso(), post_id))
        conn.commit()
        if old_status in ("changes_requested", "rejected"):
            audit(user["username"], "resubmit", post_id,
                  "Revised after %s and resubmitted to Pending Approval" % old_status)
            flash("Revised draft resubmitted to Pending Approval.")
        else:
            audit(user["username"], "edit", post_id, "Draft edited")
            flash("Draft updated.")
        return redirect(url_for("queue"))
    body = """
    <h2>Revise draft</h2>
    <p>Revising a Changes Requested or Rejected draft sends it back to Pending Approval.</p>
    <form method="post">
    <input type="hidden" name="csrf_token" value="%s">
    <label>Platform</label><select name="platform">%s</select>
    <label>Platform type</label><input type="text" name="subtype" value="%s">
    <label>Destination</label><input type="text" name="destination" value="%s">
    <label>Caption</label><textarea name="caption" required>%s</textarea>
    <label>Hashtags</label><input type="text" name="hashtags" value="%s">
    <label>Scheduled time</label><input type="text" name="scheduled_at" value="%s">
    <label>Notes</label><textarea name="notes">%s</textarea>
    <button type="submit">Save and resubmit for approval</button></form>""" % (
        csrf_token(),
        "".join('<option value="%s"%s>%s</option>' % (
            k, ' selected' if k == post["platform"] else '', v["label"])
            for k, v in PLATFORMS.items()),
        esc(post["subtype"]), esc(post["destination"]), esc(post["caption"]),
        esc(post["hashtags"]), esc(post["scheduled_at"]), esc(post["notes"]))
    return page("Revise draft", body, user=user)

# --------------------------------------------------------- publish / history
@app.route("/publish")
@admin_required
def publish_queue():
    user = current_user()
    conn = get_db()
    posts = conn.execute(
        "SELECT * FROM posts WHERE status = 'ready_to_publish' "
        "ORDER BY id DESC").fetchall()
    body = "<h2>Publish Queue - Ready to Publish</h2>"
    body += ("<p>These posts are approved, but they have NOT been published. "
             "This app does not publish automatically. If a publishing token "
             "is missing, the post stays here with a plain note about what "
             "is missing.</p>")
    for post in posts:
        body += post_card(post, user, show_actions=False)
        body += '<div class="card"><p>%s</p>' % esc(publish_explanation(post))
        if post["platform"] == "company_portal":
            body += """
            <form method="post" action="%s">
            <input type="hidden" name="csrf_token" value="%s">
            <label>Portal handoff reference (e.g. portal post ID / upload confirmation)</label>
            <input type="text" name="reference" required>
            <button type="submit" name="action" value="hand_off">Mark Handed off to Portal</button></form>""" % (
                url_for("publish_post", post_id=post["id"]), csrf_token())
        body += """
        <form method="post" action="%s">
        <input type="hidden" name="csrf_token" value="%s">
        <label>Live link (only after you have published it externally, e.g. in the network's own tools)</label>
        <input type="text" name="live_url" placeholder="https://..." required>
        <button type="submit" name="action" value="mark_published">Record as Published with this live link</button></form></div>""" % (
            url_for("publish_post", post_id=post["id"]), csrf_token())
    if not posts:
        body += "<p>No approved posts waiting to publish.</p>"
    return page("Publish Queue", body, user=user)


@app.route("/posts/<int:post_id>/publish", methods=["POST"])
@admin_required
def publish_post(post_id):
    user = current_user()
    check_csrf()
    action = request.form.get("action", "")
    conn = get_db()
    post = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    if not post:
        abort(404)
    if post["status"] != "ready_to_publish":
        flash("Only Ready to Publish posts can be recorded as published or handed off.")
        return redirect(url_for("publish_queue"))
    if action == "hand_off":
        if post["platform"] != "company_portal":
            flash("Handoff is only for Company Portal posts.")
            return redirect(url_for("publish_queue"))
        reference = request.form.get("reference", "").strip()
        if not reference:
            flash("A portal handoff reference is required.")
            return redirect(url_for("publish_queue"))
        conn.execute(
            "UPDATE posts SET status = 'handed_off', publish_note = ?, updated_at = ? WHERE id = ?",
            ("Handed off to Company Portal. Reference: " + reference, now_iso(), post_id))
        conn.commit()
        audit(user["username"], "hand_off_portal", post_id,
              "Marked handed off to Company Portal. Reference: " + reference)
        flash("Post marked Handed off to Portal. This is a handoff record, not an automatic publish.")
    elif action == "mark_published":
        live_url = request.form.get("live_url", "").strip()
        if not live_url.startswith("http://") and not live_url.startswith("https://"):
            flash("Enter a full live link starting with http:// or https://.")
            return redirect(url_for("publish_queue"))
        conn.execute(
            "UPDATE posts SET status = 'published', live_url = ?, updated_at = ? WHERE id = ?",
            (live_url, now_iso(), post_id))
        conn.commit()
        audit(user["username"], "mark_published", post_id,
              "Recorded as published with live link: " + live_url)
        flash("Recorded as Published with the live link you entered.")
    else:
        flash("Unknown publish action.")
    return redirect(url_for("history"))


@app.route("/history")
@login_required
def history():
    user = current_user()
    conn = get_db()
    posts = conn.execute(
        "SELECT * FROM posts WHERE status IN ('published', 'handed_off', 'rejected') "
        "ORDER BY id DESC").fetchall()
    body = "<h2>Published / History</h2>"
    for post in posts:
        body += post_card(post, user, show_actions=False)
        if user["role"] == "admin" and post["status"] == "rejected":
            body += '<p><a href="%s">Revise and resubmit this rejected draft</a></p>' % url_for("edit_post", post_id=post["id"])
    if not posts:
        body += "<p>No published, handed-off, or rejected posts yet.</p>"
    return page("Published / History", body, user=user)


@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    # Only files created by this app (uuid names) are served, from uploads/.
    if ".." in filename or "/" in filename:
        abort(404)
    return send_from_directory(UPLOAD_DIR, filename)


# -------------------------------------------------------------- users/audit
@app.route("/users", methods=["GET", "POST"])
@app.route("/team", methods=["GET", "POST"])
@admin_required
def users_page():
    user = current_user()
    if request.method == "POST":
        check_csrf()
        form_action = request.form.get("form_action", "create")
        conn = get_db()
        if form_action == "create":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "manager")
            if role not in ("admin", "manager", "viewer"):
                role = "manager"
            if not username or not password:
                flash("Username and password are required.")
            else:
                try:
                    conn.execute(
                        "INSERT INTO users(username, password_hash, role, created_at) "
                        "VALUES (?, ?, ?, ?)",
                        (username, hash_password(password), role, now_iso()))
                    conn.commit()
                except sqlite3.IntegrityError:
                    flash("That username already exists.")
                    return redirect(url_for("users_page"))
                audit(user["username"], "user_created", None,
                      "Created %s account: %s" % (role, username))
                flash("Account created for %s (%s)." % (username, role))
        else:
            try:
                target_id = int(request.form.get("target_id", "0"))
            except ValueError:
                target_id = 0
            target = conn.execute("SELECT * FROM users WHERE id = ?", (target_id,)).fetchone()
            if not target:
                flash("Team member not found.")
                return redirect(url_for("users_page"))
            if form_action == "reset_password":
                new_password = request.form.get("new_password", "")
                if not new_password:
                    flash("Enter a new password.")
                else:
                    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                                 (hash_password(new_password), target_id))
                    conn.commit()
                    audit(user["username"], "password_reset", None,
                          "Password reset for account: %s" % target["username"])
                    flash("Password reset for %s." % target["username"])
            elif form_action == "deactivate":
                if target_id == user["id"]:
                    flash("You cannot deactivate your own account.")
                else:
                    conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (target_id,))
                    conn.commit()
                    audit(user["username"], "user_deactivated", None,
                          "Deactivated (removed) account: %s" % target["username"])
                    flash("Removed (deactivated) %s. They can no longer log in." % target["username"])
            elif form_action == "reactivate":
                conn.execute("UPDATE users SET is_active = 1 WHERE id = ?", (target_id,))
                conn.commit()
                audit(user["username"], "user_reactivated", None,
                      "Reactivated account: %s" % target["username"])
                flash("Reactivated %s." % target["username"])
            elif form_action == "delete":
                if target_id == user["id"]:
                    flash("You cannot delete your own account.")
                else:
                    conn.execute("DELETE FROM users WHERE id = ?", (target_id,))
                    conn.commit()
                    audit(user["username"], "user_deleted", None,
                          "Deleted account: %s" % target["username"])
                    flash("Deleted %s." % target["username"])
            else:
                flash("Unknown team action.")
        return redirect(url_for("users_page"))
    conn = get_db()
    rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    body = """
    <h2>Team (admin only)</h2>
    <p>Admin (Aman) creates team accounts here. Passwords are stored hashed,
    never in plain text. Every account change below is audit-logged.
    Give each person their username and password in person or by a channel
    you trust.</p>
    <p class="muted">Roles: Admin = full control, creates accounts, sees audit
    log and settings. Manager = approves / rejects / requests changes, sees
    approval queue and activity. Viewer = read-only, sees activity and
    published posts, changes nothing.</p>
    <form method="post">
    <input type="hidden" name="csrf_token" value="%s">
    <input type="hidden" name="form_action" value="create">
    <label>Username / login</label><input type="text" name="username" required>
    <label>Password</label><input type="password" name="password" required>
    <label>Role</label><select name="role">
    <option value="manager">Manager (approves posts)</option>
    <option value="viewer">Viewer (read-only)</option>
    <option value="admin">Admin</option></select>
    <button type="submit">Create team account</button></form>
    <table><tr><th>Username</th><th>Role</th><th>Active</th><th>Created</th><th>Actions</th></tr>""" % csrf_token()
    for row in rows:
        reset_form = ('<form method="post" style="display:inline">'
                      '<input type="hidden" name="csrf_token" value="%s">'
                      '<input type="hidden" name="form_action" value="reset_password">'
                      '<input type="hidden" name="target_id" value="%d">'
                      '<input type="password" name="new_password" placeholder="New password" required> '
                      '<button type="submit">Reset password</button></form>') % (csrf_token(), row["id"])
        toggle_action = "reactivate" if not row["is_active"] else "deactivate"
        toggle_label = "Reactivate" if not row["is_active"] else "Remove"
        toggle_form = ('<form method="post" style="display:inline">'
                       '<input type="hidden" name="csrf_token" value="%s">'
                       '<input type="hidden" name="form_action" value="%s">'
                       '<input type="hidden" name="target_id" value="%d">'
                       '<button type="submit">%s</button></form>') % (csrf_token(), toggle_action, row["id"], toggle_label)
        delete_form = ('<form method="post" style="display:inline">'
                       '<input type="hidden" name="csrf_token" value="%s">'
                       '<input type="hidden" name="form_action" value="delete">'
                       '<input type="hidden" name="target_id" value="%d">'
                       '<button type="submit">Delete</button></form>') % (csrf_token(), row["id"])
        body += "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s %s %s</td></tr>" % (
            esc(row["username"]), esc(row["role"]), "Yes" if row["is_active"] else "No",
            esc(row["created_at"]), reset_form, toggle_form, delete_form)
    body += "</table>"
    return page("Team", body, user=user)


@app.route("/audit")
@admin_required
def audit_page():
    user = current_user()
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
    body = "<h2>Audit Log (admin only)</h2><table><tr><th>Time</th><th>Actor</th><th>Action</th><th>Post</th><th>Detail</th></tr>"
    for row in rows:
        body += "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(row["created_at"]), esc(row["actor"]), esc(row["action"]),
            esc(row["post_id"] or ""), esc(row["detail"]))
    body += "</table>"
    if not rows:
        body += "<p>No audit entries yet.</p>"
    return page("Audit Log", body, user=user)


# ------------------------------------------------------- activity + chat
@app.route("/activity")
@login_required
def activity_page():
    user = current_user()
    conn = get_db()
    placeholders = ",".join("?" for _ in ACTIVITY_ACTIONS)
    rows = conn.execute(
        "SELECT * FROM audit_log WHERE action IN (%s) ORDER BY id DESC LIMIT 200" % placeholders,
        ACTIVITY_ACTIONS).fetchall()
    body = "<h2>Team Activity</h2><p>Post activity for the whole team: drafts created, approvals, changes requested, rejections, publishes and portal handoffs. Admin-only actions such as password resets and settings changes are in the Audit Log, not here.</p>"
    body += "<table><tr><th>Time</th><th>Actor</th><th>Action</th><th>Post</th><th>Detail</th></tr>"
    for row in rows:
        body += "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(row["created_at"]), esc(row["actor"]), esc(row["action"]),
            esc(row["post_id"] or ""), esc(row["detail"]))
    body += "</table>"
    if not rows:
        body += "<p>No team activity yet.</p>"
    return page("Activity", body, user=user)


def _detect_platform(text):
    low = text.lower()
    if "company portal" in low or "portal" in low:
        return "company_portal"
    for key in ("linkedin", "instagram", "facebook"):
        if key in low:
            return key
    return None


def _chat_field(text, name, stops):
    match = re.search(r"\b" + name + r":\s*", text, re.IGNORECASE)
    if not match:
        return ""
    rest = text[match.end():]
    cut = len(rest)
    for stop in stops:
        found = re.search(r"\b" + stop + r":", rest, re.IGNORECASE)
        if found:
            cut = min(cut, found.start())
    return rest[:cut].strip().strip(",").strip()


def _chat_status_answer():
    conn = get_db()
    counts = {}
    for row in conn.execute("SELECT status, COUNT(*) AS n FROM posts GROUP BY status"):
        counts[row["status"]] = row["n"]
    lines = ["Post status:"]
    for key in ("pending", "changes_requested", "rejected", "ready_to_publish", "published", "handed_off"):
        lines.append("- %s: %d" % (status_label(key), counts.get(key, 0)))
    pending = conn.execute(
        "SELECT * FROM posts WHERE status = 'pending' ORDER BY id DESC LIMIT 10").fetchall()
    if pending:
        lines.append("Pending approval:")
        for post in pending:
            caption = (post["caption"] or "")[:80]
            lines.append("- Post #%d: %s (%s) - %s" % (
                post["id"], PLATFORMS.get(post["platform"], {}).get("label", post["platform"]),
                post["subtype"] or "", caption))
    else:
        lines.append("No posts are pending approval right now.")
    lines.append("Nothing in this list has been published automatically; approved posts stay Ready to Publish until an admin records a live link or a portal handoff.")
    return "\n".join(lines)


def _handle_chat_message(user, text):
    low = text.lower().strip()
    # A specific post lookup: "post 12" / "post #12"
    match = re.search(r"\bpost\s*#?(\d+)\b", low)
    if match and ("status" in low or "post" in low):
        conn = get_db()
        post = conn.execute("SELECT * FROM posts WHERE id = ?", (int(match.group(1)),)).fetchone()
        if post:
            return ("Post #%d is %s - %s (%s). Caption: %s" % (
                post["id"], status_label(post["status"]),
                PLATFORMS.get(post["platform"], {}).get("label", post["platform"]),
                post["subtype"] or "", post["caption"])), post["id"]
    # Status / queue questions - answered from the real database, no LLM needed.
    if any(word in low for word in ("pending", "approval queue", "how many", "status", "ready to publish", "published")):
        return _chat_status_answer(), None
    # Draft creation from chat.
    is_draft = ("create" in low and ("draft" in low or "post" in low)) or low.startswith("draft:")
    if is_draft:
        if user["role"] == "viewer":
            return ("Viewer accounts are read-only, so I cannot create a draft for you. "
                    "Ask an admin or manager to create it, or check Activity and Published / History."), None
        platform = _detect_platform(text)
        caption = _chat_field(text, "caption", ["hashtags", "hashtag", "scheduled", "schedule", "platform"])
        hashtags = _chat_field(text, "hashtags", ["scheduled", "schedule", "platform"]) or _chat_field(text, "hashtag", ["scheduled", "schedule", "platform"])
        scheduled = _chat_field(text, "scheduled", ["platform"]) or _chat_field(text, "schedule", ["platform"])
        if not caption:
            # Fallback: everything after "draft:" / "create post" minus the platform name.
            fallback = re.sub(r"(?i)^.*?(create\s+(a\s+)?post|create\s+draft|draft)\s*:?\s*", "", text).strip()
            for key, info in PLATFORMS.items():
                fallback = re.sub(r"(?i)\b" + re.escape(info["label"]) + r"\b", "", fallback).strip(", ").strip()
            caption = fallback
        if not platform or not caption:
            return ("To create a draft from chat, send it like this:\n"
                    "Create draft: platform Instagram, caption: Your caption here, hashtags: #example, scheduled: 2026-11-05 10:00\n"
                    "Platform must be LinkedIn, Instagram, Facebook or Company Portal, and a caption is required."), None
        subtype = PLATFORMS[platform]["subtypes"][0]
        conn = get_db()
        cur = conn.execute(
            "INSERT INTO posts(caption, hashtags, platform, subtype, destination, scheduled_at, "
            "notes, status, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, '', ?, 'Created from Agent Chat', 'pending', ?, ?, ?)",
            (caption, hashtags, platform, subtype, scheduled, user["username"], now_iso(), now_iso()))
        post_id = cur.lastrowid
        conn.commit()
        audit(user["username"], "chat_draft_created", post_id,
              "Draft created from Agent Chat for %s (%s)" % (PLATFORMS[platform]["label"], subtype))
        return ("Draft #%d created for %s (%s) and sent to Pending Approval. "
                "It will not publish until a manager approves it. See Approval Queue." % (
                    post_id, PLATFORMS[platform]["label"], subtype)), post_id
    # General chat: only a real configured LLM may answer; otherwise say so plainly.
    base_url = get_setting("llm_base_url").strip()
    model = get_setting("llm_model").strip()
    api_key = get_setting("llm_api_key").strip()
    if not base_url or not model or not api_key:
        return ("No LLM key is configured in Settings (admin only), so I cannot give an AI reply yet. "
                "I can still answer from the database - try 'How many posts are pending?' - "
                "and I can create a draft from chat with: Create draft: platform Instagram, caption: ..., hashtags: ..., scheduled: ... "
                "Manual post creation also still works."), None
    context = _chat_status_answer()
    answer, error = call_llm([
        {"role": "system", "content": (
            "You are the Social Manager agent inside a local team app. "
            "Use the post-status summary below for any status questions. "
            "Never claim a post was published, and never invent a live link. "
            "If asked to publish, explain that a manager must approve first.")},
        {"role": "user", "content": "Post status summary:\n%s\n\nUser question: %s" % (context, text)},
    ])
    if error:
        return ("LLM request failed: %s. You can still ask about post status from the database, "
                "or create a draft from chat." % error), None
    return answer, None


@app.route("/chat", methods=["GET", "POST"])
@login_required
def chat_page():
    user = current_user()
    if request.method == "POST":
        check_csrf()
        message = request.form.get("message", "").strip()
        if message:
            save_chat_message(user, "user", message)
            answer, post_id = _handle_chat_message(user, message)
            save_chat_message(user, "assistant", answer, post_id=post_id)
        return redirect(url_for("chat_page"))
    conn = get_db()
    messages = conn.execute(
        "SELECT * FROM chat_messages WHERE user_id = ? ORDER BY id ASC LIMIT 200",
        (user["id"],)).fetchall()
    llm_ready = bool(get_setting("llm_base_url") and get_setting("llm_model") and get_setting("llm_api_key"))
    body = "<h2>Agent Chat</h2>"
    if llm_ready:
        body += "<p>Connected to the OpenAI-compatible endpoint configured in Settings (admin only).</p>"
    else:
        body += ("<p><strong>No LLM key is set in Settings (admin only), so AI replies are off.</strong> "
                 "This page does not fake AI replies. You can still ask about post status and the approval queue, "
                 "create a draft from chat (admin / manager only), and create posts manually.</p>")
    body += ("<p class='muted'>Try: 'How many posts are pending?' &nbsp;|&nbsp; "
             "'Create draft: platform Instagram, caption: Hello team, hashtags: #hello, scheduled: 2026-11-05 10:00' &nbsp;|&nbsp; "
             "'What is the status of post 1?'</p>")
    for msg in messages:
        body += '<div class="card"><p><strong>%s</strong> <span class="muted">%s</span></p><p>%s</p>' % (
            esc("You" if msg["role"] == "user" else "Agent"), esc(msg["created_at"]),
            esc(msg["content"]).replace("\n", "<br>"))
        if msg["post_id"]:
            body += '<p><a href="%s">Draft #%d in Approval Queue</a></p>' % (url_for("queue"), msg["post_id"])
        body += "</div>"
    if not messages:
        body += "<p>No chat history yet for your account. Chat history is saved per user.</p>"
    body += """
    <form method="post">
    <input type="hidden" name="csrf_token" value="%s">
    <label>Message</label><textarea name="message" required></textarea>
    <button type="submit">Send to agent</button></form>""" % csrf_token()
    return page("Agent Chat", body, user=user)


# ---------------------------------------------------------------- settings
SECRET_KEYS = ("llm_api_key", "meta_access_token", "linkedin_access_token",
               "portal_api_key")
ALL_SETTING_KEYS = (
    "llm_base_url", "llm_model", "llm_api_key",
    "meta_access_token", "facebook_page_id",
    "linkedin_access_token", "linkedin_company_page",
    "portal_name", "portal_endpoint", "portal_upload_target", "portal_api_key",
)


@app.route("/settings", methods=["GET", "POST"])
@admin_required
def settings_page():
    user = current_user()
    if request.method == "POST":
        check_csrf()
        for key in ALL_SETTING_KEYS:
            value = request.form.get(key, "")
            # For secrets: blank means "keep the stored value", not "clear it".
            if key in SECRET_KEYS and value == "":
                continue
            set_setting(key, value.strip())
        audit(user["username"], "settings_updated", None, "Settings updated")
        flash("Settings saved. Keys are stored only in the local database and shown masked here.")
        return redirect(url_for("settings_page"))

    def field(label, key, hint=""):
        current = get_setting(key)
        if key in SECRET_KEYS:
            shown = mask(current)
            return ('<label>%s (stored: %s - leave blank to keep)</label>'
                    '<input type="password" name="%s" autocomplete="off">'
                    '<p class="muted">%s</p>') % (label, shown, key, hint)
        return ('<label>%s</label><input type="text" name="%s" value="%s">'
                '<p class="muted">%s</p>') % (label, key, esc(current), hint)

    body = "<h2>Settings (admin only)</h2>"
    body += "<p>Nothing on this page is written to code or files. Values are stored only in the local database file (social.db) on this machine/server. Protect that file like you would any file containing keys.</p>"
    body += '<form method="post"><input type="hidden" name="csrf_token" value="%s">' % csrf_token()
    body += "<h3>Agent / LLM draft help (OpenAI-compatible)</h3>"
    body += field("LLM base URL", "llm_base_url",
                  "e.g. https://api.openai.com/v1 - or your own OpenAI-compatible endpoint.")
    body += field("LLM model", "llm_model", "e.g. gpt-4o-mini, or your local model name.")
    body += field("LLM API key", "llm_api_key",
                  "Stored only in the local database, shown masked. If this is empty, manual drafting still works fully.")
    body += "<h3>Instagram / Facebook (Meta)</h3>"
    body += field("Meta access token", "meta_access_token",
                  "Needed for any future live Meta publishing. Not assumed present. A personal Instagram account is not assumed to work for Graph API publishing - a professional/business account is normally required.")
    body += field("Facebook Page ID / name", "facebook_page_id", "Optional, for Facebook Page posts.")
    body += "<h3>LinkedIn</h3>"
    body += field("LinkedIn access token", "linkedin_access_token",
                  "Needed for any future live LinkedIn publishing. Not assumed present.")
    body += field("LinkedIn company page", "linkedin_company_page", "e.g. company page name or URN, if posting as a Company Page.")
    body += "<h3>Company Portal (configurable - empty by default)</h3>"
    body += field("Portal name", "portal_name",
                  "No specific portal is invented here. Enter your company's portal name, or leave empty.")
    body += field("Portal endpoint / upload target", "portal_endpoint",
                  "e.g. the portal URL or upload destination your company uses, or leave empty.")
    body += field("Portal upload target description", "portal_upload_target",
                  "Free text: where in the portal an approved post should go.")
    body += field("Portal API key", "portal_api_key", "Only if your portal needs one. Leave empty otherwise.")
    body += '<button type="submit">Save settings</button></form>'
    body += ("<h3>Honest limits</h3><ul>"
             "<li>This local app does NOT use Muse's own connectors. Aman's @onlyamanahmed Instagram link in Muse does not connect this app.</li>"
             "<li>Facebook and Threads are not connected to this app, and no live publish is assumed.</li>"
             "<li>Automatic publishing is not implemented in this version. Approved posts are recorded as Published only with a live link an admin enters after publishing externally, or as Handed off to Portal with a reference.</li>"
             "</ul>")
    return page("Settings", body, user=user)


@app.route("/health")
def health():
    return {"ok": True}


init_db()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    print("Social Manager running at http://%s:%d" % (host, port))
    print("First run: open the page and create the Admin account on Setup.")
    app.run(host=host, port=port)
