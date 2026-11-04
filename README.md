# Social Manager — local approval app

A standalone local app, **not a Muse artifact**, so a separate social media
manager can log in with her own username and password. The agent (or Aman
as Admin) creates post drafts; the manager approves them; nothing publishes
without approval.

## What it does, in order

1. **Agent / Admin creates a post draft** — caption, hashtags, media upload
   (image/video), platform, scheduled time, notes.
2. **Draft goes to Pending Approval.**
3. **Manager logs in and Approves, Rejects, or Requests Changes** with a
   comment. Rejecting or requesting changes requires a comment.
4. **Only Approved posts move to Ready to Publish.** Nothing publishes
   automatically. An Admin approving a post is recorded in the audit log
   as an **admin override**.
5. **Publish Queue** shows approved posts. An admin records a live link
   only after publishing externally, or (for a Company Portal) marks the
   post **Handed off to Portal** with a reference. No publish is faked.

## Platforms

- **LinkedIn** — Company Page or Personal profile
- **Instagram** — Feed, Reel, Story, Carousel
- **Facebook** — Page post or Personal post
- **Company Portal** — a generic, configurable destination (see Settings).
  No specific portal is invented: portal name and endpoint / upload target
  are empty by default and are set by an Admin in Settings.

The same approval gate applies to every platform.

## Team, logins and roles

- **Admin (Aman)** — full control: creates team accounts, sees Audit Log
  and Settings, creates drafts, handles the Publish Queue.
- **Manager** — approves / rejects / requests changes, sees the Approval
  Queue, Activity and Published / History. Blocked server-side (not just
  hidden in the UI) from Settings, Team and Audit Log.
- **Viewer** — read-only: sees Activity and Published / History, changes
  nothing. Viewer approval, create, publish and chat-draft actions are
  blocked server-side with a 403 / read-only message.

Passwords are stored hashed (PBKDF2-SHA256, per-user salt), never in plain
text. Sessions are cookie-based; Logout clears the session.

## Agent Chat (in the app)

- **Agent Chat** page for any logged-in team member. Chat history is saved
  per user.
- The chatbot uses the same OpenAI-compatible endpoint / model / key
  configured in Settings (admin only).
- **If no key is set, the chat page says so plainly and does not fake AI
  replies.** You can still ask about post status and the approval queue
  (answered from the real database), and Admin / Manager can still create
  drafts from chat. Manual post creation also still works fully.
- From chat, the agent can:
  - answer questions about post status and the approval queue, e.g.
    “How many posts are pending?” or “What is the status of post 1?”
  - create a new draft that goes into Pending Approval exactly like a
    manually created draft, e.g.
    `Create draft: platform Instagram, caption: Hello team, hashtags: #hello, scheduled: 2026-11-05 10:00`
  - The created draft is shown in chat with its post number and a link to
    the Approval Queue.
- Chat draft creations appear in the team **Activity** feed and in the
  Audit Log as `chat_draft_created`. Viewer accounts cannot create drafts
  from chat (read-only).

## Pages

Dashboard (counts by status) · Create Post (admin) · Approval Queue ·
Activity (team) · Agent Chat · Publish Queue (admin) ·
Published / History · Team (admin) · Audit Log (admin) · Settings (admin)

## Install and run — exact steps

Requires Python 3.9 or newer. From inside this folder:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python server.py
```

Then open:

```
http://127.0.0.1:8080
```

For a company server on your local network instead of only this machine:

```bash
HOST=0.0.0.0 .venv/bin/python server.py
```

Then open `http://<that-machine's-IP>:8080` from another machine on the
same network. Do not expose this to the public internet without adding
HTTPS and a reverse proxy in front of it — this app is built for local /
company-network use.

Optional environment variables:

- `HOST` — default `127.0.0.1`
- `PORT` — default `8080`
- `SOCIAL_MANAGER_SECRET` — session secret; if not set, a random one is
  generated on each start (sessions reset on restart)
- `SOCIAL_MANAGER_DB` / `SOCIAL_MANAGER_UPLOADS` — override database /
  uploads locations (used by the test script)

## First-time setup — default admin flow

1. On first run there are no users, so the app redirects to **Setup**.
2. Create the Admin account (Aman) with a username and password.
   There is no shipped default password — you choose it on Setup, so do
   not look for one in the code (there is none).
3. Log in as Admin.
4. Go to **Team** and create the social media manager account:
   username, password, role **Manager**. Give her those credentials
   directly / in person, not by forwarding them around unnecessarily.
5. Create **Viewer** accounts the same way if other team members only
   need to watch activity and published posts.
6. The manager logs in at the same address with her own account and
   works from **Approval Queue** and **Agent Chat**.

### Team management (Admin, Team page)

- **Add** a team member: username, password, role (Admin / Manager / Viewer).
- **Reset password**: enter a new password next to that member.
- **Remove**: the Remove button deactivates the account (they can no
  longer log in); Reactivate restores it. Delete removes the account
  permanently.
- Every account change (create, password reset, deactivate, reactivate,
  delete) is written to the Audit Log. You cannot deactivate or delete
  your own admin account while logged in as it.

## LLM / agent draft help (Settings, admin only)

Settings holds an OpenAI-compatible endpoint + model + API key.

- The key is stored **only in the local database file (`social.db`)**,
  is shown masked in the UI, and is **never written to code or files**.
  Protect that database file like any file containing a key.
- Leaving a secret field blank on Save keeps the stored value; entering
  a new value replaces it.
- **If no key is set, manual draft creation still works fully and is
  not blocked**, and Agent Chat says plainly that AI replies are off.

## Honest limits — read before expecting a live publish

- **This local app does NOT use Muse's own connectors.** Aman's
  Instagram link inside Muse (`@onlyamanahmed`) does not connect this
  app, and does not give it a publishing token.
- **Live publishing is not implemented as an automatic step in this
  version.** The Publish Queue explains, per post, what is missing.
  If no publishing token is configured, the approved post stays
  **Ready to Publish**. An admin records it as Published only with a
  live link entered after publishing externally, or as Handed off to
  Portal with a reference. That is a record, not an automatic publish.
- **Instagram:** live publishing via the Meta Graph API normally needs
  a professional / business Instagram account and an access token.
  Aman's linked `@onlyamanahmed` account in Muse is a **personal**
  account, so live Instagram publishing from it is **not assumed to
  work**. Do not expect a personal-account token to publish.
- **Facebook / Threads:** not connected to this app, and no live publish
  is assumed for them either. Facebook Page publishing would need a
  Page access token (set in Settings); Threads has no token field in
  this version and is not a selectable platform here.
- **LinkedIn:** live publishing would need a LinkedIn API connection
  and token for the company page / profile. No token is assumed present.
- **Company Portal:** configurable only. Until an Admin sets a portal
  name and endpoint / upload target in Settings, portal posts also stay
  Ready to Publish with a plain note saying what is missing.
- **No real credentials, tokens or API keys are in the code.** Do not
  add any. Put them only in Settings, which stores them in the local
  database.

## Files

- `server.py` — the whole app (Flask + SQLite, Python 3.9-compatible)
- `requirements.txt` — Flask only
- `test_e2e.py` — end-to-end test (see below); run it, it uses a
  temporary database and uploads folder and does not touch your real data
- `social.db` — created on first run; not shipped
- `uploads/` — created on first run; uploaded media lives here

## End-to-end test

```bash
python3 -m venv /tmp/social-test-venv
/tmp/social-test-venv/bin/pip install -q -r requirements.txt
/tmp/social-test-venv/bin/python test_e2e.py
```

The test covers: admin setup/login, draft creation for LinkedIn,
Instagram, Facebook and Company Portal, manager account creation,
manager approve, manager reject, manager request-changes + admin
resubmit + manager approve, publish queue staying Ready to Publish
with no token configured, recording a live link, portal handoff,
viewer read-only blocks, manager blocked from Settings/Team/Audit Log,
Agent Chat status answer with no LLM key, Agent Chat draft creation,
per-user chat history, and audit-log entries for each step.
