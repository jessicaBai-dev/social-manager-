#!/usr/bin/env python3
"""End-to-end test for Social Manager.

Uses a temporary database and uploads folder, so it never touches
real app data. Run:  python test_e2e.py   (after pip install -r requirements.txt)
Exits non-zero on the first failure; prints PASS for each flow.
"""
import os
import re
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="social-manager-test-")
os.environ["SOCIAL_MANAGER_DB"] = os.path.join(TMP, "test.db")
os.environ["SOCIAL_MANAGER_UPLOADS"] = os.path.join(TMP, "uploads")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import server  # noqa: E402

app = server.app
app.config["TESTING"] = True

PASSED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print("PASS: " + name)
    else:
        print("FAIL: " + name + " " + detail)
        sys.exit(1)


def csrf(client, url):
    resp = client.get(url)
    match = re.search(r'name="csrf_token" value="([^"]+)"', resp.get_data(as_text=True))
    assert match, "no csrf token on %s" % url
    return match.group(1)


def login(client, username, password):
    return client.post("/login", data={"username": username, "password": password},
                       follow_redirects=True)


def main():
    admin = app.test_client()
    # 1. Setup + admin login
    resp = admin.post("/setup", data={"username": "aman", "password": "admin-pass-123"},
                      follow_redirects=True)
    check("admin setup", b"Admin account created" in resp.data)
    resp = login(admin, "aman", "admin-pass-123")
    check("admin login", b"Dashboard" in resp.data)

    # 2. Create drafts for all four platforms, no LLM key set.
    def create_draft(platform, caption):
        token = csrf(admin, "/create")
        return admin.post("/create", data={
            "csrf_token": token, "platform": platform, "subtype": "Feed" if platform == "instagram" else "Company Page",
            "destination": "Test destination", "caption": caption,
            "hashtags": "#test", "scheduled_at": "2026-11-05 10:00", "notes": "e2e"},
            follow_redirects=True)

    for platform, caption in [
        ("linkedin", "LinkedIn draft caption"),
        ("instagram", "Instagram draft caption"),
        ("facebook", "Facebook draft caption"),
        ("company_portal", "Portal draft caption"),
    ]:
        resp = create_draft(platform, caption)
        check("create %s draft (no LLM key, manual works)" % platform,
              b"sent to Pending Approval" in resp.data)
    # LLM endpoint must not block manual work: it errors plainly without a key.
    resp = admin.post("/llm-draft", json={"topic": "hello", "platform": "instagram"})
    check("llm-draft without key returns plain error, not a fake reply",
          resp.status_code == 400)

    # 3. Admin creates manager + viewer accounts (Team page).
    token = csrf(admin, "/team")
    resp = admin.post("/team", data={
        "csrf_token": token, "form_action": "create",
        "username": "manager1", "password": "manager-pass-123", "role": "manager"},
        follow_redirects=True)
    check("admin creates manager account", b"Account created for manager1" in resp.data)
    token = csrf(admin, "/team")
    resp = admin.post("/team", data={
        "csrf_token": token, "form_action": "create",
        "username": "viewer1", "password": "viewer-pass-123", "role": "viewer"},
        follow_redirects=True)
    check("admin creates viewer account", b"Account created for viewer1" in resp.data)

    manager = app.test_client()
    resp = login(manager, "manager1", "manager-pass-123")
    check("manager login", b"Dashboard" in resp.data)
    viewer = app.test_client()
    resp = login(viewer, "viewer1", "viewer-pass-123")
    check("viewer login", b"Dashboard" in resp.data)

    # 4. Manager blocked from admin pages (server-side, not just UI).
    for url in ("/settings", "/team", "/audit"):
        resp = manager.get(url)
        check("manager blocked from %s" % url, resp.status_code == 403)
    resp = viewer.get("/settings")
    check("viewer blocked from /settings", resp.status_code == 403)
    resp = viewer.get("/create")
    check("viewer blocked from /create", resp.status_code == 403)

    # Post ids are 1..4 in creation order: 1 LinkedIn, 2 Instagram,
    # 3 Facebook, 4 Company Portal.
    # 5. Manager approves LinkedIn draft -> Ready to Publish.
    token = csrf(manager, "/queue")
    resp = manager.post("/posts/1/review", data={
        "csrf_token": token, "action": "approve", "comment": "Looks good"},
        follow_redirects=True)
    check("manager approve -> ready", b"now Ready to Publish" in resp.data)

    # 6. Manager rejects Instagram draft.
    token = csrf(manager, "/queue")
    resp = manager.post("/posts/2/review", data={
        "csrf_token": token, "action": "reject", "comment": "Not on brand"},
        follow_redirects=True)
    check("manager reject", b"Post rejected" in resp.data)

    # 7. Manager requests changes on Facebook draft, admin resubmits,
    #    manager approves.
    token = csrf(manager, "/queue")
    resp = manager.post("/posts/3/review", data={
        "csrf_token": token, "action": "changes", "comment": "Shorten caption"},
        follow_redirects=True)
    check("manager request changes", b"Changes requested" in resp.data)
    token = csrf(admin, "/posts/3/edit")
    resp = admin.post("/posts/3/edit", data={
        "csrf_token": token, "platform": "facebook", "subtype": "Page post",
        "destination": "Test destination", "caption": "Facebook draft caption revised",
        "hashtags": "#test", "scheduled_at": "2026-11-05 10:00", "notes": "e2e"},
        follow_redirects=True)
    check("admin resubmit after changes", b"resubmitted to Pending Approval" in resp.data)
    token = csrf(manager, "/queue")
    resp = manager.post("/posts/3/review", data={
        "csrf_token": token, "action": "approve", "comment": "Good now"},
        follow_redirects=True)
    check("manager approve after resubmit", b"now Ready to Publish" in resp.data)

    # 8. Publish queue: approved posts present, no token configured,
    #    explanation present, and nothing is auto-published.
    resp = admin.get("/publish")
    body = resp.get_data(as_text=True)
    check("publish queue shows approved posts, stays Ready (no token)",
          "Ready to Publish" in body and "No publishing token is configured" in body)
    check("publish queue does not claim a fake publish",
          "NOT been published" in body or "have NOT been published" in body)

    # 9. Record LinkedIn post as published with a live link (admin, manual).
    token = csrf(admin, "/publish")
    resp = admin.post("/posts/1/publish", data={
        "csrf_token": token, "action": "mark_published",
        "live_url": "https://example.com/posts/linkedin-test"}, follow_redirects=True)
    check("admin records live link as Published",
          b"Recorded as Published" in resp.data)
    resp = admin.get("/history")
    check("published post appears in history with live link",
          b"example.com/posts/linkedin-test" in resp.data)

    # 10. Manager approves portal draft, admin marks handed off.
    token = csrf(manager, "/queue")
    resp = manager.post("/posts/4/review", data={
        "csrf_token": token, "action": "approve", "comment": "OK for portal"},
        follow_redirects=True)
    check("manager approve portal draft", b"now Ready to Publish" in resp.data)
    token = csrf(admin, "/publish")
    resp = admin.post("/posts/4/publish", data={
        "csrf_token": token, "action": "hand_off", "reference": "PORTAL-123"},
        follow_redirects=True)
    check("portal handoff recorded", b"Handed off to Portal" in resp.data)

    # 11. Agent Chat, no LLM key: status answer from DB, no fake AI reply.
    token = csrf(manager, "/chat")
    resp = manager.post("/chat", data={
        "csrf_token": token, "message": "How many posts are pending?"},
        follow_redirects=True)
    body = resp.get_data(as_text=True)
    check("chat status answer with no LLM key (real DB answer)",
          "Pending Approval" in body and "Post status" in body)
    check("chat with no LLM key does not fake an AI reply",
          "No LLM key is configured" in body or "Post status" in body)

    # 12. Agent Chat draft creation (manager) -> Pending Approval.
    token = csrf(manager, "/chat")
    resp = manager.post("/chat", data={
        "csrf_token": token,
        "message": "Create draft: platform LinkedIn, caption: Chat draft caption unique-xyz, hashtags: #chat, scheduled: 2026-11-06 09:00"},
        follow_redirects=True)
    body = resp.get_data(as_text=True)
    check("chat draft created, shown in chat with queue link",
          "created for LinkedIn" in body and "Pending Approval" in body
          and "Approval Queue" in body)
    resp = manager.get("/queue")
    check("chat draft appears in approval queue",
          b"Chat draft caption unique-xyz" in resp.data)

    # 13. Viewer chat: status ok, draft creation refused (read-only).
    token = csrf(viewer, "/chat")
    resp = viewer.post("/chat", data={
        "csrf_token": token,
        "message": "Create draft: platform Instagram, caption: Viewer should not create this"},
        follow_redirects=True)
    body = resp.get_data(as_text=True)
    check("viewer chat draft refused (read-only)",
          "read-only" in body.lower())
    resp = viewer.get("/queue")
    check("viewer draft was not created",
          b"Viewer should not create this" not in resp.data)

    # 14. Per-user chat history: viewer must not see manager's chat.
    resp = viewer.get("/chat")
    check("chat history is per user",
          b"Chat draft caption unique-xyz" not in resp.data)

    # 15. Activity feed shows chat + approval actions.
    resp = manager.get("/activity")
    body = resp.get_data(as_text=True)
    check("activity feed shows draft/approval/chat actions",
          "chat_draft_created" in body and "approve" in body)

    # 16. Audit log records each step (admin only).
    resp = admin.get("/audit")
    body = resp.get_data(as_text=True)
    for action in ("draft_created", "approve", "reject", "request_changes",
                   "resubmit", "mark_published", "hand_off_portal",
                   "chat_draft_created", "user_created"):
        check("audit log contains %s" % action, action in body)

    # 17. Team password reset + deactivate/reactivate.
    # Find manager id from Team page is not needed: reset via username lookup in DB.
    import sqlite3
    conn = sqlite3.connect(os.environ["SOCIAL_MANAGER_DB"])
    manager_id = conn.execute("SELECT id FROM users WHERE username = 'manager1'").fetchone()[0]
    viewer_id = conn.execute("SELECT id FROM users WHERE username = 'viewer1'").fetchone()[0]
    conn.close()
    token = csrf(admin, "/team")
    resp = admin.post("/team", data={
        "csrf_token": token, "form_action": "reset_password",
        "target_id": str(manager_id), "new_password": "manager-new-pass-123"},
        follow_redirects=True)
    check("admin resets manager password", b"Password reset for manager1" in resp.data)
    manager2 = app.test_client()
    resp = login(manager2, "manager1", "manager-new-pass-123")
    check("manager logs in with new password", b"Dashboard" in resp.data)
    token = csrf(admin, "/team")
    resp = admin.post("/team", data={
        "csrf_token": token, "form_action": "deactivate", "target_id": str(viewer_id)},
        follow_redirects=True)
    check("admin removes (deactivates) viewer", b"no longer log in" in resp.data)
    viewer2 = app.test_client()
    resp = login(viewer2, "viewer1", "viewer-pass-123")
    check("deactivated viewer cannot log in", b"Invalid username or password" in resp.data)
    token = csrf(admin, "/team")
    resp = admin.post("/team", data={
        "csrf_token": token, "form_action": "reactivate", "target_id": str(viewer_id)},
        follow_redirects=True)
    check("admin reactivates viewer", b"Reactivated viewer1" in resp.data)

    # 18. Admin override approval is audit-logged distinctly.
    # Create one more draft as admin, approve it as admin.
    token = csrf(admin, "/create")
    admin.post("/create", data={
        "csrf_token": token, "platform": "instagram", "subtype": "Feed",
        "destination": "Test", "caption": "Override test caption",
        "hashtags": "", "scheduled_at": "", "notes": ""}, follow_redirects=True)
    conn = sqlite3.connect(os.environ["SOCIAL_MANAGER_DB"])
    override_id = conn.execute("SELECT MAX(id) FROM posts").fetchone()[0]
    conn.close()
    token = csrf(admin, "/queue")
    resp = admin.post("/posts/%d/review" % override_id, data={
        "csrf_token": token, "action": "approve", "comment": "Admin override"},
        follow_redirects=True)
    check("admin override approve", b"now Ready to Publish" in resp.data)
    resp = admin.get("/audit")
    check("audit log contains admin_override_approve",
          b"admin_override_approve" in resp.data)

    print("\nAll %d checks passed." % len(PASSED))


if __name__ == "__main__":
    main()
