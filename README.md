# Guardian Vault — New App MVP Foundation

A fresh, runnable Flask + SQLite application foundation for private child-welfare case organization. It includes account registration/login, user-isolated cases, child records, a connected chronological record log, private file uploads/downloads, global search, and a responsive dashboard.

## Run locally

Python 3.10+ recommended.

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

Open `http://localhost:5000`.

## Replit setup

1. Create a new Python Replit project.
2. Upload/extract this ZIP into the project.
3. Add `Flask>=3.0,<4.0` to dependencies or install `requirements.txt`.
4. Set a strong `SECRET_KEY` in Replit Secrets.
5. Ensure the `instance/` data directory is on persistent storage. Uploaded evidence and SQLite data must not be kept on an ephemeral filesystem for a real deployment.
6. Run `python app.py` for development. Use an appropriate production WSGI server and HTTPS for production.

## Included MVP features

- Password-hashed account registration and login.
- Per-user case ownership checks on case, timeline, search, and file routes.
- Case details and child records.
- Timeline records for notes, communications, visits, incidents, appointments, hearings, deadlines, case plans, and request/response tracking.
- Private attachment storage with randomized server filenames and authorized download routes.
- Search across record metadata and file names/descriptions.
- SQLite foreign keys, indexes, and automatic schema initialization.
- Responsive web UI and CSRF tokens on form submissions.

## Important limitations

This is a new MVP foundation, not a completed production product. It does not yet include multi-factor authentication, email verification, password reset, malware scanning, object storage, automated backups, full-text extraction/OCR/transcription, calendar sync, push/email reminders, AI analysis, advanced roles/sharing, export packets, audit-event history, or comprehensive automated test coverage. Do not store highly sensitive live case records until security review, persistent storage, backups, deployment hardening, and recovery procedures have been completed.

The development server is not a production server. Configure HTTPS, a stable secret, secure cookies, persistent storage, monitoring, and a production WSGI server before public launch.
