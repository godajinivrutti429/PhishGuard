PhishGuard Scan History Upgrade

Files in this archive replace app.py, templates/index.html, and static/style.css, and add templates/history.html.
The upgrade uses Python's built-in sqlite3 module; no extra packages are required.

Installation (Windows PowerShell, from your existing project root):

1. Stop Flask with Ctrl+C.
2. Extract this ZIP into a temporary folder, e.g. .\_history_upgrade.
3. Copy the files in this archive to the matching paths in your project:
   Copy-Item .\_history_upgrade\app.py .\app.py -Force
   Copy-Item .\_history_upgrade\templates\index.html .\templates\index.html -Force
   Copy-Item .\_history_upgrade\templates\history.html .\templates\history.html -Force
   Copy-Item .\_history_upgrade\static\style.css .\static\style.css -Force
4. Start the server:
   .\.venv\Scripts\python.exe app.py
5. Open http://127.0.0.1:5000 and analyze a URL. Successful scans are stored in data\phishguard_history.db.
6. Open http://127.0.0.1:5000/history to view history. The Clear history button deletes all saved scans.

Privacy: the database stores the submitted URL. Do not scan URLs containing password reset tokens, API keys, session IDs, credentials, or sensitive query parameters. History is local to this folder.

This app uses the model at models\phishing_model.joblib and feature extraction in utils\features.py. Keep those files and your trained model in place.
