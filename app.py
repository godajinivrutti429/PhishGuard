from pathlib import Path
import json
import sqlite3

import joblib
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, flash

from utils.features import FEATURE_NAMES, extract_features

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "phishing_model.joblib"
METRICS_PATH = BASE_DIR / "models" / "model_metrics.json"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "phishguard_history.db"

app = Flask(__name__)
# Used only for local flash messages. Change this before any deployment.
app.secret_key = "change-this-local-development-key"


def get_db_connection():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                prediction INTEGER NOT NULL CHECK (prediction IN (0, 1)),
                label TEXT NOT NULL,
                phishing_probability REAL NOT NULL,
                scanned_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
            )
            """
        )


def load_model():
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    return None


def load_metrics():
    if not METRICS_PATH.exists():
        return None
    try:
        return json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        app.logger.exception("Could not read saved model metrics")
        return None


def save_scan(url: str, prediction: int, label: str, risk: float) -> None:
    # Store scans only after the model completes successfully.
    # Do not submit URLs containing private tokens or sensitive query values.
    with get_db_connection() as connection:
        connection.execute(
            "INSERT INTO scan_history (url, prediction, label, phishing_probability) VALUES (?, ?, ?, ?)",
            (url, prediction, label, risk),
        )


init_db()
model = load_model()


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    url = ""

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            error = "Please enter a URL."
        elif len(url) > 2048:
            error = "URL is too long (maximum 2048 characters)."
        elif model is None:
            error = "No trained model found. Run train_model.py and restart the app."
        else:
            try:
                features = extract_features(url)
                row = pd.DataFrame(
                    [[features[name] for name in FEATURE_NAMES]],
                    columns=FEATURE_NAMES,
                )
                prediction = int(model.predict(row)[0])
                class_values = list(model.classes_)
                if 1 not in class_values:
                    raise RuntimeError("The trained model has no phishing class (label 1).")
                probabilities = model.predict_proba(row)[0]
                risk = round(float(probabilities[class_values.index(1)]) * 100, 1)
                label = "Likely phishing" if prediction == 1 else "Likely legitimate"

                save_scan(url, prediction, label, risk)
                result = {
                    "label": label,
                    "risk": risk,
                    "features": features,
                    "note": (
                        "This is a model estimate, not a guarantee. A low score does not prove a website is safe. "
                        "Do not enter passwords on unfamiliar sites."
                    ),
                }
            except ValueError as exc:
                error = str(exc)
            except Exception:
                app.logger.exception("URL analysis failed")
                error = "The URL could not be analyzed. Confirm the model is trained and try again."

    return render_template("index.html", result=result, error=error, url=url)


@app.route("/history", methods=["GET"])
def history():
    with get_db_connection() as connection:
        scans = connection.execute(
            "SELECT id, url, label, phishing_probability, scanned_at "
            "FROM scan_history ORDER BY id DESC LIMIT 200"
        ).fetchall()
        total = connection.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
    return render_template("history.html", scans=scans, total=total)


@app.route("/history/clear", methods=["POST"])
def clear_history():
    with get_db_connection() as connection:
        connection.execute("DELETE FROM scan_history")
    flash("Scan history cleared.", "success")
    return redirect(url_for("history"))


@app.route("/model-performance", methods=["GET"])
def model_performance():
    metrics = load_metrics()
    return render_template("model_performance.html", metrics=metrics)


if __name__ == "__main__":
    # Local development only. Do not expose Flask debug mode to the public internet.
    app.run(debug=True)
