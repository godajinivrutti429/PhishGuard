<<<<<<< HEAD
# PhishGuard — AI-Based Phishing URL Detection

A Python/Flask + scikit-learn educational project that extracts URL features and predicts whether a URL resembles a phishing example.

## Features
- URL input validation
- Feature extraction (length, hostname, punctuation, digits, IP address pattern, suspicious terms)
- Random Forest model training
- Prediction and estimated phishing probability
- Feature summary dashboard
- Model evaluation report in the terminal

## Requirements
- Python 3.10–3.12 recommended
- pip
- VS Code (optional)

## Run on Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python train_model.py
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

If PowerShell blocks activation, run the commands below instead of activating the environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe train_model.py
.\.venv\Scripts\python.exe app.py
```

## Important dataset note
The included training examples are synthetic and are only intended to make the app runnable for demonstration. Their reported metrics are not a valid measure of real-world phishing detection. For a final-year submission, use a properly licensed public dataset, document its source and date, remove duplicates, prevent train/test leakage, and evaluate on a held-out set. Report precision, recall, F1-score, confusion matrix, and class balance.

## Suggested future improvements
1. Add user authentication and SQLite/PostgreSQL scan history.
2. Add CSV batch upload.
3. Add charts for model evaluation.
4. Compare Random Forest with Logistic Regression and Gradient Boosting.
5. Add tests and CI using GitHub Actions.
6. Deploy with a production WSGI server; do not use Flask debug mode in production.

## Security and limitations
- This is a learning prototype, not a guarantee that a site is safe or malicious.
- Do not automatically open submitted URLs.
- Avoid collecting passwords or personal information.
- Do not present the probability as a calibrated real-world risk score until validated on suitable data.
=======
# PhishGuard
ML-based phishing URL detection and risk analysis system.
>>>>>>> 4c94338f4e62613ecc7387b8986d20be697efe38
