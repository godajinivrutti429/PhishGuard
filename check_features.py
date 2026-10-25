"""Compare locally extracted features with the values already stored in the CSV."""
from pathlib import Path
import pandas as pd
from utils.features import FEATURE_NAMES, extract_features

DATA_PATH = Path('data/phishing_urls.csv')
if not DATA_PATH.exists():
    raise SystemExit(f'Dataset not found: {DATA_PATH.resolve()}')

df = pd.read_csv(DATA_PATH, nrows=25, low_memory=False)
needed = ['url'] + FEATURE_NAMES
missing = [c for c in needed if c not in df.columns]
if missing:
    raise SystemExit('Missing required columns: ' + ', '.join(missing))

checked = 0
mismatches = []
for idx, row in df.iterrows():
    try:
        got = extract_features(str(row['url']))
    except Exception as exc:
        mismatches.append((idx, 'EXTRACTION_ERROR', str(exc)))
        continue
    checked += 1
    for name in FEATURE_NAMES:
        expected = float(row[name])
        actual = float(got[name])
        # Tolerance only for floating-point ratio/entropy calculations.
        if abs(expected - actual) > 1e-5:
            mismatches.append((idx, name, f'CSV={expected} calculated={actual} URL={row["url"]}'))

print(f'Checked {checked} sample rows.')
if not mismatches:
    print('PASS: all checked features match the CSV for these rows.')
else:
    print(f'Found {len(mismatches)} differences. Showing at most 30:')
    for idx, name, details in mismatches[:30]:
        print(f'row {idx}, feature {name}: {details}')
    print('\nDo not assume live predictions are well-aligned until these differences are reviewed.')
