# ML Wireless Intrusion Detection System (WIDS / WIPS)

Detects Wi-Fi **deauthentication flood** attacks with a scikit-learn Random Forest.
Works on AWID3-style CSV exports, or live in monitor mode on a lab network you are authorised to test.

## Setup
```
pip install pandas numpy scikit-learn matplotlib joblib
pip install scapy        # only for live mode
```

## 1. Train + evaluate (your real files)
```
python wids.py train --data "C:\Users\vickm\OneDrive\Desktop\WIDS_project" --pattern "Deauth_*.csv" --rows-per-file 100000
```
Outputs in `output/`: `wids_model.joblib`, `results.json` (accuracy, precision, recall, F1, confusion matrix),
`confusion_matrix.png`. Raise `--rows-per-file` for more data (files are 40-70 MB each; 100k rows each is plenty for a prototype).

## 2. Detect + prevent (demo)
```
python wids.py replay --csv Deauth_5.csv --wips --speed 1
```
Prints red ALERT lines, writes `output/alerts.log`, and with `--wips` adds the attacker MAC to `output/blocklist.json`.
Use a file that was not in your training sample for a fair demo (or train on a subset of files).

Live (Linux, monitor mode, own network only):
```
sudo python wids.py live --iface wlan0mon --wips
```

## 3. Poster
```
python poster.py output/results.json WIDS_poster_A1.pdf
```
A1 PDF (594 x 841 mm). Edit name/ID and the AI-usage statement in `poster.py`.

## Testing without the dataset
`python make_synthetic.py` creates fake AWID3-style CSVs. Results from them are **not** real; train with `--synthetic` to flag the poster.

## If your CSV columns differ
`wids.py` looks for `frame.time_epoch, frame.len, radiotap.dbm_antsignal / wlan_radio.signal_dbm, wlan.fc.type, wlan.fc.subtype, wlan.sa, wlan.da, Label`.
Edit the `CANDIDATES` dict at the top if your headers are named differently.
