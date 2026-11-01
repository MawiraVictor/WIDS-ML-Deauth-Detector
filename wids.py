#!/usr/bin/env python3
"""
WIDS / WIPS prototype - detects Wi-Fi deauthentication flood attacks with a Random Forest.

Modes
  train   : read AWID3-style CSVs, build features, train + evaluate, save model + results
  replay  : stream a CSV through the trained model in 1-second windows and raise alerts (WIPS: block MAC)
  live    : sniff a monitor-mode interface with scapy (ONLY on a network you are authorised to test)

Examples
  python wids.py train  --data "C:/Users/me/WIDS_project" --pattern "Deauth_*.csv" --rows-per-file 200000
  python wids.py replay --csv Deauth_5.csv --wips
  sudo python wids.py live --iface wlan0mon --wips
"""
import argparse, glob, json, os, sys, time
from collections import defaultdict

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, classification_report)
from sklearn.model_selection import GroupShuffleSplit

# ---------------------------------------------------------------- column names
# AWID3 CSVs come from tshark, so columns are Wireshark field names. Different
# releases name a few of them differently, so we accept several candidates.
CANDIDATES = {
    "time":    ["frame.time_epoch", "frame.time_relative"],
    "length":  ["frame.len", "radiotap.length"],
    "signal":  ["radiotap.dbm_antsignal", "wlan_radio.signal_dbm", "wlan_radio.signal_dbm"],
    "type":    ["wlan.fc.type"],
    "subtype": ["wlan.fc.subtype"],
    "typesub": ["wlan.fc.type_subtype"],
    "src":     ["wlan.sa", "wlan.ta", "wlan.addr"],
    "dst":     ["wlan.da", "wlan.ra"],
    "label":   ["Label", "label", "class", "Class"],
}
DEAUTH_SUBTYPE = 12          # management frame subtype 12 = Deauthentication
DEAUTH_TYPESUB = 12          # wlan.fc.type_subtype for deauth is 12 as well
FEATURES = ["frame_type", "frame_subtype", "is_deauth", "length", "signal_dbm",
            "src_fps", "src_deauth_fps", "src_unique_dst", "global_deauth_fps", "deauth_ratio"]
BEHAVIOUR = ["length", "signal_dbm", "src_fps", "src_unique_dst"]   # no deauth-count / subtype features


def pick(cols, key):
    for c in CANDIDATES[key]:
        if c in cols:
            return c
    return None


def to_num(s):
    """tshark exports sometimes contain hex ('0x000c'), '', or lists like '-40,-41'."""
    s = s.astype(str).str.split(",").str[0].str.strip()
    hexmask = s.str.startswith("0x")
    out = pd.to_numeric(s.where(~hexmask), errors="coerce")
    if hexmask.any():
        out[hexmask] = s[hexmask].apply(lambda v: int(v, 16))
    return out


def load_csv(path, nrows=None):
    header = pd.read_csv(path, nrows=0).columns.tolist()
    m = {k: pick(header, k) for k in CANDIDATES}
    need = [m["time"], m["src"]]
    if any(n is None for n in need):
        sys.exit(f"{path}: cannot find time/source columns. Header starts: {header[:15]}")
    use = sorted({c for c in m.values() if c})
    df = pd.read_csv(path, usecols=use, nrows=nrows, low_memory=False)
    out = pd.DataFrame()
    out["time"] = to_num(df[m["time"]])
    out["length"] = to_num(df[m["length"]]) if m["length"] else 0
    out["signal_dbm"] = to_num(df[m["signal"]]) if m["signal"] else np.nan
    out["frame_type"] = to_num(df[m["type"]]) if m["type"] else np.nan
    if m["subtype"]:
        out["frame_subtype"] = to_num(df[m["subtype"]])
    elif m["typesub"]:
        out["frame_subtype"] = to_num(df[m["typesub"]])
    else:
        out["frame_subtype"] = np.nan
    out["src"] = df[m["src"]].astype(str).str.split(",").str[0]
    out["dst"] = df[m["dst"]].astype(str).str.split(",").str[0] if m["dst"] else ""
    if m["label"]:
        lab = df[m["label"]].astype(str).str.strip().str.lower()
        out["y"] = (~lab.isin(["normal", "0", "benign"])).astype(int)
    else:
        out["y"] = -1                      # unlabelled (live / replay without labels)
    out = out.dropna(subset=["time"]).reset_index(drop=True)
    return out


# ---------------------------------------------------------------- features
def add_features(df):
    """Per-frame features + 'how busy was this sender in this 1-second window'."""
    df = df.copy()
    df["frame_type"] = df["frame_type"].fillna(-1)
    df["frame_subtype"] = df["frame_subtype"].fillna(-1)
    df["signal_dbm"] = df["signal_dbm"].fillna(df["signal_dbm"].median() if df["signal_dbm"].notna().any() else -100)
    df["length"] = df["length"].fillna(0)
    df["is_deauth"] = ((df["frame_type"] == 0) & (df["frame_subtype"] == DEAUTH_SUBTYPE)).astype(int)
    df["window"] = np.floor(df["time"]).astype("int64")

    g = df.groupby(["window", "src"])
    df["src_fps"] = g["time"].transform("size")                      # frames/s sent by this MAC
    df["src_deauth_fps"] = g["is_deauth"].transform("sum")           # deauth frames/s sent by this MAC
    df["src_unique_dst"] = g["dst"].transform("nunique")             # distinct targets hit
    gw = df.groupby("window")
    df["global_deauth_fps"] = gw["is_deauth"].transform("sum")       # deauth frames/s on the channel
    df["deauth_ratio"] = df["global_deauth_fps"] / gw["time"].transform("size")
    return df


# ---------------------------------------------------------------- train
def cmd_train(a):
    files = sorted(glob.glob(os.path.join(a.data, a.pattern)))
    if not files:
        sys.exit(f"No files match {a.pattern} in {a.data}")
    frames = []
    for i, f in enumerate(files):
        print(f"[{i+1}/{len(files)}] {os.path.basename(f)}")
        d = load_csv(f, nrows=a.rows_per_file)
        d["window"] = np.floor(d["time"]).astype("int64")
        d["file_id"] = i
        frames.append(add_features(d).assign(file_id=i))
    df = pd.concat(frames, ignore_index=True)
    df = df[df["y"] >= 0]
    print(f"Total frames: {len(df):,}   malicious: {df['y'].sum():,} ({df['y'].mean():.1%})")
    if df["y"].nunique() < 2:
        sys.exit("Only one class in the data - need both Normal and attack rows.")

    # File-level split: whole capture files are held out, so the test set is genuinely unseen traffic.
    # Attack-containing and attack-free files are split separately so both appear in the test set.
    rng = np.random.default_rng(42)
    has_atk = df.groupby("file_id")["y"].max()
    test_files = []
    for grp in (has_atk[has_atk == 1].index.values, has_atk[has_atk == 0].index.values):
        grp = rng.permutation(np.array(grp))
        test_files += list(grp[:max(1, int(round(0.3 * len(grp))))]) if len(grp) > 1 else []
    te_mask = df["file_id"].isin(test_files).values
    tr, te = np.where(~te_mask)[0], np.where(te_mask)[0]
    print(f"Held-out test files: {sorted(int(f) for f in test_files)}  (train {len(tr):,} frames, test {len(te):,})")
    y = df["y"]

    def fit_eval(cols):
        m = RandomForestClassifier(n_estimators=100, max_depth=12, class_weight="balanced",
                                   n_jobs=-1, random_state=42).fit(df[cols].iloc[tr], y.iloc[tr])
        p = m.predict(df[cols].iloc[te])
        return m, p

    clf, pred = fit_eval(FEATURES)
    _, pred_b = fit_eval(BEHAVIOUR)
    rule = df["is_deauth"].iloc[te].values            # baseline: "every deauth frame is an attack"
    def met(p):
        yt = y.iloc[te]
        return {"accuracy": accuracy_score(yt, p), "precision": precision_score(yt, p, zero_division=0),
                "recall": recall_score(yt, p, zero_division=0), "f1": f1_score(yt, p, zero_division=0)}
    cm = confusion_matrix(y.iloc[te], pred, labels=[0, 1])
    res = {
        **met(pred),
        "confusion_matrix": cm.tolist(),
        "baseline_rule": met(rule), "behaviour_only": met(pred_b),
        "behaviour_only_cm": confusion_matrix(y.iloc[te], pred_b, labels=[0, 1]).tolist(),
        "n_train": int(len(tr)), "n_test": int(len(te)),
        "n_files": len(files), "n_test_files": len(test_files), "pct_malicious": float(df["y"].mean()),
        "feature_importance": dict(zip(FEATURES, map(float, clf.feature_importances_))),
        "synthetic": bool(a.synthetic),
    }
    print("\n== Full model (all features) ==")
    print(classification_report(y.iloc[te], pred, target_names=["normal", "deauth"], zero_division=0))
    print("Confusion matrix [[TN FP][FN TP]]:\n", cm)
    print("\n== Baseline: 'subtype==deauth' rule ==", {k: round(v, 4) for k, v in res["baseline_rule"].items()})
    print("== Behaviour-only model (no subtype/deauth counts) ==", {k: round(v, 4) for k, v in res["behaviour_only"].items()})
    print("   confusion:", res["behaviour_only_cm"])
    os.makedirs(a.out, exist_ok=True)
    joblib.dump(clf, os.path.join(a.out, "wids_model.joblib"))
    json.dump(res, open(os.path.join(a.out, "results.json"), "w"), indent=2)
    plot_cm(cm, os.path.join(a.out, "confusion_matrix.png"))
    print(f"Saved model, results.json and confusion_matrix.png to {a.out}")


def cmd_scan(a):
    """Count malicious frames per file so you know which files to use for the replay demo."""
    for f in sorted(glob.glob(os.path.join(a.data, a.pattern)), key=lambda p: int(''.join(c for c in os.path.basename(p) if c.isdigit()) or 0)):
        d = load_csv(f, nrows=a.rows_per_file)
        print(f"{os.path.basename(f):16s} frames={len(d):>8,}  malicious={int(d['y'].sum()):>7,}  deauth-subtype={int(((d.frame_type==0)&(d.frame_subtype==DEAUTH_SUBTYPE)).sum()):>7,}")


def plot_cm(cm, path):
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(4.5, 4))
    ax.imshow(cm, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i][j]:,}", ha="center", va="center",
                    color="white" if cm[i][j] > np.max(cm) / 2 else "black", fontsize=13)
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["Normal", "Deauth"]); ax.set_yticklabels(["Normal", "Deauth"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title("Confusion matrix")
    fig.tight_layout(); fig.savefig(path, dpi=200); plt.close(fig)


# ---------------------------------------------------------------- detection / prevention
class Responder:
    """Alerts and (WIPS) blocks. 'Blocking' = add MAC to blocklist.json + log; a real
    deployment would feed this list to the AP's MAC filter / hostapd deny file."""
    def __init__(self, wips, outdir, min_frames=10):
        self.wips, self.min_frames = wips, min_frames
        self.blocklist_path = os.path.join(outdir, "blocklist.json")
        self.log_path = os.path.join(outdir, "alerts.log")
        self.blocked = set(json.load(open(self.blocklist_path))) if os.path.exists(self.blocklist_path) else set()
        os.makedirs(outdir, exist_ok=True)

    def handle(self, window, per_src_counts):
        for mac, n in per_src_counts.items():
            if n < self.min_frames:          # ignore stray single misclassified frames
                continue
            ts = time.strftime("%H:%M:%S", time.localtime(window))
            msg = f"[{ts}] ALERT deauth flood from {mac}: {n} malicious frames in 1 s"
            if self.wips and mac not in self.blocked:
                self.blocked.add(mac)
                json.dump(sorted(self.blocked), open(self.blocklist_path, "w"), indent=2)
                msg += "  -> MAC added to blocklist"
            print("\033[91m" + msg + "\033[0m")
            open(self.log_path, "a").write(msg + "\n")


def cmd_replay(a):
    clf = joblib.load(os.path.join(a.out, "wids_model.joblib"))
    df = add_features(load_csv(a.csv, nrows=a.rows))
    df["pred"] = clf.predict(df[FEATURES])
    resp = Responder(a.wips, a.out, a.min_frames)
    n_alerts = 0
    for w, grp in df.groupby("window"):
        bad = grp[grp["pred"] == 1]
        counts = bad.groupby("src").size().to_dict()
        if any(v >= a.min_frames for v in counts.values()):
            n_alerts += 1
        resp.handle(w, counts)
        if a.speed > 0:
            time.sleep(1.0 / a.speed)
    print(f"Replay finished: {len(df):,} frames, {n_alerts} alert windows, {len(resp.blocked)} MACs blocked")


def cmd_live(a):
    from scapy.all import sniff, Dot11, Dot11Deauth, RadioTap
    clf = joblib.load(os.path.join(a.out, "wids_model.joblib"))
    resp = Responder(a.wips, a.out, a.min_frames)
    buf, state = [], {"win": None}

    def flush():
        if not buf:
            return
        df = add_features(pd.DataFrame(buf))
        df["pred"] = clf.predict(df[FEATURES])
        resp.handle(state["win"], df[df["pred"] == 1].groupby("src").size().to_dict())
        buf.clear()

    def on_pkt(p):
        if not p.haslayer(Dot11):
            return
        t = time.time()
        sig = getattr(p[RadioTap], "dBm_AntSignal", None) if p.haslayer(RadioTap) else None
        buf.append({"time": t, "length": len(p), "signal_dbm": sig if sig is not None else np.nan,
                    "frame_type": p[Dot11].type, "frame_subtype": p[Dot11].subtype,
                    "src": p[Dot11].addr2 or "?", "dst": p[Dot11].addr1 or "?", "y": -1})
        w = int(t)
        if state["win"] is None:
            state["win"] = w
        if w != state["win"]:
            flush(); state["win"] = w

    print(f"Sniffing on {a.iface} (Ctrl-C to stop) ...")
    sniff(iface=a.iface, prn=on_pkt, store=False)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = p.add_subparsers(dest="cmd", required=True)
    t = sp.add_parser("train")
    t.add_argument("--data", default="."); t.add_argument("--pattern", default="Deauth_*.csv")
    t.add_argument("--rows-per-file", type=int, default=100000)
    t.add_argument("--out", default="output"); t.add_argument("--synthetic", action="store_true")
    c = sp.add_parser("scan")
    c.add_argument("--data", default="."); c.add_argument("--pattern", default="Deauth_*.csv")
    c.add_argument("--rows-per-file", type=int, default=100000)
    r = sp.add_parser("replay")
    r.add_argument("--csv", required=True); r.add_argument("--rows", type=int, default=None)
    r.add_argument("--out", default="output"); r.add_argument("--wips", action="store_true")
    r.add_argument("--min-frames", type=int, default=10)
    r.add_argument("--speed", type=float, default=0, help="windows per second (0 = as fast as possible; 1 = real time)")
    l = sp.add_parser("live")
    l.add_argument("--iface", required=True); l.add_argument("--out", default="output")
    l.add_argument("--wips", action="store_true"); l.add_argument("--min-frames", type=int, default=10)
    a = p.parse_args()
    {"train": cmd_train, "scan": cmd_scan, "replay": cmd_replay, "live": cmd_live}[a.cmd](a)


if __name__ == "__main__":
    main()
