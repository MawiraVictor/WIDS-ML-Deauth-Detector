#!/usr/bin/env python3
"""Builds the single A1 poster (594 x 841 mm) from output/results.json.
Usage:  python poster.py output/results.json WIDS_poster_A1.pdf
EDIT the three variables below (name line, AI statement) before printing."""
import json, sys, textwrap
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import numpy as np
 
# ------------------------------------------------------------------ EDIT THESE
NAME_LINE = "Mawira Victor  ·  193423  ·  Mobile and Wireless Security  ·  Strathmore University  ·  2026"
AI_STATEMENT = ("I used Claude (Anthropic) to help write the Python code: CSV loading, the 1-second "
                "window features, the scikit-learn training and evaluation script, the alert and "
                "blocklist logic, and this poster generator. I reviewed and tested the code and can "
                "explain each part in the demo: how the features are computed, why the split is by "
                "whole files, how the Random Forest votes, and how the WIPS action works.")
# ------------------------------------------------------------------------------
 
res = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "output/results.json"))
out = sys.argv[2] if len(sys.argv) > 2 else "WIDS_poster_A1.pdf"
NAVY, TEAL, RED, GREY, INK = "#14213d", "#0f766e", "#b91c1c", "#475569", "#111827"
U = 16.84            # points per layout unit (page is 100 x 141.6 units)
 
fig = plt.figure(figsize=(23.39, 33.11))
bg = fig.add_axes([0, 0, 1, 1]); bg.axis("off"); bg.set_xlim(0, 100); bg.set_ylim(0, 141.6)
 
def box(x, y, w, h, fc="#f1f5f9"):
    bg.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.8", fc=fc, ec="none"))
 
def heading(x, y, s):
    bg.text(x, y, s, fontsize=40, fontweight="bold", color=TEAL, va="top")
 
def para(x, y, s, size, width, color=INK, mono=False, gap=1.0):
    """Word-wrap each line of s to `width` layout units and draw it. Returns y below the text."""
    cpl = max(10, int(width * U / (size * (0.62 if mono else 0.51))))
    lines = []
    for p in s.split("\n"):
        if not p.strip():
            lines.append(""); continue
        ind = "  " if p.startswith("•") else ""
        lines += textwrap.wrap(p, cpl, subsequent_indent=ind) or [""]
    bg.text(x, y, "\n".join(lines), fontsize=size, color=color, va="top", linespacing=1.35,
            family="monospace" if mono else None)
    return y - len(lines) * size * 1.62 / U - gap
 
# ---------------------------------------------------------------- title band
box(0, 128, 100, 13.6, fc=NAVY)
bg.text(3, 139.8, "Machine-Learning Wireless Intrusion Detection System (WIDS)", fontsize=40, fontweight="bold", color="white", va="top")
bg.text(3, 134.6, "Detecting and blocking Wi-Fi deauthentication flood attacks with a Random Forest", fontsize=27, color="#cbd5e1", va="top")
bg.text(3, 130.6, NAME_LINE, fontsize=22, color="#94a3b8", va="top")
if res.get("synthetic"):
    bg.text(97, 130.6, "DEMO NUMBERS (synthetic data) - re-run on AWID3 before printing", fontsize=20, color="#fca5a5", ha="right", va="top", fontweight="bold")
 
# ---------------------------------------------------------------- 1 + 2 (left)
box(2, 54, 46, 72)
heading(4, 124.5, "1  The problem")
y = para(4, 120.5,
    "A deauthentication frame is an unauthenticated 802.11 management frame that tells a client to disconnect. "
    "An attacker can forge it (spoofing the access point's MAC) and flood the channel, kicking users off "
    "repeatedly. It is the first step of evil-twin and handshake-capture attacks, and 802.11w (PMF) is rarely enforced.",
    23, 42, gap=1.0)
y = para(4, y, "Goal: read wireless frames, extract a few simple features, let a classifier label traffic Normal or "
    "Malicious, then alert and (WIPS) block the offending MAC.", 23, 42, gap=1.5)
 
heading(4, y, "2  How the system works")
fy = y - 5.5
steps = ["Capture / CSV\n(AWID3 or\nmonitor mode)", "Feature\nextraction\n(1 s windows)", "Random Forest\n(scikit-learn)", "Alert +\nblock MAC\n(WIPS)"]
for i, s in enumerate(steps):
    x = 4 + i * 10.9
    box(x, fy - 11, 9.5, 11, fc=TEAL if i != 3 else RED)
    bg.text(x + 4.75, fy - 5.5, s, fontsize=16, color="white", ha="center", va="center", fontweight="bold")
    if i < 3:
        bg.annotate("", xy=(x + 10.85, fy - 5.5), xytext=(x + 9.55, fy - 5.5), arrowprops=dict(arrowstyle="->", lw=3, color=GREY))
y = fy - 12.5
y = para(4, y,
    "Per frame: type, subtype, is_deauth, length, signal strength (dBm).\n"
    "Per sender per second: frames/s, deauth frames/s, distinct targets.\n"
    "Channel-wide: deauth frames/s and deauth ratio.\n"
    "Split by whole capture files, so the test traffic is unseen.", 22, 42, gap=1.0)
para(4, y, "Replay mode streams a CSV window by window; live mode sniffs a monitor-mode interface "
    "(own, authorised lab network only). An alert needs 10 or more malicious frames from one MAC in 1 s.", 20, 42, color=GREY)
 
# ---------------------------------------------------------------- 3 results (right)
box(52, 54, 46, 72)
heading(54, 124.5, "3  Results")
bg.text(54, 119.3, f"Held-out test: {res['n_test']:,} frames from {res.get('n_test_files','?')} of {res['n_files']} capture files",
        fontsize=19, color=GREY, va="top")
 
def draw_cm(rect, cmx, title):
    ax = fig.add_axes(rect); cmx = np.array(cmx)
    ax.imshow(cmx, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cmx[i][j]:,}", ha="center", va="center", fontsize=19,
                    color="white" if cmx[i][j] > cmx.max() / 2 else "black")
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["Normal", "Deauth"], fontsize=15); ax.set_yticklabels(["Normal", "Deauth"], fontsize=15, rotation=90, va="center")
    ax.set_xlabel("Predicted", fontsize=15); ax.set_ylabel("Actual", fontsize=15)
    ax.set_title(title, fontsize=18, pad=8)
beh = res.get("behaviour_only", res)
draw_cm([0.555, 0.665, 0.16, 0.115], res["confusion_matrix"], "All features")
draw_cm([0.775, 0.665, 0.16, 0.115], res.get("behaviour_only_cm", res["confusion_matrix"]), "Behaviour-only")
 
bg.text(54, 89, "Behaviour-only model (no subtype / deauth counts)", fontsize=20, color=GREY, va="top", fontweight="bold")
for i, (k, v) in enumerate([("Accuracy", beh["accuracy"]), ("Precision", beh["precision"]), ("Recall", beh["recall"]), ("F1", beh["f1"])]):
    x = 54 + i * 11
    bg.text(x, 85.5, f"{v:.2%}", fontsize=33, fontweight="bold", color=TEAL, va="top")
    bg.text(x, 81.2, k, fontsize=19, color=GREY, va="top")
para(54, 78.2,
     f"Random Forest, 100 trees, depth 12. The simple rule 'subtype = deauth' scores "
     f"{res.get('baseline_rule', {}).get('accuracy', 0):.2%} accuracy, as good as the all-features model, "
     "so the behaviour-only model is the fairer ML result.", 21, 42, color=GREY)
 
ax2 = fig.add_axes([0.70, 0.405, 0.25, 0.08])
fi = sorted(res["feature_importance"].items(), key=lambda kv: kv[1])
ax2.barh([k for k, _ in fi], [v for _, v in fi], color=TEAL)
ax2.set_title("Which features mattered (all-features model)", fontsize=17, loc="left")
ax2.tick_params(labelsize=14)
for s in ("top", "right"): ax2.spines[s].set_visible(False)
 
# ---------------------------------------------------------------- 4 + 5
box(2, 29, 46, 23)
heading(4, 50.5, "4  What I would improve")
para(4, 46.2,
     "• A simple rule is as accurate as the full model, so strengthen the behaviour-only features.\n"
     "• Test on unseen attack types (disassociation, evil twin, KRACK) and other networks.\n"
     "• Attackers spoof the AP's MAC, so blocking it can block the real AP: detect forged frames with sequence numbers and RSSI.\n"
     "• Push the blocklist to the AP (hostapd deny list) and recommend 802.11w.\n"
     "• Measure real-time latency and CPU on a Raspberry Pi sensor.", 19, 42, gap=0.4)
 
box(52, 29, 46, 23)
heading(54, 50.5, "5  Use of AI coding assistants")
para(54, 46.2, AI_STATEMENT, 21, 42)
 
# ---------------------------------------------------------------- 6 ethics + run
box(2, 2, 96, 25, fc="#fff7ed")
heading(4, 25.5, "6  Ethics & scope")
para(4, 21.2,
     "All data comes from the public AWID3 dataset (or an isolated lab network I own or am authorised to test). "
     "No attack traffic was generated against any third-party network. The WIPS action in this prototype only "
     "logs and blocklists a MAC address; it does not transmit frames or jam anything.", 23, 90, gap=1.2)
bg.text(4, 12.6, "Run it:", fontsize=24, fontweight="bold", color=NAVY, va="top")
bg.text(4, 9.4,
        'python wids.py train  --data WIDS_project --pattern "Deauth_*.csv"\n'
        "python wids.py replay --csv Deauth_27.csv --wips\n"
        "sudo python wids.py live --iface wlan0mon --wips", fontsize=19, family="monospace", va="top", color=INK, linespacing=1.4)
 
fig.savefig(out, dpi=100)
print("saved", out)
 
