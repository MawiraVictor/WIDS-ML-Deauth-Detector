#!/usr/bin/env python3
"""Make small AWID3-style CSVs (same column names) so the pipeline can be tested without the real dataset.
   NOT real data - results from these files must not be reported as AWID3 results."""
import argparse, os
import numpy as np, pandas as pd

def mac(rng):
    return ":".join(f"{b:02x}" for b in rng.integers(0, 256, 6))

def make(seed, seconds=120):
    rng = np.random.default_rng(seed)
    aps = [mac(rng) for _ in range(3)]
    clients = [mac(rng) for _ in range(12)]
    attacker = mac(rng)
    rows = []
    attack_secs = set(rng.choice(seconds, size=seconds // 4, replace=False))
    t0 = 1_700_000_000
    for s in range(seconds):
        n = rng.integers(40, 120)                       # normal background traffic
        for _ in range(n):
            c, ap = rng.choice(clients), rng.choice(aps)
            kind = rng.choice(["data", "beacon", "probe", "ack", "deauth"], p=[.6, .2, .1, .095, .005])
            ty, st = {"data": (2, 0), "beacon": (0, 8), "probe": (0, 4), "ack": (1, 13), "deauth": (0, 12)}[kind]
            src, dst = (ap, "ff:ff:ff:ff:ff:ff") if kind == "beacon" else (c, ap) if rng.random() < .5 else (ap, c)
            rows.append((t0 + s + rng.random(), rng.integers(30, 1500), rng.normal(-55, 6), ty, st, src, dst, "Normal"))
        if s in attack_secs:                            # deauth flood: spoofed AP address, many frames/s
            for _ in range(rng.integers(150, 400)):
                rows.append((t0 + s + rng.random(), 26, rng.normal(-35, 4), 0, 12,
                             rng.choice(aps) if rng.random() < .8 else attacker, rng.choice(clients), "Deauth"))
    df = pd.DataFrame(rows, columns=["frame.time_epoch", "frame.len", "radiotap.dbm_antsignal",
                                     "wlan.fc.type", "wlan.fc.subtype", "wlan.sa", "wlan.da", "Label"])
    return df.sort_values("frame.time_epoch")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default="synthetic"); ap.add_argument("--n", type=int, default=4)
    a = ap.parse_args(); os.makedirs(a.out, exist_ok=True)
    for i in range(a.n):
        make(i).to_csv(os.path.join(a.out, f"Deauth_{i}.csv"), index=False)
    print("wrote", a.n, "files to", a.out)
