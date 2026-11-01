# ML Wireless Intrusion Detection and Prevention System (WIDS / WIPS)

This project is a working prototype of a Machine Learning-based Wireless Intrusion Detection System (WIDS) with an optional Prevention System (WIPS) component. It is designed to detect Wi-Fi Deauthentication flood attacks (DoS) using a Random Forest classifier from the scikit-learn library. 

The system is trained on the public AWID3 (Aegean Wi-Fi Intrusion Dataset) and evaluates 802.11 wireless frames in real-time to determine if traffic is Normal or a Deauthentication Attack. If the Prevention mode is enabled, the system automatically logs the malicious MAC address and adds it to a blocklist.

## Architecture and Feature Engineering

Instead of analyzing raw bytes, the system processes individual 802.11 frames and engineers specific behavioral features over rolling 1-second windows to distinguish normal traffic from attack traffic.

The features extracted for the Random Forest model include:
* `frame_type` and `frame_subtype`: Identifies Management frames (Type 0, Subtype 12 indicates a Deauthentication frame).
* `is_deauth`: A boolean flag (0 or 1) confirming if the current frame is a deauth frame.
* `length`: The size of the frame in bytes.
* `signal_dbm`: The RSSI (Received Signal Strength Indicator) of the packet.
* `src_fps`: The total number of frames sent by the source MAC address in a 1-second window.
* `src_deauth_fps`: The number of deauthentication frames sent by the source MAC address in a 1-second window.
* `src_unique_dst`: The number of unique destination MAC addresses targeted by the source MAC.
* `global_deauth_fps`: The total number of deauth frames observed across the entire channel in a 1-second window.
* `deauth_ratio`: The ratio of deauth frames to total frames in the current window.

## Project Components

### 1. Training and Evaluation (train)
The `train` command loads the AWID3 CSV files, extracts the features listed above, and splits the data into a training set (70%) and a test set (30%). Crucially, the split is done using `GroupShuffleSplit` based on 1-second time windows. This ensures that frames from the same second do not leak into both the training and testing sets, providing a mathematically honest accuracy score.

The model uses a Random Forest Classifier with 100 estimators (decision trees) and a maximum depth of 12 to prevent overfitting.

### 2. Detection and Prevention (replay / live)
* **Replay:** Since live packet capture requires a monitor-mode wireless adapter, the `replay` command streams a CSV file through the trained model in simulated real-time. 
* **Live:** If running on Linux with a monitor-mode interface, the `live` command uses Scapy to sniff actual over-the-air traffic (this must only be used on authorized lab networks).
* **WIPS Responder:** If the Random Forest detects a frame as malicious, the `Responder` class evaluates the frequency. If a single MAC address exceeds the `min_frames` threshold (e.g., 10 deauth frames per second), the system raises a red terminal alert, writes the event to `output/alerts.log`, and adds the offending MAC to `output/blocklist.json`. In a production environment, this JSON file would be consumed by the Access Point's firewall rules to drop the attacker.

## Setup and Installation

Ensure Python 3 is installed. Install the required data science and networking libraries:

```
pip install pandas numpy scikit-learn matplotlib joblib
pip install scapy
```
Usage
1. Train the Model
Run the training script using the dataset directory. The --pattern argument allows you to select specific attack files.

```bash
python wids.py train --data "path/to/dataset" --pattern "Deauth_*.csv" --rows-per-file 100000
```
Upon completion, the model is saved to output/wids_model.joblib. A results.json file is generated containing the accuracy, precision, recall, F1-score, and confusion matrix.

2. Run the WIPS Demo (Replay)
To simulate an attack and test the Prevention system, replay a CSV file that was not used in the training phase. The --wips flag activates the prevention mechanism, and --speed 5 speeds up the simulation.
```
python wids.py replay --csv Deauth_27.csv --wips --speed 5
```
This command will output red alerts to the terminal showing the detected attack rate (frames per second) and block the MAC addresses by writing them to output/blocklist.json.

3. Run Live Detection
On a Linux machine with a wireless adapter in monitor mode:

```
sudo python wids.py live --iface wlan0mon --wips
```
4. Generate the A1 Poster
The poster.py script automatically reads the results.json file and the generated confusion matrix to create a print-ready A1 PDF poster.

```
python poster.py output/results.json WIDS_poster_A1.pdf
```
AI Usage Statement
AI coding assistants were utilized during the development of this prototype. Specifically, AI was used to assist in refactoring the data processing pipeline, engineering the time-window feature extraction logic (add_features), debugging Python environment configurations on Windows, and generating the baseline template for the A1 PDF poster.

---
Future Improvements
Hardware Integration: 
* Deploying the system on a Raspberry Pi with a dedicated monitor-mode adapter (e.g., Alfa AWUS036) for continuous 24/7 live monitoring.
* Multi-Attack Classification: Expanding the Random Forest training to detect other AWID3 attack classes, such as Evil Twin, KRACK, and SSDP floods.
* Active Defense: Integrating the blocklist.json output directly with router firmware (via SSH or API) to dynamically drop malicious MAC addresses at the Access Point level.
