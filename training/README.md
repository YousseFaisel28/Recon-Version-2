# Training Modules

This directory contains scripts for training and artifact generation for the Recon-X models.

## Available Training Scripts

- `train_model3.py`: Trains the Supervised ML classifier (Logistic Regression) for Technology Vulnerability Detection using NVD ground truth.
- `train_model4.py`: Trains the Unsupervised Anomaly Detection model (Isolation Forest) using baseline HTTP/Traffic features.

## Why only Model 3 & 4?
- **Model 1 & 2** are deterministic (Rule-based) or use pre-defined industry tools (Nmap/Sublist3r) and do not require custom training pipelines in this implementation.
- **Model 5** is a Reinforcement Learning agent (Q-Learning). It learns on-the-fly or through simulation. While it has a saved state (`model5_qtable.pkl`), it does not follow a traditional supervised accuracy-based training cycle.

## Usage
Run these scripts to regenerate model artifacts in `models/artifacts/`.
```bash
python training/train_model3.py
python training/train_model4.py
```
