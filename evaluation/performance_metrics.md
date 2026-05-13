# Performance Metrics: Recon X ML Engine

This document provides a comprehensive overview of the performance metrics for the AI models integrated into the Recon X pipeline. These metrics ensure the system remains efficient, accurate, and stable under various network reconnaissance scenarios.

## 1. Performance Overview

| Metric Category | Target Objective | Current Baseline |
| :--- | :--- | :--- |
| **Speed** | Minimize inference latency for real-time scanning. | < 50ms (Local Inference) |
| **Accuracy** | High precision to reduce false positives in vulnerability reports. | > 92% (Mean across models) |
| **Resource Usage** | Maintain low footprint for deployment on lightweight VPS. | < 500MB RAM (Standard Scan) |

---

## 2. Detailed Performance Metrics

### A. Speed (Latency & Throughput)
Speed is critical for automated reconnaissance to ensure large-scale scans complete within reasonable timeframes.

- **Inference Time**: The time taken for a single model prediction.
  - **Traditional ML (RF, DT, LR)**: ~2ms - 5ms per record.
  - **Deep Learning (LSTM)**: ~25ms - 40ms per batch.
- **Preprocessing Latency**: Time spent on feature extraction and normalization (Avg: 10ms).
- **Throughput**: Number of entities (subdomains/vulnerabilities) processed per second (Target: 100+ entities/sec).

### B. Accuracy (Reliability & Precision)
Accuracy ensures that the data provided to the security analyst is trustworthy.

- **Precision**: Focuses on reducing false positives (critical for vulnerability filtering).
- **Recall**: Ensures no critical threats are missed.
- **F1-Score**: The harmonic mean of precision and recall, providing a balanced view of model performance.
- **Anomalous Detection Rate**: Specifically for Model 1 and Model 4, measuring how effectively they flag outliers.

### C. Resource Usage (Efficiency)
Recon X is designed to be resource-efficient for cloud and edge deployments.

- **CPU Utilization**: Peak usage during LSTM training/inference (Avg: 15-20% on modern CPUs).
- **RAM Consumption**: 
  - Base: ~150MB.
  - Full Pipeline (ML + Scanner): ~450MB - 600MB.
- **Disk I/O**: Minimal, primarily for loading saved model weights and logging.

---

## 3. ML Model Accuracy Report

The following metrics represent the performance of each model on their respective test datasets.

| Model ID | Task | Accuracy | Precision | Recall | F1-Score |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Model 2** | Service Classification | 87.65% | 87.96% | 87.65% | 87.29% |
| **Model 3** | Vulnerability Identification | 100%* | 100% | 100% | 100% |
| **Model 6** | Risk Scoring & Prioritization | 97.00% | 96.80%** | 97.00% | 96.90% |

*\*Note: Model 3 metrics are based on a curated validation set of 40 samples.*
*\**Estimated based on multi-class weighted averages.*

---

## 4. How to Test AI Models

Testing AI models requires a multi-layered approach beyond traditional software testing.

| Test Type | Description | Target Metric |
| :--- | :--- | :--- |
| **Unit Testing** | Verifies individual components (e.g., feature extraction functions). | Logic Correctness |
| **Inference Testing** | Checks if the model returns the expected output for a known input. | Accuracy / Consistency |
| **Cross-Validation** | Splitting data into folds to ensure the model generalizes well. | F1-Score / Stability |
| **Stress Testing** | Running the models against extremely large or corrupted datasets. | Resource Usage / OOM |
| **Latency Profiling** | Measuring time spent in each pipeline stage using profilers (e.g., `cProfile`). | Speed (ms) |
| **Adversarial Testing** | Inputting "edge cases" designed to trick the ML logic. | Robustness |
| **A/B Testing** | Comparing a new model's performance against the previous baseline. | Overall Efficacy |
