
import numpy as np


def detect_anomaly(traffic_data, current_value, threshold=3):
    """
    Detect unusual network traffic using statistical analysis.
    """

    if len(traffic_data) < 2:
        raise ValueError("At least two baseline traffic values are required.")

    if threshold <= 0:
        raise ValueError("Threshold must be greater than zero.")

    mean = float(np.mean(traffic_data))
    std_dev = float(np.std(traffic_data))

    if std_dev == 0:
        z_score = 0.0 if current_value == mean else float("inf")
    else:
        z_score = abs((current_value - mean) / std_dev)

    is_anomaly = z_score > threshold

    return {
        "mean": round(mean, 2),
        "standard_deviation": round(std_dev, 2),
        "current_value": current_value,
        "z_score": round(z_score, 2) if np.isfinite(z_score) else None,
        "is_anomaly": is_anomaly,
        "status": "ANOMALY DETECTED" if is_anomaly else "NORMAL"
    }
