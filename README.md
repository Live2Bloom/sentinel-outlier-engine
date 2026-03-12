# SentinelLog: Behavioral Anomaly Detection Engine
SentinelLog is a high-performance security monitoring tool developed in C, designed to instantly flag suspicous activity, capturing their ip address and keeping a profile of their behavior. It does this by identifying network intrusions through statistical modeling rather than static signature matching. By analyzing traffic as multidimensional vectors, the engine detects patterns such as low-and-slow data exfiltration and high-velocity brute force attacks.
---
## Technical Overview
The system processes raw server logs to establish a behavioral baseline for every unique IP address. It treats user activity as a coordinate in a 3D space defined by:
* **X-Axis:** Total Request Volume
* **Y-Axis:** Data Transfer (Bytes)
* **Z-Axis:** Error Frequency (Status Codes)

### Key Features
* **Statistical Outlier Detection:** Utilizes Z-Score normalization to identify users deviating from the established network mean.
* **Custom Indexing:** Implements a Jenkins-style hash table with linear probing for O(1) user profile lookups.
* **Vector Analysis:** Distinguishes between attack types by calculating the behavioral angle of the activity vector.
* **Automated Testing Suite:** Includes a Python-based simulation engine for generating realistic traffic baselines.
---
## Performance Logic
The engine does not rely on arbitrary thresholds. Instead, it calculates the Euclidean Magnitude of a user activity:

$$Magnitude = \sqrt{req^2 + bytes^2 + errors^2}$$

If the resulting Z-Score exceeds a specific threshold (e.g., 3.0 for massive datasets & 1.5 for small datasets), the system flags the IP. By comparing the ratio of requests to bytes, SentinelLog categorizes specific intent:

| Attack Type | Logic Pattern | Priority |
| :--- | :--- | :--- |
| **Brute Force** | High request frequency + Minimal data transfer | High |
| **Data Exfiltration** | Low request frequency + Massive data payloads | High |
---
## Installation and Usage
### Prerequisites
* GCC (GNU Compiler Collection)
* Python 3.x

### Setup
1. **Clone the repository:**
   ```bash
   git clone [https://github.com/your-username/secure_tracking.git](https://github.com/your-username/secure_tracking.git)
   ```
2. **Navigate to directory:**
   ```bash
   cd secure_tracking
   ```
3. **Compile the engine:**
   ```bash
   gcc activity_tracker.c -o sentinel -lm
    ```

### Simulation Workflow
1. **Generate Traffic:**
   ```bash
   python3 gen_logs.py
   ```
2. **Execute Detection:**
    ```bash
    ./sentinel
    ```
3. **Review Results:**
    Check alert.csv for flagged anomalies

## Documentation
For detailed information on deploying this tool in a production-simulated environment using SSH tunnels, refer to the [Deployment Guide](DEPLOYMENT.md).

## Future Roadmap
- [ ] Integration of a FastAPI dashboard for real-time visualization.
- [ ] Implementation of PostgreSQL for historical trend analysis.
- [ ] Transitioning detection logic into a standalone AI Agent for incident response.

