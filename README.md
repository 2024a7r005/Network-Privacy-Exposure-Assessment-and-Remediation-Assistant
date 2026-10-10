# Network Privacy Exposure Assessment and Remediation Assistant

---

## 1. Ideation

Network communications can reveal privacy-relevant information through exposed metadata and the use of insecure protocols. The project idea is to make this information easier to assess by combining Wireshark traffic data with automated analysis and practical remediation guidance.

---

## 2. Problem Statement

Manually reviewing network traffic can make it difficult to identify potential privacy exposure, understand the significance of observed traffic, and determine appropriate corrective actions. A structured solution is needed to analyze captured traffic, highlight potential concerns with supporting evidence, and guide users toward remediation.

---

## 3. Proposed Solution

A Python-based web application that analyzes Wireshark CSV exports, summarizes network traffic, identifies selected privacy exposure indicators through rule-based checks, presents supporting evidence, and generates remediation recommendations and assessment reports.

---

## 4. Key Features

* Wireshark CSV import and validation
* Network traffic and protocol analysis
* Rule-based privacy findings with packet evidence
* Remediation recommendations
* Downloadable assessment reports

---

## 5. Technology Stack

* **Language:** Python
* **Framework:** Streamlit
* **Data Processing:** Pandas
* **Traffic Capture:** Wireshark
* **Input Format:** CSV

---

## 6. Methodology

1. Capture authorized network traffic using Wireshark.
2. Export packet data to CSV.
3. Process and analyze the captured data.
4. Identify potential privacy concerns using predefined rules.
5. Review evidence and remediation recommendations.
6. Export the assessment report.

---

## 7. Installation and Execution

Install dependencies:

```bash
py -m pip install -r requirements.txt
```

Run the application:

```bash
py -m streamlit run app.py
```

---

## 8. Limitations

Findings depend on the available packet metadata and implemented rules. Protocol labels alone do not confirm data exposure, and encrypted traffic contents are not decrypted. Findings should be validated against the original capture.

---

## 9. Responsible Use

Use the application only with network traffic you own or are authorized to analyze. Review captured data for sensitive information before sharing it.

---
