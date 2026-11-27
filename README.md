# 🛡️ Shadow AI & Data Exfiltration Detector

A lightweight, Python-based blue team utility designed to parse network proxy logs, detect unauthorized generative AI endpoint usage (Shadow AI), and flag anomalous payload sizes indicative of data exfiltration. 

This project serves as a practical, engineering-focused implementation of the concepts explored in my scholarly research on *Shadow AI as an Enterprise Insider Risk*.

## 🎯 Overview
As organizations struggle with employees uploading proprietary code and sensitive data to unauthorized LLMs, security operations centers (SOCs) need quick, automated ways to audit proxy traffic. This script bridges the gap between raw log data and actionable threat intelligence by identifying exactly *who* is using AI, *what* services they are connecting to, and the *risk level* based on upload sizes.

## ✨ Features
* **Regex-Powered Endpoint Detection:** Automatically hunts for traffic targeting OpenAI, Anthropic, Hugging Face, Claude, and Gemini.
* **Exfiltration Alerting:** Analyzes HTTP payload sizes and flags requests exceeding 20KB as `CRITICAL (Data Leak)`.
* **SOC-Ready JSON Reporting:** Outputs findings in a structured, parsed JSON format, grouping violations by internal IP addresses for rapid incident response.
* **Zero Dependencies:** Built entirely with native Python libraries for easy deployment on any system.

## 🚀 Usage

**1. Clone the repository**
```bash
git clone [https://github.com/nimramanzoor/shadow-ai-detector.git](https://github.com/nimramanzoor/shadow-ai-detector.git)
cd shadow-ai-detector