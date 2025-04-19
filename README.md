# 🛡️ PhishGuard - Intelligent Phishing Website Detection

> ⚠️ Stay ahead of phishing attacks with real-time AI-powered detection.

---

## 📌 Overview

**PhishGuard** is a lightweight, intelligent phishing detection web app that uses machine learning to classify websites as either *Safe* or *Phishing*. With an intuitive user interface and a robust backend model, it empowers users to identify potential threats in real-time by simply submitting a URL.

---

## ✨ Features

- 🔍 **URL-based phishing detection**
- 📈 Uses **88 handcrafted features** for precise classification
- 🧠 Built on a **Random Forest Classifier** with 93.44% accuracy
- 💡 Clean and responsive web interface
- ⚡ Instant predictions with animation effects for better UX
- 📱 Mobile-friendly layout

---

## 🧠 How It Works

1. Users input a URL via the homepage.
2. The system extracts a comprehensive set of **88 features** from the URL.
3. These features are passed to a **pre-trained Random Forest model**.
4. The result is displayed on-screen, indicating if the URL is:
   - ✅ Safe
   - ❌ Phishing

---

## 🔬 Tech Stack

### Backend

- `Python`
- `Flask`
- `Scikit-learn`
- `Joblib` (for model serialization)

### Frontend

- `HTML5`, `CSS3`, `JavaScript`
- Responsive design with animated elements

---

## 📊 Model Performance

| Model               | Accuracy   |
| ------------------- | ---------- |
| ✅ Random Forest     | **93.44%** |
| Decision Tree       | 89.28%     |
| AdaBoost Classifier | 88.41%     |

---

## 🚀 Getting Started

### 🔄 Clone the Repository

```bash
git clone https://github.com/CHINMAYEEBHAT/Webpage-Phishing-detection.git
cd Webpage-Phishing-detection
```

### ⚙️ Set Up Environment

Make sure Python 3.8+ is installed.

Install the required packages:

```bash
pip install -r requirements.txt
```

### ▶️ Run the Application

```bash
python app.py
```

Now visit `http://127.0.0.1:5000` in your browser to start detecting phishing websites.

---

## 👩‍💻 Authors

- **Chinmayee Bhat**
- **Deeksha R Kunder**

---
