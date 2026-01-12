# Enhanced Phishing Website Detection using Machine Learning

## Overview
This project implements a machine learning–based system to detect phishing websites using URL-based features and ensemble learning techniques.

## Dataset
- Sources: Kaggle, PhishTank
- Size: 11,000+ URLs (phishing and legitimate)

## Methodology
- Feature extraction from URLs (length, HTTPS, domain age, special characters)
- Data preprocessing and class balancing
- Model training and evaluation

## Models Used
- Gradient Boosting (Best Performer)
- CatBoost, XGBoost
- Random Forest, SVM, Logistic Regression

## Results
- Accuracy: 97.4%
- F1-score: 0.98
- Recall: 0.99

## Tech Stack
- Python, scikit-learn, Pandas, NumPy
- Flask (for deployment)

## Future Work
- Deep learning models (LSTM, CNN)
- Browser extension for real-time detection

