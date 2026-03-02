# PhishGuard AI: Offline-First Progressive Web App for AI-Powered Phishing Detection in Critical Infrastructure
## Overview
PhishGuard AI is a full-stack AI-powered platform for detecting phishing, scam, and suspicious messages across email, SMS, and chat. It combines advanced NLP, engineered features, and machine learning to deliver real-time threat analysis, batch scanning, and actionable insights for enterprise security teams.

## Features
- **On-Device AI Threat Detection**: Fast, privacy-preserving analysis of messages using a trained ML model.
- **Batch Scan Console**: Upload or input multiple messages for bulk threat analysis.
- **Single Scan Console**: Analyze individual messages for phishing indicators.
- **Threat Analytics Dashboard**: Visualize scan history, risk trends, and feature importance.
- **Incident Marking & Logging**: Save scan results, mark incidents, and review scan history.
- **Modern PWA Frontend**: Responsive, accessible UI built with React, TypeScript, Vite, and Tailwind.
- **API-Driven Backend**: FastAPI Python backend with endpoints for single and batch scan, model inference, and feature extraction.

## Architecture
- **Backend**: Python (FastAPI), scikit-learn, joblib, custom NLP engine, trained model, engineered features.
- **Frontend**: React 18, TypeScript, Vite, Tailwind, PWA-ready, modular UI components.
- **Data**: Multiple CSV datasets, features.csv, model.joblib for training and inference.

## Folder Structure
```
phishing_shield/
├── backend/           # FastAPI backend, model, NLP engine
├── PWA_frontend/      # React PWA frontend, UI, pages, components
├── data/              # Raw datasets, features.csv
├── requirements.txt   # Python dependencies
├── README.md          # Project documentation
```

## Quick Start
### Backend
1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Generate features and train model:
   ```bash
   python backend/model/generate_features.py
   python backend/model/train_model.py
   ```
3. Start FastAPI server:
   ```bash
   uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
   ```

### Frontend
1. Install Node dependencies:
   ```bash
   cd phishing_shield/PWA_frontend
   npm install
   ```
2. Start development server:
   ```bash
   npm run dev
   ```

## API Endpoints
- `POST /scan`         : Analyze a single message
- `POST /batch-scan`   : Analyze multiple messages
- `GET /health`        : API/model/vectorizer/database status
- `POST /credentials`  : Store credential profile (Google/email account supported; password hashed)
- `GET /credentials`   : List stored credential profiles

## Security & Best Practices
- Sensitive data never leaves the device during scan
- Model and feature engineering based on real-world phishing datasets
- Node modules and build artifacts excluded from version control (.gitignore)

## Contributors

- [Krishita Garg](https://github.com/KrishitaGarg)
- [Riddhi Poddar](https://github.com/r1ddh118)
- [Prashansa Bhatia](https://github.com/prashu0705)
- [Himi Vyas](https://github.com/himi0001)
- [IshwiDhanuka](https://github.com/IshwiDhanuka)
## Authors & Attribution
- See `PWA_frontend/ATTRIBUTIONS.md` for credits and third-party libraries

---
For detailed system overview, see `PWA_frontend/SYSTEM_OVERVIEW.md`.
For deployment instructions, see `PWA_frontend/DEPLOYMENT.md`.
