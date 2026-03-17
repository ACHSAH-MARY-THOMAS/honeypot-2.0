# Honeypot 2.0 — Deception-Based Cyber Threat Detection

A live deception technology system that deploys a Cowrie SSH honeypot,
processes attack logs through a Python FastAPI backend with Machine Learning,
and visualises everything on a React.js real-time dashboard.

## Live Results
- 1042+ real attack events captured
- 73.5% detection accuracy
- 98.6% zero-day capture rate
- 6 ML and behavioural intelligence modules

## Tech Stack
- Ubuntu 22.04 LTS inside VirtualBox
- Python 3.12 + FastAPI + Uvicorn
- scikit-learn + numpy
- React.js + Recharts
- Cowrie 2.5 SSH Honeypot

## Setup

### Backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000

### Frontend
cd frontend
npm install
npm start

## Reference
Moric et al. Informatics 2025, 12, 14.
