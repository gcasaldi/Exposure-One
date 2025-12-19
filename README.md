# 🎯 Exposure One

> **Attack Surface Discovery & Misconfiguration Assessment Tool**

Exposure One è uno strumento di sicurezza progettato per fornire una fotografia rapida, affidabile e leggibile del livello di esposizione di un asset pubblico (dominio o IP).

## 🧠 Cos'è Exposure One?

Non sostituisce piattaforme EDR o vulnerability scanner completi, ma **anticipa il rischio**, permettendo decisioni rapide e prioritarizzazione.

### Posizionamento

- ✅ Pre-assessment tool
- ✅ Security posture snapshot  
- ✅ Attack surface awareness layer

## 🔍 Moduli di Analisi

### 1️⃣ Network Exposure
- Verifica porte comuni esposte (80, 443, 22, 3389, ecc.)
- Identificazione servizi accessibili pubblicamente
- Rilevazione di superfici inutilmente esposte

### 2️⃣ TLS & Transport Security
- Presenza HTTPS
- Versioni TLS supportate
- Indicatori di configurazioni deboli

### 3️⃣ HTTP Security Headers
Analisi header critici:
- Content-Security-Policy
- X-Frame-Options
- Strict-Transport-Security
- X-Content-Type-Options

### 4️⃣ Domain Intelligence
- Età del dominio
- Coerenza DNS di base
- Segnali di infrastruttura instabile

### 5️⃣ Email Security Posture
- SPF
- DKIM
- DMARC
- Valutazione protezione anti-spoofing

## 📊 Risk Scoring

Exposure Score (0-100) basato su:
- Severità
- Probabilità di abuso
- Impatto potenziale

**Output classificato:**
- 🟢 Low Exposure (0-25)
- 🟡 Moderate Exposure (26-50)
- 🟠 High Exposure (51-75)
- 🔴 Critical Exposure (76-100)

## 👁️ Doppia Vista

### 🔹 Executive View
- Exposure score sintetico
- 3 principali fattori di rischio
- 3 raccomandazioni operative

**Pensata per:** management, decision maker, audit preliminari

### 🔹 Technical View
- Dettaglio controlli
- Evidenze tecniche
- Perché il controllo conta
- Impatto potenziale

**Pensata per:** security analyst, architect, remediation planning

## ⚙️ Stack Tecnologico

- **Backend:** FastAPI (Python)
- **Librerie:** requests, ssl, socket, dnspython
- **Frontend:** Single-page UI (HTML/JS)
- **Output:** JSON + visualizzazione semaforica

## 🔒 Filosofia di Sicurezza

- ✅ Nessun agent
- ✅ Nessuna intrusione
- ✅ Nessun dato persistente
- ✅ Solo analisi on-demand, stateless, non invasiva

### Configurazione di sicurezza (runtime)
- `ALLOW_ORIGINS` (default: `http://localhost:8000,http://127.0.0.1:8000`): lista di origin consentite per CORS
- `ALLOW_INSECURE_HTTPS` (default: `false`): se `true` consente certificati non validi nel modulo headers (sconsigliato in produzione)
- `ALLOW_PRIVATE_TARGETS` (default: `false`): se `true` permette la scansione di IP privati/loopback

## 🚀 Installazione e Uso

### Prerequisiti
- Python 3.9+

### Setup
```bash
# Clona il repository
git clone <repo-url>
cd Exposure-One

# Crea ambiente virtuale
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Installa dipendenze
pip install -r requirements.txt

# Avvia il server
python main.py
```

### Utilizzo
Apri il browser su `http://localhost:8000`

Oppure usa l'API direttamente:
```bash
# Scansione dominio
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

# Scansione IP
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "1.2.3.4"}'
```

#### Uso da terminale (senza frontend)
```bash
python cli.py --target example.com           # output tabellare
python cli.py --target example.com --format json  # output JSON completo
```

## 📁 Struttura Progetto

```
Exposure-One/
├── main.py                 # Entry point FastAPI
├── requirements.txt        # Dipendenze Python
├── README.md              # Documentazione
│
├── app/
│   ├── __init__.py
│   ├── api/               # API endpoints
│   │   ├── __init__.py
│   │   └── routes.py
│   │
│   ├── core/              # Core engine
│   │   ├── __init__.py
│   │   ├── scanner.py     # Scanner orchestrator
│   │   └── risk_scorer.py # Risk scoring engine
│   │
│   ├── modules/           # Moduli di scanning
│   │   ├── __init__.py
│   │   ├── network.py     # Network exposure
│   │   ├── tls.py         # TLS security
│   │   ├── headers.py     # HTTP headers
│   │   ├── domain.py      # Domain intelligence
│   │   └── email.py       # Email security
│   │
│   └── models/            # Data models
│       ├── __init__.py
│       └── schemas.py
│
└── static/                # Frontend
    ├── index.html
    ├── css/
    │   └── style.css
    └── js/
        └── app.js
```

## 📝 Licenza

MIT License - vedi file LICENSE

## 🤝 Contributi

Contributi benvenuti! Apri una issue o una pull request.

---

**Exposure One** - Know your attack surface before attackers do.
