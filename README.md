# 🎯 Exposure One

> **Attack Surface Discovery & Misconfiguration Assessment Tool**

Exposure One è uno strumento di sicurezza progettato per fornire una fotografia rapida, affidabile e leggibile del livello di esposizione di un asset pubblico (dominio o IP).

## 🧠 Cos'è Exposure One?

Non sostituisce piattaforme EDR o vulnerability scanner completi, ma **anticipa il rischio**, permettendo decisioni rapide e prioritarizzazione.

source venv/bin/activate  # Linux/Mac
# Exposure One

Snapshot rapido dell'esposizione di un dominio/IP: network, TLS, HTTP security headers, DNS/DNSSEC/CAA, SPF/DMARC. Output JSON e CLI.

## Requisiti
- Python 3.9+
- `pip install -r requirements.txt`

## Uso rapido
Server API/web:
- `python main.py`
- API: `curl -X POST http://localhost:8000/api/scan -H "Content-Type: application/json" -d '{"target":"example.com"}'`

Solo terminale (CLI):
- Interattivo: `python cli.py`
- Non interattivo: `python cli.py --target example.com` (JSON: `--format json`)

Target accettati: dominio o IP (niente URL con path).

## Config opzionali
- `ALLOW_ORIGINS` per CORS (default localhost)
- `ALLOW_INSECURE_HTTPS=true` per accettare cert non validi nel modulo headers (solo test)
- `ALLOW_PRIVATE_TARGETS=true` per scansionare IP privati/loopback (disabilitato di default)

Licenza: MIT
- Età del dominio
