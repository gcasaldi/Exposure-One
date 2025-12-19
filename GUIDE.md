# Exposure One - Guida Utente

## 📖 Introduzione

Exposure One è uno strumento di **attack surface discovery** e **misconfiguration assessment** che fornisce una valutazione rapida del livello di esposizione di un asset pubblico.

## 🚀 Quick Start

### 1. Installazione

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
```

### 2. Avvio del Servizio

```bash
python main.py
```

Il servizio sarà disponibile su:
- **Frontend UI**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🔍 Come Funziona

### Input Accettati

- **Dominio**: `example.com`, `www.example.com`, `subdomain.example.com`
- **Indirizzo IP**: `1.2.3.4`

### Flusso di Scansione

1. **Input**: Inserisci dominio o IP
2. **Scanning**: Esecuzione automatica di 5 moduli:
   - Network Exposure
   - TLS Security
   - HTTP Security Headers
   - Domain Intelligence
   - Email Security
3. **Risk Scoring**: Calcolo automatico dell'Exposure Score (0-100)
4. **Output**: Visualizzazione con doppia vista

## 📊 Interpretazione dei Risultati

### Exposure Score

| Punteggio | Livello | Significato |
|-----------|---------|-------------|
| 0-25 | 🟢 Low | Configurazione sicura, rischi minimi |
| 26-50 | 🟡 Moderate | Alcuni problemi da risolvere |
| 51-75 | 🟠 High | Rischi significativi, intervento necessario |
| 76-100 | 🔴 Critical | Esposizione critica, priorità massima |

### Executive View 👔

**Per chi:** Management, Decision Maker, Audit

**Contenuto:**
- Exposure Score sintetico
- Top 3 rischi identificati
- 3 raccomandazioni prioritarie
- Breakdown per categoria

**Obiettivo:** Decisioni rapide e prioritarizzazione

### Technical View 🔧

**Per chi:** Security Analyst, Architect, DevSecOps

**Contenuto:**
- Dettaglio di ogni controllo eseguito
- Evidenze tecniche
- Impact e recommendation per ogni finding
- Metadata di esecuzione

**Obiettivo:** Remediation planning e implementazione

## 🔍 Moduli di Scansione

### 1️⃣ Network Exposure

**Cosa fa:**
- Scansiona porte comuni (80, 443, 22, 3389, etc.)
- Identifica servizi esposti pubblicamente
- Rileva superfici inutilmente esposte

**Porte ad alto rischio:**
- **23 (Telnet)**: Trasmissione credenziali in chiaro
- **3389 (RDP)**: Target per brute force
- **5900 (VNC)**: Spesso con autenticazione debole
- **445 (SMB)**: Vettore ransomware
- **Database ports**: MySQL, PostgreSQL, Redis, MongoDB

**Best practice:**
- Chiudere porte non necessarie
- Usare VPN per servizi amministrativi
- Firewall rules con whitelist IP

### 2️⃣ TLS & Transport Security

**Cosa fa:**
- Verifica disponibilità HTTPS
- Controlla versioni TLS supportate
- Analizza cipher suite
- Valida certificato TLS

**Finding comuni:**
- **HTTPS non disponibile**: Comunicazioni non cifrate
- **TLS 1.0/1.1**: Protocolli deprecati e insicuri
- **Cipher suite deboli**: RC4, DES, 3DES
- **Certificato invalido**: Warning per gli utenti

**Best practice:**
- Abilitare solo TLS 1.2 e 1.3
- Usare cipher suite moderne (AES-GCM)
- Certificati validi da CA riconosciute
- HSTS con max-age >= 1 anno

### 3️⃣ HTTP Security Headers

**Cosa fa:**
- Analizza header di sicurezza HTTP
- Verifica configurazioni deboli
- Identifica information disclosure

**Header critici:**

| Header | Protezione | Valore consigliato |
|--------|------------|-------------------|
| `Strict-Transport-Security` | Downgrade attack | `max-age=31536000; includeSubDomains` |
| `Content-Security-Policy` | XSS, injection | Policy restrittiva senza `unsafe-*` |
| `X-Frame-Options` | Clickjacking | `DENY` o `SAMEORIGIN` |
| `X-Content-Type-Options` | MIME sniffing | `nosniff` |

**Best practice:**
- Implementare tutti gli header critici
- Evitare `unsafe-inline` e `unsafe-eval` in CSP
- Rimuovere header informativi (`Server`, `X-Powered-By`)

### 4️⃣ Domain Intelligence

**Cosa fa:**
- Verifica risoluzione DNS
- Controlla record di sicurezza (CAA, DNSSEC)
- Analizza infrastruttura DNS

**Controlli:**
- **DNS resolution**: Dominio risolvibile
- **CAA records**: Controllo emissione certificati
- **DNSSEC**: Protezione da DNS poisoning

**Best practice:**
- Configurare DNSSEC
- Impostare CAA records per limitare CA
- Monitorare cambiamenti DNS

### 5️⃣ Email Security Posture

**Cosa fa:**
- Verifica SPF, DKIM, DMARC
- Valuta protezione anti-spoofing
- Analizza policy email

**Record critici:**

**SPF (Sender Policy Framework)**
```
v=spf1 include:_spf.example.com -all
```
- Definisce server autorizzati
- `-all`: hard fail (raccomandato)
- `~all`: soft fail (permissivo)

**DMARC (Domain-based Message Authentication)**
```
v=DMARC1; p=reject; rua=mailto:reports@example.com
```
- `p=none`: Solo monitoring ❌
- `p=quarantine`: Quarantena email sospette ⚠️
- `p=reject`: Blocca email non autenticate ✅

**Best practice:**
- Configurare SPF con `-all`
- Implementare DMARC con policy `reject`
- Setup DKIM per signing
- Monitorare report DMARC

## 🔧 Uso Avanzato

### API REST

#### POST /api/scan

Esegue una scansione completa.

**Request:**
```json
{
  "target": "example.com"
}
```

**Response:**
```json
{
  "target": "example.com",
  "scan_id": "abc123",
  "timestamp": "2025-12-19T10:00:00Z",
  "risk_score": {
    "total_score": 45,
    "risk_level": "moderate",
    "category_scores": {
      "Network": 30,
      "TLS": 20,
      "HTTP Headers": 50,
      "Domain": 10,
      "Email Security": 60
    }
  },
  "executive_view": { ... },
  "technical_view": { ... },
  "scan_duration": 8.5
}
```

#### GET /api/health

Verifica stato del servizio.

**Response:**
```json
{
  "status": "healthy",
  "modules": {
    "network": "operational",
    "tls": "operational",
    "headers": "operational",
    "domain": "operational",
    "email": "operational"
  }
}
```

### Integrazione CI/CD

Esempio con GitHub Actions:

```yaml
name: Security Scan

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan with Exposure One
        run: |
          curl -X POST http://your-exposure-one/api/scan \
            -H "Content-Type: application/json" \
            -d '{"target": "${{ secrets.DOMAIN }}"}' \
            | jq '.risk_score.total_score' \
            | awk '{ if ($1 > 50) exit 1 }'
```

## ⚠️ Limitazioni

### Cosa NON è Exposure One

❌ **NON è un vulnerability scanner completo**
- Non esegue exploit
- Non testa CVE specifiche
- Non fa penetration testing

❌ **NON sostituisce EDR/SIEM**
- Non monitoring continuo
- Non incident response
- Non threat intelligence

❌ **NON è un compliance checker completo**
- Non copre tutti i framework (PCI-DSS, GDPR, etc.)
- Non genera report di compliance formali

### Cosa È Exposure One

✅ **Pre-assessment tool**
- Snapshot rapido dell'esposizione
- Identificazione quick wins
- Prioritarizzazione interventi

✅ **Security posture awareness**
- Visibilità attack surface
- Misconfiguration detection
- Risk scoring

✅ **Decision support**
- Executive + Technical views
- Actionable recommendations
- Fast feedback loop

## 🔒 Privacy e Sicurezza

### Garanzie

✅ **Nessun dato persistente**
- Nessun database
- Nessun log persistente
- Stateless by design

✅ **Analisi non invasiva**
- Solo controlli passivi e low-impact
- Nessun exploit
- Nessun stress test

✅ **No agent required**
- Scan remoto via rete
- Nessuna installazione su target
- Zero footprint

### Raccomandazioni

⚠️ **Prima di scansionare:**
- Assicurati di avere autorizzazione
- Non scansionare asset di terze parti senza permesso
- Rispetta rate limiting e ToS dei servizi

## 📚 Risorse

### Standard di Riferimento

- OWASP Top 10
- OWASP ASVS
- CIS Benchmarks
- NIST Cybersecurity Framework

### Tools Complementari

**Per approfondimenti:**
- **Nmap**: Network scanning completo
- **SSLLabs**: Test TLS approfondito
- **SecurityHeaders.com**: Analisi header
- **MXToolbox**: Diagnostica email completa

**Per vulnerability assessment:**
- **Nessus**: Vulnerability scanner
- **OpenVAS**: Open source scanner
- **Qualys**: Cloud security platform

## 🤝 Supporto

Per problemi, domande o suggerimenti:
- Apri una Issue su GitHub
- Consulta la documentazione API: `/docs`
- Verifica health status: `/api/health`

---

**Know your attack surface before attackers do.** 🎯
