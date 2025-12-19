# Esempi di Utilizzo - Exposure One

## Esempio 1: Scansione Dominio Web Standard

### Input
```
example.com
```

### Output Atteso (Executive View)
```
Exposure Score: 45
Risk Level: MODERATE

Top 3 Rischi:
1. [HTTP Headers] Header di sicurezza mancante: Content-Security-Policy
2. [Email Security] DMARC non configurato
3. [TLS] TLS 1.3 non rilevato

Raccomandazioni:
1. Configurare DMARC con policy reject/quarantine
2. Aggiungere header 'Content-Security-Policy' alla configurazione del server
3. Considerare l'upgrade a TLS 1.3
```

---

## Esempio 2: Scansione con Rischio Critico

### Input
```
vulnerable-site.com
```

### Possibile Output (Executive View)
```
Exposure Score: 82
Risk Level: CRITICAL

Top 3 Rischi:
1. [Network] RDP esposto pubblicamente
2. [Email Security] Protezione email completamente assente
3. [TLS] HTTPS non disponibile

Raccomandazioni:
1. PRIORITÀ: Configurare immediatamente SPF e DMARC
2. Chiudere porta 3389 o limitare accesso tramite VPN/firewall
3. Configurare certificato TLS e abilitare HTTPS
```

---

## Esempio 3: Configurazione Sicura

### Input
```
secure-enterprise.com
```

### Output Atteso (Executive View)
```
Exposure Score: 18
Risk Level: LOW

Top 3 Rischi:
✓ Nessun rischio critico identificato

Raccomandazioni:
✓ Mantenere le attuali best practice di sicurezza
```

---

## Esempio 4: API Usage con cURL

### Scansione Base
```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

### Scansione con Formatting (jq)
```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}' | jq '.'
```

### Estrarre Solo il Risk Score
```bash
curl -s -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}' \
  | jq '.risk_score.total_score'
```

### Estrarre Top Risks
```bash
curl -s -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}' \
  | jq '.executive_view.top_risks[]'
```

---

## Esempio 5: Python Script Integration

```python
import requests
import json

def scan_target(target):
    """Esegue una scansione e restituisce i risultati"""
    url = "http://localhost:8000/api/scan"
    payload = {"target": target}
    
    response = requests.post(url, json=payload)
    
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Scan failed: {response.status_code}")

# Esegui scansione
result = scan_target("example.com")

# Mostra risultati executive
print(f"Target: {result['target']}")
print(f"Exposure Score: {result['risk_score']['total_score']}")
print(f"Risk Level: {result['risk_score']['risk_level'].upper()}")
print("\nTop Risks:")
for risk in result['executive_view']['top_risks']:
    print(f"  - {risk}")

# Check se score è accettabile
if result['risk_score']['total_score'] > 50:
    print("\n⚠️  WARNING: Exposure score is HIGH!")
    exit(1)
else:
    print("\n✓ Exposure score is acceptable")
    exit(0)
```

---

## Esempio 6: Batch Scanning

```bash
#!/bin/bash

# Lista di domini da scansionare
DOMAINS=(
    "example1.com"
    "example2.com"
    "example3.com"
)

echo "Starting batch scan..."

for domain in "${DOMAINS[@]}"; do
    echo ""
    echo "Scanning $domain..."
    
    SCORE=$(curl -s -X POST http://localhost:8000/api/scan \
        -H "Content-Type: application/json" \
        -d "{\"target\": \"$domain\"}" \
        | jq '.risk_score.total_score')
    
    echo "  Score: $SCORE"
    
    if [ "$SCORE" -gt 50 ]; then
        echo "  ⚠️  HIGH RISK!"
    else
        echo "  ✓ OK"
    fi
done

echo ""
echo "Batch scan completed!"
```

---

## Esempio 7: Filtro per Severità

Estrarre solo finding critici:

```bash
curl -s -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}' \
  | jq '.technical_view.modules_results[].findings[] | select(.severity == "critical")'
```

---

## Esempio 8: Report Generation

```python
import requests
from datetime import datetime

def generate_report(target):
    """Genera un report markdown della scansione"""
    
    response = requests.post(
        "http://localhost:8000/api/scan",
        json={"target": target}
    )
    
    data = response.json()
    
    # Genera report
    report = f"""
# Security Scan Report

**Target:** {data['target']}  
**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Scan ID:** {data['scan_id']}

## Executive Summary

- **Exposure Score:** {data['risk_score']['total_score']}/100
- **Risk Level:** {data['risk_score']['risk_level'].upper()}
- **Total Findings:** {data['technical_view']['total_findings']}

### Risk Breakdown
- Critical: {data['technical_view']['findings_by_severity']['critical']}
- High: {data['technical_view']['findings_by_severity']['high']}
- Moderate: {data['technical_view']['findings_by_severity']['moderate']}
- Low: {data['technical_view']['findings_by_severity']['low']}

### Top Risks
"""
    for risk in data['executive_view']['top_risks']:
        report += f"- {risk}\n"
    
    report += "\n### Recommendations\n"
    for rec in data['executive_view']['recommendations']:
        report += f"- {rec}\n"
    
    return report

# Genera report
report = generate_report("example.com")

# Salva su file
with open(f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md", "w") as f:
    f.write(report)

print("Report generated!")
```

---

## Esempio 9: Monitoring Script

```bash
#!/bin/bash

# Monitor exposure score ogni ora
DOMAIN="example.com"
THRESHOLD=50

while true; do
    SCORE=$(curl -s -X POST http://localhost:8000/api/scan \
        -H "Content-Type: application/json" \
        -d "{\"target\": \"$DOMAIN\"}" \
        | jq '.risk_score.total_score')
    
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$TIMESTAMP] $DOMAIN: Score $SCORE"
    
    if [ "$SCORE" -gt "$THRESHOLD" ]; then
        echo "⚠️  ALERT: Score exceeded threshold!"
        # Qui potresti inviare una notifica (email, Slack, etc.)
    fi
    
    # Attendi 1 ora
    sleep 3600
done
```

---

## Esempio 10: CI/CD Integration (GitLab)

```yaml
# .gitlab-ci.yml

security_scan:
  stage: test
  script:
    - |
      SCORE=$(curl -s -X POST http://exposure-one:8000/api/scan \
        -H "Content-Type: application/json" \
        -d "{\"target\": \"$CI_PROJECT_NAME.example.com\"}" \
        | jq '.risk_score.total_score')
      
      echo "Exposure Score: $SCORE"
      
      if [ "$SCORE" -gt 50 ]; then
        echo "❌ Security scan failed: exposure score too high"
        exit 1
      fi
      
      echo "✅ Security scan passed"
  only:
    - main
    - production
```

---

Questi esempi coprono i casi d'uso più comuni di Exposure One, dal semplice scan interattivo all'integrazione in pipeline automatizzate.
