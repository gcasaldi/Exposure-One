git clone <repo-url>
# Exposure One - Guida rapida

1) Installazione
```bash
pip install -r requirements.txt
```

2) Modalità server (API/UI)
```bash
python main.py
# scan API
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com"}'
```

3) Solo terminale (CLI)
```bash
python cli.py              # interattivo
python cli.py --target example.com --format json  # non interattivo
```

Note
- Target: dominio o IP (no URL con path).
- Env utili: `ALLOW_ORIGINS`, `ALLOW_INSECURE_HTTPS=true`, `ALLOW_PRIVATE_TARGETS=true`.
