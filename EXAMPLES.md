# Esempi rapidi

CLI (tabellare):
```bash
python cli.py --target example.com
```

CLI (JSON):
```bash
python cli.py --target example.com --format json
```

API cURL:
```bash
curl -X POST http://localhost:8000/api/scan \
    -H "Content-Type: application/json" \
    -d '{"target":"example.com"}'
```

Solo risk score:
```bash
curl -s -X POST http://localhost:8000/api/scan \
    -H "Content-Type: application/json" \
    -d '{"target":"example.com"}' | jq '.risk_score.total_score'
```
