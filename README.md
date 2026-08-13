# URL Threat Analysis System

A production-ready Python backend for comprehensive URL threat analysis and phishing detection. This system combines static URL analysis, dynamic content scraping, DOM signal extraction, and machine learning to provide accurate threat verdicts.

## Features

- **Multi-Layer Analysis**
  - Static URL analysis (domain age, typosquatting, TLD risk, etc.)
  - Dynamic content scraping with Playwright
  - DOM signal extraction (password forms, obfuscated JS, brand impersonation)
  - Machine learning classification

- **Security**
  - SSRF protection with private IP blocking
  - Rate limiting (10 requests/minute per IP)
  - Input validation and sanitization

- **Performance**
  - Redis caching (1-hour TTL)
  - Async/await throughout
  - Structured JSON logging

- **Production-Ready**
  - Docker & Docker Compose support
  - Health check endpoints
  - Comprehensive error handling
  - Full test suite

## Architecture

```
url-analyzer/
├── app/
│   ├── main.py                  # FastAPI application
│   ├── schemas.py               # Pydantic models
│   ├── api/
│   │   └── routes.py            # API endpoints
│   ├── core/
│   │   ├── config.py            # Configuration management
│   │   ├── cache.py             # Redis caching
│   │   └── limiter.py           # Rate limiting
│   ├── analyzer/
│   │   ├── static.py            # Static URL analysis (10 checks)
│   │   ├── scraper.py           # Content scraping with SSRF protection
│   │   ├── dom_signals.py       # DOM signal extraction (10 checks)
│   │   ├── features.py          # Feature extraction (32 features)
│   │   └── orchestrator.py      # Analysis coordination
│   └── ml/
│       ├── model.py             # ML model wrapper
│       ├── train.py             # Training script
│       └── artifacts/           # Trained model files
├── tests/                       # Test suite
├── Dockerfile                   # Container definition
├── docker-compose.yml           # Multi-container setup
└── requirements.txt             # Python dependencies
```

## Setup

### Prerequisites

- Python 3.11+
- Docker & Docker Compose (for containerized deployment)
- Redis (for caching)

### Local Development

1. **Clone the repository**
   ```bash
   cd url-analyzer
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Playwright browsers**
   ```bash
   playwright install chromium --with-deps
   ```

5. **Start Redis**
   ```bash
   docker run -d -p 6379:6379 redis:7-alpine
   ```

6. **Run the application**
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

7. **Access the API**
   - API: http://localhost:8000
   - Health check: http://localhost:8000/health
   - Interactive docs: http://localhost:8000/docs

### Docker Deployment

1. **Build and start services**
   ```bash
   docker-compose up -d
   ```

2. **View logs**
   ```bash
   docker-compose logs -f api
   ```

3. **Stop services**
   ```bash
   docker-compose down
   ```

## Configuration

Environment variables (create a `.env` file):

```env
REDIS_URL=redis://localhost:6379
SAFE_BROWSING_API_KEY=your-api-key-here  # Optional
CACHE_TTL=3600
RATE_LIMIT=10/minute
MAX_URL_LENGTH=2048
SCRAPER_TIMEOUT=12000
LOG_LEVEL=INFO
MODEL_PATH=app/ml/artifacts/model.pkl
SCALER_PATH=app/ml/artifacts/scaler.pkl
```

### Google Safe Browsing API (Optional)

To enable Google Safe Browsing checks:

1. Get an API key from https://developers.google.com/safe-browsing/v4/get-started
2. Set `SAFE_BROWSING_API_KEY` environment variable

## Usage

### Analyze a URL

```bash
curl -X POST http://localhost:8000/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Response:**
```json
{
  "url": "https://example.com",
  "verdict": "safe",
  "confidence": 0.123,
  "reasons": [],
  "cached": false,
  "analysis_time_ms": 1523
}
```

**Verdicts:**
- `safe`: Confidence < 0.45
- `suspicious`: Confidence 0.45 - 0.75
- `malicious`: Confidence >= 0.75

### Health Check

```bash
curl http://localhost:8000/health
```

**Response:**
```json
{
  "status": "ok",
  "redis": true,
  "model_loaded": false
}
```

### Example Requests

**Analyze a phishing URL:**
```bash
curl -X POST http://localhost:8000/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://fake-paypal.tk/login"}'
```

**Analyze a safe URL:**
```bash
curl -X POST http://localhost:8000/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'
```

## Machine Learning Model

The system includes an ML model (RandomForest) that can be trained on labeled datasets.

### Training the Model

1. **Prepare dataset**

   Create a CSV file with columns: `url`, `label`
   - `label = 0` for benign URLs
   - `label = 1` for phishing URLs

   **Dataset sources:**
   - PhishTank: https://www.phishtank.com/developer_info.php
   - Tranco (benign): https://tranco-list.eu/

   **Example dataset.csv:**
   ```csv
   url,label
   https://www.google.com,0
   https://www.facebook.com,0
   http://phishing-site.xyz/login,1
   http://fake-paypal.tk/verify,1
   ```

2. **Run training script**
   ```bash
   python -m app.ml.train \
     --input dataset.csv \
     --output-dir app/ml/artifacts \
     --max-samples 1000  # Optional: limit for testing
   ```

3. **Training output**
   - Model saved to `app/ml/artifacts/model.pkl`
   - Scaler saved to `app/ml/artifacts/scaler.pkl`
   - Classification report printed to console

4. **Restart the application**
   ```bash
   docker-compose restart api
   ```

### Fallback Behavior

If no trained model is found, the system uses rule-based scoring:
- 40% weight on static analysis
- 60% weight on DOM analysis

## Analysis Components

### Static Analysis (10 Checks)

1. **Domain Age** - Flags domains < 30 days old
2. **URL Entropy** - Detects random-looking hostnames
3. **Subdomain Depth** - Flags excessive subdomains (> 3)
4. **IP as Hostname** - Detects raw IP addresses
5. **Typosquatting** - Levenshtein distance to top 20 brands
6. **Suspicious Keywords** - login, verify, secure, etc.
7. **High-Risk TLD** - .tk, .ml, .xyz, etc.
8. **URL Length** - Flags URLs > 100 characters
9. **Google Safe Browsing** - API threat check (optional)
10. **Redirect Count** - Flags > 2 redirect hops

### DOM Analysis (10 Checks)

1. **Password Inputs** - Detects password forms
2. **External Form Actions** - Forms submitting to different domains
3. **External Scripts** - Scripts loaded from external domains
4. **Iframes** - Embedded content
5. **Hidden Elements** - High ratio of hidden elements
6. **Obfuscated JavaScript** - eval(), atob(), unescape()
7. **Brand Impersonation** - Brand names in page without matching domain
8. **Favicon Mismatch** - Favicon from different domain
9. **Urgency Language** - "Act now", "verify immediately"
10. **Data URI Scripts** - JavaScript loaded via data: URIs

### Feature Extraction (32 Features)

- URL features: length, entropy, subdomains, keywords
- Domain features: age, TLD risk, typosquatting distance
- Content features: forms, scripts, iframes, obfuscation
- Composite scores: static and DOM analysis results

## Testing

### Run Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/test_api.py

# With coverage
pytest --cov=app tests/

# Verbose output
pytest -v
```

### Test Coverage

- `test_api.py`: API endpoint tests with mocked dependencies
- `test_static.py`: Unit tests for all 10 static checks
- `test_dom.py`: Unit tests for all 10 DOM signal checks

## API Endpoints

### POST /analyze-url

Analyze a URL for threats.

**Request:**
```json
{
  "url": "string"
}
```

**Response:**
```json
{
  "url": "string",
  "verdict": "safe | suspicious | malicious",
  "confidence": 0.0-1.0,
  "reasons": ["string"],
  "cached": boolean,
  "analysis_time_ms": integer
}
```

**Rate Limit:** 10 requests/minute per IP

**Status Codes:**
- 200: Success
- 400: Invalid URL
- 429: Rate limit exceeded
- 500: Internal server error

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "ok | degraded",
  "redis": boolean,
  "model_loaded": boolean
}
```

## Logging

All logs are structured JSON for easy parsing:

```json
{
  "event": "analysis_complete",
  "url_hash": "a1b2c3d4",
  "verdict": "suspicious",
  "confidence": 0.67,
  "analysis_time_ms": 2341,
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "info"
}
```

## Performance

- **Average analysis time**: 1.5-3 seconds (with scraping)
- **Cache hit time**: < 10ms
- **Rate limit**: 10 requests/minute per IP
- **Cache TTL**: 1 hour

## Security Considerations

1. **SSRF Protection**: Blocks requests to private IP ranges
2. **Input Validation**: URL format, length, and scheme validation
3. **Rate Limiting**: Prevents abuse
4. **Sandboxed Scraping**: Chromium runs with security flags
5. **Error Handling**: No sensitive information in error messages

## Troubleshooting

### Redis Connection Failed

```bash
# Check Redis is running
docker ps | grep redis

# Check Redis connectivity
redis-cli ping
```

### Playwright Install Issues

```bash
# Reinstall Playwright browsers
playwright install --force chromium --with-deps
```

### Model Not Loading

```bash
# Check model files exist
ls -la app/ml/artifacts/

# Retrain model if needed
python -m app.ml.train --input dataset.csv
```

### Docker Build Fails

```bash
# Clean rebuild
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Ensure all tests pass: `pytest`
5. Submit a pull request

## License

MIT License - See LICENSE file for details

## Acknowledgments

- Static analysis inspired by phishing research papers
- ML features based on industry best practices
- SSRF protection follows OWASP guidelines
