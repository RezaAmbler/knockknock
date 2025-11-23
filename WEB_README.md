# Knock Knock Web Application

Production-grade web interface for the Knock Knock security scanner.

## Quick Start

### Development Mode (Local)

1. **Install dependencies:**
   ```bash
   pip install -r requirements-web.txt
   ```

2. **Set environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env and set SECRET_KEY
   ```

3. **Initialize database:**
   ```bash
   python scripts/init_db.py
   ```

4. **Start Redis (required for Celery):**
   ```bash
   # macOS with Homebrew:
   brew install redis
   brew services start redis

   # Or with Docker:
   docker run -d -p 6379:6379 redis:7-alpine
   ```

5. **Run the web server:**
   ```bash
   uvicorn web.main:app --reload
   ```

6. **Run Celery worker (in another terminal):**
   ```bash
   celery -A web.jobs.celery_app worker --loglevel=info
   ```

7. **Run Celery Beat scheduler (in another terminal):**
   ```bash
   celery -A web.jobs.celery_app beat --loglevel=info
   ```

8. **Access the API:**
   - API docs: http://localhost:8000/docs
   - Health check: http://localhost:8000/api/health

### Production Mode (Docker)

1. **Create .env file:**
   ```bash
   cp .env.example .env
   # Set SECRET_KEY to a random string
   ```

2. **Build and start services:**
   ```bash
   cd docker
   docker-compose up -d
   ```

3. **Access the application:**
   - API: http://localhost:8000
   - API docs: http://localhost:8000/docs

## Architecture

```
┌─────────────┐  ┌─────────────┐  ┌──────────────┐
│   FastAPI   │  │   Celery    │  │ Celery Beat  │
│     Web     │  │   Worker    │  │  (Scheduler) │
└──────┬──────┘  └──────┬──────┘  └──────┬───────┘
       │                │                │
       └────────────────┼────────────────┘
                        ↓
                  ┌──────────┐
                  │  Redis   │
                  └──────────┘
                        ↓
       ┌────────────────┴────────────────┐
       ↓                                  ↓
  ┌─────────┐                      ┌──────────┐
  │ SQLite  │                      │ Scanner  │
  │   DB    │                      │ Library  │
  └─────────┘                      └──────────┘
```

## API Usage

### 1. Register/Login

```bash
# Register
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'

# Login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'

# Returns: {"access_token":"eyJ0...","token_type":"bearer"}
```

### 2. Create Targets

```bash
TOKEN="your-token-here"

curl -X POST http://localhost:8000/api/targets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "friendly_name": "Production Firewall",
    "ip_address": "192.168.1.1",
    "description": "Main firewall"
  }'
```

### 3. Create Target List

```bash
curl -X POST http://localhost:8000/api/target-lists \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Devices",
    "description": "All production infrastructure",
    "target_ids": [1, 2, 3]
  }'
```

### 4. Create Schedule

```bash
curl -X POST http://localhost:8000/api/schedules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Weekly Scan",
    "type": "cron",
    "cron_expression": "0 2 * * 0",
    "timezone": "UTC",
    "target_list_id": 1,
    "send_email": true,
    "enabled": true
  }'
```

### 5. Run Ad-Hoc Scan

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_ids": [1, 2],
    "overrides": {
      "masscan_rate": 1000,
      "max_concurrent": 5
    },
    "send_email": false
  }'
```

### 6. View Scan Results

```bash
# List scans
curl http://localhost:8000/api/scans \
  -H "Authorization: Bearer $TOKEN"

# Get specific scan
curl http://localhost:8000/api/scans/1 \
  -H "Authorization: Bearer $TOKEN"

# Download HTML report
curl http://localhost:8000/api/reports/1/html \
  -H "Authorization: Bearer $TOKEN" \
  -o report.html
```

### 7. Dashboard Analytics

```bash
# Get dashboard stats
curl http://localhost:8000/api/analytics/dashboard \
  -H "Authorization: Bearer $TOKEN"

# Get scans over time
curl http://localhost:8000/api/analytics/scans-over-time?days=30 \
  -H "Authorization: Bearer $TOKEN"
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=web --cov-report=html

# Run specific test file
pytest tests/test_api/test_targets.py -v
```

## Database Schema

### Web Tables (New)
- `users` - User accounts with roles
- `targets` - Scan targets (IP/DNS + metadata)
- `target_lists` - Groups of targets
- `target_list_items` - Many-to-many target assignments
- `schedules` - Recurring scan schedules
- `scan_runs` - Scan execution records
- `artifacts` - Scan output files

### Scanner Tables (Existing)
- `runs` - Legacy scan runs
- `hosts` - Host scan results
- `ports` - Port discoveries
- `ssh_audit` - SSH audit results
- `nuclei_results` - Vulnerability findings

## Development

### Project Structure
```
web/
├── auth/          # Authentication (JWT, passwords)
├── models/        # SQLAlchemy models
├── schemas/       # Pydantic request/response schemas
├── api/           # FastAPI route handlers
├── jobs/          # Celery tasks & scheduler
├── services/      # Business logic
├── ui/            # Frontend (future)
├── database.py    # Database connection
├── config.py      # Application settings
└── main.py        # FastAPI app factory
```

### Adding New Endpoints

1. Create Pydantic schemas in `web/schemas/`
2. Create API router in `web/api/`
3. Register router in `web/main.py`

### Creating Celery Tasks

1. Add task function to `web/jobs/tasks.py`
2. Use `@celery_app.task` decorator
3. Call with `.delay()` or `.apply_async()`

## Configuration

All configuration in `.env`:

- `SECRET_KEY` - JWT signing key (REQUIRED)
- `DATABASE_URL` - Database connection string
- `CELERY_BROKER_URL` - Redis URL for Celery
- `ADMIN_EMAIL` / `ADMIN_PASSWORD` - Bootstrap admin user

## Security Notes

- Always use HTTPS in production
- Set strong `SECRET_KEY`
- Review CORS settings in `web/config.py`
- Admin user created automatically on first startup
- Passwords hashed with bcrypt

## Troubleshooting

### "SECRET_KEY environment variable is not set"
Set `SECRET_KEY` in `.env` file

### "Redis connection refused"
Ensure Redis is running: `redis-cli ping` should return `PONG`

### "masscan requires sudo"
Worker container has CAP_NET_RAW capability. For local dev, see main README.

### Scans stuck in QUEUED status
Check Celery worker is running: `celery -A web.jobs.celery_app inspect active`

## CLI Still Works!

The original CLI is unchanged:
```bash
python knock_knock.py --targets targets.csv
```

Web application is an **additive layer** on top of the existing scanner.
