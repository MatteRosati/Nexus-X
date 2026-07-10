# Mead External Attack Surface v2 — production baseline

Applicazione EASM passiva con FastAPI, worker separato, coda persistente PostgreSQL, scope allowlist, autenticazione API, collector crt.sh/DNS/Censys Platform API v3, inventario asset, finding, dashboard e report HTML con auto-escaping.

> **Importante:** questa release è una baseline di produzione, non un'autorizzazione a scansionare terze parti. Configurare `EASM_ALLOWED_DOMAINS` esclusivamente con domini per i quali esiste un'autorizzazione esplicita. Il prodotto usa collector passivi e non esegue port scan attivi.

## Cosa è stato corretto rispetto alla v1

- risultati dei collector realmente persistiti;
- scan ID e stati `queued`, `running`, `completed`, `partial_failed`, `failed`;
- worker separato e coda nel database, con recovery dei job interrotti;
- PostgreSQL in Docker Compose e migrazioni Alembic;
- autenticazione `X-API-Key`;
- allowlist obbligatoria dello scope;
- validazione forte del dominio;
- collector con timeout, limiti e gestione errori;
- integrazione Censys Platform API v3 con PAT;
- report Jinja2 con auto-escaping e CSP;
- dashboard collegata alle API;
- container non-root, `read_only`, `cap_drop: ALL`, healthcheck;
- dipendenze versionate;
- test per API, scope, collector e regressione XSS.

## Avvio con Docker Compose

1. Copiare la configurazione:

```bash
cp .env.example .env
```

2. Generare due segreti diversi:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Usare un valore per `APP_API_KEY` e un altro per `POSTGRES_PASSWORD`; aggiornare anche la password dentro `DATABASE_URL`.

3. Configurare lo scope autorizzato:

```dotenv
EASM_ALLOWED_DOMAINS=azienda.it,azienda.com
ALLOW_ARBITRARY_TARGETS=false
```

4. Avviare:

```bash
docker compose up --build -d
```

5. Verificare:

```bash
curl http://127.0.0.1:8000/health/live
curl http://127.0.0.1:8000/health/ready
```

6. Aprire `http://127.0.0.1:8000`, inserire la `APP_API_KEY` nel pannello e avviare una scansione autorizzata.

Per default la porta è pubblicata solo su loopback. Per Internet, mettere un reverse proxy TLS davanti all'applicazione e non esporre direttamente Uvicorn.

## Esempio API

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans   -H "X-API-Key: $APP_API_KEY"   -H "Content-Type: application/json"   -d '{"domain":"example.com"}'
```

```bash
curl http://127.0.0.1:8000/api/v1/scans   -H "X-API-Key: $APP_API_KEY"
```

## Censys

La v2 usa la **Censys Platform API v3**. Non usa più `CENSYS_API_ID` e `CENSYS_API_SECRET` della Legacy Search API.

Configurazione minima:

```dotenv
CENSYS_ENABLED=true
CENSYS_PAT=censys_...
CENSYS_ORGANIZATION_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CENSYS_MAX_RESULTS=100
CENSYS_MAX_CONCURRENCY=1
```

Leggere `docs/CENSYS_CONFIGURATION.md` prima di abilitarla. Il collector usa la ricerca globale passiva e può consumare crediti API.

## Test

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

## Migrazioni

Docker Compose esegue automaticamente:

```bash
alembic upgrade head
```

Per creare una nuova revisione:

```bash
alembic revision --autogenerate -m "descrizione"
alembic upgrade head
```

## Architettura

```text
Browser / API client
        |
        v
FastAPI (auth + scope validation)
        |
        v
PostgreSQL queue + inventory
        |
        v
Worker --> crt.sh
       --> DNS
       --> Censys Platform API v3 (opzionale)
        |
        v
Asset + Finding + CollectorRun
        |
        +--> Dashboard
        +--> Report HTML sicuro
```

## Limiti consapevoli

- La baseline è single-tenant: per un servizio MSSP/mROC multi-cliente servono tenant ID, RBAC e segregazione dati.
- L'allowlist è un controllo amministrativo; non prova automaticamente la proprietà del dominio.
- I finding Censys indicano esposizione osservata, non dimostrano una vulnerabilità.
- Prima di scalare i worker, verificare i limiti di concorrenza e crediti del proprio piano Censys.
- Per alta disponibilità servono backup testati, monitoraggio, reverse proxy TLS/WAF, secret manager e una strategia di upgrade/rollback.

Vedere `docs/PRODUCTION_CHECKLIST.md` e `SECURITY.md`.
