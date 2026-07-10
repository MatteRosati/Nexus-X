# Validation record — 2026-07-10

Verifiche eseguite sul pacchetto consegnato:

- `python -m compileall app migrations tests`: OK.
- `pytest -q`: 15 test passati.
- `pip check`: nessuna dipendenza rotta.
- `bandit -r app`: nessun finding riportato.
- `alembic upgrade head` su database pulito: OK.
- `alembic check`: nessuna operazione di upgrade mancante.
- parsing YAML di `docker-compose.yml`: servizi `db`, `migrate`, `web`, `worker` riconosciuti.
- avvio Uvicorn reale con SQLite di test: OK.
- `/health/live`: HTTP 200.
- `/health/ready`: HTTP 200.
- API senza `X-API-Key`: HTTP 401.
- creazione scansione autorizzata con API key: HTTP 202.
- regressione XSS del report: coperta da test automatico.
- pipeline orchestrator -> asset/finding -> database: coperta da test automatico.

Verifiche non eseguibili nell'ambiente di revisione:

- build e avvio Docker Compose completo: il Docker Engine non era disponibile.
- chiamata Censys reale: non sono state fornite credenziali Censys e non devono essere inserite nel pacchetto.
- `pip-audit`: il comando è stato avviato, ma il runtime non riusciva a risolvere `pypi.org`; ripeterlo nel CI con accesso di rete.

Questi limiti non vanno nascosti: prima del go-live eseguire build Compose, test con un PAT Censys dedicato e vulnerability audit delle dipendenze nel proprio CI/CD.
