# Configurazione Censys Platform API v3

## 1. Credenziale corretta

Questa applicazione usa la **Censys Platform API v3** e autentica le richieste con un **Personal Access Token (PAT)** tramite header Bearer.

Non inserire più:

```dotenv
CENSYS_API_ID=...
CENSYS_API_SECRET=...
```

Quella coppia appartiene alla Legacy Search API e non è usata dalla v2.

## 2. Requisiti del piano

Il collector esegue una ricerca su:

```text
POST https://api.platform.censys.io/v3/global/search/query
```

La documentazione Censys indica che gli utenti Free dispongono degli endpoint di lookup, mentre le ricerche Global Data sono disponibili dai piani Starter/Search/Core. Per un'organizzazione Starter/Search/Core l'utente deve inoltre avere il ruolo **API Access**.

Se il piano non consente la ricerca, lasciare:

```dotenv
CENSYS_ENABLED=false
```

## 3. Creare il Personal Access Token

Nel portale Censys Platform:

1. Accedere con l'utente che dovrà eseguire le query.
2. Aprire il menu dell'utente in alto a destra.
3. Selezionare **API Access**.
4. Fare clic su **Create New Token**.
5. Dare al token un nome specifico, ad esempio `mead-easm-production`.
6. Copiare il token al momento della creazione e salvarlo in un secret manager.

Non mettere il PAT in Git, nel Dockerfile, nel frontend o in ticket/chat.

## 4. Recuperare l'Organization ID

Con l'organizzazione corretta selezionata nel portale, aprire la pagina dei Personal Access Token/API Access. L'ID è mostrato nel riquadro dell'organizzazione corrente.

Per usare gli entitlement e il wallet dell'organizzazione, configurare:

```dotenv
CENSYS_ORGANIZATION_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

Senza organization ID, Censys può tentare di usare i permessi del wallet Free dell'utente.

## 5. Configurare `.env`

```dotenv
CENSYS_ENABLED=true
CENSYS_PAT=censys_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
CENSYS_ORGANIZATION_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CENSYS_MAX_RESULTS=100
CENSYS_MAX_CONCURRENCY=1
```

`CENSYS_MAX_RESULTS` è limitato a 100 per pagina dal codice e dall'endpoint usato. La baseline non pagina automaticamente oltre 100 risultati, per controllare costi e volume.

`CENSYS_MAX_CONCURRENCY=1` è un valore prudente. Censys documenta limiti di concorrenza dipendenti dal piano; non aumentarlo senza verificare il proprio account.

## 6. Riavviare e verificare

```bash
docker compose up -d --build web worker
```

Controllare i log del worker:

```bash
docker compose logs -f worker
```

Per un test esplicito del collector (può consumare crediti API):

```bash
docker compose run --rm worker python -m app.tools.check_censys example.com
```

Usare solo un dominio autorizzato.

## 7. Errori comuni

### 401 — PAT rifiutato

Verificare:

- token copiato integralmente;
- token non revocato;
- nessuno spazio o virgolette aggiuntive nel `.env`.

### 403 — accesso negato

Verificare:

- piano con accesso alla Global Search;
- ruolo **API Access** assegnato all'utente dell'organizzazione;
- `CENSYS_ORGANIZATION_ID` corretto;
- organizzazione selezionata correttamente quando è stato creato il token.

### 429 — rate limit

Ridurre:

```dotenv
WORKER_CONCURRENCY=1
CENSYS_MAX_CONCURRENCY=1
```

Se vengono avviate più repliche del worker, il semaforo è per processo: la concorrenza totale va controllata a livello di deployment.

## 8. Rotazione sicura

1. Creare un nuovo PAT.
2. Aggiornare il secret nel secret manager o nel file `.env` protetto.
3. Riavviare web/worker.
4. Verificare una query.
5. Revocare il PAT precedente.

Non riutilizzare lo stesso PAT tra sviluppo e produzione.

## Riferimenti ufficiali

- Get Started with Censys APIs: https://docs.censys.com/reference/get-started
- Platform API Transition Guide: https://docs.censys.com/docs/platform-api-transition-guide
- Run a search query: https://docs.censys.com/reference/v3-globaldata-search-query
- Censys Query Language: https://docs.censys.com/docs/censys-query-language
