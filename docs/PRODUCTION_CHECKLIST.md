# Checklist prima del go-live

## Obbligatorio

- [ ] `APP_API_KEY` casuale, lungo almeno 32 caratteri e custodito in un secret manager.
- [ ] `POSTGRES_PASSWORD` diverso dalla API key.
- [ ] `EASM_ALLOWED_DOMAINS` compilato; `ALLOW_ARBITRARY_TARGETS=false`.
- [ ] Porta 8000 non esposta direttamente a Internet.
- [ ] Reverse proxy con TLS, rate limiting e limiti request body.
- [ ] `TRUSTED_HOSTS` impostato agli hostname reali del servizio.
- [ ] Backup PostgreSQL automatici e prova periodica di restore.
- [ ] Centralizzazione log e alert su `failed` / `partial_failed`.
- [ ] Aggiornamenti dipendenze e image scanning nel CI.
- [ ] Rotazione periodica dei segreti.
- [ ] Test di restore, upgrade e rollback.

## Censys

- [ ] PAT dedicato alla produzione.
- [ ] Ruolo API Access verificato.
- [ ] Organization ID corretto.
- [ ] Crediti e limiti del piano verificati.
- [ ] `CENSYS_MAX_CONCURRENCY` coerente col piano.
- [ ] Alert su 401/403/429 nei log.

## Alta disponibilità e scala

La coda usa PostgreSQL con `FOR UPDATE SKIP LOCKED`, quindi più worker possono reclamare job distinti. Tuttavia:

- la concorrenza Censys va calcolata su tutte le repliche;
- applicare migration una sola volta per release;
- usare un bilanciatore/reverse proxy davanti a più repliche web;
- considerare pool di connessioni e limiti PostgreSQL;
- definire retention di scan/asset/finding prima che il database cresca.

## Multi-tenancy mROC/MSSP

Prima di gestire clienti diversi, aggiungere almeno:

- tenant/account model;
- RBAC;
- API key per tenant o OIDC/SAML;
- `tenant_id` obbligatorio su scan, asset, finding e collector run;
- Row-Level Security PostgreSQL o un controllo equivalente;
- audit log immutabile;
- retention e export per cliente;
- segregazione dei segreti Censys e di altri provider.
