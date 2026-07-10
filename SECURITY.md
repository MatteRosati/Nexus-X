# Security policy

## Uso autorizzato

Il software è progettato per inventario e monitoraggio difensivo di domini autorizzati. Non disabilitare l'allowlist in produzione salvo esista un controllo di autorizzazione equivalente a monte.

## Segreti

- Non committare `.env`.
- Non inserire PAT Censys o chiavi applicative nel frontend.
- Preferire Docker secrets, Kubernetes Secrets integrati con un secret manager, Vault o un servizio cloud equivalente.
- Ruotare immediatamente una credenziale sospetta.

## Segnalazioni

Per vulnerabilità interne al progetto, usare un canale privato aziendale e non pubblicare segreti o dati dei clienti.

## Hardening deployment

La configurazione Docker elimina capability Linux e usa un utente non-root, ma la sicurezza finale dipende anche da host, orchestratore, reverse proxy, rete, backup e gestione dei segreti.
