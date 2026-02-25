# Rules_Ingest_Master

Reference operativo **append-only** per il track `rules-ingest` (estrazione, validazione, normalizzazione e governance dataset).

- Scope: solo repository `rules-ingest`
- Modalita: aggiungere solo nuove sezioni in fondo al file
- Obiettivo: mantenere uno stato operativo unico, verificabile e orientato a integrazione futura (opt-in)

## Indice rapido

1. [Regole operative](#regole-operative)
2. [Stato rapido (dashboard)](#stato-rapido-dashboard)
3. [Priorita consigliata](#priorita-consigliata)
4. [Log append-only](#log-append-only)
5. [Next steps (aperti)](#next-steps-aperti)
6. [Template nuove entry](#template-nuove-entry)

## Regole operative

- Questo documento e **append-only**: non riscrivere entry storiche.
- Ogni nuova attivita va aggiunta in fondo in ordine cronologico.
- Ogni entry deve includere almeno:
  - data
  - stato (`PLANNED`, `READY TO IMPLEMENT`, `IMPLEMENTED`, `BLOCKED`)
  - scope e vincoli
  - output/deliverable
  - comandi di verifica
  - prossimo step
- Vincolo architetturale: `rules-ingest` resta data-only, senza logica runtime SSS/RE.

## Stato rapido (dashboard)

| ID | Area | Ultimo stato | Data | Esito |
|---|---|---|---|---|
| RI1 | Schema validator JSON/JSONL (`tools/validate_json.py`) | IMPLEMENTED | 2026-02-10 | Draft 2020-12 + lint rules/atoms |
| RI2 | Hardening schemi rules (`scenario`, `source.*`) | IMPLEMENTED | 2026-02-10 | Contratto piu restrittivo |
| RI3 | Atoms contract freeze (`atoms_registry`, lint/golden) | IMPLEMENTED | 2026-02-10 | Registry + validazione `--atoms` |
| RI4 | Corpus locale SRD PDF via git-lfs | IMPLEMENTED | 2026-02-11 | Asset disponibile per ingest locale |
| RI5 | Pipeline ingest (extract + candidate lint) | READY | 2026-02-16 | Tooling pronto, output locali presenti |
| RI6 | Governance output ingest (tracked vs generated) | READY TO IMPLEMENT | 2026-02-16 | Working tree sporco (`ingest/` untracked) |

## Priorita consigliata

1. Chiudere RI6: definire policy esplicita su cosa versionare in `ingest/` (candidates/atoms/text/reports) e cosa no.
2. Consolidare un baseline canonico minimo (es. `pages_0010_0025`) con manifest, candidate lint report e comandi ripetibili.
3. Aggiungere script task-oriented (es. `make`/`just`/shell) per standardizzare: extract -> lint -> validate.
4. Solo dopo baseline stabile: estendere coverage a nuovi range SRD mantenendo append-only dei dataset.

## Log append-only

## 2026-02-16 - Bootstrap master operativo (rules-ingest)

- Stato: `IMPLEMENTED`
- Scope: repository `rules-ingest`
- Vincoli:
  - nessuna integrazione automatica con SSS/RE
  - output dati ispezionabili e validati
  - principio append-only su dataset e tracciamento decisioni
- Obiettivo: creare un master operativo unico, coerente con i principi del support master gia in uso.
- Evidenze analizzate:
  - `README.md` (missione data-only e disaccoppiamento da runtime)
  - `ingest/README_ingest_pipeline.md` (comandi canonici extract/lint)
  - `tools/validate_json.py` (validator centralizzato con modalita `--schema`, `--rules`, `--atoms`)
  - stato git: branch `main...origin/main [ahead 1]` con working tree sporco (`ingest/` e un file in `extraction/structured/` non tracciati)
- Deliverable:
  1. `docs/Rules_Ingest_Master.md` (questo file)
  2. dashboard iniziale con milestone RI1..RI6
  3. backlog operativo con priorita orientata a governance dataset
- Comandi di verifica consigliati:
  - `python tools/validate_json.py --rules`
  - `python tools/validate_json.py --atoms dist`
  - `python tools/validate_json.py --schema schemas/structured.schema.json extraction/structured`
  - `python ingest/tools/extract_pages.py --start 10 --end 25`
  - `python ingest/tools/lint_candidates.py --pages ingest/text/pages_0010_0025.txt --candidates ingest/candidates/pages_0010_0025/`
- Esito: `OK` (master creato e allineato allo stato reale del repository)
- Prossimo step: decisione esplicita RI6 su tracciamento `ingest/` prima di ulteriori import massivi.

## Next steps (aperti)

1. Formalizzare policy `ingest/` in un documento breve (`docs/ingest_tracking_policy.md`) e allineare `.gitignore`.
2. Congelare un baseline ingest minimo con output validati e riproducibili (command log + manifest).
3. Aggiungere check CI locale/remote per `--rules` e `--atoms` su path canonici.
4. Preparare una prima release dataset (`v0.1-ingest`) con changelog append-only.

## Template nuove entry

```md
## YYYY-MM-DD - <Titolo milestone>

- Stato: `PLANNED|READY TO IMPLEMENT|IMPLEMENTED|BLOCKED`
- Scope: <repo/area>
- Vincoli: <vincoli tecnici>
- Obiettivo: <obiettivo>
- Deliverable:
  1. <file/artefatto>
  2. <file/artefatto>
- Verifiche:
  - `<comando 1>`
  - `<comando 2>`
- Esito: <OK/KO + note>
- Prossimo step: <azione successiva>
```
