# Rules-Ingest

Rules-Ingest è un progetto **esterno e indipendente** pensato per l’ingestione, estrazione e normalizzazione delle regole **SRD 5e** in forma di **vincoli astratti** (“Rule Atoms”), pronti per una futura integrazione controllata nel Rule Engine (RE).

> Questo repository **non implementa logica di gioco** e **non esegue effetti**.  
> Produce **solo dati strutturati e ispezionabili**.

---

## 🎯 Obiettivi

Rules-Ingest serve esclusivamente a:

- Ingerire materiale **SRD 5.1** (PDF o testo)
- Estrarre **vincoli RE-relevant** (precondizioni, limiti, requisiti)
- Normalizzare tali vincoli in **Rule Atoms atomici**
- Produrre dataset versionati, auditabili e append-only

---

## 🚫 Cosa NON fa

Rules-Ingest **non**:

- Applica danni, cure o condizioni
- Lancia dadi o calcola modificatori
- Implementa turni, azioni o stato di gioco
- Contiene testo narrativo o descrittivo SRD
- Modifica o dipende direttamente da SSS o RE

---

## 🧠 Filosofia di design

- **Data first, code later**
- Output deterministici e dichiarativi
- Nessuna assunzione implicita
- Tutto versionato, niente overwrite semantico
- Append-only come principio guida

---

## 🔗 Relazione con SSS / Rule Engine

- Repository **completamente decoupled**
- Nessuna integrazione automatica
- Nessuna modifica al contratto del Rule Engine
- I Rule Atoms sono **inermi** finché non esplicitamente abilitati

---

## 🧩 Pipeline concettuale

SRD raw text → Structured Extraction → Rule Atom Normalization → JSON / JSONL datasets

---

## 📐 Schemi canonici

- schemas/structured.schema.json
- schemas/atoms.schema.json

---

## 📁 Struttura del repository

schemas/, ingest/, extraction/, normalization/, tools/

---

## ⚖️ Copyright & SRD

- Solo materiale SRD ufficiale
- Output astratto e non narrativo

---

## 📌 Stato del progetto

- Schemi pronti
- Pipeline definita
- Nessuna integrazione attiva

---

## 🧭 Nota finale

Ogni integrazione futura è **esplicita e opt-in**.
