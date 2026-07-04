# Fase 5 — Pianificazione (Adversary Emulation)
**Progetto:** HomeSOC · Domestic Security Operations Centre
**File:** `docs/phase5-planning.md`
**Versione:** 1.0 — Luglio 2026
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI
**Fase:** 5 — Adversary Emulation (Caldera) — pianificazione
**Prerequisiti:** `phase4-incident-response.md` ✅ (Fase 4 completa — T-05 ✅, commit `[0.9.3]`/`[0.9.4]`)

> **Scopo:** Documentare la decisione di re-sequenziare Fase 5/Fase 6 rispetto al roadmap originale (charter v1.0/v1.1), e fungere da documento di pianificazione per il deployment di Caldera. Il breakdown dei task (T-01, T-02, ...) verrà aggiunto quando la pianificazione tecnica di dettaglio sarà completa, seguendo lo stesso principio "runbook scritto prima di eseguire" già applicato alle fasi precedenti.

**Changelog:**
- v1.0 — Luglio 2026 — Prima stesura: ADR-05-01 (re-sequencing Fase 5/6)

---

## Indice

1. [ADR-05-01 — Re-sequencing Fase 5/6](#1-adr-05-01--re-sequencing-fase-5-opencti-e-fase-6-caldera)
2. [Prossimi passi](#2-prossimi-passi)

---

## 1. ADR-05-01 — Re-sequencing Fase 5 (OpenCTI) e Fase 6 (Caldera)

**Data:** 3 luglio 2026
**Stato:** Accettata

### Decisione

Invertire l'ordine originale del roadmap (`docs/00-charter.md`, sezione 5): eseguire **Caldera (adversary emulation)** come nuova Fase 5, prima di **OpenCTI (threat intelligence)**, che diventa Fase 6 — non il contrario come originariamente pianificato.

### Contesto

Il roadmap originale (charter v1.0/v1.1, sezione 5) prevedeva:

| Fase | Contenuto | Prerequisito |
|---|---|---|
| Fase 5 (originale) | OpenCTI + feed STIX/TAXII, correlazione IoC | Fase 4 OK |
| Fase 6 (originale) | Caldera, Infection Monkey, Nuclei | Fase 5 OK, VLAN lab isolata |

A completamento della Fase 4 (IR Layer: TheHive 5.7.2 + Cortex 3.1.8, integrazione Wazuh→TheHive, 3 analyzer Cortex, 4 playbook IR), sono emerse due condizioni non previste nella stesura originale del charter:

1. **Hard gate hardware su OpenCTI.** OpenCTI richiede realisticamente 8–12 GB RAM aggiuntivi. SOC-01 dispone di 32 GB, già allocati per ~22 GB tra le VM esistenti (vedi ADR-04-03 in `phase4-incident-response.md`). L'upgrade a 64 GB non è ancora stato eseguito. Non è un problema di sequenza risolvibile riordinando task — è un blocco fisico, indipendente da qualunque altra decisione.
2. **Necessità di un dataset labeled per l'analyzer LLM.** È in fase di design un Cortex analyzer basato su LLM locale (`LocalLLM_Triage_1_0`, via Ollama) per il triage automatico degli alert. Per misurarne precision/recall in modo credibile — requisito esplicito anche in ottica colloqui (Fortinet) — serve un corpus di attacchi noti con ground truth verificata. Un adversary emulation framework come Caldera genera questo dataset naturalmente, eseguendo TTP MITRE ATT&CK controllati contro il pipeline di detection già costruito nelle Fasi 3–4.

### Motivazione

Caldera non ha dipendenze hardware bloccanti ed è eseguibile da subito. La sua esecuzione produce due benefici indipendenti dall'ordine originale del roadmap:

- **Validazione end-to-end del pipeline di detection.** Eseguire TTP noti e verificare cosa viene rilevato (e cosa no) trasforma la fiducia implicita nel deployment in evidenza misurabile — coerente con l'obiettivo di portfolio "consapevolezza dei limiti di detection come competenza Blue Team senior" già presente in `00-charter.md`.
- **Dataset di riferimento per l'analyzer LLM, disponibile prima di scrivere l'automazione.** Evita di costruire `LocalLLM_Triage_1_0` "alla cieca" e poi scoprire in produzione che non regge — la shadow-mode evaluation già pianificata per l'analyzer richiede proprio questo tipo di corpus.

OpenCTI aggiunge invece threat intelligence esterna (IoC feed, correlazione) che ha valore massimo quando il pipeline di detection sottostante è già validato. Arricchire con intelligence un sistema non ancora misurato posticiperebbe la scoperta di eventuali gap strutturali nella detection stessa.

### Conseguenze

- Il roadmap in `docs/00-charter.md` sezione 5 è stato aggiornato a v1.2 (Fase 5 = Caldera, Fase 6 = OpenCTI).
- Nessun impatto sui deliverable già completati (Fasi 0–4) — la modifica è di sequenza, non di scope.
- Il prerequisito "VLAN lab isolata", originariamente associato alla vecchia Fase 6 (Caldera), resta un prerequisito aperto della nuova Fase 5 — da affrontare con un approccio nativo al progetto (vedi §2, un'ipotesi basata su GNS3 è stata valutata e scartata per restare fedeli allo scope originale — vedi `CHANGELOG.md` `[0.9.5]`).
- OpenCTI (nuova Fase 6) resta esplicitamente **bloccata su upgrade RAM 64GB** come prerequisito primario, non solo "Fase 5 OK" — la tabella originale non catturava questo vincolo.

### Alternative scartate

- **Mantenere l'ordine originale (OpenCTI prima).** Scartata: bloccata comunque dall'hardware, quindi non eseguibile nel breve termine indipendentemente da altre considerazioni — mantenerla in ordine avrebbe solo nascosto il blocco reale dietro una sequenza numerica che non riflette la realtà operativa.
- **Eseguire Caldera e OpenCTI in parallelo.** Scartata: Caldera genera traffico e log che è utile poter isolare dal rumore di una nuova integrazione (OpenCTI) non ancora stabilizzata — l'esecuzione sequenziale riduce le variabili confuse durante la validazione del pipeline.

---

## 2. Prossimi passi

- Pianificazione tecnica dettagliata di Caldera: topologia lab, posizionamento agent, selezione TTP da eseguire (mappati sui technique ID MITRE ATT&CK già coperti dalle regole custom esistenti — vedi `detection-rules/local_rules.xml` e `configs/attack-navigator/homesoc-layer-v1.json`)
- Chiudere il prerequisito "lab isolato" ereditato dalla vecchia Fase 6: un'opzione basata su una VM GNS3 non pianificata è stata scoperta e scartata (vedi `CHANGELOG.md` `[0.9.5]`) per restare fedeli allo scope originale del progetto — da affrontare con un'alternativa che passi da scoping esplicito, non da un asset trovato per caso
- Task breakdown (T-01, T-02, ...) da scrivere seguendo il modello di `phase4-incident-response.md`, solo dopo aver definito l'ambiente di lab — coerente con il principio "runbook scritto prima di eseguire" (checklist §8.3 del charter)

---

*File: `docs/phase5-planning.md` · v1.0 · Luglio 2026*
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
