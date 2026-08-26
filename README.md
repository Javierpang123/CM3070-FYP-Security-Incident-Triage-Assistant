# Flashpoint - Multimodal Security Incident Triage Assistant
 
Flashpoint is my final year project for CM3070 at the University of London. The idea came from a real gap I noticed: small IT teams at SMBs often have lightweight SIEM tools like ELK Stack, Wazuh, or Graylog that surface alerts just fine — but there's no automated layer to actually triage them. Someone still has to read through logs, interpret dashboard screenshots, and piece everything together under pressure. Flashpoint sits in that gap.
 
The system orchestrates three pre-trained AI models across different input modalities which are log text, screenshots, and analyst voice notes and then fuses their outputs into a single structured triage report. The core question driving the project is whether combining those three modalities produces more accurate and trustworthy triage than relying on any one of them alone.
 
Everything runs fully offline by design. No data leaves the machine, which matters a lot when you're dealing with sensitive security incidents.
 
---
 
## What it does
 
**Log Analysis**
Accepts raw security log text and extracts indicators of compromise, classifies the attack type, and maps findings to MITRE ATT&CK.
 
**Screenshot Interpretation**
Takes SIEM dashboard screenshots or visual alert captures and pulls structured information from them using a vision-language model combined with OCR.
 
**Voice Note Transcription**
Accepts short analyst voice recordings and transcribes them to add first-person context to the triage, which is useful when an analyst has spotted something but hasn't had time to write it up.
 
**Multimodal Fusion**
The three model outputs are passed to an orchestration layer that combines them, using weighted scoring, into a single unified verdict. Each modality's contribution is surfaced in the output so you can see exactly where the triage is coming from.
 
**Triage Output**
Each incident produces:
- A severity rating (1–5)
- An attack classification with MITRE ATT&CK mapping
- A recommended action list
- A per-model breakdown showing individual confidence and findings
- A downloadable PDF summary of the full triage report
---
 
## Stack and Technologies
 
**Backend**
- Python 3
- Flask (API server and frontend serving)
- Ollama (local LLM runtime)
**AI Models**
- Mistral 7B via Ollama (log and text analysis)
- BLIP + Tesseract OCR (screenshot and visual content extraction)
- Whisper (analyst voice note transcription)
**Orchestration**
- Custom late fusion orchestrator module 
**Frontend**
- Single-page Flask-rendered UI (no React, no database)
- Three input panels: text area, image drop zone, audio uploader
- One structured output panel with downloadable PDF export
