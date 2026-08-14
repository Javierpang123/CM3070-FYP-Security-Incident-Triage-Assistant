from TTS.api import TTS
import os

tts = TTS(model_name="tts_models/en/ljspeech/tacotron2-DDC", progress_bar=False)

def generate_voice_note(text, incident_dir):
    os.makedirs(incident_dir, exist_ok=True)
    wav_path = os.path.join(incident_dir, "voice.wav")
    txt_path = os.path.join(incident_dir, "voice_transcript.txt")
    tts.tts_to_file(text=text, file_path=wav_path)
    with open(txt_path, "w") as f:
        f.write(text)
    print(f"Saved: {wav_path}")

# Incident: T1098 DSRM password change
script = ("Multiple failed login attempts detected from an unknown source "
          "against domain controller 2016dc.hqcorp.local. An attempt was made "
          "to set the Directory Services Restore Mode administrator password. "
          "This action requires immediate investigation.")

incident_dir = (r"C:\Users\Javier Pang JunEn\OneDrive - SIM - Singapore Institute of Management"
                r"\CM3070 FYP\FYP-Project-Code\FYP-Dataset\incidents\Credential-Access\T1098_dsrm_password_change")

generate_voice_note(script, incident_dir)