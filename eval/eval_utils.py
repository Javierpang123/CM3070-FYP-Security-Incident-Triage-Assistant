# Shared utilities for my system, Flashpoint's evaluation scripts.

import json
import logging
import sys
from pathlib import Path
from typing import Iterator, NamedTuple, Optional, Union

# Thos help me ensure project root (parent of /eval) is importable 
# so models resolves the same way it does for the Flask app.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models.text_model import parse_log_input  # noqa: E402

logger = logging.getLogger(__name__)


# Full incident record produced by dataset_pipeline.py.
class IncidentPaths(NamedTuple):
    incident_id: str
    tactic: str
    incident_dir: Path
    log_path: Optional[Path]
    screenshot_path: Optional[Path]
    voice_path: Optional[Path]
    voice_transcript_path: Optional[Path]
    label_path: Path

# Functions for iterating the dataset and loading ground-truth labels.
def iterate_incidents(dataset_root: Union[str, Path]) -> Iterator[IncidentPaths]:
    """
    Walk the incidents/<tactic>/<incident_id>/ folder structure and yield
    an IncidentPaths record for each incident found. Incidents are
    discovered by the presence of a label.json file, since that is the
    one file every valid incident must have.
    """
    # Ensure dataset_root is a Path object.
    incidents_root = Path(dataset_root) / "incidents"
    if not incidents_root.exists():
        raise FileNotFoundError(f"Incidents folder not found at {incidents_root}. ")

    # Variable to hold the tactic directories (e.g., "initial-access", "execution")
    tactic_dirs = sorted(p for p in incidents_root.iterdir() if p.is_dir())
    
    # Walk each tactic folder and yield an IncidentPaths for each incident.
    for tactic_dir in tactic_dirs:
        
        # Get all incident directories under this tactic folder.
        incident_dirs = sorted(p for p in tactic_dir.iterdir() if p.is_dir())
        
        # For each incident directory, check for label.json and yield an IncidentPaths.
        for incident_dir in incident_dirs:
            label_path = incident_dir / "label.json"
            
            # If label.json is missing, skip this incident and log a warning.
            if not label_path.exists():
                logger.warning("Skipping %s as no label.json found", incident_dir)
                continue

            # Optional helper that returns a Path    
            def optional(filename: str) -> Optional[Path]:
                candidate = incident_dir / filename
                
                # Returns path if the file exists else None if it doesn't.
                return candidate if candidate.exists() else None

            # Create an IncidentPaths record for this incident.
            yield IncidentPaths(incident_id=incident_dir.name,
                                tactic=tactic_dir.name,
                                incident_dir=incident_dir,
                                log_path=optional("log.json"),
                                screenshot_path=optional("screenshot.png"),
                                voice_path=optional("voice.wav"),
                                voice_transcript_path=optional("voice_transcript.txt"),
                                label_path=label_path)

# Functions for loading ground-truth labels.
def load_ground_truth_tactic(label_path: Path) -> str:
    """
    Read label.json and return the ground-truth MITRE ATT&CK tactic
    string from the 'attack_class' field.
    """
    # Open the label.json file and parse it as JSON.
    with open(label_path, "r", encoding="utf-8-sig") as f:
        label = json.load(f)
        
    # Extract the 'attack_class' field.
    tactic = label.get("attack_class")
    
    # If the field is missing, raise an error.
    if not tactic:
        raise ValueError(f"label.json at {label_path} has no 'attack_class' field")
    return tactic

# Functions for loading text model inputs and ground-truth labels.
def load_text_model_input(log_path: Path) -> Union[str, dict]:
    """
    Load a log.json file exactly the way routes.py's POST /analyse route
    does, so the text model sees the same input shape in evaluation as
    it does in the live app.
    """
    # Load the log.json file and parse it.
    content = log_path.read_text(encoding="utf-8-sig")
    return parse_log_input(content)

# Functions for loading voice transcripts for WER evaluation.
def load_voice_transcript(transcript_path: Path) -> str:
    # Return the contents of voice_transcript.txt, 
    # stripped of leading/trailing whitespace.
    return transcript_path.read_text(encoding="utf-8-sig").strip()
