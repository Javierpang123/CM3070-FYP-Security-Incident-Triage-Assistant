import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.eval_utils import iterate_incidents, load_ground_truth_tactic, load_voice_transcript  # noqa: E402
from models.utilities import SPEECH_KEYWORDS  # noqa: E402

RESULTS_DIR = Path(__file__).resolve().parent / "results"
LEAKAGE_CSV = RESULTS_DIR / "transcript_leakage_check.csv"
LEAKAGE_REPORT = RESULTS_DIR / "transcript_leakage_report.txt"

# Function to check if the transcript literally names its own ground-truth tactic
def check_tactic_name_leak(transcript: str, tactic: str) -> bool:
    # Returns True if the transcript literally names its actual tactic.
    return tactic.lower() in transcript.lower()

# Function to check if the transcript contains any of its own tactic's keywords 
# from the list of keywords used to classify tactics, which willl indicate potential leakage of answer to classifier.
def check_keyword_leak(transcript: str, tactic: str) -> list:
    lower = transcript.lower()
    keywords = SPEECH_KEYWORDS.get(tactic, [])
    return [kw for kw in keywords if kw in lower]


def main():
    
    parser = argparse.ArgumentParser(description="Check voice transcripts for tactic-name/keyword leakage")
    parser.add_argument("--dataset-root", required=True)
    args = parser.parse_args()

    # Ensure the results directory exists
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Iterate through all incidents in the dataset and check for tactic name and keyword leakage in voice transcripts
    rows = []
    for incident in iterate_incidents(args.dataset_root):
        # Skip incidents that are missing the voice transcript
        if incident.voice_transcript_path is None:
            continue

        # Load the ground-truth tactic and the transcript for this incident    
        tactic = load_ground_truth_tactic(incident.label_path)
        transcript = load_voice_transcript(incident.voice_transcript_path)

        # Check for tactic name leakage and keyword leakage in the transcript
        name_leak = check_tactic_name_leak(transcript, tactic)
        keyword_leaks = check_keyword_leak(transcript, tactic)

        # Append the results for this incident to the rows list, 
        # including whether the tactic name appears verbatim and any matched keywords
        rows.append({"incident_id": incident.incident_id,
                     "tactic": tactic,
                     "tactic_name_appears_verbatim": int(name_leak),
                     "own_tactic_keywords_matched": "; ".join(keyword_leaks),
                     "keyword_match_count": len(keyword_leaks)})

    # Write the leakage results to CSV file and generate a summary report
    with open(LEAKAGE_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["incident_id", "tactic", 
                                               "tactic_name_appears_verbatim",
                                               "own_tactic_keywords_matched", 
                                               "keyword_match_count"])
        writer.writeheader()
        writer.writerows(rows)

    # Generate a summary report of the leakage findings, 
    # including counts and percentages of incidents with tactic name leakage and keyword matches
    n = len(rows)
    name_leaks = sum(r["tactic_name_appears_verbatim"] for r in rows)
    any_keyword_leak = sum(1 for r in rows if r["keyword_match_count"] > 0)
    total_keyword_matches = sum(r["keyword_match_count"] for r in rows)

    # Writee the summary report to a text file
    report_lines = [
        f"n = {n} incidents with voice_transcript.txt",
        f"Transcripts that literally name their own ground-truth tactic: "
        f"{name_leaks}/{n} ({100*name_leaks/n:.1f}%)",
        f"Transcripts containing at least one of their own tactic's "
        f"SPEECH_KEYWORDS terms: {any_keyword_leak}/{n} ({100*any_keyword_leak/n:.1f}%)",
        f"Total keyword matches across all transcripts: {total_keyword_matches}",
    ]
    report_text = "\n".join(report_lines)
    print(report_text)
    LEAKAGE_REPORT.write_text(report_text, encoding="utf-8")
    
    # Print the paths to the CSV and report files for easy reference to us
    print(f"\nFull report written to {LEAKAGE_REPORT}")
    print(f"Per-incident detail: {LEAKAGE_CSV}")


if __name__ == "__main__":
    main()
