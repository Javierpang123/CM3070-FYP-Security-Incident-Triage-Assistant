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


def check_tactic_name_leak(transcript: str, tactic: str) -> bool:
    # Returns True if the transcript literally names its actual tactic.
    return tactic.lower() in transcript.lower()


def check_keyword_leak(transcript: str, tactic: str) -> list:
    """
    Returns this tactic's own SPEECH_KEYWORDS terms that appear verbatim
    in the transcript - i.e. the exact vocabulary classify_tactic() uses
    to make its decision, so a match here means the script is handing
    the classifier its answer directly rather than the classifier
    inferring it from technical description.
    """
    lower = transcript.lower()
    keywords = SPEECH_KEYWORDS.get(tactic, [])
    return [kw for kw in keywords if kw in lower]


def main():
    parser = argparse.ArgumentParser(description="Check voice transcripts for tactic-name/keyword leakage")
    parser.add_argument("--dataset-root", required=True)
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    rows = []
    for incident in iterate_incidents(args.dataset_root):
        if incident.voice_transcript_path is None:
            continue

        tactic = load_ground_truth_tactic(incident.label_path)
        transcript = load_voice_transcript(incident.voice_transcript_path)

        name_leak = check_tactic_name_leak(transcript, tactic)
        keyword_leaks = check_keyword_leak(transcript, tactic)

        rows.append({"incident_id": incident.incident_id,
                     "tactic": tactic,
                     "tactic_name_appears_verbatim": int(name_leak),
                     "own_tactic_keywords_matched": "; ".join(keyword_leaks),
                     "keyword_match_count": len(keyword_leaks)})

    with open(LEAKAGE_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["incident_id", "tactic", 
                                               "tactic_name_appears_verbatim",
                                               "own_tactic_keywords_matched", 
                                               "keyword_match_count"])
        writer.writeheader()
        writer.writerows(rows)

    n = len(rows)
    name_leaks = sum(r["tactic_name_appears_verbatim"] for r in rows)
    any_keyword_leak = sum(1 for r in rows if r["keyword_match_count"] > 0)
    total_keyword_matches = sum(r["keyword_match_count"] for r in rows)

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
    print(f"\nFull report written to {LEAKAGE_REPORT}")
    print(f"Per-incident detail: {LEAKAGE_CSV}")


if __name__ == "__main__":
    main()
