# Scores ablation predictions produced by evaluate_ablation.py.
import csv
from pathlib import Path

from sklearn.metrics import f1_score, classification_report

RESULTS_DIR = Path(__file__).resolve().parent / "results"
ABLATION_CSV = RESULTS_DIR / "ablation_predictions.csv"
REPORT_PATH = RESULTS_DIR / "ablation_f1_report.txt"

# The four ablation combinations to score, 
# with their corresponding column names in ablation_predictions.csv.
COMBINATIONS = [("log_only_pred", "Log-only (text modality alone)"),
                ("screenshot_only_pred", "Screenshot-only (vision modality alone)"),
                ("voice_only_pred", "Voice-only (speech modality alone)"),
                ("all_three_fused_pred", "All-three-fused (late_fusion_orchestrator)")]

# Main function to read the ablation_predictions.csv, 
# compute macro F1 for each combination, and write a report.
def main():
    
    # Check that the ablation_predictions.csv file exists, otherwise raise an error
    if not ABLATION_CSV.exists():
        raise FileNotFoundError(f"{ABLATION_CSV} not found - run evaluate_ablation.py first.")

    # Open the ablation_predictions.csv file and read all rows into a list of dictionaries
    with open(ABLATION_CSV, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    # Extract the ground-truth tactic labels from the rows for scoring
    y_true = [row["tactic_actual"] for row in rows]

    # Initialize lists to hold summary and detailed report lines
    summary_lines = []
    detail_lines = []
   
    # For each ablation combination, compute macro F1 
    # and generate a detailed classification report
    for col, label in COMBINATIONS:
        y_pred = [row[col] for row in rows]
        labels = sorted(set(y_true) | set(y_pred))
        macro_f1 = f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)

        summary_lines.append(f"{label}: macro F1 = {macro_f1:.4f}")

        detail_lines.append(f"=== {label} ===")
        detail_lines.append(f"Macro F1: {macro_f1:.4f}")
        detail_lines.append("")
        detail_lines.append(classification_report(y_true, y_pred, labels=labels, zero_division=0))
        detail_lines.append("")

    summary = "\n".join(["ABLATION SUMMARY (does fusion beat the best single modality?)", ""] 
                        + summary_lines)
    full_report = summary + "\n\n" + "\n".join(detail_lines)

    # Print the summary and write the full report to a text file
    print(full_report)
    REPORT_PATH.write_text(full_report, encoding="utf-8")
    print(f"\nFull report written to {REPORT_PATH}")


if __name__ == "__main__":
    main()
