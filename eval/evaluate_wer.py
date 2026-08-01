# Word Error Rate (WER) evaluation for Flashpoint's Whisper wrapper (eval item 2).

"""
Compares Whisper's transcription (via analyse_audio()) against each
incident's ground-truth voice_transcript.txt
"""

import argparse
import csv
import logging
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models import analyse_audio 
from eval.eval_utils import iterate_incidents, load_voice_transcript  

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

RESULTS_DIR = Path(__file__).resolve().parent / "results"
WER_CSV = RESULTS_DIR / "wer_predictions.csv"
WER_REPORT = RESULTS_DIR / "wer_report.txt"
WER_TARGET = 0.15

# Function to tokenize words by lowercasing and removing punctuation
def tokenize_words(text: str) -> list:
    text = text.lower()
    text = re.sub(r"[^\w\s]", " ", text)
    return text.split()

# Computes Word Error Rate (WER) between the ground-truth transcript and
# Whisper's predicted transcript, via word-level Levenshtein distance.
# WER = (substitutions + deletions + insertions) / ground_truth_word_count
def word_error_rate(ground_truth_words: list, whisper_predicted_words: list) -> float:

    ground_truth_word_count = len(ground_truth_words)
    whisper_predicted_word_count = len(whisper_predicted_words)

    # No ground truth: 0.0 if prediction is also empty, else 1.0 (all insertions)
    if ground_truth_word_count == 0:
        return 0.0 if whisper_predicted_word_count == 0 else 1.0

    # edit_distance_table[i][j] = min edits to turn the first i ground-truth
    # words into the first j predicted words
    edit_distance_table = [[0] * (whisper_predicted_word_count + 1)
                           for _ in range(ground_truth_word_count + 1)]

    # Base case: i deletions to reach zero predicted words
    for i in range(ground_truth_word_count + 1):
        edit_distance_table[i][0] = i

    # Base case: j insertions to build up from zero ground-truth words
    for j in range(whisper_predicted_word_count + 1):
        edit_distance_table[0][j] = j

    # Match = free (carry diagonal); otherwise cheapest edit + 1
    for i in range(1, ground_truth_word_count + 1):
        for j in range(1, whisper_predicted_word_count + 1):
            if ground_truth_words[i - 1] == whisper_predicted_words[j - 1]:
                edit_distance_table[i][j] = edit_distance_table[i - 1][j - 1]
            else:
                deletion = edit_distance_table[i - 1][j]          # drop a ground-truth word
                insertion = edit_distance_table[i][j - 1]          # add a predicted word
                substitution = edit_distance_table[i - 1][j - 1]   # swap one word for another
                edit_distance_table[i][j] = 1 + min(deletion, insertion, substitution)

    total_word_edits = edit_distance_table[ground_truth_word_count][whisper_predicted_word_count]
    return total_word_edits / ground_truth_word_count

# Function to load existing WER results from CSV 
# and return a set of incident IDs that have already been processed
def load_existing_results() -> set:
    done = set()
    if WER_CSV.exists():
        with open(WER_CSV, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                done.add(row["incident_id"])
    return done

# Main function to evaluate WER for all incidents in the dataset
def main():
    parser = argparse.ArgumentParser(description="WER evaluation for Flashpoint's Whisper model wrapper.")
    parser.add_argument("--dataset-root",
                        required=True,
                        help="Path to the FYP-Dataset folder.")
    args = parser.parse_args()

    ## Ensure results directory exists and load existing WER results
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    already_done = load_existing_results()
    file_is_new = not WER_CSV.exists()

    # Opewn the WER CSV file for appending new results
    with open(WER_CSV, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, 
                                fieldnames=["incident_id",
                                            "wer",
                                            "ground_truth_word_count", 
                                            "whisper_predicted_word_count"])
        
        # Write header if it's a new file
        if file_is_new:
            writer.writeheader()

        # Iterate through incidents in the dataset and compute WER for each
        for incident in iterate_incidents(args.dataset_root):
            
            # Skip incidents that have already been processeds
            if incident.incident_id in already_done:
                logger.info("Skipping %s", incident.incident_id)
                continue

            # Skip incidents that are missing either the voice audio or the ground-truth transcript    
            if incident.voice_path is None or incident.voice_transcript_path is None:
                logger.warning("Skipping %s as missing voice.wav or voice_transcript.txt",
                               incident.incident_id)
                continue
            
            # Log the incident being processed and run the audio analysis    
            logger.info("Transcribing %s", incident.incident_id)
            
            # Try run the audio analysis and handle any exceptions that may occur
            try:
                result = analyse_audio(incident.voice_path)
            except Exception as e:
                logger.error("%s failed: %s", incident.incident_id, e)
                continue

            # Compare Whisper's predicted transcript to the ground-truth transcript
            whisper_predicted_transcript = result.get("raw", "")
            ground_truth_transcript = load_voice_transcript(incident.voice_transcript_path)

            # Tokenize both transcripts for word-level comparison
            ground_truth_words = tokenize_words(ground_truth_transcript)
            whisper_predicted_words = tokenize_words(whisper_predicted_transcript)
            
            # Compute WER
            wer = word_error_rate(ground_truth_words, whisper_predicted_words)

            # write the WER results to CSV file
            writer.writerow({"incident_id": incident.incident_id,
                             "wer": round(wer, 4),
                             "ground_truth_word_count": len(ground_truth_words),
                             "whisper_predicted_word_count": len(whisper_predicted_words)})
            
            # Flush the file to ensure data is written to disk
            f.flush()

    
    rows = []
    # Open the WER CSV file to read the results
    with open(WER_CSV, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    
    # If there are no WER results, log a warning and exit
    if not rows:
        logger.warning("No WER results to summarise.")
        return

    # Compute the mean WER across all incidents
    wers = [float(row["wer"]) for row in rows]
    mean_wer = sum(wers) / len(wers)

    # Generate a summary report of the WER evaluation
    report_lines = [f"n = {len(wers)} incidents",
                    f"Mean WER: {mean_wer:.4f} ({mean_wer * 100:.2f}%)",
                    f"Design 3.7 target: WER <= {WER_TARGET:.0%}",
                    f"Target met: {'YES' if mean_wer <= WER_TARGET else 'NO'}"]
    
    # Write the summary report to a text file and print it to the console
    report_text = "\n".join(report_lines)
    print(report_text)
    
    # Write the full report to a text file
    WER_REPORT.write_text(report_text, encoding="utf-8")
    
    # Print the pAth location of the full report
    print(f"\nFull report written to {WER_REPORT}")

# Run the main function if this fie is run directly
if __name__ == "__main__":
    main()
