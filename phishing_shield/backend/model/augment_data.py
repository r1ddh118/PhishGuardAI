import pandas as pd
import numpy as np
from pathlib import Path

# Phrases to use for synthetic data
GREETINGS = ["hey what's up?", "hello", "hi there", "good morning", "how's it going?", "hey", "yo"]
CASUAL_WORK = [
    "Meeting at 5pm in the conference room.",
    "Can you send me the doc?",
    "Thanks for the update.",
    "Let's catch up later.",
    "Are you coming to the meeting?",
    "I'll be there in 10 minutes.",
    "Got it, thanks!",
    "Can we talk?",
    "See you later.",
    "Please review this.",
    "Lunch?",
    "Approved.",
    "Rejected.",
    "Wait for my signal."
]

def generate_benign_samples(count=1000):
    samples = []
    for i in range(count):
        # Mix greetings and casual work stuff
        phrase = np.random.choice(GREETINGS) + " " + np.random.choice(CASUAL_WORK)
        samples.append({
            "id": f"synthetic_{i}",
            "sender": "internal@company.com",
            "receiver": "user@company.com",
            "date": "2026-03-02",
            "subject": "Quick note",
            "body": phrase,
            "label": 0  # Legitimate
        })
    return pd.DataFrame(samples)

def main():
    data_dir = Path("data")
    original_csv = data_dir / "features.csv"
    augmented_csv = data_dir / "features_augmented.csv"
    
    print("Generating synthetic benign samples...")
    synthetic_df = generate_benign_samples(1000)
    
    # We need to extract the labels and bodies to match generate_features.py logic
    # or just append to the raw data files and re-run feature generation.
    # To keep it simple and surgical, we'll create a new "synthetic_benign.csv"
    # and update train_model.py to load it too.
    
    output_path = data_dir / "synthetic_benign.csv"
    synthetic_df.to_csv(output_path, index=False)
    print(f"Saved {len(synthetic_df)} samples to {output_path}")

if __name__ == "__main__":
    main()
