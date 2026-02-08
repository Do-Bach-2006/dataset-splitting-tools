import os
import hashlib
from pathlib import Path
from collections import defaultdict


def get_file_hash(filepath):
    """Calculates MD5 hash of a file to detect content duplicates."""
    hasher = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            # Read in chunks to handle large files efficiently
            buf = f.read(65536)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(65536)
        return hasher.hexdigest()
    except Exception as e:
        return None


def verify_dataset(dataset_root):
    root_dir = Path(dataset_root)

    # Structure to hold data: data[dataset_name][label] = count
    stats = defaultdict(lambda: defaultdict(int))

    # Structure to track duplicates: seen_hashes[md5_hash] = list_of_locations
    seen_hashes = defaultdict(list)

    # The three expected splits
    splits = ["Target", "Adv", "Test"]

    print(f"--- Starting Verification on '{dataset_root}' ---")

    total_files_scanned = 0

    for split in splits:
        split_path = root_dir / split
        if not split_path.exists():
            print(f"Warning: Directory {split} does not exist!")
            continue

        # Walk through the directory
        for label_dir in split_path.iterdir():
            if label_dir.is_dir():
                label_name = label_dir.name
                files = list(label_dir.iterdir())

                # Update counts
                stats[split][label_name] = len(files)

                # Check Hashes
                for file_path in files:
                    if file_path.is_file():
                        file_hash = get_file_hash(file_path)
                        if file_hash:
                            seen_hashes[file_hash].append(
                                f"{split}/{label_name}/{file_path.name}"
                            )
                            total_files_scanned += 1

    # --- REPORT 1: DUPLICATES ---
    print(f"\n[1] Duplicate Check (Scanned {total_files_scanned} files)")
    duplicates_found = {k: v for k, v in seen_hashes.items() if len(v) > 1}

    if not duplicates_found:
        print("✅ PASSED: No duplicate files found across any datasets.")
    else:
        print(
            f"❌ FAILED: Found {len(duplicates_found)} unique files appearing in multiple locations!"
        )
        for h, locations in list(duplicates_found.items())[:5]:  # Show first 5 errors
            print(f"   Hash {h} found in:")
            for loc in locations:
                print(f"     - {loc}")
        if len(duplicates_found) > 5:
            print(f"   ... and {len(duplicates_found) - 5} others.")

    # --- REPORT 2: DISTRIBUTION ---
    print("\n[2] Distribution Check (Expect ~40% / 40% / 20%)")

    # Get all unique labels found
    all_labels = set()
    for s in stats:
        all_labels.update(stats[s].keys())

    # Print Header
    header = (
        f"{'Label':<15} | {'Target':<10} | {'Adv':<10} | {'Test':<10} | {'Total':<10}"
    )
    print("-" * len(header))
    print(header)
    print("-" * len(header))

    for label in sorted(all_labels):
        t_count = stats["Target"].get(label, 0)
        a_count = stats["Adv"].get(label, 0)
        te_count = stats["Test"].get(label, 0)
        total = t_count + a_count + te_count

        if total == 0:
            continue

        # Calculate percentages
        t_pct = (t_count / total) * 100
        a_pct = (a_count / total) * 100
        te_pct = (te_count / total) * 100

        print(
            f"{label:<15} | {t_count:<4} ({t_pct:.0f}%) | {a_count:<4} ({a_pct:.0f}%) | {te_count:<4} ({te_pct:.0f}%) | {total:<10}"
        )

    print("-" * len(header))


# --- RUN CONFIGURATION ---
if __name__ == "__main__":
    # Point this to the output folder from the previous script
    DATASET_LOCATION = "splitted_dataset"

    verify_dataset(DATASET_LOCATION)
