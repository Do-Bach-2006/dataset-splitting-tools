import os
import shutil
import random
import math
from pathlib import Path
from tqdm import tqdm  # Optional: for a nice progress bar


def split_dataset(source_path, output_root):
    """
    Splits a dataset into Target (40%), Adv (40%), and Test (20%).
    Moves files (Cut operation) to ensure no duplicates.
    """

    # Define split configuration
    splits = {"Target": 0.40, "Adv": 0.40, "Test": 0.20}

    source_dir = Path(source_path)
    if not source_dir.exists():
        print(f"Error: Source directory '{source_dir}' not found.")
        return

    # Get list of classes (subdirectories like Benign, Locker, etc.)
    classes = [d for d in source_dir.iterdir() if d.is_dir()]

    print(f"Found {len(classes)} classes: {[c.name for c in classes]}")
    print("Starting split operation...\n")

    for class_dir in classes:
        class_name = class_dir.name

        # Get all files in this class
        files = [f for f in class_dir.iterdir() if f.is_file()]
        total_files = len(files)

        # Shuffle to ensure random distribution
        random.seed(42)  # Fixed seed for reproducibility
        random.shuffle(files)

        # Calculate split indices
        # We calculate the cutoff points based on the total count
        count_target = math.floor(total_files * splits["Target"])
        count_adv = math.floor(total_files * splits["Adv"])
        # Test gets the remainder to account for rounding errors

        # Slice the list of files
        files_target = files[:count_target]
        files_adv = files[count_target : count_target + count_adv]
        files_test = files[count_target + count_adv :]

        # Map the file lists to their destination names
        split_mapping = {"Target": files_target, "Adv": files_adv, "Test": files_test}

        print(
            f"Processing '{class_name}': {total_files} files "
            f"-> Target: {len(files_target)}, Adv: {len(files_adv)}, Test: {len(files_test)}"
        )

        # Perform the move
        for split_name, file_list in split_mapping.items():
            # Create destination directory: output_root/Target/Benign
            dest_dir = Path(output_root) / split_name / class_name
            dest_dir.mkdir(parents=True, exist_ok=True)

            for file_path in file_list:
                try:
                    shutil.move(str(file_path), str(dest_dir / file_path.name))
                except Exception as e:
                    print(f"Error moving {file_path.name}: {e}")

    # Cleanup: Remove empty original class folders if they are empty
    # (Optional: remove this block if you want to keep the empty folder structure)
    try:
        for class_dir in classes:
            if not any(class_dir.iterdir()):
                class_dir.rmdir()
        if not any(source_dir.iterdir()):
            source_dir.rmdir()
        print("\nOriginal empty directories cleaned up.")
    except Exception as e:
        print(f"Cleanup note: {e}")

    print(
        f"\nSuccess! Dataset split into '{output_root}/Target', '{output_root}/Adv', and '{output_root}/Test'"
    )


# --- RUN CONFIGURATION ---
if __name__ == "__main__":
    # Update this path to your actual location
    ORIGINAL_DATASET_PATH = "./label_only_dataset"

    # This will create a folder named 'processed_dataset' containing the 3 splits
    OUTPUT_PATH = "splitted_dataset"

    split_dataset(ORIGINAL_DATASET_PATH, OUTPUT_PATH)
