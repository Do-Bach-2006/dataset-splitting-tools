import numpy as np
import pandas as pd


# Thong tin
NPZ_FILE = "Target.npz"
CSV_FILE = "Target.csv"


def npz_to_csv_preview(npz_filepath, csv_filepath):
    print(f"[*] Đang tải dữ liệu từ {npz_filepath}...")
    # Thêm allow_pickle=True để đọc các mảng object chứa chuỗi và mảng lởm chởm
    data = np.load(npz_filepath, allow_pickle=True)

    # 1. Bóc tách ĐÚNG 5 trường dữ liệu bạn đã trích xuất
    names = data["name"]
    labels = data["label"]
    op_codes = data["op_code"]
    apis = data["api"]
    raw_bytes = data["raw_byte"]

    print(f"[*] Đã tải thành công {len(names)} mẫu.")
    print("[*] Đang xử lý định dạng hiển thị cho CSV...")

    # 2. Xử lý hiển thị Raw Byte thành dạng Hex để không làm treo file CSV
    raw_byte_previews = []
    for rb in raw_bytes:
        if len(rb) > 40:
            head_hex = " ".join([f"{b:02x}" for b in rb[:20]])
            tail_hex = " ".join([f"{b:02x}" for b in rb[-20:]])
            preview = f"{head_hex} ... [DỮ LIỆU ĐÃ ĐƯỢC ẨN] ... {tail_hex}"
        else:
            preview = " ".join([f"{b:02x}" for b in rb])
        raw_byte_previews.append(preview)

    # 3. Đóng gói vào Pandas DataFrame (Không có file_size)
    df = pd.DataFrame(
        {
            "File_Name": names,
            "Label": labels,
            "Static_API": apis,
            "Op_Code_Sequence": op_codes,
            "Raw_Byte_Preview_(Hex)": raw_byte_previews,
        }
    )

    # 4. Lưu ra CSV
    print(f"[*] Đang xuất ra file {csv_filepath}...")
    df.to_csv(csv_filepath, index=False, encoding="utf-8")
    print("[+] Hoàn tất! Bạn có thể mở file CSV bằng Excel hoặc VS Code.")


npz_to_csv_preview(NPZ_FILE, CSV_FILE)
