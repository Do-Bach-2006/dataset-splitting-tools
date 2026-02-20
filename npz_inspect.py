import numpy as np

# Thong tin
NPZ_FILE = "Target.npz"


def inspect_npz_element(npz_filepath, index=0):
    print(f"[*] Đang tải dữ liệu từ {npz_filepath}...\n")
    # allow_pickle=True là bắt buộc để đọc mảng object chứa chuỗi/mảng con
    data = np.load(npz_filepath, allow_pickle=True)

    # Kiểm tra xem file có rỗng không
    if len(data["name"]) == 0:
        print("[!] File .npz không có dữ liệu.")
        return

    # Lấy thông tin của phần tử tại vị trí `index`
    name = data["name"][index]
    label = data["label"][index]
    raw_byte = data["raw_byte"][index]
    op_code = data["op_code"][index]
    api = data["api"][index]

    print("=" * 60)
    print(f" THÔNG TIN PHẦN TỬ THỨ {index} TRONG DATASET")
    print("=" * 60)

    print(f"[+] Tên file (name): {name}")
    print(f"[+] Nhãn (label):   {label}")

    # ---------------------------------------------------------
    # In Raw Byte
    # ---------------------------------------------------------
    print(f"\n[+] RAW BYTE")
    print(f"    - Kiểu dữ liệu: {type(raw_byte)}")
    print(f"    - Kích thước:   {len(raw_byte)} bytes")

    if len(raw_byte) > 50:
        hex_preview = " ".join([f"{b:02x}" for b in raw_byte[:50]])
        print(f"    - Preview (50 byte đầu): {hex_preview} ... [CÒN TIẾP]")
    else:
        hex_preview = " ".join([f"{b:02x}" for b in raw_byte])
        print(f"    - Preview: {hex_preview}")

    # ---------------------------------------------------------
    # In Op Code
    # ---------------------------------------------------------
    print(f"\n[+] OP CODE SEQUENCE")
    print(f"    - Kiểu dữ liệu: {type(op_code)}")
    print(f"    - Độ dài chuỗi: {len(op_code)} ký tự")

    if len(op_code) > 200:
        print(f"    - Preview (200 ký tự đầu): {op_code[:200]} ... [CÒN TIẾP]")
    else:
        print(f"    - Preview: {op_code}")

    # ---------------------------------------------------------
    # In Static API
    # ---------------------------------------------------------
    print(f"\n[+] STATIC API SEQUENCE")
    print(f"    - Kiểu dữ liệu: {type(api)}")
    print(f"    - Độ dài chuỗi: {len(api)} ký tự")

    if len(api) > 200:
        print(f"    - Preview (200 ký tự đầu): {api[:200]} ... [CÒN TIẾP]")
    else:
        print(f"    - Preview: {api}")

    print("=" * 60)


inspect_npz_element(NPZ_FILE, index=0)
