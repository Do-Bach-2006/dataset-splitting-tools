import os
import time
import requests
import numpy as np
import json

# --- CẤU HÌNH CUCKOO ---
CUCKOO_HOST = "http://10.144.10.212:8090"
API_TOKEN = "4tnVmJAddAjA7AUuGR6yvA"
HEADERS = {"Authorization": f"Bearer {API_TOKEN}"}

# Thư mục gốc chứa dữ liệu
ROOT_DIR = "Target"
OUTPUT_FILE = "Target.npz"


def submit_file(file_path):
    """Gửi file lên Cuckoo với thời gian giới hạn 300 giây"""
    url = f"{CUCKOO_HOST}/tasks/create/file"

    # Thêm tham số cấu hình cho task
    data_params = {
        "timeout": 300,  # Bắt buộc dừng sau 300 giây (5 phút)
        "enforce_timeout": False,  # (Tùy chọn) True: Bắt buộc chạy ĐỦ 300s ngay cả khi malware dừng sớm.
        # False: Dừng ngay khi malware kết thúc hành vi (tối đa 300s).
        "priority": 1,  # (Tùy chọn) Độ ưu tiên
    }

    try:
        with open(file_path, "rb") as f:
            # files chứa file binary
            files = {"file": (os.path.basename(file_path), f)}

            # data chứa các tham số (timeout, priority...)
            r = requests.post(url, headers=HEADERS, files=files, data=data_params)

            r.raise_for_status()
            task_id = r.json().get("task_id")
            print(f" -> Đã submit Task ID: {task_id} (Timeout: 300s)")
            return task_id

    except Exception as e:
        print(f"[!] Lỗi submit file {file_path}: {e}")
        return None


def wait_for_report(task_id):
    """Đợi Cuckoo phân tích xong và trả về Report JSON"""
    print(f"[*] Đang đợi phân tích Task {task_id}...", end="", flush=True)
    status_url = f"{CUCKOO_HOST}/tasks/view/{task_id}"
    report_url = f"{CUCKOO_HOST}/tasks/report/{task_id}"

    while True:
        try:
            r = requests.get(status_url, headers=HEADERS)
            if r.status_code == 200:
                status = r.json()["task"]["status"]
                if status == "reported":
                    print(" Xong!")
                    # Lấy report JSON
                    rep = requests.get(report_url, headers=HEADERS)
                    return rep.json()
                elif status == "failed_analysis":
                    print(" Thất bại!")
                    return None
            time.sleep(5)  # Đợi 5 giây trước khi kiểm tra lại
        except Exception as e:
            print(f"\n[!] Lỗi khi check status: {e}")
            return None


def extract_features(report):
    """Trích xuất API, PE Import, PE Section từ JSON Report"""
    features = {"api_calls": [], "pe_imports": [], "pe_sections": []}

    # 1. Trích xuất API Calls (Lấy HẾT từ process chính)
    # Cuckoo trả về behavior -> processes. Ta lấy process đầu tiên có gọi API.
    try:
        processes = report.get("behavior", {}).get("processes", [])
        for proc in processes:
            # Tìm process có thực hiện calls
            if len(proc.get("calls", [])) > 0:
                # Lấy tên API (với API 'calls' trả về list các dict, cần lấy key 'api')
                calls = [call["api"] for call in proc["calls"]]
                features["api_calls"] = calls
                break  # Chỉ lấy process chính đầu tiên (thường là malware chính)
    except Exception:
        pass  # Để trống nếu lỗi

    # 2. Trích xuất PE Imports (Giới hạn 1000)
    try:
        # static -> pe_imports là list các DLL, mỗi DLL chứa list imports
        pe_imports_raw = report.get("static", {}).get("pe_imports", [])
        flattened_imports = []
        for dll in pe_imports_raw:
            for func in dll.get("imports", []):
                if func.get("name"):
                    flattened_imports.append(func["name"])

        # Giới hạn 1000 imports đầu tiên
        features["pe_imports"] = flattened_imports[:1000]
    except Exception:
        pass

    # 3. Trích xuất PE Sections (Lấy HẾT)
    try:
        # static -> pe_sections là list các dict chứa info section
        features["pe_sections"] = report.get("static", {}).get("pe_sections", [])
    except Exception:
        pass

    return features


def main():
    # Danh sách chứa dữ liệu để save
    data_filenames = []
    data_labels = []
    data_apis = []
    data_imports = []
    data_sections = []

    print(f"--- Bắt đầu quét thư mục {ROOT_DIR} ---")

    for root, dirs, files in os.walk(ROOT_DIR):
        for filename in files:
            file_path = os.path.join(root, filename)
            # Label là tên thư mục cha
            label = os.path.basename(root)

            print(f"\n>>> Xử lý: {filename} (Label: {label})")

            # 1. Submit file
            task_id = submit_file(file_path)
            if not task_id:
                continue

            # 2. Đợi và lấy kết quả
            report = wait_for_report(task_id)
            if not report:
                print(f"[!] Không lấy được báo cáo cho {filename}")
                continue

            # 3. Trích xuất đặc trưng
            feats = extract_features(report)

            # 4. Lưu vào list tạm
            data_filenames.append(filename)
            data_labels.append(label)
            data_apis.append(np.array(feats["api_calls"]))
            data_imports.append(np.array(feats["pe_imports"]))
            # PE sections là list of dicts, ta lưu thẳng object
            data_sections.append(feats["pe_sections"])

    # Chuyển đổi sang Numpy Array
    # Lưu ý: dtype=object là bắt buộc vì độ dài các mảng con không đều nhau
    np_filenames = np.array(data_filenames)
    np_labels = np.array(data_labels)
    np_apis = np.array(data_apis, dtype=object)
    np_imports = np.array(data_imports, dtype=object)
    np_sections = np.array(data_sections, dtype=object)

    print(f"\n--- Đang lưu file {OUTPUT_FILE} ---")
    print(f"Số lượng mẫu: {len(np_filenames)}")

    np.savez_compressed(
        OUTPUT_FILE,
        name=np_filenames,
        label=np_labels,
        api=np_apis,
        pe_imports=np_imports,
        pe_sections=np_sections,
    )

    print("Hoàn tất!")


if __name__ == "__main__":
    main()

