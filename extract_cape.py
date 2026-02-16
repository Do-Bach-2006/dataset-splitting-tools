import os
import time
import requests
import numpy as np
import json

# --- CẤU HÌNH ĐÃ XÁC THỰC ---
# Dựa trên kết quả curl của bạn: Port 8000, Server 10.144.5.64
CAPE_HOST = "http://10.144.5.64:8000"
API_TOKEN = "5f42b8083e6a6e95bd32ff2037ae323252dcb8ff"

# Header xác thực
HEADERS = {"Authorization": f"Token {API_TOKEN}"}

# Thư mục dữ liệu
ROOT_DIR = "Adv"
OUTPUT_FILE = "Adv.npz"


def submit_to_cape(file_path):
    """
    Gửi file lên CAPEv2 (Endpoint: /apiv2/tasks/create/file/)
    """
    # URL này chắc chắn đúng vì HTML của bạn có link /apiv2/
    url = f"{CAPE_HOST}/apiv2/tasks/create/file/"

    # Cấu hình: Timeout 300s (5 phút)
    data_params = {"timeout": 300, "platform": "windows", "enforce_timeout": False}

    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}

            print(f" -> Đang gửi file lên {url} ...")
            r = requests.post(url, headers=HEADERS, files=files, data=data_params)

            # Nếu server trả về 200 OK
            if r.status_code == 200:
                resp = r.json()
                # CAPE return: {"data": {"task_ids": [123]}, "error": false}
                task_ids = resp.get("data", {}).get("task_ids", [])
                if task_ids:
                    print(f" [OK] Submit thành công. Task ID: {task_ids[0]}")
                    return task_ids[0]

            print(f" [!] Lỗi submit: {r.text}")
            return None

    except Exception as e:
        print(f" [!] Lỗi kết nối: {e}")
        return None


def wait_for_report(task_id):
    """
    Đợi phân tích xong và tải báo cáo JSON
    """
    status_url = f"{CAPE_HOST}/apiv2/tasks/view/{task_id}/"
    report_url = f"{CAPE_HOST}/apiv2/tasks/get/report/{task_id}/json/"

    print(f" [*] Đang đợi Task {task_id}...", end="", flush=True)

    # Vòng lặp đợi (Tối đa 10 phút)
    for i in range(60):
        try:
            r = requests.get(status_url, headers=HEADERS)
            if r.status_code == 200:
                data = r.json().get("data", {})
                status = data.get("status")

                if status == "reported":
                    print(" Xong! Đang tải JSON...")
                    # Tải báo cáo
                    rep = requests.get(report_url, headers=HEADERS)
                    return rep.json()
                elif status == "failed_analysis":
                    print(" Thất bại (Analysis Failed)!")
                    return None
                elif status == "error":
                    print(" Lỗi hệ thống CAPE!")
                    return None

            # Đợi 10s rồi check lại
            time.sleep(10)
        except Exception as e:
            print(f" [!] Lỗi polling: {e}")
            pass

    print(" Timeout (Quá thời gian chờ)!")
    return None


def extract_features(report):
    """
    Trích xuất: API Calls (All), Imports (1000), Sections (All)
    """
    features = {"api": [], "imports": [], "sections": []}

    if not report:
        return features

    # 1. Trích xuất API Calls (Behavior)
    # Lấy process có nhiều hành vi nhất
    try:
        processes = report.get("behavior", {}).get("processes", [])
        if processes:
            # Tìm process có số lượng call lớn nhất
            best_proc = max(processes, key=lambda x: len(x.get("calls", [])))

            # Lấy list tên API
            calls = best_proc.get("calls", [])
            features["api"] = [c.get("api") for c in calls if c.get("api")]
    except Exception:
        pass

    # 2. Trích xuất Static Info (Imports & Sections)
    try:
        pe = report.get("static", {}).get("pe", {})

        # Sections: Lấy hết
        features["sections"] = pe.get("sections", [])

        # Imports: Lấy tên hàm, giới hạn 1000
        imports_list = []
        for dll in pe.get("imports", []):
            for func in dll.get("imports", []):
                if func.get("name"):
                    imports_list.append(func["name"])
        features["imports"] = imports_list[:1000]

    except Exception:
        pass

    return features


def main():
    # Mảng lưu dữ liệu
    all_names = []
    all_labels = []
    all_apis = []
    all_imports = []
    all_sections = []

    print(f"--- BẮT ĐẦU QUÉT TRÊN SERVER {CAPE_HOST} ---")

    for root, dirs, files in os.walk(ROOT_DIR):
        for filename in files:
            # Bỏ qua file ẩn
            if filename.startswith("."):
                continue

            file_path = os.path.join(root, filename)
            label = os.path.basename(root)

            print(f"\n>>> Xử lý: {filename} (Label: {label})")

            # 1. Submit
            tid = submit_to_cape(file_path)
            if not tid:
                continue

            # 2. Đợi kết quả
            report = wait_for_report(tid)
            if not report:
                continue

            # 3. Trích xuất
            feats = extract_features(report)

            # 4. Lưu vào list
            all_names.append(filename)
            all_labels.append(label)
            all_apis.append(np.array(feats["api"]))  # Array of strings
            all_imports.append(np.array(feats["imports"]))  # Array of strings
            all_sections.append(feats["sections"])  # List of Dicts

            print(
                f" -> Thu được: {len(feats['api'])} APIs, {len(feats['imports'])} Imports"
            )

    # Lưu file .npz
    print(f"\n--- ĐANG LƯU FILE {OUTPUT_FILE} ---")
    np.savez_compressed(
        OUTPUT_FILE,
        name=np.array(all_names),
        label=np.array(all_labels),
        api=np.array(all_apis, dtype=object),
        pe_imports=np.array(all_imports, dtype=object),
        pe_sections=np.array(all_sections, dtype=object),
    )
    print("HOÀN TẤT!")


if __name__ == "__main__":
    main()
