import os
import time
import requests
import numpy as np
import json
import glob
import sys

# --- CẤU HÌNH CAPEv2 (Đã chuẩn theo script của bạn) ---
CAPE_HOST = "http://10.144.5.64:8000"
API_TOKEN = "5f42b8083e6a6e95bd32ff2037ae323252dcb8ff"
HEADERS = {"Authorization": f"Token {API_TOKEN}"}

# Cấu hình thư mục
ROOT_DIR = "Test"  # Thư mục chứa mẫu malware
FINAL_OUTPUT_FILE = "Test.npz"

# Cấu hình Workspace (Nơi chứa file tạm và log)
WORKSPACE_DIR = "progress_Test"
PROGRESS_LOG = os.path.join(WORKSPACE_DIR, "processed_log.json")
BATCH_SIZE = 10

# ==============================================================================
# 1. CÁC HÀM HỖ TRỢ BATCH & LOGGING (GIỐNG CUCKOO)
# ==============================================================================


def ensure_workspace():
    if not os.path.exists(WORKSPACE_DIR):
        os.makedirs(WORKSPACE_DIR)


def load_processed_set():
    """Load danh sách file đã làm xong để bỏ qua (Resume)"""
    if os.path.exists(PROGRESS_LOG):
        try:
            with open(PROGRESS_LOG, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except:
            return set()
    return set()


def save_batch_npz(data_dict):
    """Lưu batch ra .npz VÀ cập nhật ngay file JSON log."""
    if not data_dict["name"]:
        return

    count = len(data_dict["name"])
    timestamp = int(time.time())

    filename = f"batch_{timestamp}_{count}_samples.npz"
    filepath = os.path.join(WORKSPACE_DIR, filename)

    print(f"\n [SAVE] Đang lưu {count} file vào đĩa -> {filename}")

    try:
        np.savez_compressed(
            filepath,
            name=np.array(data_dict["name"]),
            label=np.array(data_dict["label"]),
            api=np.array(data_dict["api"], dtype=object),
            pe_imports=np.array(data_dict["pe_imports"], dtype=object),
            pe_sections=np.array(data_dict["pe_sections"], dtype=object),
        )
    except Exception as e:
        print(f" [!] Lỗi KHI LƯU FILE NPZ: {e}")
        return

    # Cập nhật JSON Log
    current_log = []
    if os.path.exists(PROGRESS_LOG):
        try:
            with open(PROGRESS_LOG, "r", encoding="utf-8") as f:
                current_log = json.load(f)
        except:
            pass

    current_log.extend(data_dict["name"])

    try:
        with open(PROGRESS_LOG, "w", encoding="utf-8") as f:
            json.dump(current_log, f, indent=2)
        print(" [LOG] Đã cập nhật file processed_log.json.")
    except Exception as e:
        print(f" [!] Lỗi cập nhật JSON Log: {e}")


def merge_all_npz():
    """Gộp tất cả file con thành file lớn cuối cùng"""
    print(f"\n--- GIAI ĐOẠN CUỐI: GỘP TOÀN BỘ FILE ---")
    npz_files = glob.glob(os.path.join(WORKSPACE_DIR, "*.npz"))
    if not npz_files:
        print(" [!] Không có file nào để gộp.")
        return

    all_data = {"name": [], "label": [], "api": [], "pe_imports": [], "pe_sections": []}

    print(f" -> Tìm thấy {len(npz_files)} file batch. Đang gộp...")
    for f in npz_files:
        try:
            d = np.load(f, allow_pickle=True)
            all_data["name"].append(d["name"])
            all_data["label"].append(d["label"])
            all_data["api"].append(d["api"])
            all_data["pe_imports"].append(d["pe_imports"])
            all_data["pe_sections"].append(d["pe_sections"])
        except Exception as e:
            print(f" [!] Lỗi đọc file {f}: {e}")

    print(f" -> Đang nối dữ liệu và lưu vào {FINAL_OUTPUT_FILE}...")
    try:
        np.savez_compressed(
            FINAL_OUTPUT_FILE,
            name=np.concatenate(all_data["name"]),
            label=np.concatenate(all_data["label"]),
            api=np.concatenate(all_data["api"]),
            pe_imports=np.concatenate(all_data["pe_imports"]),
            pe_sections=np.concatenate(all_data["pe_sections"]),
        )
        print(" [DONE] Hoàn tất!")
    except Exception as e:
        print(f" [!] Lỗi khi gộp file: {e}")


# ==============================================================================
# 2. CÁC HÀM TƯƠNG TÁC CAPE (Logic của bạn + Auto Delete)
# ==============================================================================


def submit_to_cape(file_path):
    url = f"{CAPE_HOST}/apiv2/tasks/create/file/"

    # --- TURBO MODE (TỪ SCRIPT CỦA BẠN) ---
    options_str = "sniffer=0,procmemdump=0,dumpprocess=0,dump_r0=0,curtain=0,sysmon=0"
    data_params = {
        "timeout": 300,
        "platform": "windows",
        "enforce_timeout": False,
        "options": options_str,
    }

    while True:  # Retry Loop
        try:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                r = requests.post(
                    url, headers=HEADERS, files=files, data=data_params, timeout=30
                )

                if r.status_code == 200:
                    task_ids = r.json().get("data", {}).get("task_ids", [])
                    if task_ids:
                        return task_ids[0]
                elif r.status_code >= 500:
                    print(" [!] Server quá tải (500). Đợi 15s...", end="\r")
                    time.sleep(15)
                    continue
                else:
                    print(f" [!] Lỗi Submit (HTTP {r.status_code}): {r.text}")
                    return None
        except requests.exceptions.RequestException:
            print(" [!] Mất kết nối. Đợi 10s...", end="\r")
            time.sleep(10)
        except Exception as e:
            print(f" [!] Lỗi lạ: {e}")
            return None


def wait_for_report(task_id):
    """
    Sử dụng logic check lỗi 'error: true' của bạn + Retry
    """
    status_url = f"{CAPE_HOST}/apiv2/tasks/view/{task_id}/"
    report_url = f"{CAPE_HOST}/apiv2/tasks/get/report/{task_id}/json/"

    print(f"[*] Đợi Task {task_id}...", end="", flush=True)

    # Đợi tối đa 40 phút
    for i in range(240):
        try:
            r = requests.get(status_url, headers=HEADERS, timeout=10)
            if r.status_code == 200:
                data = r.json().get("data", {})
                status = data.get("status")

                if status in ["reported", "failed_analysis", "timeout", "completed"]:
                    # Tải Report
                    rep_req = requests.get(report_url, headers=HEADERS, timeout=60)
                    if rep_req.status_code == 200:
                        report_data = rep_req.json()

                        # --- [LOGIC QUAN TRỌNG CỦA BẠN] ---
                        # Nếu server báo đang phân tích dở (error: true) -> Đợi tiếp
                        if report_data.get("error") is True:
                            time.sleep(5)
                            print(" (Wait JSON gen...)", end="")
                            continue

                        # Check sơ bộ dữ liệu
                        if (
                            "target" in report_data
                            or "behavior" in report_data
                            or "static" in report_data
                        ):
                            print(" OK!")
                            return report_data

            time.sleep(10)
            if i % 6 == 0:
                print(".", end="", flush=True)

        except requests.exceptions.RequestException:
            print("x", end="", flush=True)
            time.sleep(10)
        except Exception:
            pass

    print(" Timeout! Thử tải lần cuối...")
    try:
        return requests.get(report_url, headers=HEADERS, timeout=60).json()
    except:
        return {}


def delete_task(task_id):
    """Xóa task trên CAPE để giải phóng ổ cứng"""
    url = f"{CAPE_HOST}/apiv2/tasks/delete/{task_id}/"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            return True  # Xóa thành công
        elif r.status_code == 404:
            return True  # Đã xóa từ trước
        return False
    except:
        return False


def extract_features_raw(report):
    """Sử dụng logic trích xuất chuẩn của bạn"""
    features = {"api": [], "imports": [], "sections": []}
    if not report:
        print(" [!] Report rỗng!")
        return features

    # 1. API Calls (Lấy TOÀN BỘ)
    try:
        processes = report.get("behavior", {}).get("processes", [])
        all_calls = []
        for proc in processes:
            # CAPEv2 cấu trúc call có thể là dict hoặc list
            for call in proc.get("calls", []):
                if isinstance(call, dict) and call.get("api"):
                    all_calls.append(call["api"])
        features["api"] = all_calls
    except Exception as e:
        print(f" [!] Lỗi API: {e}")

    # 2. Static Info (Imports & Sections)
    try:
        # Ưu tiên lấy từ target > static > pe
        target_pe = report.get("target", {}).get("file", {}).get("pe", {})
        static_pe = report.get("static", {}).get("pe", {})
        pe_node = target_pe if target_pe else static_pe

        # Imports
        raw_imports = pe_node.get("imports", [])
        flat_imp = []
        if isinstance(raw_imports, dict):  # Format mới
            for d in raw_imports.values():
                for f in d.get("imports", []):
                    if f.get("name"):
                        flat_imp.append(f["name"])
        elif isinstance(raw_imports, list):  # Format cũ
            for d in raw_imports:
                for f in d.get("imports", []):
                    if f.get("name"):
                        flat_imp.append(f["name"])
        features["imports"] = flat_imp[:1000]

        # Sections
        features["sections"] = pe_node.get("sections", [])
    except Exception as e:
        print(f" [!] Lỗi Static: {e}")

    return features


# ==============================================================================
# 3. MAIN LOOP (FULL OPTION)
# ==============================================================================


def main():
    ensure_workspace()

    processed_set = load_processed_set()
    print(f"--- Đã hoàn thành {len(processed_set)} file trước đó (Skip) ---")

    current_batch = {
        "name": [],
        "label": [],
        "api": [],
        "pe_imports": [],
        "pe_sections": [],
    }

    try:
        for root, dirs, files in os.walk(ROOT_DIR):
            for filename in files:
                if filename.startswith("."):
                    continue
                if filename in processed_set:
                    continue

                file_path = os.path.join(root, filename)
                label = os.path.basename(root)
                print(f"\n>>> File: {filename} | Label: {label}")

                start_time = time.time()

                # 1. Submit
                tid = submit_to_cape(file_path)
                if not tid:
                    continue

                # 2. Wait Report (Với logic fix lỗi của bạn)
                report = wait_for_report(tid)

                # 3. Extract Features
                feats = extract_features_raw(report)

                duration = time.time() - start_time

                # 4. In kết quả & Thời gian
                n_api = len(feats["api"])
                n_imp = len(feats["imports"])
                n_sec = len(feats["sections"])
                print(f"   [RESULT] API: {n_api} | Import: {n_imp} | Section: {n_sec}")
                print(f"   [TIME]   Hoàn thành trong: {duration:.2f}s")

                # 5. Lưu RAM
                current_batch["name"].append(filename)
                current_batch["label"].append(label)
                current_batch["api"].append(np.array(feats["api"]))
                current_batch["pe_imports"].append(np.array(feats["imports"]))
                current_batch["pe_sections"].append(feats["sections"])

                processed_set.add(filename)

                # 6. Xóa Task ngay lập tức
                delete_task(tid)

                print(f"   [BATCH]  {len(current_batch['name'])}/{BATCH_SIZE}")

                # 7. Lưu xuống đĩa nếu đủ batch
                if len(current_batch["name"]) >= BATCH_SIZE:
                    save_batch_npz(current_batch)
                    current_batch = {
                        "name": [],
                        "label": [],
                        "api": [],
                        "pe_imports": [],
                        "pe_sections": [],
                    }

    except KeyboardInterrupt:
        print("\n\n [STOP] ĐANG DỪNG BỞI NGƯỜI DÙNG... (Đợi lưu file cuối)")
    except Exception as e:
        print(f"\n\n [CRASH] Lỗi: {e}")
    finally:
        # --- SAFETY SAVE ---
        if len(current_batch["name"]) > 0:
            print(f"\n [SAFETY SAVE] Lưu {len(current_batch['name'])} file cuối...")
            save_batch_npz(current_batch)

        # Gộp file
        merge_all_npz()


if __name__ == "__main__":
    main()
