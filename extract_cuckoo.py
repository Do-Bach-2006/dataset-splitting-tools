import os
import time
import requests
import numpy as np
import json
import glob
import sys

# --- CẤU HÌNH CUCKOO ---
CUCKOO_HOST = "http://10.144.10.212:8090"
API_TOKEN = "4tnVmJAddAjA7AUuGR6yvA"
HEADERS = {"Authorization": f"Bearer {API_TOKEN}"}

# Cấu hình thư mục
ROOT_DIR = "Target"
FINAL_OUTPUT_FILE = "Target.npz"

# Cấu hình Workspace
WORKSPACE_DIR = "progress_target"
PROGRESS_LOG = os.path.join(WORKSPACE_DIR, "processed_log.json")
BATCH_SIZE = 10

# ==============================================================================
# 1. CÁC HÀM HỖ TRỢ
# ==============================================================================


def ensure_workspace():
    if not os.path.exists(WORKSPACE_DIR):
        os.makedirs(WORKSPACE_DIR)


def load_processed_set():
    if os.path.exists(PROGRESS_LOG):
        try:
            with open(PROGRESS_LOG, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except:
            return set()
    return set()


def save_batch_npz(data_dict):
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
# 2. CÁC HÀM TƯƠNG TÁC CUCKOO API
# ==============================================================================


def submit_file(file_path):
    url = f"{CUCKOO_HOST}/tasks/create/file"
    # Turbo Mode: Tắt dump rác
    options = "procmemdump=0,dumpprocess=0,memory_dump=0,sniffer=0"
    data = {"timeout": 300, "enforce_timeout": False, "priority": 1, "options": options}

    while True:
        try:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                r = requests.post(
                    url, headers=HEADERS, files=files, data=data, timeout=30
                )

                if r.status_code == 200:
                    return r.json().get("task_id")
                elif r.status_code == 500:
                    print(" [!] Server 500. Đợi 10s...", end="\r")
                    time.sleep(10)
                    continue
                else:
                    print(f" [!] Lỗi Submit (HTTP {r.status_code}): {r.text}")
                    return None
        except requests.exceptions.RequestException as e:
            print(f" [!] Lỗi mạng submit: {e}. Đợi 10s...", end="\r")
            time.sleep(10)
        except Exception as e:
            print(f" [!] Lỗi lạ submit: {e}")
            return None


def wait_for_report(task_id):
    status_url = f"{CUCKOO_HOST}/tasks/view/{task_id}"
    report_url = f"{CUCKOO_HOST}/tasks/report/{task_id}"

    print(f"[*] Đợi Task {task_id}...", end="", flush=True)

    for i in range(240):  # 40 phút
        try:
            r = requests.get(status_url, headers=HEADERS, timeout=10)
            if r.status_code == 200:
                status = r.json().get("task", {}).get("status")
                if status in ["reported", "failed_analysis", "completed"]:
                    rep = requests.get(report_url, headers=HEADERS, timeout=60)
                    if rep.status_code == 200:
                        print(" OK!")
                        return rep.json()
                    else:
                        print(f" [!] Lỗi tải report (HTTP {rep.status_code})", end="")
            elif r.status_code != 200:
                print(f" [!] Status {r.status_code}", end="")

            time.sleep(10)
            if i % 6 == 0:
                print(".", end="", flush=True)

        except requests.exceptions.RequestException as e:
            print(f" [!] Mạng: {e}", end="")
            time.sleep(10)
        except Exception as e:
            print(f" [!] Lạ: {e}", end="")
            time.sleep(10)

    print(" Timeout! Thử tải lần cuối...")
    try:
        final = requests.get(report_url, headers=HEADERS, timeout=60)
        if final.status_code == 200:
            return final.json()
    except:
        pass
    return {}


def delete_task(task_id):
    url = f"{CUCKOO_HOST}/tasks/delete/{task_id}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            print(f" [CLEANUP] Đã xóa Task {task_id}")
            return True
        elif r.status_code == 404:
            print(f" [CLEANUP] Task {task_id} đã tự biến mất (404).")
            return True
        else:
            print(f" [!] Xóa thất bại (HTTP {r.status_code})")
            return False
    except Exception as e:
        print(f" [!] Lỗi xóa task: {e}")
        return False


def extract_features_raw(report):
    features = {"api": [], "imports": [], "sections": []}
    if not report:
        print(" [!] Report rỗng!")
        return features

    try:  # API
        for proc in report.get("behavior", {}).get("processes", []):
            for call in proc.get("calls", []):
                if "api" in call:
                    features["api"].append(call["api"])
    except Exception as e:
        print(f" [!] Lỗi API: {e}")

    try:  # Imports
        imp_raw = report.get("static", {}).get("pe_imports", [])
        flat_imp = []
        if isinstance(imp_raw, list):
            for d in imp_raw:
                for f in d.get("imports", []):
                    if f.get("name"):
                        flat_imp.append(f["name"])
        elif isinstance(imp_raw, dict):
            for d in imp_raw.values():
                for f in d.get("imports", []):
                    if f.get("name"):
                        flat_imp.append(f["name"])
        features["imports"] = flat_imp[:1000]
    except Exception as e:
        print(f" [!] Lỗi Imports: {e}")

    try:  # Sections
        sec = report.get("static", {}).get("pe_sections", [])
        if not sec:
            sec = report.get("static", {}).get("pe", {}).get("sections", [])
        features["sections"] = sec
    except Exception as e:
        print(f" [!] Lỗi Sections: {e}")

    return features


# ==============================================================================
# 3. MAIN LOOP
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

                # --- BẮT ĐẦU TÍNH GIỜ ---
                start_time = time.time()

                # 1. Submit
                tid = submit_file(file_path)
                if not tid:
                    continue

                # 2. Wait Report
                report = wait_for_report(tid)

                # 3. Extract Features
                feats = extract_features_raw(report)

                # --- KẾT THÚC TÍNH GIỜ ---
                end_time = time.time()
                duration = end_time - start_time

                # 4. In thông số
                n_api = len(feats["api"])
                n_imp = len(feats["imports"])
                n_sec = len(feats["sections"])
                print(f"   [RESULT] API: {n_api} | Import: {n_imp} | Section: {n_sec}")

                # --- [NEW] IN THỜI GIAN ---
                print(f"   [TIME]   Hoàn thành trong: {duration:.2f}s")
                # --------------------------

                # 5. Lưu vào RAM
                current_batch["name"].append(filename)
                current_batch["label"].append(label)
                current_batch["api"].append(np.array(feats["api"]))
                current_batch["pe_imports"].append(np.array(feats["imports"]))
                current_batch["pe_sections"].append(feats["sections"])

                processed_set.add(filename)

                # 6. Xóa Task
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
        print(f"\n\n [CRASH] GẶP LỖI KHÔNG MONG MUỐN: {e}")
    finally:
        if len(current_batch["name"]) > 0:
            print(
                f"\n [SAFETY SAVE] Phát hiện {len(current_batch['name'])} file chưa lưu. Đang lưu nốt..."
            )
            save_batch_npz(current_batch)
        else:
            print("\n [INFO] Bộ nhớ đệm sạch.")

        merge_all_npz()


if __name__ == "__main__":
    main()
