import tkinter as tk
from tkinter import scrolledtext
import threading
import time
import os
from datetime import datetime
from datarecord import ensure_buffers, collect_system_calls
from predictor import load_model, predict_attacks

MODEL_PATH = "trained_model.pkl"
FEATURE_PATH = "feature_columns.pkl"

model = load_model(MODEL_PATH)
feature_columns = load_model(FEATURE_PATH)
running = False

def log_message(log_box, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_box.insert(tk.END, f"[{timestamp}] {message}\n")
    log_box.see(tk.END)

def ids_loop(update_status, update_result, log_box):
    global running
    buffer_id = 1
    while running:
        record_buffer = f"buffer{buffer_id}.csv"
        predict_buffer = f"buffer{2 if buffer_id == 1 else 1}.csv"

        update_status(f"🛠️ Recording system calls to {record_buffer}")
        log_message(log_box, f"Started recording to {record_buffer}")

        collect_system_calls(duration_sec=60, which_buffer=record_buffer)

        update_status(f"✅ Finished recording to {record_buffer}")
        log_message(log_box, f"Recording finished: {record_buffer}")

        predict_path = os.path.join("dataset", predict_buffer)
        try:
            label = predict_attacks(model, feature_columns, predict_path)
            update_result(label)
            log_message(log_box, f"Prediction from {predict_buffer}: {label}")
            os.remove(predict_path)
            with open(predict_path, "w") as f:
                f.write("timestamp,syscall,direction,pid,ppid,uid,auid,comm,exe\n")
        except Exception as e:
            log_message(log_box, f"⚠️ Skipped prediction from {predict_buffer}: {str(e)}")

        buffer_id = 2 if buffer_id == 1 else 1
        time.sleep(1)

def start_monitoring(status_label, result_label, log_box):
    global running
    if not running:
        ensure_buffers()
        running = True
        thread = threading.Thread(target=ids_loop, args=(
            lambda msg: status_label.config(text=msg),
            lambda result: result_label.config(text=result, fg="red" if "ATTACK" in result else "#00ff88"),
            log_box
        ))
        thread.daemon = True
        thread.start()

def stop_monitoring(status_label, log_box):
    global running
    if running:
        running = False
        msg = "🛑 Monitoring stopped."
        status_label.config(text=msg)
        log_message(log_box, msg)

def create_gui():
    root = tk.Tk()
    root.title("🔐 Intrusion Detection System")
    root.geometry("720x520")
    root.configure(bg="#1e1e2e")

    title = tk.Label(root, text="🛡️  IDS S.H.I.L.D ", font=("Helvetica", 20, "bold"), fg="#00ffe0", bg="#1e1e2e")
    title.pack(pady=15)

    status_label = tk.Label(root, text="Status: Not Running", font=("Helvetica", 13), fg="#00ff88", bg="#1e1e2e")
    status_label.pack(pady=5)

    result_label = tk.Label(root, text="✅ NORMAL", font=("Helvetica", 24, "bold"), fg="#00ff88", bg="#1e1e2e")
    result_label.pack(pady=10)

    button_frame = tk.Frame(root, bg="#1e1e2e")
    button_frame.pack(pady=10)

    start_btn = tk.Button(button_frame, text="▶ Start Monitoring", font=("Helvetica", 12), bg="#28a745", fg="white",
                          width=20, command=lambda: start_monitoring(status_label, result_label, log_box))
    start_btn.grid(row=0, column=0, padx=10)

    stop_btn = tk.Button(button_frame, text="⏹ Stop Monitoring", font=("Helvetica", 12), bg="#dc3545", fg="white",
                         width=20, command=lambda: stop_monitoring(status_label, log_box))
    stop_btn.grid(row=0, column=1, padx=10)

    log_label = tk.Label(root, text="📜 System Log", font=("Helvetica", 14), fg="#00ffe0", bg="#1e1e2e")
    log_label.pack(pady=(20, 5))

    log_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=85, height=10, font=("Consolas", 11), bg="#282c34", fg="#ffffff")
    log_box.pack(padx=10, pady=5)

    root.mainloop()

if __name__ == "__main__":
    create_gui()

