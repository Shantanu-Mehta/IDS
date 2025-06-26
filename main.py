# main.py
import os
from datarecord import ensure_buffers, collect_system_calls, create_buffer, delete_buffer
from predictor import load_model, predict_attacks

MODEL_PATH = "trained_model.pkl"
FEATURE_PATH = "feature_columns.pkl"

def run_ids_loop(model, feature_columns):
    buffer_id = 1
    while True:
        record_buffer = f"buffer{buffer_id}.csv"
        predict_buffer = f"buffer{2 if buffer_id == 1 else 1}.csv"

        print(f"\n=== IDS Cycle Using {record_buffer} for recording ===")
        collect_system_calls(duration_sec=60, which_buffer=record_buffer)

        print(f"[🔍] Prediction from {predict_buffer}: ", end="")
        try:
            label = predict_attacks(model, feature_columns, os.path.join("dataset", predict_buffer))
            print(label)
        except Exception as e:
            print(f"[⚠️] Skipped prediction due to: {e}")

        delete_buffer(predict_buffer)
        create_buffer(predict_buffer)

        buffer_id = 2 if buffer_id == 1 else 1

if __name__ == "__main__":
    print("=== Intrusion Detection Started ===")
    ensure_buffers()

    model = load_model(MODEL_PATH)
    feature_columns = load_model(FEATURE_PATH)

    run_ids_loop(model, feature_columns)

