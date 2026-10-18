import json

def avg_latency_jsonl(file_path, latency_key="latency_ms", warmup_skip=10):
    count = 0
    total = 0.0
    skipped = 0

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
                lat = float(obj[latency_key])
            except:
                continue

            if skipped < warmup_skip:
                skipped += 1
                continue

            total += lat
            count += 1

    if count == 0:
        raise ValueError("No samples after warm-up")

    return total / count


if __name__ == "__main__":
    avg_golom = avg_latency_jsonl("Argon2_ron_admin_logs.jsonl", warmup_skip=10)
    avg_elad  = avg_latency_jsonl("Argon2_shaked77_logs.jsonl", warmup_skip=10)
    avg_Loffy  = avg_latency_jsonl("Argon2_cyberFun_logs.jsonl", warmup_skip=10)

    print(f"ron_admin average latency: {avg_golom:.3f} ms")
    print(f"shaked77 average latency: {avg_elad:.3f} ms")
    print(f"cyberFun average latency: {avg_Loffy:.3f} ms")
    