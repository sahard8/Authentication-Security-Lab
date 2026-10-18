import time
from tracemalloc import start
import psutil
import threading

MS_IN_SECOND = 1000

def measure_server_resources(process, duration_seconds = 5, sample_interval = 1):
    """Measures CPU and memory usage of the server process over a specified duration."""
    cpu_samples = []
    rss_samples = []

    process.cpu_percent(interval=None)  # Initialize CPU percent measurement

    end_time = time.perf_counter() + duration_seconds
    while time.perf_counter() < end_time:
        cpu = process.cpu_percent(interval=sample_interval)
        rss = process.memory_info().rss

        cpu_samples.append(cpu)
        rss_samples.append(rss)

    avg_cpu = sum(cpu_samples) / len(cpu_samples) if cpu_samples else 0
    peack_rss_mb = max(rss_samples) / (1024 * 1024) if rss_samples else 0

    return  {"average_cpu_percent": avg_cpu, "peak_rss_mb": peack_rss_mb, "samples_count": len(cpu_samples)}


def find_server_process():
    """
    Find the python process running server.py.
    Assumes only one instance is running.
    Returns psutil.Process or None.
    """
    for proc in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
        try:
            name = proc.info['name'].lower()
            cmdline = proc.info.get("cmdline")
            if cmdline is None:
                cmd = ""
            elif isinstance(cmdline, (list, tuple)):
                cmd = " ".join(str(part) for part in cmdline)
            else:
                cmd = str(cmdline)

            if "python" in name and "server.py" in cmd:
                return psutil.Process(proc.info['pid'])
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return None


def sample_server_resources(process, samples, stop_event, sample_interval = 1.0):
    """Samples CPU and memory usage of the server process until stop_event is set."""
    process.cpu_percent(interval=None)  # Initialize CPU percent measurement
    while not stop_event.is_set():
        cpu = process.cpu_percent(interval=sample_interval)
        rss = process.memory_info().rss
        samples.append((cpu, rss))


def summarize_samples(samples):
    """ Returns (avg_cpu_percent, peak_rss_mb, samples_count)"""
    if not samples:
        return 0.0, 0.0, 0
    
    cpu_values = [x[0] for x in samples]
    rss_values = [x[1] for x in samples]

    avg_cpu = sum(cpu_values) / len(cpu_values)
    
    cpu_sorted = sorted(cpu_values)
    mid = len(cpu_sorted) // 2
    if len(cpu_sorted) % 2 == 1:
        median_cpu = cpu_sorted[mid]
    else:
        median_cpu = (cpu_sorted[mid - 1] + cpu_sorted[mid]) / 2.0
    peak_rss_mb = max(rss_values) / (1024.0 * 1024.0)
    return avg_cpu, median_cpu, peak_rss_mb, len(samples)


def run_with_server_monitoring(attack_func, sample_interval=1.0):
    """
    Runs attack_func() while monitoring the real server process resources.

    Key point:
    - find_server_process() may return a Flask parent process (reloader/launcher).
      If it has children, we switch to the child that actually runs server.py
      (fallback: child with largest RSS).

    Returns dict with attempts/sec and server resource stats.
    """
    server = find_server_process()
    if server is None:
        raise RuntimeError("Server not found. Run: python server.py")

    print(f"Monitoring server process: PID = {server.pid}, name = {server.name()}")

    # If Flask spawned a worker child, switch to the real worker process
    try:
        children = server.children(recursive=True)
    except Exception:
        children = []

    if children:
        server_py_children = []
        for c in children:
            try:
                cmd = " ".join(c.cmdline()).lower()
                if "server.py" in cmd:
                    server_py_children.append(c)
            except Exception:
                pass

        try:
            if server_py_children:
                server = max(server_py_children, key=lambda p: p.memory_info().rss)
            else:
                server = max(children, key=lambda p: p.memory_info().rss)

        except Exception:
            # If switching fails for any reason, continue with the original process
            pass

    samples = []
    stop_event = threading.Event()

    t = threading.Thread(
        target=sample_server_resources,
        args=(server, samples, stop_event, sample_interval)
    )

    start = time.perf_counter()
    t.start()

    # Give the monitor thread time to prime cpu_percent() and take a baseline sample
    time.sleep(sample_interval)
    attack_start = time.perf_counter()
    attempts = attack_func()
    attack_elapsed = time.perf_counter() - attack_start

    stop_event.set()
    t.join()

    avg_cpu, median_cpu, peak_rss_mb, count = summarize_samples(samples)
    attempts_per_sec = attempts / attack_elapsed if attack_elapsed > 0 else 0.0

    return {
        "attempts": attempts,
        "elapsed_seconds": attack_elapsed,
        "attempts_per_second": attempts_per_sec,
        "average_cpu_percent": avg_cpu,
        "median_cpu_percent": median_cpu,
        "peak_rss_mb": peak_rss_mb,
        "samples_count": count,
    }




def split_seconds(elapsed_seconds):
    """Converts elapsed seconds into (hours, minutes, seconds)."""
    hours = int(elapsed_seconds // 3600)
    minutes = int((elapsed_seconds % 3600) // 60)
    seconds = elapsed_seconds % 60
    return hours, minutes, seconds


def print_attack_summary(summary):
    """Prints a summary of the attack performance and server resource usage."""
    hours, minutes, seconds = split_seconds(summary["elapsed_seconds"])
    print(f"Total attempts: {summary['attempts']}")
    print(f"Run time: {hours} Hours, {minutes} Minutes and {seconds:.2f} seconds")
    print(f"Attempts per second: {summary['attempts_per_second']:.2f}")
    print(f"Average CPU usage: {summary['average_cpu_percent']:.2f}%")
    print(f"Median CPU usage: {summary['median_cpu_percent']:.2f}%")
    print(f"Peak RSS Memory usage: {summary['peak_rss_mb']:.2f} MB")
    print(f"Resource samples collected: {summary['samples_count']}")


def get_latency_ms(start):
    return int((time.perf_counter() - start) * MS_IN_SECOND)


