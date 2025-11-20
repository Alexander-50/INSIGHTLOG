import time
import os

def follow_log(path):
    

    def open_file(p):
        f = open(p, "r", errors="ignore")
        st = os.fstat(f.fileno())
        return f, st.st_ino

    f, inode = open_file(path)
    f.seek(0, os.SEEK_END)

    print(f"[LIVE] Started monitoring {path}")

    while True:
        line = f.readline()

        if not line:
            time.sleep(0.25)

            # Check file rotation (inode changed)
            try:
                st = os.stat(path)
                if st.st_ino != inode:
                    print("[LIVE] Log rotation detected. Reopening file...")
                    f.close()
                    f, inode = open_file(path)
            except FileNotFoundError:
                # file temporarily missing during rotation
                pass

            continue

        yield line


def start_live_monitor(path, parser_func, process_record_callback):
    """
    Reads log lines in real time, parsing and processing each.
    """
    print(f"[LIVE] Monitoring {path} (Ctrl+C to stop)")

    try:
        for line in follow_log(path):
            record = parser_func(line)
            if record:
                process_record_callback(record)

    except KeyboardInterrupt:
        print("\n[LIVE] Monitoring stopped.")
