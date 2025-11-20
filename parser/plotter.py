import matplotlib.pyplot as plt

def plot_status_codes(status_counts):
    labels = [str(code) for code, _ in status_counts]
    values = [count for _, count in status_counts]

    plt.figure()
    plt.bar(labels, values)
    plt.title("HTTP Status Code Distribution")
    plt.xlabel("Status Code")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.show()


def plot_top_ips(top_ips):
    labels = [ip for ip, _ in top_ips]
    values = [count for _, count in top_ips]

    plt.figure()
    plt.bar(labels, values)
    plt.title("Top IP Addresses")
    plt.xlabel("IP Address")
    plt.ylabel("Requests")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()


def plot_top_urls(top_urls):
    labels = [url for url, _ in top_urls]
    values = [count for _, count in top_urls]

    plt.figure()
    plt.bar(labels, values)
    plt.title("Top Requested URLs")
    plt.xlabel("URL")
    plt.ylabel("Hits")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()


def plot_all(summary, log_type=None):
    """
    Smart plot handler.
    Only generates plots relevant to the log type.
    """

    # Apache → Status codes exist
    if log_type == "apache" and summary.get("status_counts"):
        plot_status_codes(summary["status_counts"])
    else:
        print("[INFO] Skipping status code plot (not applicable).")

    # Both logs → IP plot always relevant
    if summary.get("top_ips"):
        plot_top_ips(summary["top_ips"])
    else:
        print("[INFO] No IP data to plot.")

    # Apache → URLs exist
    if log_type == "apache" and summary.get("top_urls"):
        plot_top_urls(summary["top_urls"])
    else:
        print("[INFO] Skipping URL plot (not applicable).")
