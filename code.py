import re
import sys
import csv


log_pattern = re.compile(
    r"^(\w{3})\s+(\d+)\s+(\d+:\d+:\d+)\s+(\S+)\s+([A-Za-z0-9_.-]+)(?:\[(\d+)\])?:\s+(.*)$"
)


def parse_line(line):
    match = log_pattern.match(line)

    if match is None:
        return None

    month = match.group(1)
    day = match.group(2)
    clock = match.group(3)
    program = match.group(5)
    pid = match.group(6)
    message = match.group(7)

    event = {
        "timestamp": month + " " + day + " " + clock,
        "source_ip": "",
        "username": "",
        "event_type": "",
        "status": "",
        "pid": pid if pid else "",
        "port": ""
    }

    parts = message.split()

    # SSH successful login
    if "Accepted" in message:
        try:
            event["username"] = parts[3]
            event["source_ip"] = parts[5]
            event["port"] = parts[7]
            event["event_type"] = "SSH authentication"
            event["status"] = "Success"
        except IndexError:
            return None

    # SSH failed login
    elif "Failed" in message:
        try:
            if parts[3] == "invalid":
                event["username"] = parts[5]
                event["source_ip"] = parts[7]
                event["port"] = parts[9]
            else:
                event["username"] = parts[3]
                event["source_ip"] = parts[5]
                event["port"] = parts[7]

            event["event_type"] = "SSH authentication"
            event["status"] = "Failure"

        except IndexError:
            return None

    # sudo command
    elif program == "sudo" and "COMMAND=" in message:
        try:
            event["username"] = parts[0]
            event["event_type"] = "sudo command execution"
            event["status"] = "Success"

        except IndexError:
            return None

    # PAM session opened
    elif "session opened for user" in message:
        try:
            i = parts.index("user")
            event["username"] = parts[i + 1].split("(")[0]
            event["event_type"] = "Session open"
            event["status"] = "Success"

        except (ValueError, IndexError):
            return None

    # PAM session closed
    elif "session closed for user" in message:
        try:
            i = parts.index("user")
            event["username"] = parts[i + 1]
            event["event_type"] = "Session close"
            event["status"] = "Success"

        except (ValueError, IndexError):
            return None

    else:
        return None

    return event


def read_log(filename):
    events = []

    try:
        file = open(filename, "r")

    except FileNotFoundError:
        print("Error: file was not found.")
        return events

    except PermissionError:
        print("Error: permission denied.")
        return events

    for line in file:
        event = parse_line(line)

        if event is not None:
            events.append(event)

    file.close()

    return events


def show_summary(events):
    total = 0
    success = 0
    failure = 0

    usernames = {}
    ips = {}

    for event in events:

        if event["event_type"] == "SSH authentication":

            total += 1

            if event["status"] == "Success":
                success += 1
            else:
                failure += 1

            user = event["username"]
            ip = event["source_ip"]

            if user in usernames:
                usernames[user] += 1
            else:
                usernames[user] = 1

            if ip in ips:
                ips[ip] += 1
            else:
                ips[ip] = 1

    print("\n----- AUTHENTICATION LOG SUMMARY -----")

    print("Total login attempts:", total)
    print("Successful attempts :", success)
    print("Failed attempts     :", failure)

    print("\nTop targeted usernames:")

    top_users = sorted(
        usernames.items(),
        key=lambda x: x[1],
        reverse=True
    )

    for user, count in top_users[:5]:
        print(user, ":", count)

    print("\nTop source IP addresses:")

    top_ips = sorted(
        ips.items(),
        key=lambda x: x[1],
        reverse=True
    )

    for ip, count in top_ips[:5]:
        print(ip, ":", count)


def show_brute_force(events):
    failed_ips = {}

    for event in events:

        if event["event_type"] == "SSH authentication":

            if event["status"] == "Failure":

                ip = event["source_ip"]

                if ip in failed_ips:
                    failed_ips[ip] += 1
                else:
                    failed_ips[ip] = 1

    print("\n----- POSSIBLE BRUTE FORCE ATTACKS -----")

    found = False

    for ip in failed_ips:

        if failed_ips[ip] >= 5:

            print(
                "IP:", ip,
                "| Failed attempts:", failed_ips[ip],
                "| Warning: Possible brute force attack"
            )

            found = True

    if found == False:
        print("No possible brute force attacks detected.")


def show_events(events):
    print("\n----- PARSED EVENTS -----")

    print(
        f"{'Timestamp':<19} "
        f"{'Source IP':<16} "
        f"{'Username':<10} "
        f"{'Event Type':<22} "
        f"{'Status':<9} "
        f"{'PID':<6} "
        f"{'Port':<6}"
    )

    print("-" * 95)

    for event in events:

        source_ip = event["source_ip"] if event["source_ip"] else "-"
        port = event["port"] if event["port"] else "-"

        print(
            f"{event['timestamp']:<19} "
            f"{source_ip:<16} "
            f"{event['username']:<10} "
            f"{event['event_type']:<22} "
            f"{event['status']:<9} "
            f"{event['pid']:<6} "
            f"{port:<6}"
        )


def save_csv(events, filename):
    file = open(filename, "w", newline="")

    writer = csv.writer(file)

    writer.writerow([
        "Timestamp",
        "Source IP",
        "Username",
        "Event Type",
        "Status",
        "PID",
        "Port"
    ])

    for event in events:

        writer.writerow([
            event["timestamp"],
            event["source_ip"],
            event["username"],
            event["event_type"],
            event["status"],
            event["pid"],
            event["port"]
        ])

    file.close()

    print("\nCSV file created:", filename)


def main():

    if len(sys.argv) < 2:
        print("Usage: python auth_log_parser.py <logfile>")
        return

    events = read_log(sys.argv[1])

    if len(events) == 0:
        print("No authentication events were found.")
        return

    show_events(events)

    show_summary(events)

    show_brute_force(events)

    save_csv(events, "output.csv")


main()
