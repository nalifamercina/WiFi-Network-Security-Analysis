import csv
import os


REPORT_FOLDER = "reports"


def save_csv(filename, headers, rows):

    os.makedirs(REPORT_FOLDER, exist_ok=True)

    filepath = os.path.join(REPORT_FOLDER, filename)

    with open(filepath, "w", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        writer.writerow(headers)

        writer.writerows(rows)

    print(f"✓ Generated: {filepath}")