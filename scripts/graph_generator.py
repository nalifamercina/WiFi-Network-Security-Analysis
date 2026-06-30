import os
import matplotlib.pyplot as plt


IMAGE_FOLDER = "images"


def save_bar_chart(title, labels, values, filename):

    os.makedirs(IMAGE_FOLDER, exist_ok=True)

    plt.figure(figsize=(14, 7))
    plt.barh(labels, values)
    plt.title(title)

    plt.xlabel("Category")
    plt.ylabel("Count")

    plt.xticks(rotation=60, ha="right", fontsize=8)

    plt.tight_layout()
    plt.grid(axis="y", linestyle="--", alpha=0.5)

    filepath = os.path.join(IMAGE_FOLDER, filename)

    plt.savefig(filepath)

    plt.close()

    print(f"✓ Graph Generated : {filepath}")