"""
Refreshes safe words datasets for name-fallback PII redaction.
Downloads world cities and builds US states list.
Designed to run in the background so it doesn't block user requests.
"""

import logging
import requests
from pathlib import Path

# --- Centralized logging config ---
LOG_FILE = Path("logs/app.log")
LOG_FILE.parent.mkdir(exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(module)s] %(message)s",
)

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

WORLD_CITIES_URL = (
    "https://simplemaps.com/static/data/world-cities/basic/simplemaps_worldcities_basicv1.75/worldcities.csv"
)

def fetch_world_cities():
    logging.info("Fetching world cities...")
    r = requests.get(WORLD_CITIES_URL, timeout=30)
    r.raise_for_status()
    cities = set()
    for line in r.text.splitlines()[1:]:  # skip header
        city = line.split(",")[0].strip()
        if city:
            cities.add(city)
    logging.info(f"Loaded {len(cities):,} cities.")
    return sorted(cities)

def fetch_us_states():
    logging.info("Loading US states list...")
    return sorted([
        "Alabama", "Alaska", "Arizona", "Arkansas", "California", "Colorado",
        "Connecticut", "Delaware", "Florida", "Georgia", "Hawaii", "Idaho",
        "Illinois", "Indiana", "Iowa", "Kansas", "Kentucky", "Louisiana",
        "Maine", "Maryland", "Massachusetts", "Michigan", "Minnesota",
        "Mississippi", "Missouri", "Montana", "Nebraska", "Nevada",
        "New Hampshire", "New Jersey", "New Mexico", "New York",
        "North Carolina", "North Dakota", "Ohio", "Oklahoma", "Oregon",
        "Pennsylvania", "Rhode Island", "South Carolina", "South Dakota",
        "Tennessee", "Texas", "Utah", "Vermont", "Virginia", "Washington",
        "West Virginia", "Wisconsin", "Wyoming"
    ])

def save_list(filename, items):
    Path(filename).write_text("\n".join(items), encoding="utf-8")
    logging.info(f"Saved {len(items):,} entries to {filename}")

if __name__ == "__main__":
    try:
        cities = fetch_world_cities()
        save_list(DATA_DIR / "world_cities.txt", cities)

        states = fetch_us_states()
        save_list(DATA_DIR / "us_states.txt", states)

        logging.info("Safe words refresh complete ✅")
    except Exception as e:
        logging.error(f"Safe words refresh failed ❌: {e}", exc_info=True)
