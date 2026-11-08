import argparse
import json
import logging
import os
import stat
from pathlib import Path

from labctl.db.config import DEFAULT_CLASSES, DEFAULT_DB_PATH, get_engine, metadata, seed_classes_and_subnets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Inizializza il database SQLite per LabCtl / fwdd")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help="Percorso del file SQLite")
    parser.add_argument("--classes-json", help="File JSON opzionale con le definizioni delle classi")
    args = parser.parse_args()

    db_file = Path(args.db)
    db_file.parent.mkdir(parents=True, exist_ok=True)

    engine = get_engine(str(db_file))
    logger.info("Creazione/verifica tabelle in %s...", db_file)
    metadata.create_all(engine)

    class_defs = DEFAULT_CLASSES
    if args.classes_json:
        with open(args.classes_json, "r", encoding="utf-8") as f:
            class_defs = json.load(f)

    seed_classes_and_subnets(engine, class_defs)

    # Imposta permessi restrittivi 0660 sul file DB e sui file WAL/SHM
    for suffix in ("", "-wal", "-shm"):
        p = Path(f"{db_file}{suffix}")
        if p.exists():
            os.chmod(p, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)

    logger.info("Inizializzazione completata con successo.")


if __name__ == "__main__":
    main()
