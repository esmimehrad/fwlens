"""fwlens command line.

fwlens db upgrade                 create / migrate the schema
fwlens load-config FILE [--vendor panos|fortigate]
fwlens load-logs FILE
fwlens load-samples               load every sample config and log in data/samples
"""

import argparse
import logging
from pathlib import Path

from fwlens.db.load import load_config, load_log_file
from fwlens.db.migrate import upgrade_schema
from fwlens.db.session import get_engine
from fwlens.models import Vendor
from fwlens.parsers import parse_config_file
from fwlens.samplegen import SAMPLES


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="fwlens", description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)

    db = commands.add_parser("db", help="database schema")
    db.add_argument("action", choices=["upgrade"])

    config = commands.add_parser("load-config", help="load a firewall config")
    config.add_argument("file", type=Path)
    config.add_argument("--vendor", choices=[v.value for v in Vendor])

    logs = commands.add_parser("load-logs", help="load a traffic log file")
    logs.add_argument("file", type=Path)

    commands.add_parser("load-samples", help="load the sample configs and logs")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    match args.command:
        case "db":
            upgrade_schema()
        case "load-config":
            _load_configs([(args.file, args.vendor)])
        case "load-logs":
            _load_logs([args.file])
        case "load-samples":
            _load_configs([(p, None) for p in sorted(SAMPLES.glob("*/*.xml"))])
            _load_configs([(p, None) for p in sorted(SAMPLES.glob("*/*.conf"))])
            _load_logs(sorted((SAMPLES / "logs").glob("*.log")))


def _load_configs(files: list[tuple[Path, str | None]]) -> None:
    for path, vendor in files:
        config = parse_config_file(path, vendor)
        with get_engine().begin() as conn:
            load_config(conn, config)
        print(
            f"{config.vendor}:{config.device}: {len(config.rules)} rules, "
            f"{len(config.addresses)} addresses, {len(config.services)} services"
        )


def _load_logs(files: list[Path]) -> None:
    for path in files:
        with get_engine().begin() as conn:
            count = load_log_file(conn, path)
        status = "already loaded, skipped" if count is None else f"{count} events"
        print(f"{path.name}: {status}")


if __name__ == "__main__":
    main()
