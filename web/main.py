try:
    from .ui import launch
except ImportError:
    from ui import launch


def main() -> int:
    return launch()


if __name__ == "__main__":
    raise SystemExit(main())

