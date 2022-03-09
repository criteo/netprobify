"""Common configuration parameters."""

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "format_handler": {
            "format": 'module="%(name)s" level="%(levelname)s" message="%(message)s"'
        }
    },
    "handlers": {
        "stream_handler": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
            "formatter": "format_handler",
        }
    },
    "loggers": {
        "": {"level": "INFO", "handlers": ["stream_handler"], "propagate": "false"},
        "scapy.runtime": {"level": "ERROR"},
        "pykwalify.core": {"level": "WARNING"},
        "tornado.access": {"level": "WARNING"},
    },
}

DEFAULT_ADDRESS_FAMILY = "ipv4"
