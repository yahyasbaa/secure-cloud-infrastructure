"""WSGI entry point used by gunicorn."""

from .logging_setup import configure_logging
from .main import create_app

configure_logging()
app = create_app()
