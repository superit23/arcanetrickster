from textual.app import ComposeResult
from textual.widgets import Button, Static


class TimeDisplay(Static):
    """A widget to display elapsed time."""


class Stopwatch(Static):
    """A stopwatch widget."""

    def compose(self) -> ComposeResult:
        """Create child widgets of a stopwatch."""
        yield Button("Start", id="start", variant="success")
        yield Button("Stop", id="stop", variant="error")
        yield Button("Reset", id="reset")
        yield TimeDisplay("00:00:00.00")
