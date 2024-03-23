from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static
from textual.containers import ScrollableContainer

class ArcaneApp(App):
    """A Textual app to manage stopwatches."""

    BINDINGS = [("d", "toggle_dark", "Toggle dark mode")]

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        yield Footer()
        yield Static(id="top")
        yield Static(id="bottom")


    def action_toggle_dark(self) -> None:
        """An action to toggle dark mode."""
        self.dark = not self.dark


if __name__ == "__main__":
    app = ArcaneApp()
    app.run()