from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, DataTable
from textual.containers import ScrollableContainer
from arcane.runtime import on_event
from arcane.events import NetworkInterfaceEvent

class ArcaneApp(App):
    """A Textual app to manage stopwatches."""

    BINDINGS = [
        ("d", "toggle_dark", "Toggle dark mode"),
        ("`", "command_palette", "Show command palette")
    ]

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        yield Footer()
        yield DataTable(id="top")
        yield Static(id="bottom")


    def action_toggle_dark(self) -> None:
        """An action to toggle dark mode."""
        self.dark = not self.dark


    def add_header(self):
        self.query_one(DataTable).add_columns("Event", "Args", "Kwargs")
    

    @on_event(NetworkInterfaceEvent.READ)
    def add_row(self, iface, proto, data):
        self.query_one(DataTable).add_row(NetworkInterfaceEvent.READ, (iface, data), {})
        


if __name__ == "__main__":
    from arcane.network.interface import NetworkInterface
    eth0 = NetworkInterface("eth0")
    app = ArcaneApp()
    app.run()