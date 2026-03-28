"""
Main application window for the Secure Vault.
Orchestrates the initial setup, unlock, and vault screens.
"""
import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QPushButton, QMessageBox,
    QStackedWidget, QStatusBar, QListWidget, QListWidgetItem,
    QDialog, QLineEdit, QComboBox, QTextEdit, QFormLayout,
    QMenu, QInputDialog
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QCursor
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QIcon

from src.presentation.styles import get_dark_stylesheet
from src.presentation.initial_setup import InitialSetupDialog
from src.presentation.unlock_screen import UnlockScreen

from src.application.vault_service import VaultService
from src.infrastructure.database import DatabaseManager
from src.core.crypto import CryptoManager


class EntryForm(QDialog):
    """
    Dialog for creating and editing password entries.
    Supports different entry types: Web, SSH, Notes, Bank, Email, etc.
    """
    def __init__(self, vault_service, entry=None, parent=None):
        super().__init__(parent)
        self.vault_service = vault_service
        self.entry = entry
        self.setWindowTitle("Add New Entry" if not entry else "Edit Entry")
        self.setMinimumSize(400, 500)
        self.setStyleSheet(get_dark_stylesheet())

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(30, 30, 30, 30)

        form_layout = QFormLayout()
        form_layout.setSpacing(10)

        # Title
        self.title_input = QLineEdit()
        self.title_input.setPlaceholderText("Entry title (e.g. Gmail, SSH Server)")
        if self.entry:
            self.title_input.setText(self.entry.title)
        form_layout.addRow("Title:", self.title_input)

        # Type/Category
        self.type_combo = QComboBox()
        self.type_combo.addItems([
            "Web/App", "SSH Key", "Secure Note", "Bank Account",
            "Email Account", "WiFi Password", "Credit Card", "Other"
        ])
        if self.entry:
            self.type_combo.setCurrentText(self.entry.category)
        form_layout.addRow("Type:", self.type_combo)

        # Username
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username or email")
        if self.entry:
            self.username_input.setText(self.entry.username)
        form_layout.addRow("Username:", self.username_input)

        # Password with show/hide button
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        if self.entry:
            # For editing, we'd need to decrypt, but keeping simple for now
            self.password_input.setText("••••••••")

        self.show_password_btn = QPushButton("Show")
        self.show_password_btn.setObjectName("secondary")
        self.show_password_btn.setMaximumWidth(60)

        password_layout = QHBoxLayout()
        password_layout.addWidget(self.password_input)
        password_layout.addWidget(self.show_password_btn)

        form_layout.addRow("Password:", password_layout)

        # URL
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        if self.entry:
            self.url_input.setText(self.entry.url)
        form_layout.addRow("URL:", self.url_input)

        # Notes
        self.notes_input = QTextEdit()
        self.notes_input.setMaximumHeight(100)
        if self.entry:
            self.notes_input.setText(self.entry.notes)
        form_layout.addRow("Notes:", self.notes_input)

        layout.addLayout(form_layout)
        layout.addStretch()

        # Buttons
        button_layout = QHBoxLayout()
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("secondary")
        self.save_btn = QPushButton("Save Entry")

        button_layout.addWidget(self.cancel_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.save_btn)

        layout.addLayout(button_layout)
        self.setLayout(layout)

        # Connect signals
        self.save_btn.clicked.connect(self.accept)
        self.cancel_btn.clicked.connect(self.reject)
        self.show_password_btn.clicked.connect(self._toggle_password_visibility)

    def _toggle_password_visibility(self):
        """Toggle password visibility in the form."""
        if self.password_input.echoMode() == QLineEdit.Password:
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.show_password_btn.setText("Hide")
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.show_password_btn.setText("Show")

    def get_entry_data(self):
        """Return the form data as a dictionary."""
        return {
            'title': self.title_input.text().strip(),
            'category': self.type_combo.currentText(),
            'username': self.username_input.text().strip(),
            'password': self.password_input.text().strip(),
            'url': self.url_input.text().strip(),
            'notes': self.notes_input.toPlainText().strip(),
        }


class EntryDetailDialog(QDialog):
    """
    Dialog to view entry details with 'Show Password' functionality.
    Also provides Edit and Delete options.
    """
    def __init__(self, vault_service, entry_id, parent=None):
        super().__init__(parent)
        self.vault_service = vault_service
        self.entry_id = entry_id
        self.setWindowTitle("Entry Details")
        self.setMinimumSize(450, 400)
        self.setStyleSheet(get_dark_stylesheet())

        self.entry = None
        self._load_entry()
        self._setup_ui()

    def _load_entry(self):
        """Load the entry data."""
        try:
            self.entry = self.vault_service.get_decrypted_entry(self.entry_id)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not load entry: {str(e)}")

    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(30, 30, 30, 30)

        if not self.entry:
            error_label = QLabel("Could not load entry details.")
            layout.addWidget(error_label)
            self.setLayout(layout)
            return

        # Entry info
        info_layout = QFormLayout()
        info_layout.setSpacing(10)

        info_layout.addRow("Title:", QLabel(self.entry.title))
        info_layout.addRow("Type:", QLabel(self.entry.category))
        info_layout.addRow("Username:", QLabel(self.entry.username or "—"))
        info_layout.addRow("URL:", QLabel(self.entry.url or "—"))
        info_layout.addRow("Notes:", QLabel(self.entry.notes or "—"))

        layout.addLayout(info_layout)

        # Password section
        password_group = QVBoxLayout()
        password_label = QLabel("Password:")
        password_label.setStyleSheet("font-weight: bold;")
        password_group.addWidget(password_label)

        self.password_display = QLineEdit()
        self.password_display.setEchoMode(QLineEdit.Password)
        self.password_display.setText("••••••••••••")
        self.password_display.setReadOnly(True)
        password_group.addWidget(self.password_display)

        button_layout = QHBoxLayout()
        self.show_password_btn = QPushButton("👁️ Show Password")
        self.show_password_btn.clicked.connect(self._toggle_password_visibility)
        self.copy_btn = QPushButton("📋 Copy")
        self.copy_btn.clicked.connect(self._copy_password)

        button_layout.addWidget(self.show_password_btn)
        button_layout.addWidget(self.copy_btn)
        password_group.addLayout(button_layout)

        layout.addLayout(password_group)

        # Action buttons
        actions_layout = QHBoxLayout()
        self.edit_btn = QPushButton("✏️ Edit")
        self.edit_btn.clicked.connect(self._edit_entry)
        self.delete_btn = QPushButton("🗑️ Delete")
        self.delete_btn.setObjectName("danger")
        self.delete_btn.clicked.connect(self._delete_entry)

        actions_layout.addWidget(self.edit_btn)
        actions_layout.addWidget(self.delete_btn)
        layout.addLayout(actions_layout)

        self.setLayout(layout)

    def _toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.password_display.echoMode() == QLineEdit.Password:
            try:
                password = self.vault_service.get_decrypted_password(self.entry_id)
                self.password_display.setText(password)
                self.password_display.setEchoMode(QLineEdit.Normal)
                self.show_password_btn.setText("🙈 Hide Password")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not decrypt password: {str(e)}")
        else:
            self.password_display.setText("••••••••••••")
            self.password_display.setEchoMode(QLineEdit.Password)
            self.show_password_btn.setText("👁️ Show Password")

    def _copy_password(self):
        """Copy password to clipboard."""
        try:
            password = self.vault_service.get_decrypted_password(self.entry_id)
            clipboard = QApplication.clipboard()
            clipboard.setText(password)
            QMessageBox.information(self, "Copied", "Password copied to clipboard!")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not copy password: {str(e)}")

    def _edit_entry(self):
        """Edit this entry."""
        dialog = EntryForm(self.vault_service, self.entry, self)
        if dialog.exec_() == QDialog.Accepted:
            data = dialog.get_entry_data()
            try:
                self.vault_service.update_entry(
                    self.entry_id,
                    title=data['title'],
                    password=data['password'] if data['password'] and data['password'] != "••••••••" else None,
                    username=data['username'],
                    url=data['url'],
                    notes=data['notes'],
                    category=data['category']
                )
                QMessageBox.information(self, "Success", "Entry updated successfully!")
                self.accept()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to update entry: {str(e)}")

    def _delete_entry(self):
        """Delete this entry."""
        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Delete entry '{self.entry.title}'?\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            try:
                self.vault_service.delete_entry(self.entry_id)
                QMessageBox.information(self, "Deleted", "Entry deleted successfully!")
                self.accept()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete entry: {str(e)}")


class VaultHomeScreen(QWidget):
    """
    Main vault home screen showing list of password entries.
    Supports different entry types and entry management.
    """

    lock_requested = pyqtSignal()  # Signal for locking the vault

    def __init__(self, vault_service, parent=None):
        super().__init__(parent)
        self.vault_service = vault_service

        self.setStyleSheet(get_dark_stylesheet())
        self._setup_ui()
        self._load_entries()

    def _setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        # Header
        header = QHBoxLayout()

        title = QLabel("🔐 Secure Vault")
        title.setObjectName("title")
        header.addWidget(title)

        header.addStretch()

        # Add Entry button
        self.add_btn = QPushButton("➕ Add Entry")
        self.add_btn.clicked.connect(self._show_add_entry_dialog)
        header.addWidget(self.add_btn)

        # Lock button
        self.lock_btn = QPushButton("🔒 Lock")
        self.lock_btn.setObjectName("secondary")
        self.lock_btn.clicked.connect(self._on_lock)
        header.addWidget(self.lock_btn)

        layout.addLayout(header)

        # Search
        search_layout = QHBoxLayout()
        search_label = QLabel("🔍")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search entries...")
        self.search_input.textChanged.connect(self._filter_entries)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        layout.addLayout(search_layout)

        # Entries list
        self.entries_list = QListWidget()
        self.entries_list.itemDoubleClicked.connect(self._on_entry_double_clicked)
        self.entries_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.entries_list.customContextMenuRequested.connect(self._show_context_menu)
        layout.addWidget(self.entries_list)

        # Status
        self.status_label = QLabel("No entries yet. Click 'Add Entry' to get started.")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #a0a0a0; font-style: italic;")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def _load_entries(self):
        """Load and display all entries."""
        try:
            entries = self.vault_service.get_all_entries()
            self.entries_list.clear()

            if not entries:
                self.status_label.setText("No entries yet. Click 'Add Entry' to get started.")
                return

            for entry in entries:
                # Show title (even if encrypted, we can show basic info)
                # In a real app, we'd decrypt on demand for the list view
                item_text = f"🔑 {entry.title or 'Untitled'}"
                if entry.username:
                    item_text += f" • {entry.username}"

                item = QListWidgetItem(item_text)
                item.setData(Qt.UserRole, entry.id)  # Store ID for later use
                self.entries_list.addItem(item)

            self.status_label.setText(f"{len(entries)} entries • Vault unlocked")

        except Exception as e:
            self.status_label.setText(f"Error loading entries: {str(e)}")

    def _show_add_entry_dialog(self):
        """Show dialog to add a new entry."""
        dialog = EntryForm(self.vault_service, parent=self)
        if dialog.exec_() == QDialog.Accepted:
            data = dialog.get_entry_data()

            if not data['title']:
                QMessageBox.warning(self, "Error", "Title is required")
                return

            try:
                # Create the entry
                self.vault_service.create_entry(
                    title=data['title'],
                    password=data['password'],
                    username=data['username'],
                    url=data['url'],
                    notes=data['notes'],
                    category=data['category']
                )

                # Refresh the list
                self._load_entries()

                QMessageBox.information(self, "Success", "Entry created successfully!")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to create entry: {str(e)}")

    def _on_entry_double_clicked(self, item):
        """Handle double-click on an entry - show detailed view."""
        entry_id = item.data(Qt.UserRole)
        if not entry_id:
            return

        dialog = EntryDetailDialog(self.vault_service, entry_id, self)
        dialog.exec_()
        # Refresh list in case entry was edited or deleted
        self.refresh()

    def _show_context_menu(self, position):
        """Show context menu for entries."""
        item = self.entries_list.itemAt(position)
        if not item:
            return

        entry_id = item.data(Qt.UserRole)
        if not entry_id:
            return

        menu = QMenu()
        view_action = menu.addAction("👁️ View Details")
        edit_action = menu.addAction("✏️ Edit")
        delete_action = menu.addAction("🗑️ Delete")

        action = menu.exec_(QCursor.pos())

        if action == view_action:
            dialog = EntryDetailDialog(self.vault_service, entry_id, self)
            dialog.exec_()
        elif action == edit_action:
            entry = self.vault_service.get_decrypted_entry(entry_id)
            dialog = EntryForm(self.vault_service, entry, self)
            if dialog.exec_() == QDialog.Accepted:
                data = dialog.get_entry_data()
                try:
                    self.vault_service.update_entry(
                        entry_id,
                        title=data['title'],
                        password=data['password'] if data['password'] and data['password'] != "••••••••" else None,
                        username=data['username'],
                        url=data['url'],
                        notes=data['notes'],
                        category=data['category']
                    )
                    QMessageBox.information(self, "Success", "Entry updated successfully!")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to update entry: {str(e)}")
        elif action == delete_action:
            reply = QMessageBox.question(
                self, "Confirm Delete",
                f"Delete this entry?\nThis action cannot be undone.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                try:
                    self.vault_service.delete_entry(entry_id)
                    QMessageBox.information(self, "Deleted", "Entry deleted successfully!")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to delete entry: {str(e)}")

        # Refresh the list
        self.refresh()

    def _filter_entries(self, query):
        """Filter entries based on search query."""
        # Simple client-side filtering for now
        query = query.lower().strip()
        if not query:
            self._load_entries()
            return

        # In a real implementation, we'd use the search functionality
        # For now, just reload (could be optimized)
        self._load_entries()

    def _on_lock(self):
        """Handle lock button click."""
        self.lock_requested.emit()

    def refresh(self):
        """Refresh the entries list."""
        self._load_entries()


class SecureVaultApp(QMainWindow):
    """
    Main application window for the Secure Vault.
    
    Flow:
    1. App starts
    2. Check if vault is initialized (has metadata)
    3. If not: Show initial setup dialog
    4. If yes: Show unlock screen
    5. When unlocked: Show main vault UI
    
    SECURITY:
    - Keys stored only in RAM
    - Keys wiped on lock
    - Plaintext passwords never stored
    """
    
    def __init__(self):
        super().__init__()
        
        # Initialize services
        self.db_manager = DatabaseManager()
        self.crypto_manager = CryptoManager()
        self.vault_service = VaultService(
            db_manager=self.db_manager,
            crypto_manager=self.crypto_manager
        )
        
        # UI setup
        self.setWindowTitle("Secure Vault")
        self.setMinimumSize(800, 600)
        self.setStyleSheet(get_dark_stylesheet())
        
        self._setup_ui()
        self._connect_signals()
        
        # Check initial state
        self._check_initial_state()
    
    def _setup_ui(self):
        """Set up the main UI."""
        # Central widget with stacked layout
        central = QWidget()
        self.setCentralWidget(central)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Stacked widget for different screens
        self.stacked = QStackedWidget()
        
        # Create screens
        self.unlock_screen = UnlockScreen(self.vault_service)
        self.home_screen = VaultHomeScreen(self.vault_service)

        # Connect home screen lock signal
        self.home_screen.lock_requested.connect(self._on_lock)

        self.stacked.addWidget(self.unlock_screen)
        self.stacked.addWidget(self.home_screen)
        
        layout.addWidget(self.stacked)
        
        central.setLayout(layout)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Vault locked - Enter master password to unlock")
    
    def _connect_signals(self):
        """Connect signal handlers."""
        # Unlock screen signals
        self.unlock_screen.unlock_success.connect(self._on_unlock_success)
        self.unlock_screen.unlock_failed.connect(self._on_unlock_failed)
    
    def _check_initial_state(self):
        """Check if vault is initialized and show appropriate screen."""
        if not self.vault_service.is_initialized:
            # First time - show initial setup
            self._show_initial_setup()
        else:
            # Existing vault - show unlock screen
            self.stacked.setCurrentWidget(self.unlock_screen)
            self.status_bar.showMessage("Vault locked - Enter master password to unlock")
    
    def _show_initial_setup(self):
        """Show initial setup dialog."""
        dialog = InitialSetupDialog(self)
        dialog.setup_complete.connect(self._on_initial_setup_complete)
        
        result = dialog.exec_()
        
        if result == InitialSetupDialog.Accepted:
            # Setup complete, now show unlock
            self.stacked.setCurrentWidget(self.unlock_screen)
        else:
            # User cancelled - exit app
            self.close()
    
    def _on_initial_setup_complete(self, master_password: str):
        """
        Handle initial vault setup completion.

        SECURITY: Master password is used only to derive key,
        never stored anywhere.
        """
        try:
            # Initialize new vault (this also unlocks it)
            self.vault_service.initialize_new_vault(master_password)

            # Clear password from memory
            master_password = None

            QMessageBox.information(
                self,
                "Vault Created",
                "✅ Your secure vault has been created!\n\n"
                "Your master password was used to derive an encryption key.\n"
                "This key is stored in RAM only and will be wiped when you lock."
            )

            # Since initialize_new_vault() already unlocked the vault,
            # switch directly to the home screen and load entries
            self.stacked.setCurrentWidget(self.home_screen)
            self.home_screen.refresh()
            self.status_bar.showMessage("✅ Vault unlocked - Encryption key in RAM")

        except Exception as e:
            QMessageBox.critical(
                self,
                "Setup Failed",
                f"Failed to create vault: {str(e)}"
            )
            self.close()
    
    def _on_unlock_success(self):
        """Handle successful vault unlock."""
        # Switch to home screen and refresh entries
        self.stacked.setCurrentWidget(self.home_screen)
        self.home_screen.refresh()  # Load entries from database
        self.status_bar.showMessage("✅ Vault unlocked - Encryption key in RAM")
    
    def _on_unlock_failed(self):
        """Handle failed unlock attempt."""
        self.status_bar.showMessage("❌ Unlock failed - Invalid password", 3000)
    
    def _on_lock(self):
        """Handle lock request."""
        reply = QMessageBox.question(
            self,
            "Lock Vault",
            "Lock the vault?\n\n"
            "Your encryption key will be securely wiped from memory.\n"
            "You will need to enter your master password to unlock again.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )
        
        if reply == QMessageBox.Yes:
            self.vault_service.lock()
            self.unlock_screen.clear()
            self.stacked.setCurrentWidget(self.unlock_screen)
            self.status_bar.showMessage("🔒 Vault locked - Key wiped from memory")
    
    def closeEvent(self, event):
        """
        Handle application close.
        
        SECURITY: Ensure vault is locked (keys wiped) before exit.
        """
        if self.vault_service.is_unlocked:
            self.vault_service.lock()
        
        self.vault_service.close()
        event.accept()


def run_app():
    """Run the Secure Vault application."""
    app = QApplication(sys.argv)
    app.setApplicationName("Secure Vault")
    app.setStyle('Fusion')
    
    window = SecureVaultApp()
    window.show()
    
    sys.exit(app.exec_())
