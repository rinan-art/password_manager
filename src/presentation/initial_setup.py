"""
Initial setup dialog for first-time vault creation.
User sets their master password and the app initializes the database.
"""
import re
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QProgressBar, QMessageBox, QWidget
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QIcon

from src.presentation.styles import get_dark_stylesheet, get_password_strength_stylesheet


class InitialSetupDialog(QDialog):
    """
    Dialog for initial vault setup.
    
    User creates their master password which will be used to:
    1. Derive the encryption key
    2. Create verification hash (stored in DB)
    3. Initialize the SQLite database
    
    SECURITY: Master password never touches storage.
    """
    
    setup_complete = pyqtSignal(str)  # Emits master password when setup done
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Secure Vault - Initial Setup")
        self.setMinimumSize(450, 550)
        self.setModal(True)
        
        # Apply dark theme
        self.setStyleSheet(get_dark_stylesheet())
        
        self._setup_ui()
        self._connect_signals()
    
    def _setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(40, 40, 40, 40)
        
        # Title
        title = QLabel("🔐 Secure Vault")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("Create your master password to get started")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)
        
        # Warning
        warning = QLabel(
            "⚠️ Your master password cannot be recovered!\n"
            "Make sure to remember it or store it securely."
        )
        warning.setObjectName("warning")
        warning.setAlignment(Qt.AlignCenter)
        warning.setWordWrap(True)
        layout.addWidget(warning)
        
        layout.addSpacing(20)
        
        # Master password input
        password_label = QLabel("Master Password:")
        password_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(password_label)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your master password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMinimumHeight(45)
        layout.addWidget(self.password_input)
        
        # Show/hide password button
        self.show_password_btn = QPushButton("Show")
        self.show_password_btn.setObjectName("secondary")
        self.show_password_btn.setMaximumWidth(80)
        self.show_password_btn.setMaximumHeight(30)
        
        password_layout = QHBoxLayout()
        password_layout.addWidget(self.password_input)
        password_layout.addWidget(self.show_password_btn)
        layout.addLayout(password_layout)
        
        # Password strength indicator
        strength_label = QLabel("Password Strength:")
        strength_label.setStyleSheet("font-size: 11px; color: #a0a0a0;")
        layout.addWidget(strength_label)
        
        self.strength_bar = QProgressBar()
        self.strength_bar.setMaximum(4)
        self.strength_bar.setValue(0)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setMinimumHeight(10)
        layout.addWidget(self.strength_bar)
        
        self.strength_text = QLabel("Enter a password")
        self.strength_text.setStyleSheet("font-size: 11px; color: #a0a0a0;")
        layout.addWidget(self.strength_text)
        
        layout.addSpacing(10)
        
        # Confirm password input
        confirm_label = QLabel("Confirm Master Password:")
        confirm_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(confirm_label)
        
        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Confirm your master password")
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.confirm_input.setMinimumHeight(45)
        layout.addWidget(self.confirm_input)
        
        # Match indicator
        self.match_label = QLabel("")
        self.match_label.setStyleSheet("font-size: 11px;")
        layout.addWidget(self.match_label)
        
        layout.addSpacing(20)
        
        # Requirements
        requirements = QLabel(
            "Requirements:\n"
            "• At least 8 characters\n"
            "• Mix of letters and numbers recommended\n"
            "• Special characters add strength"
        )
        requirements.setStyleSheet("font-size: 11px; color: #a0a0a0;")
        requirements.setWordWrap(True)
        layout.addWidget(requirements)
        
        layout.addStretch()
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("secondary")
        
        self.create_btn = QPushButton("Create Vault")
        self.create_btn.setEnabled(False)
        
        button_layout.addWidget(self.cancel_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.create_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def _connect_signals(self):
        """Connect signal handlers."""
        self.show_password_btn.clicked.connect(self._toggle_password_visibility)
        self.password_input.textChanged.connect(self._on_password_changed)
        self.confirm_input.textChanged.connect(self._on_confirm_changed)
        self.create_btn.clicked.connect(self._on_create)
        self.cancel_btn.clicked.connect(self.reject)
    
    def _toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.password_input.echoMode() == QLineEdit.Password:
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.show_password_btn.setText("Hide")
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.show_password_btn.setText("Show")
    
    def _calculate_strength(self, password: str) -> int:
        """
        Calculate password strength (0-4).
        
        Returns:
            Strength level 0-4
        """
        if not password:
            return 0
        
        strength = 0
        
        # Length check
        if len(password) >= 8:
            strength += 1
        if len(password) >= 12:
            strength += 1
        
        # Character variety
        if re.search(r'[a-z]', password) and re.search(r'[A-Z]', password):
            strength += 1
        if re.search(r'\d', password):
            strength += 1
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            strength += 1
        
        return min(strength, 4)
    
    def _on_password_changed(self, password: str):
        """Handle password input change."""
        strength = self._calculate_strength(password)
        self.strength_bar.setValue(strength)
        
        # Update strength text
        strength_texts = {
            0: "Enter a password",
            1: "Weak",
            2: "Fair",
            3: "Strong",
            4: "Very Strong",
        }
        self.strength_text.setText(strength_texts.get(strength, "Unknown"))
        
        # Update strength bar color
        self.strength_bar.setStyleSheet(get_password_strength_stylesheet(strength))
        
        # Check match
        self._check_match()
        self._update_create_button()
    
    def _on_confirm_changed(self, confirm: str):
        """Handle confirm input change."""
        self._check_match()
        self._update_create_button()
    
    def _check_match(self):
        """Check if passwords match."""
        password = self.password_input.text()
        confirm = self.confirm_input.text()
        
        if not confirm:
            self.match_label.setText("")
            self.match_label.setStyleSheet("font-size: 11px;")
        elif password == confirm:
            self.match_label.setText("✓ Passwords match")
            self.match_label.setStyleSheet("font-size: 11px; color: #4ecca3;")
        else:
            self.match_label.setText("✗ Passwords do not match")
            self.match_label.setStyleSheet("font-size: 11px; color: #e74c3c;")
    
    def _update_create_button(self):
        """Enable/disable create button based on validation."""
        password = self.password_input.text()
        confirm = self.confirm_input.text()
        
        is_valid = (
            len(password) >= 8 and
            password == confirm
        )
        
        self.create_btn.setEnabled(is_valid)
    
    def _on_create(self):
        """Handle create vault button click."""
        password = self.password_input.text()
        confirm = self.confirm_input.text()
        
        # Validation
        if len(password) < 8:
            QMessageBox.warning(
                self,
                "Invalid Password",
                "Master password must be at least 8 characters."
            )
            return
        
        if password != confirm:
            QMessageBox.warning(
                self,
                "Password Mismatch",
                "Passwords do not match."
            )
            return
        
        # Show confirmation dialog
        reply = QMessageBox.question(
            self,
            "Confirm Master Password",
            "Have you saved your master password securely?\n\n"
            "⚠️ You will NOT be able to recover it if lost!\n\n"
            "Proceed with vault creation?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.setup_complete.emit(password)
            self.accept()
    
    def get_password(self) -> str:
        """Get the entered password."""
        return self.password_input.text()
