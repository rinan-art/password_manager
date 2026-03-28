"""
Unlock screen for existing vault.
User enters master password to unlock and access vault.
"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont

from src.presentation.styles import get_dark_stylesheet


class UnlockScreen(QWidget):
    """
    Screen for unlocking an existing vault.
    
    User enters master password which:
    1. Is verified against stored verification hash
    2. Derives encryption key (stored in RAM only)
    3. Unlocks vault for access
    
    SECURITY: Master password never touches storage.
    Key is derived in RAM and wiped on lock.
    """
    
    unlock_success = pyqtSignal()  # Emitted when vault unlocked
    unlock_failed = pyqtSignal()   # Emitted on failed unlock
    
    def __init__(self, vault_service, parent=None):
        super().__init__(parent)
        self.vault_service = vault_service
        
        self.setStyleSheet(get_dark_stylesheet())
        
        self._setup_ui()
        self._connect_signals()
    
    def _setup_ui(self):
        """Set up the user interface."""
        # Main container
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Center container
        center_widget = QWidget()
        center_layout = QVBoxLayout()
        center_layout.setContentsMargins(60, 60, 60, 60)
        center_layout.setSpacing(25)
        
        # Logo/Title
        title = QLabel("🔐 Secure Vault")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)
        center_layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("Enter your master password to unlock")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        center_layout.addWidget(subtitle)
        
        center_layout.addSpacing(30)
        
        # Password input container
        password_frame = QFrame()
        password_frame.setStyleSheet("""
            QFrame {
                background-color: #16213e;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        password_layout = QVBoxLayout()
        password_layout.setSpacing(15)
        
        # Password label
        password_label = QLabel("Master Password:")
        password_label.setStyleSheet("font-weight: bold;")
        password_layout.addWidget(password_label)
        
        # Password input with show/hide
        input_layout = QHBoxLayout()
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your master password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMinimumHeight(50)
        self.password_input.setStyleSheet("font-size: 16px;")
        input_layout.addWidget(self.password_input)
        
        self.show_btn = QPushButton("Show")
        self.show_btn.setObjectName("secondary")
        self.show_btn.setMaximumWidth(70)
        self.show_btn.setMaximumHeight(50)
        input_layout.addWidget(self.show_btn)
        
        password_layout.addLayout(input_layout)
        
        # Error label (hidden by default)
        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: #e74c3c; font-size: 12px;")
        self.error_label.hide()
        password_layout.addWidget(self.error_label)
        
        password_frame.setLayout(password_layout)
        center_layout.addWidget(password_frame)
        
        center_layout.addSpacing(20)
        
        # Unlock button
        self.unlock_btn = QPushButton("🔓 Unlock Vault")
        self.unlock_btn.setMinimumHeight(50)
        self.unlock_btn.setStyleSheet("font-size: 16px;")
        center_layout.addWidget(self.unlock_btn)
        
        # Attempts counter
        self.attempts_label = QLabel("")
        self.attempts_label.setAlignment(Qt.AlignCenter)
        self.attempts_label.setStyleSheet("color: #a0a0a0; font-size: 11px;")
        center_layout.addWidget(self.attempts_label)
        
        center_layout.addStretch()
        
        # Security note
        security_note = QLabel(
            "🔒 Your encryption key is stored in memory only.\n"
            "It will be securely wiped when you lock the vault."
        )
        security_note.setAlignment(Qt.AlignCenter)
        security_note.setStyleSheet("color: #4ecca3; font-size: 11px;")
        center_layout.addWidget(security_note)
        
        center_widget.setLayout(center_layout)
        main_layout.addWidget(center_widget)
        
        self.setLayout(main_layout)
        
        # Set focus to password input
        self.password_input.setFocus()
    
    def _connect_signals(self):
        """Connect signal handlers."""
        self.show_btn.clicked.connect(self._toggle_password_visibility)
        self.unlock_btn.clicked.connect(self._on_unlock)
        self.password_input.returnPressed.connect(self._on_unlock)
    
    def _toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.password_input.echoMode() == QLineEdit.Password:
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.show_btn.setText("Hide")
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.show_btn.setText("Show")
    
    def _on_unlock(self):
        """Handle unlock button click."""
        password = self.password_input.text()
        
        if not password:
            self._show_error("Please enter your master password")
            return
        
        try:
            # Attempt to unlock
            success = self.vault_service.unlock(password)
            
            if success:
                # Clear password from input
                self.password_input.clear()
                self.error_label.hide()
                
                # Emit success signal
                self.unlock_success.emit()
            else:
                self._show_error("Invalid master password")
                self.unlock_failed.emit()
                
        except Exception as e:
            self._show_error(f"Unlock failed: {str(e)}")
    
    def _show_error(self, message: str):
        """Show error message."""
        self.error_label.setText(f"✗ {message}")
        self.error_label.show()
        
        # Clear password
        self.password_input.clear()
        self.password_input.setFocus()
    
    def clear(self):
        """Clear the unlock screen state."""
        self.password_input.clear()
        self.error_label.hide()
        self.password_input.setFocus()
