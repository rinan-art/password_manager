"""
UI Styles and theming for the password vault.
Provides a clean, modern dark theme for security-focused UI.
"""


# Dark theme colors
COLORS = {
    'bg_primary': '#1a1a2e',
    'bg_secondary': '#16213e',
    'bg_tertiary': '#0f3460',
    'text_primary': '#eaeaea',
    'text_secondary': '#a0a0a0',
    'accent': '#e94560',
    'accent_hover': '#ff6b6b',
    'success': '#4ecca3',
    'warning': '#ffc107',
    'error': '#e74c3c',
    'border': '#2a2a4a',
    'input_bg': '#1e1e3f',
}


def get_dark_stylesheet() -> str:
    """Return the dark theme stylesheet."""
    return f"""
        /* Global styles */
        QMainWindow, QWidget {{
            background-color: {COLORS['bg_primary']};
            color: {COLORS['text_primary']};
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 13px;
        }}
        
        /* Labels */
        QLabel {{
            color: {COLORS['text_primary']};
            padding: 2px;
        }}
        
        QLabel#title {{
            font-size: 24px;
            font-weight: bold;
            color: {COLORS['accent']};
        }}
        
        QLabel#subtitle {{
            font-size: 14px;
            color: {COLORS['text_secondary']};
        }}
        
        QLabel#warning {{
            color: {COLORS['warning']};
            font-weight: bold;
        }}
        
        /* Buttons */
        QPushButton {{
            background-color: {COLORS['accent']};
            color: white;
            border: none;
            border-radius: 6px;
            padding: 10px 24px;
            font-weight: bold;
            min-width: 100px;
        }}
        
        QPushButton:hover {{
            background-color: {COLORS['accent_hover']};
        }}
        
        QPushButton:pressed {{
            background-color: {COLORS['bg_tertiary']};
        }}
        
        QPushButton:disabled {{
            background-color: {COLORS['bg_tertiary']};
            color: {COLORS['text_secondary']};
        }}
        
        QPushButton#secondary {{
            background-color: {COLORS['bg_tertiary']};
            border: 1px solid {COLORS['border']};
        }}
        
        QPushButton#secondary:hover {{
            background-color: {COLORS['border']};
        }}
        
        QPushButton#danger {{
            background-color: {COLORS['error']};
        }}
        
        QPushButton#danger:hover {{
            background-color: #c0392b;
        }}
        
        /* Input fields */
        QLineEdit {{
            background-color: {COLORS['input_bg']};
            border: 1px solid {COLORS['border']};
            border-radius: 6px;
            padding: 10px;
            color: {COLORS['text_primary']};
            font-size: 14px;
        }}
        
        QLineEdit:focus {{
            border: 2px solid {COLORS['accent']};
        }}
        
        QLineEdit::placeholder {{
            color: {COLORS['text_secondary']};
        }}
        
        /* Text areas */
        QTextEdit {{
            background-color: {COLORS['input_bg']};
            border: 1px solid {COLORS['border']};
            border-radius: 6px;
            padding: 10px;
            color: {COLORS['text_primary']};
        }}
        
        /* Combo boxes */
        QComboBox {{
            background-color: {COLORS['input_bg']};
            border: 1px solid {COLORS['border']};
            border-radius: 6px;
            padding: 10px;
            color: {COLORS['text_primary']};
            min-width: 150px;
        }}
        
        QComboBox:focus {{
            border: 2px solid {COLORS['accent']};
        }}
        
        QComboBox::drop-down {{
            border: none;
            width: 30px;
        }}
        
        QComboBox::down-arrow {{
            image: none;
            border: 0px;
        }}
        
        /* List widgets */
        QListWidget {{
            background-color: {COLORS['input_bg']};
            border: 1px solid {COLORS['border']};
            border-radius: 6px;
            padding: 5px;
            color: {COLORS['text_primary']};
        }}
        
        QListWidget::item {{
            padding: 10px;
            border-radius: 4px;
        }}
        
        QListWidget::item:hover {{
            background-color: {COLORS['bg_tertiary']};
        }}
        
        QListWidget::item:selected {{
            background-color: {COLORS['accent']};
            color: white;
        }}
        
        /* Tables */
        QTableWidget {{
            background-color: {COLORS['input_bg']};
            border: 1px solid {COLORS['border']};
            border-radius: 6px;
            gridline-color: {COLORS['border']};
            color: {COLORS['text_primary']};
        }}
        
        QTableWidget::item {{
            padding: 8px;
        }}
        
        QTableWidget::item:selected {{
            background-color: {COLORS['accent']};
            color: white;
        }}
        
        QHeaderView::section {{
            background-color: {COLORS['bg_tertiary']};
            color: {COLORS['text_primary']};
            padding: 10px;
            border: none;
            font-weight: bold;
        }}
        
        /* Group boxes */
        QGroupBox {{
            border: 1px solid {COLORS['border']};
            border-radius: 8px;
            margin-top: 10px;
            padding-top: 10px;
            font-weight: bold;
        }}
        
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px;
            color: {COLORS['accent']};
        }}
        
        /* Scroll bars */
        QScrollBar:vertical {{
            background: {COLORS['bg_secondary']};
            width: 12px;
            border-radius: 6px;
        }}
        
        QScrollBar::handle:vertical {{
            background: {COLORS['bg_tertiary']};
            border-radius: 6px;
            min-height: 30px;
        }}
        
        QScrollBar::handle:vertical:hover {{
            background: {COLORS['accent']};
        }}
        
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}
        
        /* Message boxes */
        QMessageBox {{
            background-color: {COLORS['bg_secondary']};
        }}
        
        QMessageBox QLabel {{
            color: {COLORS['text_primary']};
        }}
        
        /* Progress bars */
        QProgressBar {{
            background-color: {COLORS['bg_tertiary']};
            border: 1px solid {COLORS['border']};
            border-radius: 4px;
            text-align: center;
            color: {COLORS['text_primary']};
        }}
        
        QProgressBar::chunk {{
            background-color: {COLORS['accent']};
            border-radius: 3px;
        }}
        
        /* Status bar */
        QStatusBar {{
            background-color: {COLORS['bg_secondary']};
            color: {COLORS['text_secondary']};
        }}
        
        /* Menu bar */
        QMenuBar {{
            background-color: {COLORS['bg_secondary']};
            color: {COLORS['text_primary']};
            border-bottom: 1px solid {COLORS['border']};
        }}
        
        QMenuBar::item {{
            padding: 8px 12px;
            background-color: transparent;
        }}
        
        QMenuBar::item:selected {{
            background-color: {COLORS['bg_tertiary']};
        }}
        
        QMenu {{
            background-color: {COLORS['bg_secondary']};
            color: {COLORS['text_primary']};
            border: 1px solid {COLORS['border']};
        }}
        
        QMenu::item {{
            padding: 8px 24px;
        }}
        
        QMenu::item:selected {{
            background-color: {COLORS['accent']};
        }}
    """


def get_password_strength_stylesheet(strength: int) -> str:
    """
    Get stylesheet for password strength indicator.
    
    Args:
        strength: 0-4 (weak to strong)
        
    Returns:
        Stylesheet string
    """
    colors = {
        0: COLORS['error'],      # Very weak
        1: '#ff6b35',            # Weak
        2: COLORS['warning'],    # Medium
        3: COLORS['success'],    # Strong
        4: '#2ecc71',            # Very strong
    }
    
    color = colors.get(strength, COLORS['error'])
    
    return f"""
        QProgressBar {{
            background-color: {COLORS['bg_tertiary']};
            border: 1px solid {COLORS['border']};
            border-radius: 4px;
            text-align: center;
            color: white;
        }}
        
        QProgressBar::chunk {{
            background-color: {color};
            border-radius: 3px;
        }}
    """
