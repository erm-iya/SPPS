"""
SecAudit 2.0 Enterprise - Modern PyQt6 Desktop GUI
High-performance visual dashboard inspired by FoxLoader (Fluent UI) & UroStudio Pro.
Features:
- Non-blocking multithreaded architecture (QThread) with real-time progress
- Full Pause, Resume, and Cancel scan controls
- Compact top-center configuration card with custom Source & Output directories
- Tall, vertically-scrollable left inspector drawer for Findings & PoC curl requests
- Interactive Findings table on the right with instant live search and multi-criteria filters
- 1-click Export Hub (HTML, Markdown, SARIF, JSON, and Open Output Folder)
"""

import os
import sys
import json
import threading
import webbrowser
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QSplitter, QGroupBox, QLabel, QPushButton, QLineEdit,
    QComboBox, QCheckBox, QSpinBox, QProgressBar, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit, QTabWidget, QFileDialog,
    QMessageBox, QFrame, QScrollArea, QAbstractItemView, QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QColor, QPalette, QIcon, QClipboard

from .models import ScanResult, Severity, Finding
from .orchestrator import SecAuditOrchestrator
from .reporting import HTMLReporter, JSONReporter, SARIFReporter, MarkdownReporter


DARK_THEME_QSS = """
/* Global Application Reset & Theme */
QMainWindow, QWidget#centralWidget {
    background-color: #0b0f19;
    color: #f8fafc;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    font-size: 13px;
}

/* Scrollbars */
QScrollBar:vertical {
    border: none;
    background: #0f172a;
    width: 10px;
    margin: 0px;
    border-radius: 5px;
}
QScrollBar::handle:vertical {
    background: #334155;
    min-height: 20px;
    border-radius: 5px;
}
QScrollBar::handle:vertical:hover {
    background: #475569;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    border: none;
    background: #0f172a;
    height: 10px;
    margin: 0px;
    border-radius: 5px;
}
QScrollBar::handle:horizontal {
    background: #334155;
    min-width: 20px;
    border-radius: 5px;
}

/* Card Frames */
QFrame.card {
    background-color: #151e2e;
    border: 1px solid #2e3d55;
    border-radius: 12px;
    padding: 10px;
}

/* Inputs & Form Controls */
QLineEdit, QComboBox, QSpinBox {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-radius: 7px;
    padding: 6px 10px;
    color: #f8fafc;
    font-size: 12px;
    selection-background-color: #0284c7;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #38bdf8;
    background-color: #0c1322;
}
QComboBox::drop-down {
    border: none;
    width: 22px;
}
QComboBox QAbstractItemView {
    background-color: #151e2e;
    border: 1px solid #334155;
    selection-background-color: #0284c7;
    color: #f8fafc;
    border-radius: 6px;
    padding: 4px;
}

/* Buttons */
QPushButton {
    background-color: #1e293b;
    border: 1px solid #334155;
    color: #f8fafc;
    border-radius: 7px;
    padding: 6px 14px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #2e3d55;
    border-color: #475569;
}
QPushButton:pressed {
    background-color: #0f172a;
}
QPushButton:disabled {
    background-color: #0f172a;
    color: #475569;
    border-color: #1e293b;
}

/* Primary Action Button (Start Audit) */
QPushButton#btnStart {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #0ea5e9);
    border: 1px solid #38bdf8;
    color: #ffffff;
    font-size: 13px;
    font-weight: bold;
    border-radius: 8px;
    padding: 8px 18px;
}
QPushButton#btnStart:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0369a1, stop:1 #0284c7);
}

/* Pause Button */
QPushButton#btnPause {
    background-color: #d97706;
    border: 1px solid #f59e0b;
    color: #ffffff;
    font-size: 13px;
    font-weight: bold;
    border-radius: 8px;
    padding: 8px 14px;
}
QPushButton#btnPause:hover {
    background-color: #b45309;
}

/* Cancel Button */
QPushButton#btnCancel {
    background-color: #dc2626;
    border: 1px solid #ef4444;
    color: #ffffff;
    font-size: 13px;
    font-weight: bold;
    border-radius: 8px;
    padding: 8px 14px;
}
QPushButton#btnCancel:hover {
    background-color: #b91c1c;
}

/* Progress Bar */
QProgressBar {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-radius: 6px;
    text-align: center;
    color: #ffffff;
    font-weight: bold;
    height: 14px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #10b981);
    border-radius: 5px;
}

/* Tabs */
QTabWidget::pane {
    border: 1px solid #2e3d55;
    background-color: #151e2e;
    border-radius: 10px;
}
QTabBar::tab {
    background: #0f172a;
    color: #94a3b8;
    border: 1px solid #2e3d55;
    border-bottom: none;
    padding: 7px 16px;
    margin-right: 4px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    font-weight: 600;
}
QTabBar::tab:selected {
    background: #151e2e;
    color: #38bdf8;
    border-bottom: 2px solid #38bdf8;
}

/* Table Widget */
QTableWidget {
    background-color: #0c1322;
    border: 1px solid #2e3d55;
    border-radius: 8px;
    gridline-color: #1e293b;
    selection-background-color: #1e293b;
    selection-color: #38bdf8;
    font-size: 12px;
}
QHeaderView::section {
    background-color: #151e2e;
    color: #94a3b8;
    padding: 6px 10px;
    border: 1px solid #2e3d55;
    font-weight: 600;
}

/* Text Console Logs */
QTextEdit {
    background-color: #070a11;
    border: 1px solid #2e3d55;
    border-radius: 8px;
    color: #a7f3d0;
    font-family: Consolas, Monaco, monospace;
    font-size: 12px;
    padding: 8px;
}
"""


class AuditWorker(QThread):
    """
    Background worker thread running SecAuditOrchestrator with Pause, Resume, and Cancel controls.
    """
    progress = pyqtSignal(int, str)
    log = pyqtSignal(str)
    finished = pyqtSignal(object)
    failed = pyqtSignal(str)
    cancelled = pyqtSignal()

    def __init__(
        self,
        target_url: Optional[str],
        target_dir: Optional[str],
        check_online_sca: bool,
        timeout: int,
        max_workers: int,
        diff_mode: bool,
    ):
        super().__init__()
        self.target_url = target_url
        self.target_dir = target_dir
        self.check_online_sca = check_online_sca
        self.timeout = timeout
        self.max_workers = max_workers
        self.diff_mode = diff_mode

        self._is_paused = False
        self._is_cancelled = False
        self._pause_cond = threading.Condition()

    def pause(self):
        with self._pause_cond:
            self._is_paused = True

    def resume(self):
        with self._pause_cond:
            self._is_paused = False
            self._pause_cond.notify_all()

    def cancel(self):
        with self._pause_cond:
            self._is_cancelled = True
            self._is_paused = False
            self._pause_cond.notify_all()

    def check_interrupted(self):
        if self._is_cancelled:
            raise InterruptedError("Audit cancelled by user")
        with self._pause_cond:
            while self._is_paused:
                self._pause_cond.wait(0.2)
                if self._is_cancelled:
                    raise InterruptedError("Audit cancelled by user")

    def run(self):
        try:
            self.log.emit("[*] Initializing SecAudit 2.0 Enterprise Engine...")
            if self.target_url:
                self.log.emit(f"    - Target URL:       {self.target_url}")
            if self.target_dir:
                self.log.emit(f"    - Target Directory: {self.target_dir}")

            def on_progress(percent: int, message: str):
                self.check_interrupted()
                self.progress.emit(percent, message)
                self.log.emit(f"[{percent}%] {message}")

            orchestrator = SecAuditOrchestrator(
                target_url=self.target_url,
                target_dir=self.target_dir,
                check_online_sca=self.check_online_sca,
                timeout=self.timeout,
                max_workers=self.max_workers,
                diff_mode=self.diff_mode,
                progress_callback=on_progress,
                check_interrupted=self.check_interrupted,
            )

            result = orchestrator.run()
            self.check_interrupted()

            self.progress.emit(100, "Audit completed successfully.")
            self.log.emit(f"[+] Security Score: {result.security_score}/100 (Grade: {result.grade})")
            self.log.emit(f"[+] Total Vulnerabilities Found: {len(result.findings)}")
            self.finished.emit(result)
        except InterruptedError:
            self.log.emit("[!] Security audit was stopped by user.")
            self.cancelled.emit()
        except Exception as e:
            self.failed.emit(str(e))


class SecAuditGUI(QMainWindow):
    """
    Main SecAudit 2.0 Enterprise Desktop Studio Window.
    """

    SEVERITY_COLORS = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#3b82f6",
        "INFO": "#06b6d4",
    }

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecAudit 2.0 Enterprise - Security & Compliance Studio")
        self.resize(1360, 880)
        self.setMinimumSize(1080, 720)
        self.setStyleSheet(DARK_THEME_QSS)

        self.last_result: Optional[ScanResult] = None
        self.worker: Optional[AuditWorker] = None
        self.is_paused: bool = False

        self._build_ui()

    def _build_ui(self):
        central = QWidget(self)
        central.setObjectName("centralWidget")
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(14, 12, 14, 12)
        main_layout.setSpacing(10)

        # 1. Header Bar
        header = self._build_header()
        main_layout.addWidget(header)

        # 2. Compact Top-Center Target & Options Card
        top_center_container = self._build_top_center_card()
        main_layout.addWidget(top_center_container)

        # 3. Execution Control & Progress Bar
        exec_bar = self._build_execution_bar()
        main_layout.addWidget(exec_bar)

        # 4. Main Workspace Splitter (Left: Tall Details & PoC Drawer; Right: KPI + Findings Explorer)
        workspace = self._build_main_workspace()
        main_layout.addWidget(workspace, stretch=1)

        # 5. Bottom Export Hub (Using selected Output Directory)
        export_bar = self._build_export_hub()
        main_layout.addWidget(export_bar)

    def _build_header(self) -> QWidget:
        header = QFrame()
        header.setProperty("class", "card")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(12, 8, 12, 8)

        title_layout = QVBoxLayout()
        lbl_title = QLabel("🛡️ SecAudit 2.0 Enterprise Studio")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: 800; color: #38bdf8;")
        lbl_sub = QLabel("Automated Vulnerability Auditor • DAST • SAST • SCA • IaC • OpenAPI")
        lbl_sub.setStyleSheet("color: #94a3b8; font-size: 11px;")
        title_layout.addWidget(lbl_title)
        title_layout.addWidget(lbl_sub)
        layout.addLayout(title_layout)

        layout.addStretch()

        badge = QLabel("OWASP Top 10:2025 Compliant")
        badge.setStyleSheet(
            "background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid #059669; "
            "border-radius: 8px; padding: 5px 12px; font-weight: bold; font-size: 11px;"
        )
        layout.addWidget(badge)

        return header

    def _build_top_center_card(self) -> QWidget:
        # Wrapper to center the compact configuration card
        wrapper = QWidget()
        wrap_layout = QHBoxLayout(wrapper)
        wrap_layout.setContentsMargins(0, 0, 0, 0)

        card = QFrame()
        card.setProperty("class", "card")
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        card.setMaximumWidth(1250)

        grid = QGridLayout(card)
        grid.setContentsMargins(14, 10, 14, 10)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)

        # Row 0: Source Folder Selector
        lbl_dir = QLabel("📁 Source Path:")
        lbl_dir.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        self.txt_dir = QLineEdit()
        self.txt_dir.setPlaceholderText("Select project root folder (e.g. D:\\Project\\MyApp)...")
        btn_browse_dir = QPushButton("Browse Source...")
        btn_browse_dir.clicked.connect(self._browse_source_folder)

        grid.addWidget(lbl_dir, 0, 0)
        grid.addWidget(self.txt_dir, 0, 1)
        grid.addWidget(btn_browse_dir, 0, 2)

        # Row 1: Output Folder Selector
        lbl_out = QLabel("💾 Output Path:")
        lbl_out.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        self.txt_out_dir = QLineEdit()
        self.txt_out_dir.setText(os.path.abspath("reports"))
        btn_browse_out = QPushButton("Browse Output...")
        btn_browse_out.clicked.connect(self._browse_output_folder)

        grid.addWidget(lbl_out, 1, 0)
        grid.addWidget(self.txt_out_dir, 1, 1)
        grid.addWidget(btn_browse_out, 1, 2)

        # Row 2: Target URL & Scan Mode
        lbl_url = QLabel("🌐 Website URL:")
        lbl_url.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        self.txt_url = QLineEdit()
        self.txt_url.setPlaceholderText("https://example.com or http://localhost:3000")

        self.cmb_mode = QComboBox()
        self.cmb_mode.addItems([
            "Full 360° Enterprise Audit (DAST + SAST)",
            "Local Source Code Audit (SAST, IaC, SCA, Secrets)",
            "Live Website Audit (DAST, SSL, DNS, CSP, Headers)",
        ])

        grid.addWidget(lbl_url, 2, 0)
        grid.addWidget(self.txt_url, 2, 1)
        grid.addWidget(self.cmb_mode, 2, 2)

        # Row 3: Compact Toggles & Fine-tuning
        opts_layout = QHBoxLayout()
        self.chk_diff = QCheckBox("Git Diff Mode (--diff)")
        self.chk_diff.setToolTip("Scan only changed/staged files in the current Git working tree")

        self.chk_offline = QCheckBox("Offline Mode")
        self.chk_offline.setToolTip("Skip online queries to OSV.dev vulnerability database")

        lbl_threads = QLabel("Workers:")
        lbl_threads.setStyleSheet("color: #94a3b8; font-size: 11px;")
        self.spn_threads = QSpinBox()
        self.spn_threads.setRange(1, 32)
        self.spn_threads.setValue(6)

        lbl_timeout = QLabel("Timeout (s):")
        lbl_timeout.setStyleSheet("color: #94a3b8; font-size: 11px;")
        self.spn_timeout = QSpinBox()
        self.spn_timeout.setRange(2, 60)
        self.spn_timeout.setValue(10)

        opts_layout.addWidget(self.chk_diff)
        opts_layout.addWidget(self.chk_offline)
        opts_layout.addSpacing(16)
        opts_layout.addWidget(lbl_threads)
        opts_layout.addWidget(self.spn_threads)
        opts_layout.addSpacing(10)
        opts_layout.addWidget(lbl_timeout)
        opts_layout.addWidget(self.spn_timeout)
        opts_layout.addStretch()

        grid.addLayout(opts_layout, 3, 1, 1, 2)

        wrap_layout.addWidget(card)
        return wrapper

    def _build_execution_bar(self) -> QWidget:
        bar = QFrame()
        bar.setProperty("class", "card")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 8, 12, 8)

        # Action Buttons Group: Start, Pause, Cancel
        self.btn_run = QPushButton("🚀 Start Audit")
        self.btn_run.setObjectName("btnStart")
        self.btn_run.clicked.connect(self._start_audit)

        self.btn_pause = QPushButton("⏸ Pause")
        self.btn_pause.setObjectName("btnPause")
        self.btn_pause.setEnabled(False)
        self.btn_pause.clicked.connect(self._toggle_pause)

        self.btn_cancel = QPushButton("⏹ Cancel")
        self.btn_cancel.setObjectName("btnCancel")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._cancel_audit)

        layout.addWidget(self.btn_run)
        layout.addWidget(self.btn_pause)
        layout.addWidget(self.btn_cancel)

        # Progress bar & status
        prog_layout = QVBoxLayout()
        self.lbl_status = QLabel("Ready. Select target source or URL above and click Start Audit.")
        self.lbl_status.setStyleSheet("color: #94a3b8; font-size: 12px;")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        prog_layout.addWidget(self.lbl_status)
        prog_layout.addWidget(self.progress_bar)

        layout.addLayout(prog_layout, stretch=1)
        return bar

    def _build_main_workspace(self) -> QWidget:
        # Horizontal Splitter: Left is tall scrollable Inspector Drawer; Right is Findings & KPI Table
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left Panel: Tall Scrollable Inspector Drawer
        left_panel = self._build_tall_inspector_drawer()
        splitter.addWidget(left_panel)

        # Right Panel: KPI Summary + Table + Tabs
        right_panel = self._build_right_findings_panel()
        splitter.addWidget(right_panel)

        splitter.setSizes([460, 840])
        return splitter

    def _build_tall_inspector_drawer(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: 1px solid #2e3d55; border-radius: 10px; background: #151e2e; }")

        drawer_content = QWidget()
        layout = QVBoxLayout(drawer_content)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        # Header Title
        lbl_drawer_header = QLabel("🔍 Vulnerability & PoC Inspector")
        lbl_drawer_header.setStyleSheet("font-size: 15px; font-weight: bold; color: #38bdf8;")
        layout.addWidget(lbl_drawer_header)

        # Selected Title & Severity Badge
        self.lbl_detail_title = QLabel("Select a vulnerability on the right to inspect technical proof and remediation.")
        self.lbl_detail_title.setWordWrap(True)
        self.lbl_detail_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #f8fafc;")
        layout.addWidget(self.lbl_detail_title)

        # Badges row (OWASP, Severity, CWE)
        self.lbl_meta_badge = QLabel("Awaiting selection...")
        self.lbl_meta_badge.setWordWrap(True)
        self.lbl_meta_badge.setStyleSheet(
            "background: #1e293b; color: #94a3b8; border: 1px solid #334155; "
            "padding: 6px 10px; border-radius: 6px; font-size: 11px;"
        )
        layout.addWidget(self.lbl_meta_badge)

        # Description Card
        layout.addWidget(QLabel("📖 Description:"))
        self.txt_detail_desc = QTextEdit()
        self.txt_detail_desc.setReadOnly(True)
        self.txt_detail_desc.setMinimumHeight(110)
        layout.addWidget(self.txt_detail_desc)

        # Remediation Card
        layout.addWidget(QLabel("💡 Remediation & Fix:"))
        self.txt_detail_rem = QTextEdit()
        self.txt_detail_rem.setReadOnly(True)
        self.txt_detail_rem.setMinimumHeight(95)
        self.txt_detail_rem.setStyleSheet("background: #064e3b; border: 1px solid #059669; color: #a7f3d0;")
        layout.addWidget(self.txt_detail_rem)

        # Code Evidence
        layout.addWidget(QLabel("🔬 Code Evidence / Match:"))
        self.txt_detail_evidence = QTextEdit()
        self.txt_detail_evidence.setReadOnly(True)
        self.txt_detail_evidence.setMinimumHeight(70)
        self.txt_detail_evidence.setStyleSheet("background: #070a11; border: 1px solid #1e293b; color: #e2e8f0; font-family: monospace;")
        layout.addWidget(self.txt_detail_evidence)

        # PoC curl box & Copy Button
        layout.addWidget(QLabel("🎯 Reproducible Proof of Concept (PoC Request):"))
        self.txt_poc = QTextEdit()
        self.txt_poc.setReadOnly(True)
        self.txt_poc.setMinimumHeight(75)
        self.txt_poc.setStyleSheet("background: #091e1e; border: 1px solid #0d9488; color: #2dd4bf; font-family: monospace; font-size: 12px;")
        layout.addWidget(self.txt_poc)

        btn_copy_poc = QPushButton("📋 Copy PoC curl to Clipboard")
        btn_copy_poc.clicked.connect(self._copy_poc_to_clipboard)
        layout.addWidget(btn_copy_poc)

        layout.addStretch()
        scroll.setWidget(drawer_content)
        return scroll

    def _build_right_findings_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # KPI & Security Metrics Card
        kpi_frame = QFrame()
        kpi_frame.setProperty("class", "card")
        kpi_main_layout = QVBoxLayout(kpi_frame)
        kpi_main_layout.setContentsMargins(10, 8, 10, 8)
        kpi_main_layout.setSpacing(6)

        # Row 1: Overall Score Card & Severity Badges
        kpi_row1 = QHBoxLayout()
        kpi_row1.setSpacing(8)

        self.lbl_score_card = QLabel("Score: -- / 100 (Grade: -)")
        self.lbl_score_card.setStyleSheet(
            "background: #1e293b; color: #38bdf8; font-size: 14px; font-weight: bold; "
            "padding: 7px 14px; border-radius: 8px; border: 1px solid #334155;"
        )
        kpi_row1.addWidget(self.lbl_score_card)

        self.kpi_labels = {}
        for sev, color in self.SEVERITY_COLORS.items():
            lbl = QLabel(f"{sev}: 0")
            lbl.setStyleSheet(
                f"background: rgba(15, 23, 42, 0.85); color: {color}; border: 1px solid {color}; "
                f"padding: 5px 10px; border-radius: 6px; font-weight: bold; font-size: 11px;"
            )
            self.kpi_labels[sev] = lbl
            kpi_row1.addWidget(lbl)

        kpi_row1.addStretch()
        kpi_main_layout.addLayout(kpi_row1)

        # Row 2: Volume Scale & Inventory Badges
        vol_row = QHBoxLayout()
        vol_row.setSpacing(8)

        self.lbl_vol_loc = QLabel("📏 LoC: --")
        self.lbl_vol_files = QLabel("📁 Files: --")
        self.lbl_vol_pkgs = QLabel("📦 Packages: --")
        self.lbl_vol_routes = QLabel("🌐 Endpoints: --")

        for v_lbl in [self.lbl_vol_loc, self.lbl_vol_files, self.lbl_vol_pkgs, self.lbl_vol_routes]:
            v_lbl.setStyleSheet(
                "background: #0f172a; color: #94a3b8; border: 1px solid #2e3d55; "
                "padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 600;"
            )
            vol_row.addWidget(v_lbl)

        vol_row.addStretch()
        kpi_main_layout.addLayout(vol_row)

        # Row 3: Sub-Pillar Health Scores
        pillar_row = QHBoxLayout()
        pillar_row.setSpacing(8)

        self.lbl_p_sast = QLabel("Code & Secrets: --%")
        self.lbl_p_sca = QLabel("Supply Chain: --%")
        self.lbl_p_iac = QLabel("Container/IaC: --%")
        self.lbl_p_dast = QLabel("Attack Surface: --%")

        for p_lbl in [self.lbl_p_sast, self.lbl_p_sca, self.lbl_p_iac, self.lbl_p_dast]:
            p_lbl.setStyleSheet(
                "background: rgba(30, 41, 59, 0.8); color: #38bdf8; border: 1px solid #334155; "
                "padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: bold;"
            )
            pillar_row.addWidget(p_lbl)

        pillar_row.addStretch()
        kpi_main_layout.addLayout(pillar_row)

        layout.addWidget(kpi_frame)

        # Workspace Tabs
        self.tabs = QTabWidget()

        # Tab 1: Findings Explorer
        tab_findings = QWidget()
        f_layout = QVBoxLayout(tab_findings)
        f_layout.setContentsMargins(8, 8, 8, 8)
        f_layout.setSpacing(8)

        # Filters toolbar
        toolbar = QHBoxLayout()
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Search title, category, CWE, or file...")
        self.txt_search.textChanged.connect(self._filter_findings)

        self.cmb_filter_sev = QComboBox()
        self.cmb_filter_sev.addItems(["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.cmb_filter_sev.currentIndexChanged.connect(self._filter_findings)

        toolbar.addWidget(QLabel("Filter:"))
        toolbar.addWidget(self.cmb_filter_sev)
        toolbar.addWidget(self.txt_search, stretch=1)
        f_layout.addLayout(toolbar)

        # Findings Table
        self.tbl_findings = QTableWidget(0, 5)
        self.tbl_findings.setHorizontalHeaderLabels(["Severity", "Vulnerability Title", "Category", "OWASP Top 10:2025", "Location"])
        self.tbl_findings.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tbl_findings.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tbl_findings.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl_findings.itemSelectionChanged.connect(self._on_finding_selected)
        f_layout.addWidget(self.tbl_findings)

        self.tabs.addTab(tab_findings, "📋 Findings Table")

        # Tab 2: Real-Time Audit Console Logs
        tab_logs = QWidget()
        l_layout = QVBoxLayout(tab_logs)
        l_layout.setContentsMargins(8, 8, 8, 8)
        self.txt_logs = QTextEdit()
        self.txt_logs.setReadOnly(True)
        l_layout.addWidget(self.txt_logs)
        self.tabs.addTab(tab_logs, "📜 Real-Time Console Logs")

        layout.addWidget(self.tabs, stretch=1)
        return panel

    def _build_export_hub(self) -> QWidget:
        hub = QFrame()
        hub.setProperty("class", "card")
        layout = QHBoxLayout(hub)
        layout.setContentsMargins(12, 8, 12, 8)

        lbl = QLabel("Reports & Exports:")
        lbl.setStyleSheet("font-weight: bold; color: #cbd5e1;")
        layout.addWidget(lbl)

        btn_html = QPushButton("🌐 View HTML Dashboard")
        btn_html.clicked.connect(self._export_html)

        btn_md = QPushButton("📝 Save Markdown (.md)")
        btn_md.clicked.connect(self._export_markdown)

        btn_sarif = QPushButton("🛡️ Save SARIF (.sarif)")
        btn_sarif.clicked.connect(self._export_sarif)

        btn_json = QPushButton("📊 Save JSON (.json)")
        btn_json.clicked.connect(self._export_json)

        btn_open_folder = QPushButton("📂 Open Output Folder")
        btn_open_folder.clicked.connect(self._open_output_folder)

        layout.addWidget(btn_html)
        layout.addWidget(btn_md)
        layout.addWidget(btn_sarif)
        layout.addWidget(btn_json)
        layout.addWidget(btn_open_folder)
        layout.addStretch()

        return hub

    def _browse_source_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Project Root Folder", os.getcwd())
        if folder:
            self.txt_dir.setText(folder)

    def _browse_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Reports Directory", self.txt_out_dir.text() or os.getcwd())
        if folder:
            self.txt_out_dir.setText(folder)

    def _get_output_dir(self) -> str:
        out_dir = self.txt_out_dir.text().strip() or os.path.abspath("reports")
        os.makedirs(out_dir, exist_ok=True)
        return out_dir

    def _start_audit(self):
        target_dir = self.txt_dir.text().strip() or None
        target_url = self.txt_url.text().strip() or None
        mode_idx = self.cmb_mode.currentIndex()

        if mode_idx == 1:
            target_url = None
        elif mode_idx == 2:
            target_dir = None

        if not target_dir and not target_url:
            QMessageBox.warning(self, "Missing Target", "Please specify a project directory or website URL to scan.")
            return

        if target_url and not (target_url.startswith("http://") or target_url.startswith("https://")):
            target_url = "https://" + target_url
            self.txt_url.setText(target_url)

        self.btn_run.setEnabled(False)
        self.btn_pause.setEnabled(True)
        self.btn_pause.setText("⏸ Pause")
        self.btn_cancel.setEnabled(True)
        self.is_paused = False

        self.progress_bar.setValue(0)
        self.lbl_status.setText("Starting security audit engines...")
        self.txt_logs.clear()
        self.tbl_findings.setRowCount(0)

        self.worker = AuditWorker(
            target_url=target_url,
            target_dir=target_dir,
            check_online_sca=not self.chk_offline.isChecked(),
            timeout=self.spn_timeout.value(),
            max_workers=self.spn_threads.value(),
            diff_mode=self.chk_diff.isChecked(),
        )

        self.worker.progress.connect(self._on_worker_progress)
        self.worker.log.connect(self._on_worker_log)
        self.worker.finished.connect(self._on_worker_finished)
        self.worker.failed.connect(self._on_worker_failed)
        self.worker.cancelled.connect(self._on_worker_cancelled)
        self.worker.start()

    def _toggle_pause(self):
        if not self.worker or not self.worker.isRunning():
            return

        if not self.is_paused:
            self.worker.pause()
            self.is_paused = True
            self.btn_pause.setText("▶ Resume")
            self.lbl_status.setText("Audit paused by user. Click Resume to continue.")
        else:
            self.worker.resume()
            self.is_paused = False
            self.btn_pause.setText("⏸ Pause")
            self.lbl_status.setText("Resuming audit engines...")

    def _cancel_audit(self):
        if self.worker and self.worker.isRunning():
            self.lbl_status.setText("Stopping audit engines...")
            self.worker.cancel()

    def _on_worker_progress(self, percent: int, msg: str):
        self.progress_bar.setValue(percent)
        self.lbl_status.setText(msg)

    def _on_worker_log(self, text: str):
        self.txt_logs.append(text)

    def _on_worker_finished(self, result: ScanResult):
        self.last_result = result
        self.btn_run.setEnabled(True)
        self.btn_pause.setEnabled(False)
        self.btn_cancel.setEnabled(False)
        self.lbl_status.setText(f"Completed in {result.duration_seconds:.2f}s! Score: {result.security_score}/100")

        grade_color = "#10b981" if result.grade in ["A+", "A"] else ("#3b82f6" if result.grade == "B" else ("#eab308" if result.grade == "C" else "#ef4444"))
        self.lbl_score_card.setText(f"Score: {result.security_score} / 100 (Grade: {result.grade})")
        self.lbl_score_card.setStyleSheet(
            f"background: #1e293b; color: {grade_color}; font-size: 14px; font-weight: bold; "
            f"padding: 7px 14px; border-radius: 8px; border: 1px solid {grade_color};"
        )

        for sev, count in result.stats.items():
            if sev in self.kpi_labels:
                self.kpi_labels[sev].setText(f"{sev}: {count}")

        # Update Project Volume Inventory Badges
        vm = result.volume_metrics
        self.lbl_vol_loc.setText(f"📏 LoC: {vm.total_loc:,}")
        self.lbl_vol_files.setText(f"📁 Files: {vm.total_files:,}")
        self.lbl_vol_pkgs.setText(f"📦 Packages: {vm.total_dependencies}")
        self.lbl_vol_routes.setText(f"🌐 Endpoints: {vm.total_endpoints}")

        # Update Sub-Pillar Health Scores
        ps = result.pillar_scores
        self.lbl_p_sast.setText(f"Code & Secrets: {ps.sast_score}%")
        self.lbl_p_sca.setText(f"Supply Chain: {ps.sca_score}%")
        self.lbl_p_iac.setText(f"Container/IaC: {ps.iac_score}%")
        self.lbl_p_dast.setText(f"Attack Surface: {ps.dast_score}%")

        self._populate_findings_table(result.findings)
        self.tabs.setCurrentIndex(0)

        # Auto-save HTML report into user output directory
        out_dir = self._get_output_dir()
        auto_html = os.path.join(out_dir, "report.html")
        HTMLReporter(result).export(auto_html)
        self.txt_logs.append(f"[+] Saved default HTML report to: {auto_html}")

    def _on_worker_failed(self, error_msg: str):
        self.btn_run.setEnabled(True)
        self.btn_pause.setEnabled(False)
        self.btn_cancel.setEnabled(False)
        self.lbl_status.setText("Scan failed with an error.")
        QMessageBox.critical(self, "Audit Error", f"An error occurred during scanning:\n{error_msg}")

    def _on_worker_cancelled(self):
        self.btn_run.setEnabled(True)
        self.btn_pause.setEnabled(False)
        self.btn_cancel.setEnabled(False)
        self.lbl_status.setText("Security audit cancelled by user.")
        QMessageBox.information(self, "Audit Cancelled", "The security audit was stopped.")

    def _populate_findings_table(self, findings: List[Finding]):
        self.tbl_findings.setRowCount(0)
        for row_idx, f in enumerate(findings):
            self.tbl_findings.insertRow(row_idx)

            sev_item = QTableWidgetItem(f.severity.value)
            sev_color = QColor(self.SEVERITY_COLORS.get(f.severity.value, "#cbd5e1"))
            sev_item.setForeground(sev_color)
            sev_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))

            title_item = QTableWidgetItem(f.title)
            cat_item = QTableWidgetItem(f.category)
            owasp_item = QTableWidgetItem(f.owasp_category or "-")
            loc_item = QTableWidgetItem(f.location or "-")

            title_item.setData(Qt.ItemDataRole.UserRole, f)

            self.tbl_findings.setItem(row_idx, 0, sev_item)
            self.tbl_findings.setItem(row_idx, 1, title_item)
            self.tbl_findings.setItem(row_idx, 2, cat_item)
            self.tbl_findings.setItem(row_idx, 3, owasp_item)
            self.tbl_findings.setItem(row_idx, 4, loc_item)

        if findings:
            self.tbl_findings.selectRow(0)

    def _filter_findings(self):
        if not self.last_result:
            return

        sev_filter = self.cmb_filter_sev.currentText()
        query = self.txt_search.text().strip().lower()

        filtered = []
        for f in self.last_result.findings:
            matches_sev = (sev_filter == "All Severities" or f.severity.value == sev_filter)
            matches_query = (
                not query
                or query in f.title.lower()
                or query in f.description.lower()
                or query in (f.cwe_id or "").lower()
                or query in (f.category or "").lower()
                or query in (f.location or "").lower()
            )
            if matches_sev and matches_query:
                filtered.append(f)

        self._populate_findings_table(filtered)

    def _on_finding_selected(self):
        selected_rows = self.tbl_findings.selectedItems()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        item = self.tbl_findings.item(row, 1)
        if not item:
            return

        finding: Finding = item.data(Qt.ItemDataRole.UserRole)
        if not finding:
            return

        sev_color = self.SEVERITY_COLORS.get(finding.severity.value, "#38bdf8")
        self.lbl_detail_title.setText(f"[{finding.severity.value}] {finding.title}")
        self.lbl_detail_title.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {sev_color};")

        meta_info = (
            f"Category: {finding.category} | CWE: {finding.cwe_id or 'None'}\n"
            f"OWASP Top 10:2025: {finding.owasp_category or 'Unassigned'}\n"
            f"Location: {finding.location or 'Global project space'}"
        )
        self.lbl_meta_badge.setText(meta_info)

        self.txt_detail_desc.setPlainText(finding.description or "No description provided.")
        self.txt_detail_rem.setPlainText(finding.remediation or "No remediation instructions provided.")
        self.txt_detail_evidence.setPlainText(finding.evidence or "No direct code snippet match available.")
        self.txt_poc.setPlainText(finding.poc_curl or "No PoC curl command available for this finding.")

    def _copy_poc_to_clipboard(self):
        cmd = self.txt_poc.toPlainText().strip()
        if cmd and not cmd.startswith("No PoC"):
            clipboard = QApplication.clipboard()
            clipboard.setText(cmd)
            QMessageBox.information(self, "Copied", "PoC curl command copied to clipboard!")
        else:
            QMessageBox.warning(self, "Empty PoC", "No valid PoC curl command available to copy.")

    def _export_html(self):
        if not self.last_result:
            QMessageBox.warning(self, "No Scan Data", "Run an audit first before viewing HTML dashboard.")
            return

        out_dir = self._get_output_dir()
        html_path = os.path.join(out_dir, "report.html")
        HTMLReporter(self.last_result).export(html_path)
        webbrowser.open(Path(html_path).as_uri())

    def _export_markdown(self):
        if not self.last_result:
            QMessageBox.warning(self, "No Scan Data", "Run an audit first before exporting report.")
            return

        out_dir = self._get_output_dir()
        default_save = os.path.join(out_dir, "audit_report.md")
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Markdown Report", default_save, "Markdown (*.md)")
        if save_path:
            MarkdownReporter(self.last_result).export(save_path)
            QMessageBox.information(self, "Export Successful", f"Markdown report saved to:\n{save_path}")

    def _export_sarif(self):
        if not self.last_result:
            QMessageBox.warning(self, "No Scan Data", "Run an audit first before exporting SARIF.")
            return

        out_dir = self._get_output_dir()
        default_save = os.path.join(out_dir, "results.sarif")
        save_path, _ = QFileDialog.getSaveFileName(self, "Save SARIF Report", default_save, "SARIF (*.sarif)")
        if save_path:
            SARIFReporter(self.last_result).export(save_path)
            QMessageBox.information(self, "Export Successful", f"SARIF report saved to:\n{save_path}")

    def _export_json(self):
        if not self.last_result:
            QMessageBox.warning(self, "No Scan Data", "Run an audit first before exporting JSON.")
            return

        out_dir = self._get_output_dir()
        default_save = os.path.join(out_dir, "report.json")
        save_path, _ = QFileDialog.getSaveFileName(self, "Save JSON Report", default_save, "JSON (*.json)")
        if save_path:
            JSONReporter(self.last_result).export(save_path)
            QMessageBox.information(self, "Export Successful", f"JSON report saved to:\n{save_path}")

    def _open_output_folder(self):
        out_dir = self._get_output_dir()
        if sys.platform == "win32":
            os.startfile(out_dir)
        else:
            subprocess.run(["xdg-open", out_dir])


def run_gui():
    """
    Entrypoint for launching the PyQt6 GUI.
    """
    app = QApplication(sys.argv)
    app.setApplicationName("SecAudit 2.0 Enterprise")
    window = SecAuditGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run_gui()
