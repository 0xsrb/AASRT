"""JSON report generator for AASRT."""

import json
import os
import stat
from typing import Optional

from .base import BaseReporter, ScanReport
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Security: Restrictive file permissions for report files (owner read/write only)
SECURE_FILE_PERMISSIONS = stat.S_IRUSR | stat.S_IWUSR  # 0o600


class JSONReporter(BaseReporter):
    """Generates JSON format reports."""

    def __init__(self, output_dir: str = "./reports", pretty: bool = True):
        """
        Initialize JSON reporter.

        Args:
            output_dir: Output directory for reports
            pretty: Whether to format JSON with indentation
        """
        super().__init__(output_dir)
        self.pretty = pretty

    @property
    def format_name(self) -> str:
        return "json"

    @property
    def file_extension(self) -> str:
        return "json"

    def generate(self, report: ScanReport, filename: Optional[str] = None) -> str:
        """
        Generate JSON report file.

        Args:
            report: ScanReport data
            filename: Optional custom filename

        Returns:
            Path to generated report file
        """
        output_filename = self.get_filename(report.scan_id, filename)
        filepath = self.get_filepath(output_filename)

        content = self.generate_string(report)

        # Security: Write with restrictive permissions (owner read/write only)
        fd = os.open(filepath, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, SECURE_FILE_PERMISSIONS)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(content)
        except Exception:
            os.close(fd)
            raise

        logger.info(f"Generated JSON report: {filepath}")
        return filepath

    def generate_string(self, report: ScanReport) -> str:
        """
        Generate JSON report as string.

        Args:
            report: ScanReport data

        Returns:
            JSON string
        """
        data = report.to_dict()

        # Add report metadata
        data['report_metadata'] = {
            'format': 'json',
            'version': '1.0',
            'generated_by': 'AASRT (AI Agent Security Reconnaissance Tool)'
        }

        if self.pretty:
            return json.dumps(data, indent=2, default=str, ensure_ascii=False)
        else:
            return json.dumps(data, default=str, ensure_ascii=False)

    def generate_summary(self, report: ScanReport) -> str:
        """
        Generate a summary-only JSON report.

        Args:
            report: ScanReport data

        Returns:
            JSON string with summary only
        """
        summary = {
            'scan_id': report.scan_id,
            'timestamp': report.timestamp.isoformat() if report.timestamp else None,
            'engines_used': report.engines_used,
            'total_results': report.total_results,
            'summary': {
                'critical_findings': report.critical_findings,
                'high_findings': report.high_findings,
                'medium_findings': report.medium_findings,
                'low_findings': report.low_findings,
                'average_risk_score': report.average_risk_score
            }
        }

        if self.pretty:
            return json.dumps(summary, indent=2, default=str)
        else:
            return json.dumps(summary, default=str)

    def generate_findings_only(self, report: ScanReport) -> str:
        """
        Generate JSON with findings only (no metadata).

        Args:
            report: ScanReport data

        Returns:
            JSON string with findings array
        """
        if self.pretty:
            return json.dumps(report.findings, indent=2, default=str, ensure_ascii=False)
        else:
            return json.dumps(report.findings, default=str, ensure_ascii=False)
