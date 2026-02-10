"""CSV report generator for AASRT."""

import csv
import io
import os
import stat
from typing import List, Optional

from .base import BaseReporter, ScanReport
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Security: Restrictive file permissions for report files (owner read/write only)
SECURE_FILE_PERMISSIONS = stat.S_IRUSR | stat.S_IWUSR  # 0o600


class CSVReporter(BaseReporter):
    """Generates CSV format reports."""

    # Default columns for findings export
    DEFAULT_COLUMNS = [
        'target_ip',
        'target_port',
        'target_hostname',
        'service',
        'risk_score',
        'vulnerabilities',
        'source_engine',
        'first_seen',
        'status',
        'confidence'
    ]

    def __init__(
        self,
        output_dir: str = "./reports",
        columns: Optional[List[str]] = None,
        include_metadata: bool = False
    ):
        """
        Initialize CSV reporter.

        Args:
            output_dir: Output directory for reports
            columns: Custom columns to include
            include_metadata: Whether to include metadata columns
        """
        super().__init__(output_dir)
        self.columns = columns or self.DEFAULT_COLUMNS.copy()
        self.include_metadata = include_metadata

        if include_metadata:
            self.columns.extend(['location', 'isp', 'asn'])

    @property
    def format_name(self) -> str:
        return "csv"

    @property
    def file_extension(self) -> str:
        return "csv"

    def generate(self, report: ScanReport, filename: Optional[str] = None) -> str:
        """
        Generate CSV report file.

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
            with os.fdopen(fd, 'w', encoding='utf-8', newline='') as f:
                f.write(content)
        except Exception:
            os.close(fd)
            raise

        logger.info(f"Generated CSV report: {filepath}")
        return filepath

    def generate_string(self, report: ScanReport) -> str:
        """
        Generate CSV report as string.

        Args:
            report: ScanReport data

        Returns:
            CSV content as string
        """
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=self.columns, extrasaction='ignore')

        # Write header
        writer.writeheader()

        # Write findings
        for finding in report.findings:
            row = self._format_finding(finding)
            writer.writerow(row)

        return output.getvalue()

    def _format_finding(self, finding: dict) -> dict:
        """Format a finding for CSV output."""
        row = {}

        for col in self.columns:
            if col in finding:
                value = finding[col]

                # Convert lists to comma-separated strings
                if isinstance(value, list):
                    value = '; '.join(str(v) for v in value)
                # Convert dicts to string representation
                elif isinstance(value, dict):
                    value = str(value)

                row[col] = value
            elif col == 'location':
                # Extract from metadata
                metadata = finding.get('metadata', {})
                location = metadata.get('location', {})
                if isinstance(location, dict):
                    row[col] = f"{location.get('country', '')}, {location.get('city', '')}"
                else:
                    row[col] = ''
            elif col == 'isp':
                metadata = finding.get('metadata', {})
                row[col] = metadata.get('isp', '')
            elif col == 'asn':
                metadata = finding.get('metadata', {})
                row[col] = metadata.get('asn', '')
            else:
                row[col] = ''

        return row

    def generate_summary(self, report: ScanReport, filename: Optional[str] = None) -> str:
        """
        Generate a summary CSV file.

        Args:
            report: ScanReport data
            filename: Optional custom filename

        Returns:
            Path to generated file
        """
        summary_filename = filename or f"summary_{report.scan_id[:8]}"
        if not summary_filename.endswith('.csv'):
            summary_filename = f"{summary_filename}.csv"

        filepath = self.get_filepath(summary_filename)

        output = io.StringIO()
        writer = csv.writer(output)

        # Write summary as key-value pairs
        writer.writerow(['Metric', 'Value'])
        writer.writerow(['Scan ID', report.scan_id])
        writer.writerow(['Timestamp', report.timestamp.isoformat() if report.timestamp else ''])
        writer.writerow(['Engines Used', ', '.join(report.engines_used)])
        writer.writerow(['Query', report.query or ''])
        writer.writerow(['Template', report.template_name or ''])
        writer.writerow(['Total Results', report.total_results])
        writer.writerow(['Duration (seconds)', report.duration_seconds])
        writer.writerow(['Critical Findings', report.critical_findings])
        writer.writerow(['High Findings', report.high_findings])
        writer.writerow(['Medium Findings', report.medium_findings])
        writer.writerow(['Low Findings', report.low_findings])
        writer.writerow(['Average Risk Score', report.average_risk_score])

        # Security: Write with restrictive permissions (owner read/write only)
        fd = os.open(filepath, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, SECURE_FILE_PERMISSIONS)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8', newline='') as f:
                f.write(output.getvalue())
        except Exception:
            os.close(fd)
            raise

        logger.info(f"Generated CSV summary: {filepath}")
        return filepath

    def generate_vulnerability_report(self, report: ScanReport, filename: Optional[str] = None) -> str:
        """
        Generate a vulnerability-focused CSV report.

        Args:
            report: ScanReport data
            filename: Optional custom filename

        Returns:
            Path to generated file
        """
        vuln_filename = filename or f"vulnerabilities_{report.scan_id[:8]}"
        if not vuln_filename.endswith('.csv'):
            vuln_filename = f"{vuln_filename}.csv"

        filepath = self.get_filepath(vuln_filename)

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow(['Target IP', 'Port', 'Hostname', 'Vulnerability', 'Risk Score'])

        # Write vulnerability rows
        for finding in report.findings:
            ip = finding.get('target_ip', '')
            port = finding.get('target_port', '')
            hostname = finding.get('target_hostname', '')
            risk_score = finding.get('risk_score', 0)

            vulns = finding.get('vulnerabilities', [])
            if vulns:
                for vuln in vulns:
                    writer.writerow([ip, port, hostname, vuln, risk_score])
            else:
                writer.writerow([ip, port, hostname, 'None detected', risk_score])

        # Security: Write with restrictive permissions (owner read/write only)
        fd = os.open(filepath, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, SECURE_FILE_PERMISSIONS)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8', newline='') as f:
                f.write(output.getvalue())
        except Exception:
            os.close(fd)
            raise

        logger.info(f"Generated vulnerability CSV: {filepath}")
        return filepath
