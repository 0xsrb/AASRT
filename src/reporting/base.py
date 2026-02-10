"""Base reporter class for AASRT."""

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.engines import SearchResult
from src.storage.database import Scan, Finding


@dataclass
class ScanReport:
    """Container for scan report data."""

    scan_id: str
    timestamp: datetime
    engines_used: List[str]
    query: Optional[str] = None
    template_name: Optional[str] = None
    total_results: int = 0
    duration_seconds: float = 0.0
    status: str = "completed"

    # Summary statistics
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    average_risk_score: float = 0.0

    # Detailed findings
    findings: List[Dict[str, Any]] = field(default_factory=list)

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_scan(
        cls,
        scan: Scan,
        findings: List[Finding]
    ) -> 'ScanReport':
        """Create ScanReport from database objects."""
        import json

        # Calculate severity counts
        critical = sum(1 for f in findings if f.risk_score >= 9.0)
        high = sum(1 for f in findings if 7.0 <= f.risk_score < 9.0)
        medium = sum(1 for f in findings if 4.0 <= f.risk_score < 7.0)
        low = sum(1 for f in findings if f.risk_score < 4.0)

        # Calculate average risk
        avg_risk = sum(f.risk_score for f in findings) / len(findings) if findings else 0.0

        return cls(
            scan_id=scan.scan_id,
            timestamp=scan.timestamp,
            engines_used=json.loads(scan.engines_used) if scan.engines_used else [],
            query=scan.query,
            template_name=scan.template_name,
            total_results=len(findings),
            duration_seconds=scan.duration_seconds or 0.0,
            status=scan.status,
            critical_findings=critical,
            high_findings=high,
            medium_findings=medium,
            low_findings=low,
            average_risk_score=round(avg_risk, 1),
            findings=[f.to_dict() for f in findings],
            metadata=json.loads(scan.metadata) if scan.metadata else {}
        )

    @classmethod
    def from_results(
        cls,
        scan_id: str,
        results: List[SearchResult],
        engines: List[str],
        query: Optional[str] = None,
        template_name: Optional[str] = None,
        duration: float = 0.0
    ) -> 'ScanReport':
        """Create ScanReport from search results."""
        # Calculate severity counts
        critical = sum(1 for r in results if r.risk_score >= 9.0)
        high = sum(1 for r in results if 7.0 <= r.risk_score < 9.0)
        medium = sum(1 for r in results if 4.0 <= r.risk_score < 7.0)
        low = sum(1 for r in results if r.risk_score < 4.0)

        # Calculate average risk
        avg_risk = sum(r.risk_score for r in results) / len(results) if results else 0.0

        return cls(
            scan_id=scan_id,
            timestamp=datetime.utcnow(),
            engines_used=engines,
            query=query,
            template_name=template_name,
            total_results=len(results),
            duration_seconds=duration,
            status="completed",
            critical_findings=critical,
            high_findings=high,
            medium_findings=medium,
            low_findings=low,
            average_risk_score=round(avg_risk, 1),
            findings=[r.to_dict() for r in results]
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'scan_metadata': {
                'scan_id': self.scan_id,
                'timestamp': self.timestamp.isoformat() if self.timestamp else None,
                'engines_used': self.engines_used,
                'query': self.query,
                'template_name': self.template_name,
                'total_results': self.total_results,
                'duration_seconds': self.duration_seconds,
                'status': self.status
            },
            'summary': {
                'critical_findings': self.critical_findings,
                'high_findings': self.high_findings,
                'medium_findings': self.medium_findings,
                'low_findings': self.low_findings,
                'average_risk_score': self.average_risk_score
            },
            'findings': self.findings,
            'metadata': self.metadata
        }


class BaseReporter(ABC):
    """Abstract base class for reporters."""

    def __init__(self, output_dir: str = "./reports"):
        """
        Initialize reporter.

        Args:
            output_dir: Directory for report output
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Return the format name (e.g., 'json', 'csv')."""
        pass

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """Return the file extension."""
        pass

    @abstractmethod
    def generate(self, report: ScanReport, filename: Optional[str] = None) -> str:
        """
        Generate a report file.

        Args:
            report: ScanReport data
            filename: Optional custom filename (without extension)

        Returns:
            Path to generated report file
        """
        pass

    @abstractmethod
    def generate_string(self, report: ScanReport) -> str:
        """
        Generate report as a string.

        Args:
            report: ScanReport data

        Returns:
            Report content as string
        """
        pass

    def get_filename(self, scan_id: str, custom_name: Optional[str] = None) -> str:
        """Generate a filename for the report."""
        if custom_name:
            return f"{custom_name}.{self.file_extension}"

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return f"scan_{scan_id[:8]}_{timestamp}.{self.file_extension}"

    def get_filepath(self, filename: str) -> str:
        """Get full file path for a report."""
        return os.path.join(self.output_dir, filename)
