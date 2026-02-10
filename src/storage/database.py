"""
Database storage layer for AASRT.

This module provides a production-ready database layer with:
- Connection pooling for efficient resource usage
- Automatic retry logic for transient failures
- Context managers for proper session cleanup
- Support for SQLite (default) and PostgreSQL
- Comprehensive logging and error handling

Example:
    >>> from src.storage.database import Database
    >>> db = Database()
    >>> scan = db.create_scan(engines=["shodan"], query="http.html:agent")
    >>> db.add_findings(scan.scan_id, results)
    >>> db.update_scan(scan.scan_id, status="completed")
"""

import json
import os
import uuid
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Dict, Generator, List, Optional, TypeVar

from sqlalchemy import (
    create_engine, Column, String, Integer, Float, DateTime,
    Text, Boolean, ForeignKey, Index, event
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session, scoped_session
from sqlalchemy.pool import QueuePool, StaticPool
from sqlalchemy.exc import SQLAlchemyError, OperationalError, IntegrityError

from src.engines import SearchResult
from src.utils.config import Config
from src.utils.logger import get_logger

logger = get_logger(__name__)

Base = declarative_base()

# =============================================================================
# Retry Configuration
# =============================================================================

T = TypeVar('T')

# Maximum retry attempts for transient database errors
MAX_DB_RETRIES = 3

# Base delay for exponential backoff (seconds)
DB_RETRY_BASE_DELAY = 0.5

# Exceptions that should trigger a retry
RETRYABLE_DB_EXCEPTIONS = (OperationalError,)


def with_db_retry(func: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator that adds retry logic for transient database errors.

    Retries on connection errors and deadlocks but not on
    constraint violations or other permanent errors.

    Args:
        func: Database function to wrap with retry logic.

    Returns:
        Wrapped function with retry capability.
    """
    @wraps(func)
    def wrapper(*args, **kwargs) -> T:
        last_exception = None

        for attempt in range(1, MAX_DB_RETRIES + 1):
            try:
                return func(*args, **kwargs)
            except RETRYABLE_DB_EXCEPTIONS as e:
                last_exception = e
                if attempt < MAX_DB_RETRIES:
                    delay = DB_RETRY_BASE_DELAY * (2 ** (attempt - 1))
                    logger.warning(
                        f"Database retry {attempt}/{MAX_DB_RETRIES} for {func.__name__} "
                        f"after {delay:.2f}s. Error: {e}"
                    )
                    time.sleep(delay)
                else:
                    logger.error(
                        f"All {MAX_DB_RETRIES} database retries exhausted for {func.__name__}"
                    )
            except IntegrityError as e:
                # Don't retry constraint violations
                logger.error(f"Database integrity error in {func.__name__}: {e}")
                raise
            except SQLAlchemyError as e:
                # Log and re-raise other SQLAlchemy errors
                logger.error(f"Database error in {func.__name__}: {e}")
                raise

        # All retries exhausted
        if last_exception:
            raise last_exception
        raise SQLAlchemyError(f"Unexpected database error in {func.__name__}")

    return wrapper


class Scan(Base):
    """Scan record model."""

    __tablename__ = 'scans'

    scan_id = Column(String(36), primary_key=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    engines_used = Column(Text)  # JSON array
    query = Column(Text)
    template_name = Column(String(255))
    total_results = Column(Integer, default=0)
    duration_seconds = Column(Float)
    status = Column(String(50), default='running')  # running, completed, failed, partial
    extra_data = Column(Text)  # JSON

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'scan_id': self.scan_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'engines_used': json.loads(self.engines_used) if self.engines_used else [],
            'query': self.query,
            'template_name': self.template_name,
            'total_results': self.total_results,
            'duration_seconds': self.duration_seconds,
            'status': self.status,
            'metadata': json.loads(self.extra_data) if self.extra_data else {}
        }


class Finding(Base):
    """Finding record model."""

    __tablename__ = 'findings'

    finding_id = Column(String(36), primary_key=True)
    scan_id = Column(String(36), ForeignKey('scans.scan_id'), nullable=False)
    source_engine = Column(String(50))
    target_ip = Column(String(45), nullable=False)  # Support IPv6
    target_port = Column(Integer, nullable=False)
    target_hostname = Column(String(255))
    service = Column(String(255))
    banner = Column(Text)
    risk_score = Column(Float, default=0.0)
    vulnerabilities = Column(Text)  # JSON array
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50), default='new')  # new, confirmed, false_positive, remediated
    confidence = Column(Integer, default=100)
    extra_data = Column(Text)  # JSON

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    # Indexes
    __table_args__ = (
        Index('idx_findings_risk', risk_score.desc()),
        Index('idx_findings_timestamp', first_seen.desc()),
        Index('idx_findings_ip', target_ip),
        Index('idx_findings_status', status),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'finding_id': self.finding_id,
            'scan_id': self.scan_id,
            'source_engine': self.source_engine,
            'target_ip': self.target_ip,
            'target_port': self.target_port,
            'target_hostname': self.target_hostname,
            'service': self.service,
            'banner': self.banner,
            'risk_score': self.risk_score,
            'vulnerabilities': json.loads(self.vulnerabilities) if self.vulnerabilities else [],
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'status': self.status,
            'confidence': self.confidence,
            'metadata': json.loads(self.extra_data) if self.extra_data else {}
        }

    @classmethod
    def from_search_result(cls, result: SearchResult, scan_id: str) -> 'Finding':
        """Create Finding from SearchResult."""
        return cls(
            finding_id=str(uuid.uuid4()),
            scan_id=scan_id,
            source_engine=result.source_engine,
            target_ip=result.ip,
            target_port=result.port,
            target_hostname=result.hostname,
            service=result.service,
            banner=result.banner,
            risk_score=result.risk_score,
            vulnerabilities=json.dumps(result.vulnerabilities),
            confidence=result.confidence,
            extra_data=json.dumps(result.metadata)
        )


class Database:
    """
    Database manager for AASRT with connection pooling and retry logic.

    This class provides a thread-safe database layer with:
    - Connection pooling for efficient resource usage
    - Automatic retry on transient failures
    - Context managers for proper session cleanup
    - Support for SQLite and PostgreSQL

    Attributes:
        config: Configuration instance.
        engine: SQLAlchemy engine with connection pool.
        Session: Scoped session factory.

    Example:
        >>> db = Database()
        >>> with db.session_scope() as session:
        ...     scan = Scan(scan_id="123", ...)
        ...     session.add(scan)
        >>> # Session is automatically committed and closed
    """

    # Connection pool settings
    POOL_SIZE = 5
    MAX_OVERFLOW = 10
    POOL_TIMEOUT = 30
    POOL_RECYCLE = 3600  # Recycle connections after 1 hour

    def __init__(self, config: Optional[Config] = None) -> None:
        """
        Initialize database connection with connection pooling.

        Args:
            config: Configuration instance. If None, uses default Config.

        Raises:
            SQLAlchemyError: If database connection fails.
        """
        self.config = config or Config()
        self.engine = None
        self.Session = None
        self._db_type: str = "unknown"
        self._initialize()

    def _initialize(self) -> None:
        """
        Initialize database connection, pooling, and create tables.

        Sets up connection pooling appropriate for the database type:
        - SQLite: Uses StaticPool for thread safety
        - PostgreSQL: Uses QueuePool with configurable size
        """
        self._db_type = self.config.get('database', 'type', default='sqlite')

        if self._db_type == 'sqlite':
            db_path = self.config.get('database', 'sqlite', 'path', default='./data/scanner.db')
            # Ensure directory exists
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            connection_string = f"sqlite:///{db_path}"

            # SQLite configuration - use StaticPool for thread safety
            # Also enable WAL mode for better concurrent access
            self.engine = create_engine(
                connection_string,
                echo=False,
                poolclass=StaticPool,
                connect_args={
                    "check_same_thread": False,
                    "timeout": 30
                }
            )

            # Enable WAL mode for better concurrent access
            @event.listens_for(self.engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

        else:
            # PostgreSQL with connection pooling
            host = self.config.get('database', 'postgresql', 'host', default='localhost')
            port = self.config.get('database', 'postgresql', 'port', default=5432)
            database = self.config.get('database', 'postgresql', 'database', default='aasrt')
            user = self.config.get('database', 'postgresql', 'user')
            password = self.config.get('database', 'postgresql', 'password')
            ssl_mode = self.config.get('database', 'postgresql', 'ssl_mode', default='prefer')

            # Mask password in logs
            safe_conn_str = f"postgresql://{user}:***@{host}:{port}/{database}"
            connection_string = f"postgresql://{user}:{password}@{host}:{port}/{database}?sslmode={ssl_mode}"

            self.engine = create_engine(
                connection_string,
                echo=False,
                poolclass=QueuePool,
                pool_size=self.POOL_SIZE,
                max_overflow=self.MAX_OVERFLOW,
                pool_timeout=self.POOL_TIMEOUT,
                pool_recycle=self.POOL_RECYCLE,
                pool_pre_ping=True  # Verify connections before use
            )
            logger.debug(f"PostgreSQL connection: {safe_conn_str}")

        # Use scoped_session for thread safety
        self.Session = scoped_session(sessionmaker(bind=self.engine))

        # Create tables
        Base.metadata.create_all(self.engine)
        logger.info(f"Database initialized: {self._db_type}")

    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """
        Provide a transactional scope around a series of operations.

        This context manager handles session lifecycle:
        - Creates a new session
        - Commits on success
        - Rolls back on exception
        - Always closes the session

        Yields:
            SQLAlchemy Session object.

        Raises:
            SQLAlchemyError: On database errors (after rollback).

        Example:
            >>> with db.session_scope() as session:
            ...     session.add(Scan(...))
            ...     # Automatically committed if no exception
        """
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error, rolling back: {e}")
            raise
        finally:
            session.close()

    def get_session(self) -> Session:
        """
        Get a database session (legacy method).

        Note:
            Prefer using session_scope() context manager for new code.
            This method is kept for backward compatibility.

        Returns:
            SQLAlchemy Session object.
        """
        return self.Session()

    def close(self) -> None:
        """
        Close all database connections and cleanup resources.

        Call this method during application shutdown to properly
        release database connections.
        """
        if self.Session:
            self.Session.remove()
        if self.engine:
            self.engine.dispose()
            logger.info("Database connections closed")

    def health_check(self) -> Dict[str, Any]:
        """
        Perform a health check on the database connection.

        Returns:
            Dictionary with health status:
                - healthy: bool indicating if database is accessible
                - db_type: Database type (sqlite/postgresql)
                - latency_ms: Response time in milliseconds
                - error: Error message if unhealthy (optional)
        """
        start_time = time.time()
        try:
            with self.session_scope() as session:
                # Simple query to verify connection
                session.execute("SELECT 1")

            latency = (time.time() - start_time) * 1000
            return {
                "healthy": True,
                "db_type": self._db_type,
                "latency_ms": round(latency, 2),
                "pool_size": getattr(self.engine.pool, 'size', lambda: 'N/A')() if hasattr(self.engine, 'pool') else 'N/A'
            }
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            logger.error(f"Database health check failed: {e}")
            return {
                "healthy": False,
                "db_type": self._db_type,
                "latency_ms": round(latency, 2),
                "error": str(e)
            }

    # =========================================================================
    # Scan Operations
    # =========================================================================

    @with_db_retry
    def create_scan(
        self,
        engines: List[str],
        query: Optional[str] = None,
        template_name: Optional[str] = None
    ) -> Scan:
        """
        Create a new scan record in the database.

        Args:
            engines: List of engine names used for the scan (e.g., ["shodan"]).
            query: Search query string (if using custom query).
            template_name: Template name (if using predefined template).

        Returns:
            Created Scan object with generated scan_id.

        Raises:
            SQLAlchemyError: If database operation fails.

        Example:
            >>> scan = db.create_scan(engines=["shodan"], template_name="clawdbot")
            >>> print(scan.scan_id)
        """
        scan = Scan(
            scan_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            engines_used=json.dumps(engines),
            query=query,
            template_name=template_name,
            status='running'
        )

        with self.session_scope() as session:
            session.add(scan)
            # Flush to ensure data is written before expunge
            session.flush()
            logger.info(f"Created scan: {scan.scan_id}")
            # Need to expunge to use outside session
            session.expunge(scan)
            return scan

    @with_db_retry
    def update_scan(
        self,
        scan_id: str,
        status: Optional[str] = None,
        total_results: Optional[int] = None,
        duration_seconds: Optional[float] = None,
        metadata: Optional[Dict] = None
    ) -> Optional[Scan]:
        """
        Update a scan record with new values.

        Args:
            scan_id: UUID of the scan to update.
            status: New status (running, completed, failed, partial).
            total_results: Number of results found.
            duration_seconds: Total scan duration.
            metadata: Additional metadata to merge.

        Returns:
            Updated Scan object, or None if scan not found.
        """
        with self.session_scope() as session:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            if not scan:
                logger.warning(f"Scan not found for update: {scan_id}")
                return None

            if status:
                scan.status = status
            if total_results is not None:
                scan.total_results = total_results
            if duration_seconds is not None:
                scan.duration_seconds = duration_seconds
            if metadata:
                existing = json.loads(scan.extra_data) if scan.extra_data else {}
                existing.update(metadata)
                scan.extra_data = json.dumps(existing)

            # Flush to ensure changes are written before expunge
            session.flush()
            logger.debug(f"Updated scan {scan_id}: status={status}, results={total_results}")
            session.expunge(scan)
            return scan

    @with_db_retry
    def get_scan(self, scan_id: str) -> Optional[Scan]:
        """
        Get a scan by its UUID.

        Args:
            scan_id: UUID of the scan.

        Returns:
            Scan object or None if not found.
        """
        with self.session_scope() as session:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan:
                session.expunge(scan)
            return scan

    @with_db_retry
    def get_recent_scans(self, limit: int = 10) -> List[Scan]:
        """
        Get the most recent scans.

        Args:
            limit: Maximum number of scans to return.

        Returns:
            List of Scan objects ordered by timestamp descending.
        """
        with self.session_scope() as session:
            scans = session.query(Scan).order_by(Scan.timestamp.desc()).limit(limit).all()
            for scan in scans:
                session.expunge(scan)
            return scans

    @with_db_retry
    def delete_scan(self, scan_id: str) -> bool:
        """
        Delete a scan and all its associated findings.

        Args:
            scan_id: UUID of the scan to delete.

        Returns:
            True if scan was deleted, False if not found.
        """
        with self.session_scope() as session:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan:
                session.delete(scan)
                # Note: session_scope() commits automatically on successful exit
                logger.info(f"Deleted scan: {scan_id}")
                return True
            return False

    # =========================================================================
    # Finding Operations
    # =========================================================================

    @with_db_retry
    def add_findings(self, scan_id: str, results: List[SearchResult]) -> int:
        """
        Add findings from search results to the database.

        Args:
            scan_id: Parent scan UUID.
            results: List of SearchResult objects to store.

        Returns:
            Number of findings successfully added.

        Raises:
            SQLAlchemyError: If database operation fails.

        Note:
            Findings are added in batches for efficiency.
        """
        if not results:
            logger.debug(f"No findings to add for scan {scan_id}")
            return 0

        with self.session_scope() as session:
            count = 0
            for result in results:
                try:
                    finding = Finding.from_search_result(result, scan_id)
                    session.add(finding)
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to create finding from result: {e}")
                    continue

            logger.info(f"Added {count} findings to scan {scan_id}")
            return count

    @with_db_retry
    def get_findings(
        self,
        scan_id: Optional[str] = None,
        min_risk_score: Optional[float] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Finding]:
        """
        Get findings with optional filters.

        Args:
            scan_id: Filter by scan UUID.
            min_risk_score: Minimum risk score (0.0-10.0).
            status: Finding status filter (new, confirmed, false_positive, remediated).
            limit: Maximum results to return.
            offset: Number of results to skip (for pagination).

        Returns:
            List of Finding objects matching filters, ordered by risk score descending.
        """
        with self.session_scope() as session:
            query = session.query(Finding)

            if scan_id:
                query = query.filter(Finding.scan_id == scan_id)
            if min_risk_score is not None:
                query = query.filter(Finding.risk_score >= min_risk_score)
            if status:
                query = query.filter(Finding.status == status)

            query = query.order_by(Finding.risk_score.desc())
            findings = query.offset(offset).limit(limit).all()

            for finding in findings:
                session.expunge(finding)
            return findings

    @with_db_retry
    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """
        Get a single finding by its UUID.

        Args:
            finding_id: UUID of the finding.

        Returns:
            Finding object or None if not found.
        """
        with self.session_scope() as session:
            finding = session.query(Finding).filter(Finding.finding_id == finding_id).first()
            if finding:
                session.expunge(finding)
            return finding

    @with_db_retry
    def update_finding_status(self, finding_id: str, status: str) -> bool:
        """
        Update the status of a finding.

        Args:
            finding_id: UUID of the finding.
            status: New status (new, confirmed, false_positive, remediated).

        Returns:
            True if finding was updated, False if not found.
        """
        with self.session_scope() as session:
            finding = session.query(Finding).filter(Finding.finding_id == finding_id).first()
            if finding:
                finding.status = status
                finding.last_seen = datetime.utcnow()
                logger.debug(f"Updated finding {finding_id} status to {status}")
                return True
            logger.warning(f"Finding not found for status update: {finding_id}")
            return False

    @with_db_retry
    def get_finding_by_target(self, ip: str, port: int) -> Optional[Finding]:
        """
        Get the most recent finding for a specific target.

        Args:
            ip: Target IP address.
            port: Target port number.

        Returns:
            Most recent Finding for the target, or None if not found.
        """
        with self.session_scope() as session:
            finding = session.query(Finding).filter(
                Finding.target_ip == ip,
                Finding.target_port == port
            ).order_by(Finding.last_seen.desc()).first()
            if finding:
                session.expunge(finding)
            return finding

    # =========================================================================
    # Statistics and Maintenance
    # =========================================================================

    @with_db_retry
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get overall database statistics.

        Returns:
            Dictionary containing:
                - total_scans: Total number of scans
                - total_findings: Total number of findings
                - unique_ips: Count of unique IP addresses
                - risk_distribution: Dict with critical/high/medium/low counts
                - last_scan_time: Timestamp of most recent scan (or None)

        Example:
            >>> stats = db.get_statistics()
            >>> print(f"Critical findings: {stats['risk_distribution']['critical']}")
        """
        with self.session_scope() as session:
            total_scans = session.query(Scan).count()
            total_findings = session.query(Finding).count()

            # Risk distribution using CVSS-like thresholds
            critical = session.query(Finding).filter(Finding.risk_score >= 9.0).count()
            high = session.query(Finding).filter(
                Finding.risk_score >= 7.0,
                Finding.risk_score < 9.0
            ).count()
            medium = session.query(Finding).filter(
                Finding.risk_score >= 4.0,
                Finding.risk_score < 7.0
            ).count()
            low = session.query(Finding).filter(Finding.risk_score < 4.0).count()

            # Unique IPs discovered
            unique_ips = session.query(Finding.target_ip).distinct().count()

            # Last scan timestamp
            last_scan = session.query(Scan).order_by(Scan.timestamp.desc()).first()
            last_scan_time = last_scan.timestamp.isoformat() if last_scan else None

            return {
                'total_scans': total_scans,
                'total_findings': total_findings,
                'unique_ips': unique_ips,
                'risk_distribution': {
                    'critical': critical,
                    'high': high,
                    'medium': medium,
                    'low': low
                },
                'last_scan_time': last_scan_time
            }

    @with_db_retry
    def cleanup_old_data(self, days: int = 90) -> int:
        """
        Remove scan data older than specified days.

        This is a maintenance operation that removes old scans and their
        associated findings to manage database size.

        Args:
            days: Age threshold in days. Scans older than this will be deleted.
                  Default is 90 days.

        Returns:
            Number of scans deleted (findings are cascade deleted).

        Raises:
            ValueError: If days is less than 1.
            SQLAlchemyError: If database operation fails.

        Example:
            >>> # Remove data older than 30 days
            >>> deleted = db.cleanup_old_data(days=30)
            >>> print(f"Removed {deleted} old scans")
        """
        if days < 1:
            raise ValueError("Days must be at least 1")

        cutoff = datetime.utcnow() - timedelta(days=days)
        logger.info(f"Cleaning up data older than {cutoff.isoformat()}")

        with self.session_scope() as session:
            # Count first for logging
            old_scans = session.query(Scan).filter(Scan.timestamp < cutoff).all()
            count = len(old_scans)

            if count == 0:
                logger.info("No old data to clean up")
                return 0

            for scan in old_scans:
                session.delete(scan)

            logger.info(f"Cleaned up {count} scans older than {days} days")
            return count
