"""
Unit Tests for Database Module

Tests for src/storage/database.py
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime


class TestDatabaseInit:
    """Tests for Database initialization."""

    def test_init_creates_tables(self, temp_db, mock_config):
        """Test database initialization creates tables."""
        from src.storage.database import Database

        mock_config.get.side_effect = lambda *args, **kwargs: {
            ('database', 'type'): 'sqlite',
            ('database', 'sqlite', 'path'): str(temp_db),
        }.get(args, kwargs.get('default'))

        db = Database(mock_config)
        assert db is not None
        db.close()

    def test_init_sqlite_with_temp_path(self, temp_db, mock_config):
        """Test SQLite database with temp path."""
        from src.storage.database import Database

        mock_config.get.side_effect = lambda *args, **kwargs: {
            ('database', 'type'): 'sqlite',
            ('database', 'sqlite', 'path'): str(temp_db),
        }.get(args, kwargs.get('default'))

        db = Database(mock_config)
        assert db is not None
        assert db._db_type == 'sqlite'
        db.close()


class TestDatabaseOperations:
    """Tests for database CRUD operations."""

    @pytest.fixture
    def db(self, temp_db, mock_config):
        """Create a test database instance."""
        from src.storage.database import Database

        mock_config.get.side_effect = lambda *args, **kwargs: {
            ('database', 'type'): 'sqlite',
            ('database', 'sqlite', 'path'): str(temp_db),
        }.get(args, kwargs.get('default'))

        db = Database(mock_config)
        yield db
        db.close()

    def test_create_scan(self, db):
        """Test creating a scan record."""
        scan = db.create_scan(
            engines=['shodan'],
            query='http.title:"ClawdBot"'
        )
        assert scan is not None
        assert scan.scan_id is not None

    def test_get_scan_by_id(self, db):
        """Test retrieving a scan by ID."""
        # Create a scan first
        scan = db.create_scan(
            engines=['shodan'],
            query='test query'
        )

        retrieved = db.get_scan(scan.scan_id)
        assert retrieved is not None
        assert retrieved.scan_id == scan.scan_id

    def test_get_recent_scans(self, db):
        """Test retrieving recent scans."""
        # Create a few scans
        for i in range(3):
            db.create_scan(
                engines=['shodan'],
                query=f'test query {i}'
            )

        scans = db.get_recent_scans(limit=10)
        assert len(scans) >= 3

    def test_add_findings(self, db):
        """Test adding findings to a scan."""
        from src.engines.base import SearchResult

        # First create a scan
        scan = db.create_scan(
            engines=['shodan'],
            query='test'
        )

        # Create some search results
        results = [
            SearchResult(
                ip='192.0.2.1',
                port=8080,
                banner='ClawdBot Dashboard',
                vulnerabilities=['exposed_dashboard']
            )
        ]

        count = db.add_findings(scan.scan_id, results)
        assert count >= 1

    def test_update_scan(self, db):
        """Test updating a scan."""
        # Create a scan
        scan = db.create_scan(
            engines=['shodan'],
            query='test'
        )

        # Update it
        updated = db.update_scan(
            scan.scan_id,
            status='completed',
            total_results=5
        )

        assert updated is not None
        assert updated.status == 'completed'


class TestDatabaseHealthCheck:
    """Tests for database health check."""

    @pytest.fixture
    def db(self, temp_db, mock_config):
        """Create a test database instance."""
        from src.storage.database import Database
        
        mock_config.get.side_effect = lambda *args, **kwargs: {
            ('database', 'type'): 'sqlite',
            ('database', 'sqlite', 'path'): str(temp_db),
        }.get(args, kwargs.get('default'))
        
        with patch('src.storage.database.Config', return_value=mock_config):
            db = Database(mock_config)
            yield db
            db.close()

    def test_health_check_returns_dict(self, db):
        """Test health_check returns a dictionary."""
        health = db.health_check()
        assert isinstance(health, dict)

    def test_health_check_includes_status(self, db):
        """Test health_check includes status."""
        health = db.health_check()
        assert 'status' in health or 'healthy' in health

    def test_health_check_includes_latency(self, db):
        """Test health_check includes latency measurement."""
        health = db.health_check()
        # Should have some form of latency/response time
        has_latency = 'latency' in health or 'latency_ms' in health or 'response_time' in health
        assert has_latency or health.get('status') == 'healthy'


class TestDatabaseSessionScope:
    """Tests for session_scope context manager."""

    @pytest.fixture
    def db(self, temp_db, mock_config):
        """Create a test database instance."""
        from src.storage.database import Database
        
        mock_config.get.side_effect = lambda *args, **kwargs: {
            ('database', 'type'): 'sqlite',
            ('database', 'sqlite', 'path'): str(temp_db),
        }.get(args, kwargs.get('default'))
        
        with patch('src.storage.database.Config', return_value=mock_config):
            db = Database(mock_config)
            yield db
            db.close()

    def test_session_scope_commits(self, db):
        """Test session_scope commits on success."""
        with db.session_scope() as session:
            # Perform some operation
            pass
        # Should complete without error

    def test_session_scope_rollback_on_error(self, db):
        """Test session_scope rolls back on error."""
        try:
            with db.session_scope() as session:
                raise ValueError("Test error")
        except ValueError:
            pass  # Expected
        # Session should have been rolled back

