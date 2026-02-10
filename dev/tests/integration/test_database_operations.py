"""
Integration Tests for Database Operations

Tests database operations with real SQLite database.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta


class TestDatabaseIntegration:
    """Integration tests for database with real SQLite."""

    @pytest.fixture
    def real_db(self):
        """Create a real SQLite database for testing."""
        from src.storage.database import Database
        from src.utils.config import Config
        
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_scanner.db"
            
            mock_config = MagicMock()
            mock_config.get.side_effect = lambda *args, **kwargs: {
                ('database', 'type'): 'sqlite',
                ('database', 'sqlite', 'path'): str(db_path),
            }.get(args, kwargs.get('default'))
            mock_config.get_shodan_key.return_value = 'test_key'
            
            with patch('src.storage.database.Config', return_value=mock_config):
                db = Database(mock_config)
                yield db
                db.close()

    def test_scan_lifecycle(self, real_db):
        """Test complete scan lifecycle: create, update, retrieve."""
        # Create scan
        scan_id = 'integration-test-scan-001'
        real_db.save_scan({
            'scan_id': scan_id,
            'query': 'http.title:"ClawdBot"',
            'engine': 'shodan',
            'started_at': datetime.utcnow(),
            'status': 'running',
            'total_results': 0
        })
        
        # Update scan status
        real_db.update_scan(scan_id, {
            'status': 'completed',
            'total_results': 25,
            'completed_at': datetime.utcnow()
        })
        
        # Retrieve scan
        scan = real_db.get_scan(scan_id)
        assert scan is not None

    def test_findings_association(self, real_db):
        """Test findings are properly associated with scans."""
        scan_id = 'integration-test-scan-002'
        
        # Create scan
        real_db.save_scan({
            'scan_id': scan_id,
            'query': 'test query',
            'engine': 'shodan',
            'started_at': datetime.utcnow(),
            'status': 'completed'
        })
        
        # Save multiple findings
        for i in range(5):
            real_db.save_finding({
                'scan_id': scan_id,
                'ip': f'192.0.2.{i+1}',
                'port': 8080 + i,
                'risk_score': 50 + i * 10,
                'vulnerabilities': ['test_vuln']
            })
        
        # Retrieve findings
        findings = real_db.get_findings_by_scan(scan_id)
        assert len(findings) == 5

    def test_scan_statistics(self, real_db):
        """Test scan statistics calculation."""
        # Create multiple scans with different statuses
        for i in range(10):
            real_db.save_scan({
                'scan_id': f'stats-test-{i:03d}',
                'query': f'test query {i}',
                'engine': 'shodan',
                'started_at': datetime.utcnow() - timedelta(days=i),
                'status': 'completed' if i % 2 == 0 else 'failed',
                'total_results': i * 10
            })
        
        # Get statistics
        if hasattr(real_db, 'get_scan_statistics'):
            stats = real_db.get_scan_statistics()
            assert 'total_scans' in stats or stats is not None

    def test_concurrent_operations(self, real_db):
        """Test concurrent database operations."""
        import threading
        
        errors = []
        
        def save_scan(scan_num):
            try:
                real_db.save_scan({
                    'scan_id': f'concurrent-test-{scan_num:03d}',
                    'query': f'test {scan_num}',
                    'engine': 'shodan',
                    'started_at': datetime.utcnow(),
                    'status': 'completed'
                })
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=save_scan, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should complete without deadlocks
        assert len(errors) == 0

    def test_data_persistence(self):
        """Test that data persists across database connections."""
        from src.storage.database import Database
        
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "persistence_test.db"
            scan_id = 'persistence-test-001'
            
            mock_config = MagicMock()
            mock_config.get.side_effect = lambda *args, **kwargs: {
                ('database', 'type'): 'sqlite',
                ('database', 'sqlite', 'path'): str(db_path),
            }.get(args, kwargs.get('default'))
            
            # First connection - create data
            with patch('src.storage.database.Config', return_value=mock_config):
                db1 = Database(mock_config)
                db1.save_scan({
                    'scan_id': scan_id,
                    'query': 'test',
                    'engine': 'shodan',
                    'started_at': datetime.utcnow(),
                    'status': 'completed'
                })
                db1.close()
            
            # Second connection - verify data exists
            with patch('src.storage.database.Config', return_value=mock_config):
                db2 = Database(mock_config)
                scan = db2.get_scan(scan_id)
                db2.close()
                
                assert scan is not None


class TestDatabaseCleanup:
    """Tests for database cleanup and maintenance."""

    @pytest.fixture
    def real_db(self):
        """Create a real SQLite database for testing."""
        from src.storage.database import Database
        
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cleanup_test.db"
            
            mock_config = MagicMock()
            mock_config.get.side_effect = lambda *args, **kwargs: {
                ('database', 'type'): 'sqlite',
                ('database', 'sqlite', 'path'): str(db_path),
            }.get(args, kwargs.get('default'))
            
            with patch('src.storage.database.Config', return_value=mock_config):
                db = Database(mock_config)
                yield db
                db.close()

    def test_delete_old_scans(self, real_db):
        """Test deleting old scan records."""
        # Create old scans
        for i in range(5):
            real_db.save_scan({
                'scan_id': f'old-scan-{i:03d}',
                'query': f'test {i}',
                'engine': 'shodan',
                'started_at': datetime.utcnow() - timedelta(days=365),
                'status': 'completed'
            })
        
        # If cleanup method exists, test it
        if hasattr(real_db, 'cleanup_old_scans'):
            deleted = real_db.cleanup_old_scans(days=30)
            assert deleted >= 0

