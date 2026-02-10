"""
Integration Tests for Scan Workflow

Tests the complete scan workflow from query to report generation.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
from datetime import datetime


class TestEndToEndScan:
    """Integration tests for complete scan workflow."""

    @pytest.fixture
    def mock_shodan_response(self, sample_search_results):
        """Mock Shodan API response."""
        return {
            'matches': sample_search_results,
            'total': len(sample_search_results)
        }

    @pytest.fixture
    def temp_workspace(self):
        """Create temporary workspace for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / 'reports').mkdir()
            (workspace / 'data').mkdir()
            (workspace / 'logs').mkdir()
            yield workspace

    def test_scan_template_workflow(self, mock_shodan_response, temp_workspace):
        """Test scanning using a template."""
        from unittest.mock import patch, MagicMock
        
        mock_client = MagicMock()
        mock_client.info.return_value = {'plan': 'dev', 'query_credits': 100}
        mock_client.search.return_value = mock_shodan_response
        
        with patch('shodan.Shodan', return_value=mock_client):
            with patch.dict('os.environ', {
                'SHODAN_API_KEY': 'test_key_12345',
                'AASRT_REPORTS_DIR': str(temp_workspace / 'reports'),
                'AASRT_DATA_DIR': str(temp_workspace / 'data'),
            }):
                # Import after patching
                from src.core.query_manager import QueryManager
                from src.utils.config import Config
                
                config = Config()
                qm = QueryManager(config)
                
                # Check templates are available
                templates = qm.get_available_templates()
                assert len(templates) > 0

    def test_custom_query_workflow(self, mock_shodan_response, temp_workspace):
        """Test scanning with a custom query."""
        mock_client = MagicMock()
        mock_client.info.return_value = {'plan': 'dev', 'query_credits': 100}
        mock_client.search.return_value = mock_shodan_response
        
        with patch('shodan.Shodan', return_value=mock_client):
            with patch.dict('os.environ', {
                'SHODAN_API_KEY': 'test_key_12345',
            }):
                from src.engines.shodan_engine import ShodanEngine
                from src.utils.config import Config
                
                config = Config()
                engine = ShodanEngine(config=config)
                engine._client = mock_client
                
                results = engine.search('http.title:"Test"')
                assert len(results) > 0


class TestVulnerabilityAssessmentIntegration:
    """Integration tests for vulnerability assessment pipeline."""

    def test_assess_search_results(self, sample_search_results):
        """Test vulnerability assessment on search results."""
        from src.core.vulnerability_assessor import VulnerabilityAssessor
        from src.engines.base import SearchResult
        
        assessor = VulnerabilityAssessor()
        
        # Convert sample data to SearchResult
        result = SearchResult(
            ip=sample_search_results[0]['ip_str'],
            port=sample_search_results[0]['port'],
            protocol='tcp',
            banner=sample_search_results[0].get('data', ''),
            metadata=sample_search_results[0]
        )
        
        vulns = assessor.assess(result)
        # Should return a list (may be empty if no vulns detected)
        assert isinstance(vulns, list)

    def test_risk_scoring_integration(self, sample_search_results):
        """Test risk scoring on assessed results."""
        from src.core.risk_scorer import RiskScorer
        from src.core.vulnerability_assessor import VulnerabilityAssessor
        from src.engines.base import SearchResult
        
        assessor = VulnerabilityAssessor()
        scorer = RiskScorer()
        
        result = SearchResult(
            ip=sample_search_results[0]['ip_str'],
            port=sample_search_results[0]['port'],
            protocol='tcp',
            banner=sample_search_results[0].get('data', ''),
            metadata=sample_search_results[0]
        )
        
        vulns = assessor.assess(result)
        score = scorer.score(result)
        
        assert 0 <= score <= 100


class TestReportGenerationIntegration:
    """Integration tests for report generation."""

    @pytest.fixture
    def temp_reports_dir(self):
        """Create temporary reports directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_json_report_generation(self, temp_reports_dir, sample_search_results):
        """Test JSON report generation."""
        from src.reporting import JSONReporter, ScanReport
        from src.engines.base import SearchResult
        
        # Create scan report data
        results = [
            SearchResult(
                ip=r['ip_str'],
                port=r['port'],
                protocol='tcp',
                banner=r.get('data', ''),
                metadata=r
            ) for r in sample_search_results
        ]
        
        report = ScanReport(
            scan_id='test-scan-001',
            query='test query',
            engine='shodan',
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            results=results,
            total_results=len(results)
        )
        
        reporter = JSONReporter(output_dir=str(temp_reports_dir))
        output_path = reporter.generate(report)
        
        assert Path(output_path).exists()
        assert output_path.endswith('.json')

    def test_csv_report_generation(self, temp_reports_dir, sample_search_results):
        """Test CSV report generation."""
        from src.reporting import CSVReporter, ScanReport
        from src.engines.base import SearchResult
        
        results = [
            SearchResult(
                ip=r['ip_str'],
                port=r['port'],
                protocol='tcp',
                banner=r.get('data', ''),
                metadata=r
            ) for r in sample_search_results
        ]
        
        report = ScanReport(
            scan_id='test-scan-002',
            query='test query',
            engine='shodan',
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            results=results,
            total_results=len(results)
        )
        
        reporter = CSVReporter(output_dir=str(temp_reports_dir))
        output_path = reporter.generate(report)
        
        assert Path(output_path).exists()
        assert output_path.endswith('.csv')

