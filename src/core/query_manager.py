"""Query management and execution for AASRT."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from src.engines import SearchResult, ShodanEngine
from src.utils.config import Config
from src.utils.logger import get_logger
from src.utils.exceptions import APIException, ConfigurationException

logger = get_logger(__name__)


class QueryManager:
    """Manages search queries using Shodan."""

    # Built-in query templates
    DEFAULT_TEMPLATES = {
        "clawdbot_instances": [
            'http.title:"ClawdBot Dashboard"',
            'http.html:"ClawdBot" port:3000',
            'product:"ClawdBot"'
        ],
        "autogpt_instances": [
            'http.title:"Auto-GPT"',
            'http.html:"autogpt" port:8000'
        ],
        "langchain_agents": [
            'http.html:"langchain" http.html:"agent"',
            'product:"LangChain"'
        ],
        "openai_exposed": [
            'http.title:"OpenAI Playground"',
            'http.html:"sk-" http.html:"openai"'
        ],
        "exposed_env_files": [
            'http.html:".env" http.html:"API_KEY"',
            'http.title:"Index of" http.html:".env"'
        ],
        "debug_mode": [
            'http.html:"DEBUG=True"',
            'http.html:"development mode"',
            'http.html:"stack trace"'
        ],
        "ai_dashboards": [
            'http.title:"AI Dashboard"',
            'http.title:"LLM" http.html:"chat"',
            'http.html:"anthropic" http.html:"claude"'
        ],
        "jupyter_notebooks": [
            'http.title:"Jupyter Notebook"',
            'http.title:"JupyterLab"',
            'http.html:"jupyter" port:8888'
        ],
        "streamlit_apps": [
            'http.html:"streamlit"',
            'http.title:"Streamlit"'
        ]
    }

    def __init__(self, config: Optional[Config] = None):
        """
        Initialize QueryManager.

        Args:
            config: Configuration instance
        """
        self.config = config or Config()
        self.engine: Optional[ShodanEngine] = None
        self.templates: Dict[str, List[str]] = self.DEFAULT_TEMPLATES.copy()

        self._initialize_engine()
        self._load_custom_templates()

    def _initialize_engine(self) -> None:
        """Initialize Shodan engine."""
        api_key = self.config.get_shodan_key()
        if api_key:
            shodan_config = self.config.get_shodan_config()
            self.engine = ShodanEngine(
                api_key=api_key,
                rate_limit=shodan_config.get('rate_limit', 1.0),
                timeout=shodan_config.get('timeout', 30),
                max_results=shodan_config.get('max_results', 100)
            )
            logger.info("Shodan engine initialized")
        else:
            logger.warning("Shodan API key not provided")

    def _load_custom_templates(self) -> None:
        """Load custom query templates from YAML files."""
        queries_dir = Path("queries")
        if not queries_dir.exists():
            return

        for yaml_file in queries_dir.glob("*.yaml"):
            try:
                with open(yaml_file, 'r') as f:
                    data = yaml.safe_load(f)
                    if data and 'queries' in data:
                        template_name = yaml_file.stem
                        # Support both list format and dict format
                        queries = data['queries']
                        if isinstance(queries, dict) and 'shodan' in queries:
                            self.templates[template_name] = queries['shodan']
                        elif isinstance(queries, list):
                            self.templates[template_name] = queries
                        logger.debug(f"Loaded query template: {template_name}")
            except yaml.YAMLError as e:
                logger.error(f"Failed to parse {yaml_file}: {e}")

    def is_available(self) -> bool:
        """Check if Shodan engine is available."""
        return self.engine is not None

    def get_available_templates(self) -> List[str]:
        """Get list of available query templates."""
        return list(self.templates.keys())

    def validate_engine(self) -> bool:
        """
        Validate Shodan credentials.

        Returns:
            True if credentials are valid
        """
        if not self.engine:
            return False
        try:
            return self.engine.validate_credentials()
        except Exception as e:
            logger.error(f"Failed to validate Shodan: {e}")
            return False

    def get_quota_info(self) -> Dict[str, Any]:
        """Get Shodan API quota information."""
        if not self.engine:
            return {'error': 'Engine not initialized'}
        return self.engine.get_quota_info()

    def execute_query(
        self,
        query: str,
        max_results: Optional[int] = None
    ) -> List[SearchResult]:
        """
        Execute a search query.

        Args:
            query: Shodan search query
            max_results: Maximum results to return

        Returns:
            List of SearchResult objects
        """
        if not self.engine:
            raise ConfigurationException("Shodan engine not initialized. Check your API key.")

        try:
            results = self.engine.search(query, max_results)
            logger.info(f"Query returned {len(results)} results")
            return results
        except APIException as e:
            logger.error(f"Query failed: {e}")
            raise

    def execute_template(
        self,
        template_name: str,
        max_results: Optional[int] = None
    ) -> List[SearchResult]:
        """
        Execute all queries from a template.

        Args:
            template_name: Name of the query template
            max_results: Maximum results per query

        Returns:
            Combined list of results from all queries
        """
        if template_name not in self.templates:
            raise ConfigurationException(f"Template not found: {template_name}")

        if not self.engine:
            raise ConfigurationException("Shodan engine not initialized. Check your API key.")

        queries = self.templates[template_name]
        all_results = []

        for query in queries:
            try:
                results = self.engine.search(query, max_results)
                all_results.extend(results)
            except APIException as e:
                logger.error(f"Query failed: {query} - {e}")

        logger.info(f"Template '{template_name}' returned {len(all_results)} total results")
        return all_results

    def count_results(self, query: str) -> int:
        """
        Get count of results for a query without consuming credits.

        Args:
            query: Search query

        Returns:
            Number of results
        """
        if not self.engine:
            return 0
        return self.engine.count(query)

    def add_custom_template(self, name: str, queries: List[str]) -> None:
        """
        Add a custom query template.

        Args:
            name: Template name
            queries: List of Shodan queries
        """
        self.templates[name] = queries
        logger.info(f"Added custom template: {name}")

    def save_template(self, name: str, path: Optional[str] = None) -> None:
        """
        Save a template to a YAML file.

        Args:
            name: Template name
            path: Output file path (default: queries/{name}.yaml)
        """
        if name not in self.templates:
            raise ConfigurationException(f"Template not found: {name}")

        output_path = path or f"queries/{name}.yaml"
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        template_data = {
            'name': name,
            'description': f"Query template for {name}",
            'queries': self.templates[name]
        }

        with open(output_path, 'w') as f:
            yaml.dump(template_data, f, default_flow_style=False)

        logger.info(f"Saved template to {output_path}")
