"""
CLI entry point for AASRT - AI Agent Security Reconnaissance Tool.

This module provides the command-line interface for AASRT with:
- Shodan-based security reconnaissance scanning
- Vulnerability assessment and risk scoring
- Report generation (JSON/CSV)
- Database storage and history tracking
- Signal handling for graceful shutdown

Usage:
    python -m src.main status         # Check API status
    python -m src.main scan --template clawdbot_instances
    python -m src.main history        # View scan history
    python -m src.main templates      # List available templates

Environment Variables:
    SHODAN_API_KEY: Required for scanning operations
    AASRT_LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR)
    AASRT_DEBUG: Enable debug mode (true/false)

Exit Codes:
    0: Success
    1: Error (invalid arguments, API errors, etc.)
    130: Interrupted by user (SIGINT/Ctrl+C)
"""

import atexit
import signal
import sys
import time
import uuid
from typing import Any, Dict, Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from src import __version__
from src.utils.config import Config
from src.utils.logger import setup_logger, get_logger
from src.core.query_manager import QueryManager
from src.core.result_aggregator import ResultAggregator
from src.core.vulnerability_assessor import VulnerabilityAssessor
from src.core.risk_scorer import RiskScorer
from src.storage.database import Database
from src.reporting import JSONReporter, CSVReporter, ScanReport

# =============================================================================
# Global State
# =============================================================================

console = Console()
_shutdown_requested = False
_active_database: Optional[Database] = None

# =============================================================================
# Signal Handlers
# =============================================================================

def _signal_handler(signum: int, frame: Any) -> None:
    """
    Handle interrupt signals for graceful shutdown.

    Args:
        signum: Signal number received.
        frame: Current stack frame (unused).
    """
    global _shutdown_requested

    signal_name = signal.Signals(signum).name

    if _shutdown_requested:
        # Second interrupt - force exit
        console.print("\n[red]Force shutdown requested. Exiting immediately.[/red]")
        sys.exit(130)

    _shutdown_requested = True
    console.print(f"\n[yellow]Received {signal_name}. Shutting down gracefully...[/yellow]")
    console.print("[dim]Press Ctrl+C again to force quit.[/dim]")


def _cleanup() -> None:
    """
    Cleanup function called on exit.

    Closes database connections and performs cleanup.
    """
    global _active_database

    if _active_database:
        try:
            _active_database.close()
        except Exception:
            pass  # Ignore errors during cleanup


def is_shutdown_requested() -> bool:
    """
    Check if shutdown has been requested.

    Returns:
        True if a shutdown signal was received.
    """
    return _shutdown_requested


# Register signal handlers
signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)
atexit.register(_cleanup)

# =============================================================================
# Legal Disclaimer
# =============================================================================

LEGAL_DISCLAIMER = """
[bold red]WARNING: LEGAL DISCLAIMER[/bold red]

This tool is for [bold]authorized security research and defensive purposes only[/bold].
Unauthorized access to computer systems is illegal under:
- CFAA (Computer Fraud and Abuse Act) - United States
- Computer Misuse Act - United Kingdom
- Similar laws worldwide

By proceeding, you acknowledge that:
1. You have authorization to scan target systems
2. You will comply with all applicable laws and terms of service
3. You will responsibly disclose findings
4. You will not exploit discovered vulnerabilities

[bold yellow]The authors are not responsible for misuse of this tool.[/bold yellow]
"""

# =============================================================================
# CLI Command Group
# =============================================================================

@click.group()
@click.version_option(version=__version__, prog_name="AASRT")
@click.option('--config', '-c', type=click.Path(exists=True), help='Path to config file')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], verbose: bool) -> None:
    """
    AI Agent Security Reconnaissance Tool (AASRT).

    Discover and assess exposed AI agent implementations using Shodan.

    Use 'aasrt --help' for command list or 'aasrt COMMAND --help' for command details.
    """
    ctx.ensure_object(dict)

    # Initialize configuration
    try:
        ctx.obj['config'] = Config(config)
    except Exception as e:
        console.print(f"[red]Failed to load configuration: {e}[/red]")
        sys.exit(1)

    # Setup logging
    log_level = 'DEBUG' if verbose else ctx.obj['config'].get('logging', 'level', default='INFO')
    log_file = ctx.obj['config'].get('logging', 'file')

    try:
        setup_logger('aasrt', level=log_level, log_file=log_file)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not setup logging: {e}[/yellow]")

    ctx.obj['verbose'] = verbose

    # Log startup in debug mode
    logger = get_logger('aasrt')
    logger.debug(f"AASRT v{__version__} starting (verbose={verbose})")


# =============================================================================
# Scan Command
# =============================================================================

@cli.command()
@click.option('--query', '-q', help='Custom Shodan search query')
@click.option('--template', '-t', help='Use predefined query template')
@click.option('--max-results', '-m', default=100, type=int, help='Max results to retrieve (1-10000)')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['json', 'csv', 'both']),
              default='json', help='Output format')
@click.option('--no-assess', is_flag=True, help='Skip vulnerability assessment')
@click.option('--save-db/--no-save-db', default=True, help='Save results to database')
@click.option('--yes', '-y', is_flag=True, help='Skip legal disclaimer confirmation')
@click.pass_context
def scan(
    ctx: click.Context,
    query: Optional[str],
    template: Optional[str],
    max_results: int,
    output: Optional[str],
    output_format: str,
    no_assess: bool,
    save_db: bool,
    yes: bool
) -> None:
    """
    Perform a security reconnaissance scan using Shodan.

    Searches for exposed AI agent implementations and assesses their
    security posture using passive analysis techniques.

    Examples:
        aasrt scan --template clawdbot_instances
        aasrt scan --query 'http.title:"AutoGPT"'
        aasrt scan -t exposed_env_files -m 50 -f csv
    """
    global _active_database

    config = ctx.obj['config']
    logger = get_logger('aasrt')

    logger.info(f"Starting scan command (template={template}, query={query[:50] if query else None})")

    # Display legal disclaimer
    if not yes:
        console.print(Panel(LEGAL_DISCLAIMER, title="Legal Notice", border_style="red"))
        if not click.confirm('\nDo you agree to the terms above?', default=False):
            console.print('[red]Scan aborted. You must agree to terms of use.[/red]')
            logger.info("Scan aborted: User declined legal disclaimer")
            sys.exit(1)

    # Validate max_results
    if max_results < 1:
        console.print('[red]Error: max-results must be at least 1[/red]')
        sys.exit(1)
    if max_results > 10000:
        console.print('[yellow]Warning: Limiting max-results to 10000[/yellow]')
        max_results = 10000

    # Validate inputs
    if not query and not template:
        console.print('[yellow]No query or template specified. Using default template: clawdbot_instances[/yellow]')
        template = 'clawdbot_instances'

    # Check for shutdown before heavy operations
    if is_shutdown_requested():
        console.print('[yellow]Scan cancelled due to shutdown request.[/yellow]')
        sys.exit(130)

    # Initialize query manager
    try:
        query_manager = QueryManager(config)
    except Exception as e:
        console.print(f'[red]Failed to initialize query manager: {e}[/red]')
        logger.error(f"Query manager initialization failed: {e}")
        sys.exit(1)

    # Check if Shodan is available
    if not query_manager.is_available():
        console.print('[red]Shodan is not available. Please check your API key in .env file.[/red]')
        console.print('[dim]Set SHODAN_API_KEY environment variable or add to .env file.[/dim]')
        sys.exit(1)

    console.print('\n[green]Starting Shodan scan...[/green]')
    logger.info(f"Scan started: template={template}, max_results={max_results}")

    # Generate scan ID
    scan_id = str(uuid.uuid4())
    start_time = time.time()

    # Execute scan with interrupt checking
    all_results = []
    scan_error = None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        if template:
            task = progress.add_task(f"[cyan]Scanning with template: {template}...", total=100)
            try:
                if not is_shutdown_requested():
                    all_results = query_manager.execute_template(template, max_results=max_results)
                progress.update(task, completed=100)
            except KeyboardInterrupt:
                console.print('\n[yellow]Scan interrupted by user.[/yellow]')
                scan_error = "Interrupted"
            except Exception as e:
                console.print(f'[red]Template execution failed: {e}[/red]')
                logger.error(f"Template execution error: {e}", exc_info=True)
                scan_error = str(e)
        else:
            task = progress.add_task("[cyan]Executing query...", total=100)
            try:
                if not is_shutdown_requested():
                    all_results = query_manager.execute_query(query, max_results=max_results)
                progress.update(task, completed=100)
            except KeyboardInterrupt:
                console.print('\n[yellow]Scan interrupted by user.[/yellow]')
                scan_error = "Interrupted"
            except Exception as e:
                console.print(f'[red]Query execution failed: {e}[/red]')
                logger.error(f"Query execution error: {e}", exc_info=True)
                scan_error = str(e)

    # Check if scan was interrupted or had errors
    if is_shutdown_requested():
        console.print('[yellow]Scan was interrupted. Saving partial results...[/yellow]')

    # Aggregate and deduplicate results
    console.print('\n[cyan]Aggregating results...[/cyan]')
    aggregator = ResultAggregator()
    unique_results = aggregator.aggregate({'shodan': all_results})

    console.print(f'Found [green]{len(unique_results)}[/green] unique results')
    logger.info(f"Aggregated {len(unique_results)} unique results from {len(all_results)} total")

    # Vulnerability assessment (skip if shutdown requested)
    if not no_assess and unique_results and not is_shutdown_requested():
        console.print('\n[cyan]Assessing vulnerabilities...[/cyan]')
        assessor = VulnerabilityAssessor(config.get('vulnerability_checks', default={}))
        scorer = RiskScorer()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Analyzing...", total=len(unique_results))

            for result in unique_results:
                if is_shutdown_requested():
                    console.print('[yellow]Assessment interrupted.[/yellow]')
                    break
                try:
                    vulns = assessor.assess(result)
                    scorer.score_result(result, vulns)
                except Exception as e:
                    logger.warning(f"Failed to assess result {result.ip}: {e}")
                progress.advance(task)

    # Calculate duration
    duration = time.time() - start_time

    # Determine final status
    final_status = 'completed'
    if scan_error:
        final_status = 'failed' if not unique_results else 'partial'
    elif is_shutdown_requested():
        final_status = 'partial'

    # Create report
    report = ScanReport.from_results(
        scan_id=scan_id,
        results=unique_results,
        engines=['shodan'],
        query=query,
        template_name=template,
        duration=duration
    )

    # Display summary
    _display_summary(report)

    # Save to database
    if save_db:
        try:
            db = Database(config)
            _active_database = db  # Track for cleanup

            scan_record = db.create_scan(
                engines=['shodan'],
                query=query,
                template_name=template
            )

            if unique_results:
                db.add_findings(scan_record.scan_id, unique_results)

            db.update_scan(
                scan_record.scan_id,
                status=final_status,
                total_results=len(unique_results),
                duration_seconds=duration
            )
            console.print(f'\n[green]Results saved to database. Scan ID: {scan_record.scan_id}[/green]')
            logger.info(f"Saved scan {scan_record.scan_id} with {len(unique_results)} findings")
        except Exception as e:
            console.print(f'[yellow]Warning: Failed to save to database: {e}[/yellow]')
            logger.error(f"Database save error: {e}", exc_info=True)

    # Generate reports
    output_dir = config.get('reporting', 'output_dir', default='./reports')

    try:
        if output_format in ['json', 'both']:
            json_reporter = JSONReporter(output_dir)
            json_path = json_reporter.generate(report, output)
            console.print(f'[green]JSON report: {json_path}[/green]')

        if output_format in ['csv', 'both']:
            csv_reporter = CSVReporter(output_dir)
            csv_path = csv_reporter.generate(report, output)
            console.print(f'[green]CSV report: {csv_path}[/green]')
    except Exception as e:
        console.print(f'[yellow]Warning: Failed to generate report: {e}[/yellow]')
        logger.error(f"Report generation error: {e}", exc_info=True)

    # Final status message
    if final_status == 'completed':
        console.print(f'\n[bold green]Scan completed in {duration:.1f} seconds[/bold green]')
    elif final_status == 'partial':
        console.print(f'\n[bold yellow]Scan partially completed in {duration:.1f} seconds[/bold yellow]')
    else:
        console.print(f'\n[bold red]Scan failed after {duration:.1f} seconds[/bold red]')
        sys.exit(1)


# =============================================================================
# Helper Functions
# =============================================================================

def _display_summary(report: ScanReport) -> None:
    """
    Display scan summary in a formatted table.

    Renders a Rich-formatted summary including:
    - Scan ID and duration
    - Total results and average risk score
    - Risk distribution table
    - Top 5 highest risk findings

    Args:
        report: ScanReport object with scan results.
    """
    console.print('\n')

    # Summary panel
    summary_text = f"""
[bold]Scan ID:[/bold] {report.scan_id[:8]}...
[bold]Duration:[/bold] {report.duration_seconds:.1f}s
[bold]Total Results:[/bold] {report.total_results}
[bold]Average Risk Score:[/bold] {report.average_risk_score}/10
    """
    console.print(Panel(summary_text, title="Scan Summary", border_style="green"))

    # Risk distribution table
    table = Table(title="Risk Distribution")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("[red]Critical[/red]", str(report.critical_findings))
    table.add_row("[orange1]High[/orange1]", str(report.high_findings))
    table.add_row("[yellow]Medium[/yellow]", str(report.medium_findings))
    table.add_row("[green]Low[/green]", str(report.low_findings))

    console.print(table)

    # Top findings
    if report.findings:
        console.print('\n[bold]Top 5 Highest Risk Findings:[/bold]')
        top_findings = sorted(
            report.findings,
            key=lambda x: x.get('risk_score', 0),
            reverse=True
        )[:5]

        for i, finding in enumerate(top_findings, 1):
            risk = finding.get('risk_score', 0)
            ip = finding.get('target_ip', 'N/A')
            port = finding.get('target_port', 'N/A')
            hostname = finding.get('target_hostname', '')

            # Color-code by CVSS-like severity
            if risk >= 9.0:
                color = 'red'      # Critical
            elif risk >= 7.0:
                color = 'orange1'  # High
            elif risk >= 4.0:
                color = 'yellow'   # Medium
            else:
                color = 'green'    # Low

            target = f"{ip}:{port}"
            if hostname:
                target += f" ({hostname})"

            console.print(f"  {i}. [{color}]{target}[/{color}] - Risk: [{color}]{risk}[/{color}]")


@cli.command()
@click.option('--scan-id', '-s', help='Generate report for specific scan')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['json', 'csv', 'both']),
              default='json', help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.pass_context
def report(ctx, scan_id, output_format, output):
    """Generate a report from a previous scan."""
    config = ctx.obj['config']

    try:
        db = Database(config)
    except Exception as e:
        console.print(f'[red]Failed to connect to database: {e}[/red]')
        sys.exit(1)

    if scan_id:
        scan = db.get_scan(scan_id)
        if not scan:
            console.print(f'[red]Scan not found: {scan_id}[/red]')
            sys.exit(1)
        scans = [scan]
    else:
        scans = db.get_recent_scans(limit=1)
        if not scans:
            console.print('[yellow]No scans found in database.[/yellow]')
            sys.exit(0)

    scan = scans[0]
    findings = db.get_findings(scan_id=scan.scan_id)

    report_data = ScanReport.from_scan(scan, findings)
    output_dir = config.get('reporting', 'output_dir', default='./reports')

    if output_format in ['json', 'both']:
        json_reporter = JSONReporter(output_dir)
        json_path = json_reporter.generate(report_data, output)
        console.print(f'[green]JSON report: {json_path}[/green]')

    if output_format in ['csv', 'both']:
        csv_reporter = CSVReporter(output_dir)
        csv_path = csv_reporter.generate(report_data, output)
        console.print(f'[green]CSV report: {csv_path}[/green]')


@cli.command()
@click.pass_context
def status(ctx):
    """Show status of Shodan API configuration."""
    config = ctx.obj['config']

    console.print('\n[bold]Shodan API Status[/bold]\n')

    try:
        query_manager = QueryManager(config)
    except Exception as e:
        console.print(f'[red]Failed to initialize: {e}[/red]')
        return

    # Validate Shodan
    table = Table(title="Engine Status")
    table.add_column("Engine", style="bold")
    table.add_column("Status")
    table.add_column("Details")

    if query_manager.is_available():
        is_valid = query_manager.validate_engine()
        if is_valid:
            quota = query_manager.get_quota_info()
            status_str = "[green]OK[/green]"
            details = f"Credits: {quota.get('query_credits', 'N/A')}, Plan: {quota.get('plan', 'N/A')}"
        else:
            status_str = "[red]Invalid[/red]"
            details = "API key validation failed"
    else:
        status_str = "[red]Not Configured[/red]"
        details = "Add SHODAN_API_KEY to .env file"

    table.add_row("Shodan", status_str, details)
    console.print(table)

    # Available templates
    templates = query_manager.get_available_templates()
    console.print(f'\n[bold]Available Query Templates:[/bold] {len(templates)}')
    for template in sorted(templates):
        console.print(f'  - {template}')


@cli.command()
@click.option('--limit', '-l', default=10, help='Number of recent scans to show')
@click.pass_context
def history(ctx, limit):
    """Show scan history from database."""
    config = ctx.obj['config']

    try:
        db = Database(config)
        scans = db.get_recent_scans(limit=limit)
    except Exception as e:
        console.print(f'[red]Failed to access database: {e}[/red]')
        return

    if not scans:
        console.print('[yellow]No scans found in database.[/yellow]')
        return

    table = Table(title=f"Recent Scans (Last {limit})")
    table.add_column("Scan ID", style="cyan")
    table.add_column("Timestamp")
    table.add_column("Template/Query")
    table.add_column("Results", justify="right")
    table.add_column("Status")

    for scan in scans:
        scan_id = scan.scan_id[:8] + "..."
        timestamp = scan.timestamp.strftime("%Y-%m-%d %H:%M") if scan.timestamp else "N/A"
        query_info = scan.template_name or (scan.query[:30] + "..." if scan.query and len(scan.query) > 30 else scan.query) or "N/A"

        status_color = "green" if scan.status == "completed" else "yellow" if scan.status == "running" else "red"
        status_str = f"[{status_color}]{scan.status}[/{status_color}]"

        table.add_row(scan_id, timestamp, query_info, str(scan.total_results), status_str)

    console.print(table)

    # Show database stats
    stats = db.get_statistics()
    console.print(f'\n[bold]Database Statistics:[/bold]')
    console.print(f'  Total Scans: {stats["total_scans"]}')
    console.print(f'  Total Findings: {stats["total_findings"]}')
    console.print(f'  Unique IPs: {stats["unique_ips"]}')


@cli.command()
@click.pass_context
def templates(ctx):
    """List available query templates."""
    config = ctx.obj['config']

    try:
        query_manager = QueryManager(config)
    except Exception as e:
        console.print(f'[red]Failed to initialize: {e}[/red]')
        return

    templates = query_manager.get_available_templates()

    console.print('\n[bold]Available Shodan Query Templates[/bold]\n')

    table = Table()
    table.add_column("Template Name", style="cyan")
    table.add_column("Queries")

    for template_name in sorted(templates):
        queries = query_manager.templates.get(template_name, [])
        query_count = len(queries)
        table.add_row(template_name, f"{query_count} queries")

    console.print(table)

    console.print('\n[dim]Use with: aasrt scan --template <template_name>[/dim]')


# =============================================================================
# Entry Point
# =============================================================================

def main() -> None:
    """
    Main entry point for AASRT CLI.

    Initializes the Click command group and handles top-level exceptions.
    Called when running `python -m src.main` or `aasrt` command.

    Exit Codes:
        0: Success
        1: Error
        130: Interrupted by user
    """
    try:
        cli(obj={})
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        logger = get_logger('aasrt')
        logger.exception(f"Unexpected error: {e}")
        console.print(f"\n[red]Unexpected error: {e}[/red]")
        console.print("[dim]Check logs for details.[/dim]")
        sys.exit(1)


if __name__ == '__main__':
    main()
