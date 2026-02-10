"""
AASRT - AI Agent Security Reconnaissance Tool
Streamlit Web Dashboard - STAR WARS IMPERIAL THEME

This module provides a production-ready Streamlit web interface for AASRT with:
- Interactive security reconnaissance scanning via Shodan
- Real-time vulnerability assessment and risk scoring
- ClawSec threat intelligence integration
- Scan history and database management
- Star Wars Imperial-themed UI

Security Features:
- Input validation on all user inputs
- Rate limiting on scan operations
- Session-based scan tracking
- Secure output encoding (XSS prevention)

Usage:
    streamlit run app.py

Environment Variables:
    SHODAN_API_KEY: Required for scanning operations
    AASRT_LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR)
    STREAMLIT_SERVER_PORT: Server port (default: 8501)
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
import uuid
import json
import os
import re
import textwrap
import html as _html
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

# Load environment variables first
load_dotenv()

# =============================================================================
# Security and Rate Limiting Configuration
# =============================================================================

# Rate limiting: Maximum scans per session
MAX_SCANS_PER_HOUR = int(os.getenv('AASRT_MAX_SCANS_PER_HOUR', '10'))
SCAN_COOLDOWN_SECONDS = int(os.getenv('AASRT_SCAN_COOLDOWN', '30'))

# Input validation limits
MAX_QUERY_LENGTH = 2000
MAX_RESULTS_LIMIT = 10000
MIN_RESULTS = 1

# Valid templates (whitelist for security)
VALID_TEMPLATES: set = set()  # Populated at runtime from query manager


# =============================================================================
# Input Validation Helpers
# =============================================================================

def validate_scan_query(query: Optional[str]) -> tuple[bool, str]:
    """
    Validate a custom Shodan search query.

    Args:
        query: The search query string to validate.

    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is empty.
    """
    if not query:
        return True, ""  # Empty query is valid (will use template)

    if len(query) > MAX_QUERY_LENGTH:
        return False, f"Query too long. Maximum {MAX_QUERY_LENGTH} characters allowed."

    # Check for potentially dangerous patterns
    dangerous_patterns = [
        r'<script',
        r'javascript:',
        r'\x00',  # Null byte
        r'\\x00',
    ]

    query_lower = query.lower()
    for pattern in dangerous_patterns:
        if re.search(pattern, query_lower):
            return False, "Invalid characters detected in query."

    return True, ""


def validate_max_results(max_results: int) -> tuple[int, str]:
    """
    Validate and clamp max_results to acceptable bounds.

    Args:
        max_results: The requested maximum number of results.

    Returns:
        Tuple of (clamped_value, warning_message). Warning is empty if no clamping.
    """
    warning = ""

    if max_results < MIN_RESULTS:
        max_results = MIN_RESULTS
        warning = f"Minimum results set to {MIN_RESULTS}."
    elif max_results > MAX_RESULTS_LIMIT:
        max_results = MAX_RESULTS_LIMIT
        warning = f"Maximum results capped at {MAX_RESULTS_LIMIT}."

    return max_results, warning


def validate_template(template: str, available_templates: List[str]) -> tuple[bool, str]:
    """
    Validate template name against whitelist.

    Args:
        template: The template name to validate.
        available_templates: List of valid template names.

    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is empty.
    """
    if not template:
        return False, "No template selected."

    if template not in available_templates:
        return False, f"Invalid template: {template}"

    return True, ""


def check_rate_limit() -> tuple[bool, str]:
    """
    Check if the current session has exceeded the scan rate limit.

    Uses Streamlit session state to track scan timestamps.

    Returns:
        Tuple of (allowed, message). If not allowed, message explains why.
    """
    now = datetime.now()

    # Initialize session state for rate limiting
    if 'scan_timestamps' not in st.session_state:
        st.session_state.scan_timestamps = []

    if 'last_scan_time' not in st.session_state:
        st.session_state.last_scan_time = None

    # Clean old timestamps (older than 1 hour)
    one_hour_ago = now - timedelta(hours=1)
    st.session_state.scan_timestamps = [
        ts for ts in st.session_state.scan_timestamps
        if ts > one_hour_ago
    ]

    # Check hourly limit
    if len(st.session_state.scan_timestamps) >= MAX_SCANS_PER_HOUR:
        return False, f"Rate limit exceeded. Maximum {MAX_SCANS_PER_HOUR} scans per hour."

    # Check cooldown between scans
    if st.session_state.last_scan_time:
        time_since_last = (now - st.session_state.last_scan_time).total_seconds()
        if time_since_last < SCAN_COOLDOWN_SECONDS:
            remaining = int(SCAN_COOLDOWN_SECONDS - time_since_last)
            return False, f"Please wait {remaining} seconds before next scan."

    return True, ""


def record_scan() -> None:
    """Record a scan timestamp for rate limiting."""
    now = datetime.now()
    if 'scan_timestamps' not in st.session_state:
        st.session_state.scan_timestamps = []
    st.session_state.scan_timestamps.append(now)
    st.session_state.last_scan_time = now


# =============================================================================
# Page Configuration
# =============================================================================

# Page configuration
st.set_page_config(
    page_title="AASRT - Imperial Security Scanner",
    page_icon="⭐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =============================================================================
# Security Headers (via meta tags - Streamlit limitation)
# =============================================================================
# Note: Streamlit doesn't support custom HTTP headers directly.
# These meta tags provide client-side security hints where supported.
st.markdown("""
<meta http-equiv="X-Content-Type-Options" content="nosniff">
<meta http-equiv="X-Frame-Options" content="DENY">
<meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">
<meta http-equiv="Permissions-Policy" content="geolocation=(), microphone=(), camera=()">
<meta name="robots" content="noindex, nofollow">
""", unsafe_allow_html=True)

# =============================================================================
# STAR WARS IMPERIAL THEME CSS
# =============================================================================
st.markdown("""
<style>
    /* Import Star Wars Style Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;800;900&family=Share+Tech+Mono&family=Exo+2:wght@300;400;500;600;700&display=swap');

    /* CSS Variables - Star Wars Color Palette */
    :root {
        --sw-yellow: #FFE81F;
        --sw-gold: #C9A227;
        --sw-blue: #4BD5EE;
        --sw-light-blue: #93E9F3;
        --sw-red: #FF2D2D;
        --sw-orange: #FF6B35;
        --sw-green: #39FF14;
        --sw-purple: #9D4EDD;
        --sw-dark: #000000;
        --sw-space: #0a0a12;
        --sw-gray: #1a1a2e;
        --imperial-red: #8B0000;
    }

    /* STARFIELD ANIMATED BACKGROUND */
    .stApp {
        background: radial-gradient(ellipse at bottom, #1B2838 0%, #0a0a12 100%);
        font-family: 'Exo 2', sans-serif;
        overflow-x: hidden;
    }

    /* Twinkling Stars Animation */
    .stApp::before {
        content: '';
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-image:
            radial-gradient(2px 2px at 20px 30px, #fff, transparent),
            radial-gradient(2px 2px at 40px 70px, rgba(255,255,255,0.8), transparent),
            radial-gradient(1px 1px at 90px 40px, #fff, transparent),
            radial-gradient(2px 2px at 160px 120px, rgba(255,232,31,0.8), transparent),
            radial-gradient(1px 1px at 230px 80px, #fff, transparent),
            radial-gradient(2px 2px at 300px 150px, rgba(75,213,238,0.6), transparent),
            radial-gradient(1px 1px at 370px 50px, #fff, transparent),
            radial-gradient(2px 2px at 450px 180px, rgba(255,255,255,0.7), transparent),
            radial-gradient(1px 1px at 520px 90px, #fff, transparent),
            radial-gradient(2px 2px at 600px 130px, rgba(255,232,31,0.5), transparent),
            radial-gradient(1px 1px at 680px 200px, #fff, transparent),
            radial-gradient(2px 2px at 750px 60px, rgba(75,213,238,0.4), transparent),
            radial-gradient(1px 1px at 820px 170px, #fff, transparent),
            radial-gradient(2px 2px at 900px 100px, rgba(255,255,255,0.6), transparent),
            radial-gradient(1px 1px at 980px 220px, #fff, transparent);
        background-repeat: repeat;
        background-size: 1000px 250px;
        animation: twinkle 8s ease-in-out infinite, moveStars 60s linear infinite;
        pointer-events: none;
        z-index: 0;
        opacity: 0.8;
    }

    @keyframes twinkle {
        0%, 100% { opacity: 0.8; }
        50% { opacity: 0.4; }
    }

    @keyframes moveStars {
        from { background-position: 0 0; }
        to { background-position: 1000px 250px; }
    }

    /* Hide Streamlit defaults */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}

    /* ====== STAR WARS OPENING CRAWL HEADER ====== */
    .main-header {
        font-family: 'Orbitron', sans-serif;
        font-size: 4rem;
        font-weight: 900;
        text-transform: uppercase;
        letter-spacing: 12px;
        text-align: center;
        margin-bottom: 0;
        color: #FFE81F;
        text-shadow:
            0 0 10px rgba(255, 232, 31, 0.8),
            0 0 20px rgba(255, 232, 31, 0.6),
            0 0 40px rgba(255, 232, 31, 0.4),
            0 0 80px rgba(255, 232, 31, 0.2);
        animation: glow 2s ease-in-out infinite alternate;
    }

    @keyframes glow {
        from { text-shadow: 0 0 10px rgba(255, 232, 31, 0.8), 0 0 20px rgba(255, 232, 31, 0.6), 0 0 40px rgba(255, 232, 31, 0.4); }
        to { text-shadow: 0 0 20px rgba(255, 232, 31, 1), 0 0 40px rgba(255, 232, 31, 0.8), 0 0 60px rgba(255, 232, 31, 0.6), 0 0 80px rgba(255, 232, 31, 0.4); }
    }

    .sub-header {
        font-family: 'Share Tech Mono', monospace;
        font-size: 1.2rem;
        color: #4BD5EE;
        margin-bottom: 2rem;
        text-align: center;
        letter-spacing: 6px;
        text-transform: uppercase;
        animation: flicker 4s infinite;
    }

    @keyframes flicker {
        0%, 100% { opacity: 1; }
        92% { opacity: 0.8; }
        93% { opacity: 1; }
        94% { opacity: 0.6; }
        95% { opacity: 1; }
    }

    /* ====== HOLOGRAPHIC STAT CARDS ====== */
    .stat-card {
        background: linear-gradient(180deg, rgba(75, 213, 238, 0.1) 0%, rgba(10, 10, 20, 0.95) 100%);
        border-radius: 12px;
        padding: 2rem 1.5rem;
        text-align: center;
        border: 2px solid rgba(75, 213, 238, 0.4);
        position: relative;
        overflow: hidden;
        transition: all 0.4s ease;
        backdrop-filter: blur(10px);
    }

    .stat-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 200%;
        height: 3px;
        background: linear-gradient(90deg, transparent, #4BD5EE, #FFE81F, #4BD5EE, transparent);
        animation: scanline 3s linear infinite;
    }

    @keyframes scanline {
        0% { left: -100%; }
        100% { left: 100%; }
    }

    .stat-card:hover {
        transform: translateY(-8px) scale(1.02);
        border-color: #FFE81F;
        box-shadow:
            0 0 20px rgba(255, 232, 31, 0.4),
            0 0 40px rgba(75, 213, 238, 0.2),
            inset 0 0 20px rgba(75, 213, 238, 0.1);
    }

    .stat-icon {
        font-size: 3.5rem;
        margin-bottom: 1rem;
        display: block;
        filter: drop-shadow(0 0 15px currentColor);
        animation: float 3s ease-in-out infinite;
    }

    @keyframes float {
        0%, 100% { transform: translateY(0); }
        50% { transform: translateY(-8px); }
    }

    .stat-value {
        font-family: 'Orbitron', sans-serif;
        font-size: 3rem;
        font-weight: 800;
        color: #fff;
        text-shadow: 0 0 20px currentColor;
        margin-bottom: 0.5rem;
    }

    .stat-label {
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.9rem;
        color: #4BD5EE;
        text-transform: uppercase;
        letter-spacing: 3px;
    }

    .stat-critical .stat-value { color: #FF2D2D; }
    .stat-critical .stat-icon { color: #FF2D2D; }
    .stat-high .stat-value { color: #FF6B35; }
    .stat-high .stat-icon { color: #FF6B35; }
    .stat-medium .stat-value { color: #FFE81F; }
    .stat-medium .stat-icon { color: #FFE81F; }
    .stat-low .stat-value { color: #39FF14; }
    .stat-low .stat-icon { color: #39FF14; }
    .stat-info .stat-value { color: #4BD5EE; }
    .stat-info .stat-icon { color: #4BD5EE; }

    /* ====== IMPERIAL DATA TERMINAL CARDS ====== */
    .finding-card {
        background: linear-gradient(135deg, rgba(10, 10, 20, 0.95) 0%, rgba(20, 20, 40, 0.9) 100%);
        border-radius: 8px;
        padding: 1.5rem;
        margin: 1rem 0;
        border-left: 5px solid #4BD5EE;
        border-top: 1px solid rgba(75, 213, 238, 0.3);
        border-right: 1px solid rgba(75, 213, 238, 0.2);
        border-bottom: 1px solid rgba(75, 213, 238, 0.3);
        position: relative;
        transition: all 0.3s ease;
        overflow: hidden;
    }

    .finding-card::after {
        content: '';
        position: absolute;
        top: 0;
        right: 0;
        width: 100px;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(75, 213, 238, 0.05));
        pointer-events: none;
    }

    .finding-card:hover {
        transform: translateX(10px);
        border-left-color: #FFE81F;
        box-shadow: 0 0 30px rgba(255, 232, 31, 0.2);
    }

    .finding-card.critical { border-left-color: #FF2D2D; }
    .finding-card.critical:hover { box-shadow: 0 0 30px rgba(255, 45, 45, 0.3); }
    .finding-card.high { border-left-color: #FF6B35; }
    .finding-card.medium { border-left-color: #FFE81F; }
    .finding-card.low { border-left-color: #39FF14; }

    .finding-ip {
        font-family: 'Orbitron', sans-serif;
        font-size: 1.3rem;
        color: #FFE81F;
        font-weight: 700;
        text-shadow: 0 0 10px rgba(255, 232, 31, 0.5);
    }

    .finding-port {
        background: rgba(75, 213, 238, 0.2);
        padding: 4px 12px;
        border-radius: 4px;
        font-family: 'Share Tech Mono', monospace;
        color: #4BD5EE;
        font-size: 0.95rem;
        border: 1px solid rgba(75, 213, 238, 0.4);
        margin-left: 10px;
    }

    .finding-meta {
        color: rgba(75, 213, 238, 0.85);
        font-size: 0.9rem;
        margin-top: 0.6rem;
        font-family: 'Share Tech Mono', monospace;
        letter-spacing: 1px;
    }

    .risk-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 6px 16px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 2px;
        font-family: 'Orbitron', sans-serif;
    }

    .risk-critical {
        background: linear-gradient(135deg, rgba(255, 45, 45, 0.3), rgba(139, 0, 0, 0.3));
        color: #FF2D2D;
        border: 1px solid #FF2D2D;
        box-shadow: 0 0 15px rgba(255, 45, 45, 0.4);
        animation: dangerPulse 1.5s infinite;
    }

    @keyframes dangerPulse {
        0%, 100% { box-shadow: 0 0 15px rgba(255, 45, 45, 0.4); }
        50% { box-shadow: 0 0 25px rgba(255, 45, 45, 0.7); }
    }

    .risk-high {
        background: rgba(255, 107, 53, 0.2);
        color: #FF6B35;
        border: 1px solid #FF6B35;
    }
    .risk-medium {
        background: rgba(255, 232, 31, 0.2);
        color: #FFE81F;
        border: 1px solid #FFE81F;
    }
    .risk-low {
        background: rgba(57, 255, 20, 0.2);
        color: #39FF14;
        border: 1px solid #39FF14;
    }

    /* ====== VULNERABILITY TAGS ====== */
    .vuln-tag {
        display: inline-block;
        background: rgba(255, 45, 45, 0.15);
        color: #FF6B35;
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.75rem;
        margin: 3px;
        font-family: 'Share Tech Mono', monospace;
        border: 1px solid rgba(255, 107, 53, 0.4);
        transition: all 0.2s ease;
    }

    .vuln-container {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-top: 0.8rem;
        align-items: center;
    }

    .vuln-tag:hover {
        background: rgba(255, 45, 45, 0.3);
        transform: scale(1.05);
    }

    /* ====== DEATH STAR WELCOME BOX ====== */
    .welcome-box {
        background:
            radial-gradient(circle at 30% 30%, rgba(75, 213, 238, 0.1) 0%, transparent 50%),
            linear-gradient(180deg, rgba(20, 20, 40, 0.9) 0%, rgba(10, 10, 20, 0.95) 100%);
        border-radius: 20px;
        padding: 4rem;
        text-align: center;
        border: 2px solid rgba(255, 232, 31, 0.3);
        margin: 2rem 0;
        position: relative;
        overflow: hidden;
    }

    .welcome-box::before {
        content: '';
        position: absolute;
        top: -50%;
        left: -50%;
        width: 200%;
        height: 200%;
        background: conic-gradient(from 0deg, transparent, rgba(255, 232, 31, 0.1), transparent 20%);
        animation: rotate 10s linear infinite;
    }

    @keyframes rotate {
        100% { transform: rotate(360deg); }
    }

    .welcome-icon {
        font-size: 6rem;
        margin-bottom: 1.5rem;
        display: block;
        animation: float 3s ease-in-out infinite;
        filter: drop-shadow(0 0 30px rgba(255, 232, 31, 0.6));
    }

    .welcome-title {
        font-family: 'Orbitron', sans-serif;
        font-size: 2.5rem;
        font-weight: 800;
        color: #FFE81F;
        margin-bottom: 1rem;
        text-transform: uppercase;
        letter-spacing: 6px;
        text-shadow: 0 0 20px rgba(255, 232, 31, 0.5);
    }

    .welcome-text {
        color: #4BD5EE;
        font-size: 1.1rem;
        line-height: 2;
        font-family: 'Share Tech Mono', monospace;
        max-width: 600px;
        margin: 0 auto;
    }

    /* ====== TEMPLATE TARGET CARDS ====== */
    .template-card {
        background: linear-gradient(180deg, rgba(75, 213, 238, 0.1) 0%, rgba(10, 10, 20, 0.9) 100%);
        border-radius: 12px;
        padding: 1.5rem;
        text-align: center;
        border: 2px solid rgba(75, 213, 238, 0.3);
        transition: all 0.4s ease;
        cursor: pointer;
        position: relative;
        overflow: hidden;
    }

    .template-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: radial-gradient(circle at center, rgba(255, 232, 31, 0.2) 0%, transparent 70%);
        opacity: 0;
        transition: opacity 0.4s ease;
    }

    .template-card:hover::before {
        opacity: 1;
    }

    .template-card:hover {
        border-color: #FFE81F;
        transform: translateY(-10px) scale(1.05);
        box-shadow:
            0 20px 40px rgba(0, 0, 0, 0.4),
            0 0 30px rgba(255, 232, 31, 0.3);
    }

    .template-icon {
        font-size: 4rem;
        margin-bottom: 1rem;
        display: block;
        filter: drop-shadow(0 0 15px currentColor);
        transition: transform 0.3s ease;
    }

    .template-card:hover .template-icon {
        transform: scale(1.2) rotate(5deg);
    }

    .template-name {
        font-family: 'Orbitron', sans-serif;
        font-weight: 700;
        color: #FFE81F;
        font-size: 1rem;
        text-transform: uppercase;
        letter-spacing: 2px;
    }

    .template-desc {
        font-size: 0.8rem;
        color: #4BD5EE;
        margin-top: 0.5rem;
        font-family: 'Share Tech Mono', monospace;
    }

    /* ====== SIDEBAR IMPERIAL CONSOLE ====== */
    .sidebar-title {
        font-family: 'Orbitron', sans-serif;
        font-size: 0.9rem;
        text-transform: uppercase;
        letter-spacing: 3px;
        color: #FFE81F;
        font-weight: 700;
        margin-bottom: 1rem;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid rgba(255, 232, 31, 0.4);
        text-shadow: 0 0 10px rgba(255, 232, 31, 0.5);
    }

    /* API Status */
    .api-status {
        display: flex;
        align-items: center;
        padding: 1rem;
        border-radius: 8px;
        margin: 0.5rem 0;
        font-family: 'Share Tech Mono', monospace;
    }

    .api-status.connected {
        background: linear-gradient(135deg, rgba(57, 255, 20, 0.15), rgba(57, 255, 20, 0.05));
        border: 2px solid rgba(57, 255, 20, 0.5);
    }

    .api-status.disconnected {
        background: linear-gradient(135deg, rgba(255, 45, 45, 0.15), rgba(255, 45, 45, 0.05));
        border: 2px solid rgba(255, 45, 45, 0.5);
    }

    .live-indicator {
        display: inline-block;
        width: 14px;
        height: 14px;
        background: #39FF14;
        border-radius: 50%;
        margin-right: 12px;
        box-shadow: 0 0 10px #39FF14, 0 0 20px #39FF14, 0 0 30px #39FF14;
        animation: pulse 1.5s infinite;
    }

    @keyframes pulse {
        0%, 100% { transform: scale(1); opacity: 1; }
        50% { transform: scale(1.3); opacity: 0.7; }
    }

    /* ====== PROGRESS BAR ====== */
    .scan-progress {
        background: linear-gradient(90deg, #FFE81F, #4BD5EE, #9D4EDD, #FFE81F);
        background-size: 300% 100%;
        animation: gradient 2s linear infinite;
        border-radius: 4px;
        height: 6px;
        box-shadow: 0 0 20px rgba(255, 232, 31, 0.5);
    }

    @keyframes gradient {
        0% { background-position: 0% 50%; }
        100% { background-position: 300% 50%; }
    }

    /* ====== GEO STATS ====== */
    .geo-stat {
        background: linear-gradient(180deg, rgba(75, 213, 238, 0.15) 0%, rgba(10, 10, 20, 0.9) 100%);
        border: 2px solid rgba(75, 213, 238, 0.4);
        border-radius: 8px;
        padding: 1.2rem;
        text-align: center;
        transition: all 0.3s ease;
    }

    .geo-stat:hover {
        border-color: #FFE81F;
        transform: translateY(-3px);
    }

    .geo-stat-icon {
        font-size: 2rem;
        margin-bottom: 0.5rem;
        display: block;
    }

    .geo-stat-value {
        font-family: 'Orbitron', sans-serif;
        font-size: 1.8rem;
        font-weight: 700;
        color: #4BD5EE;
        text-shadow: 0 0 15px #4BD5EE;
    }

    .geo-stat-label {
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.75rem;
        color: #FFE81F;
        text-transform: uppercase;
        letter-spacing: 2px;
        margin-top: 0.3rem;
    }

    /* ====== COUNTRY BARS ====== */
    .country-item {
        margin: 0.8rem 0;
    }

    .country-name {
        display: flex;
        justify-content: space-between;
        margin-bottom: 6px;
        font-family: 'Share Tech Mono', monospace;
    }

    .country-bar {
        background: rgba(75, 213, 238, 0.2);
        border-radius: 4px;
        height: 8px;
        overflow: hidden;
    }

    .country-bar-fill {
        background: linear-gradient(90deg, #4BD5EE, #FFE81F);
        height: 100%;
        border-radius: 4px;
        box-shadow: 0 0 10px rgba(75, 213, 238, 0.5);
        transition: width 0.5s ease;
    }

    /* ====== SCROLLBAR ====== */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }

    ::-webkit-scrollbar-track {
        background: #0a0a12;
    }

    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #FFE81F, #4BD5EE);
        border-radius: 4px;
    }

    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(180deg, #4BD5EE, #FFE81F);
    }

    /* ====== TERMINAL CURSOR ====== */
    .cursor {
        display: inline-block;
        width: 12px;
        height: 24px;
        background: #FFE81F;
        animation: blink 1s infinite;
        vertical-align: middle;
        margin-left: 5px;
        box-shadow: 0 0 10px #FFE81F;
    }

    @keyframes blink {
        0%, 50% { opacity: 1; }
        51%, 100% { opacity: 0; }
    }

    /* Section Headers */
    .section-header {
        font-family: 'Orbitron', sans-serif;
        font-size: 1.5rem;
        color: #FFE81F;
        text-transform: uppercase;
        letter-spacing: 4px;
        margin: 2rem 0 1.5rem 0;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid rgba(255, 232, 31, 0.3);
        display: flex;
        align-items: center;
        gap: 15px;
    }

    .section-header span {
        font-size: 2rem;
    }

    /* ====== CLAWSEC INTEL THEME ====== */
    .clawsec-status {
        background: linear-gradient(135deg, rgba(157, 78, 221, 0.15), rgba(157, 78, 221, 0.05));
        border: 2px solid rgba(157, 78, 221, 0.5);
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
    }

    .clawsec-indicator {
        display: inline-block;
        width: 14px;
        height: 14px;
        background: #9D4EDD;
        border-radius: 50%;
        margin-right: 12px;
        box-shadow: 0 0 10px #9D4EDD, 0 0 20px #9D4EDD;
        animation: pulse 2s infinite;
    }

    .cve-tag {
        display: inline-block;
        background: linear-gradient(135deg, rgba(157, 78, 221, 0.3), rgba(75, 213, 238, 0.2));
        color: #9D4EDD;
        padding: 4px 10px;
        border-radius: 4px;
        font-family: 'Orbitron', sans-serif;
        font-weight: 600;
        font-size: 0.7rem;
        border: 1px solid rgba(157, 78, 221, 0.5);
        margin: 3px;
        transition: all 0.2s ease;
    }

    .cve-tag:hover {
        background: rgba(157, 78, 221, 0.4);
        transform: scale(1.05);
    }

    .intel-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(157, 78, 221, 0.2);
        color: #9D4EDD;
        padding: 4px 12px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-family: 'Share Tech Mono', monospace;
        border: 1px solid rgba(157, 78, 221, 0.4);
    }

    .intel-indicator {
        display: inline-block;
        width: 8px;
        height: 8px;
        background: #9D4EDD;
        border-radius: 50%;
        animation: pulse 2s infinite;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def get_database():
    """Get cached database connection."""
    from src.storage.database import Database
    from src.utils.config import Config
    config = Config()
    return Database(config)


@st.cache_data(ttl=300)
def get_templates():
    """Get cached list of available templates."""
    from src.core.query_manager import QueryManager
    from src.utils.config import Config
    try:
        config = Config()
        qm = QueryManager(config)
        return sorted(qm.get_available_templates())
    except:
        return []


@st.cache_resource
def get_clawsec_manager():
    """Get cached ClawSec feed manager."""
    from src.enrichment import ClawSecFeedManager
    from src.utils.config import Config
    try:
        config = Config()
        if config.is_clawsec_enabled():
            manager = ClawSecFeedManager(config)
            manager.load_cache()  # Load from disk
            # Try to fetch fresh data in background
            manager.background_refresh()
            return manager
    except Exception as e:
        logger = __import__('src.utils.logger', fromlist=['get_logger']).get_logger(__name__)
        logger.warning(f"Failed to initialize ClawSec manager: {e}")
    return None


@st.cache_data(ttl=300)
def get_clawsec_stats():
    """Get ClawSec feed statistics for sidebar."""
    manager = get_clawsec_manager()
    if manager:
        return manager.get_statistics()
    return None


def get_shodan_status():
    """Get status of Shodan API configuration."""
    api_key = os.getenv('SHODAN_API_KEY')
    return {
        'configured': bool(api_key and api_key != 'your_shodan_api_key_here'),
        'api_key': api_key
    }


def get_risk_class(score):
    """Get CSS class based on risk score."""
    if score >= 9:
        return 'critical'
    elif score >= 7:
        return 'high'
    elif score >= 4:
        return 'medium'
    else:
        return 'low'


def render_html(html: str) -> None:
    """
    Render HTML reliably in Streamlit.

    Streamlit's Markdown renderer will display HTML as a code block if the HTML
    string is indented (leading whitespace). Dedent+strip prevents that.
    """
    st.markdown(textwrap.dedent(html).strip(), unsafe_allow_html=True)


def _esc(value: Any) -> str:
    """HTML-escape dynamic values inserted into unsafe HTML blocks."""
    if value is None:
        return ""
    return _html.escape(str(value), quote=True)


def sanitize_output(value: Any) -> str:
    """
    Sanitize output for safe display in the UI.

    Escapes HTML entities and removes potentially dangerous content
    to prevent XSS attacks.

    Args:
        value: The value to sanitize (will be converted to string).

    Returns:
        Sanitized string safe for display in HTML context.
    """
    if value is None:
        return ""

    text = str(value)

    # Remove null bytes
    text = text.replace('\x00', '')

    # HTML escape
    text = _html.escape(text, quote=True)

    return text


def run_scan(
    template: Optional[str] = None,
    query: Optional[str] = None,
    max_results: int = 100
) -> Optional[Any]:
    """
    Execute a security scan using Shodan.

    Performs input validation, rate limiting checks, and executes
    a security reconnaissance scan using the Shodan API.

    Args:
        template: Name of a predefined query template to use.
        query: Custom Shodan search query string.
        max_results: Maximum number of results to retrieve (1-10000).

    Returns:
        ScanReport object if successful, None if scan failed.

    Raises:
        No exceptions raised - errors displayed via st.error().
    """
    from src.utils.config import Config
    from src.core.query_manager import QueryManager
    from src.core.result_aggregator import ResultAggregator
    from src.core.vulnerability_assessor import VulnerabilityAssessor
    from src.core.risk_scorer import RiskScorer
    from src.reporting import ScanReport
    from src.utils.logger import get_logger

    logger = get_logger(__name__)

    # =========================================================================
    # Input Validation
    # =========================================================================

    # Validate rate limits first
    allowed, rate_msg = check_rate_limit()
    if not allowed:
        st.warning(f"⏳ {rate_msg}")
        logger.warning(f"Rate limit check failed: {rate_msg}")
        return None

    # Validate max_results
    max_results, results_warning = validate_max_results(max_results)
    if results_warning:
        st.info(f"ℹ️ {results_warning}")

    # Validate custom query if provided
    if query:
        valid, query_error = validate_scan_query(query)
        if not valid:
            st.error(f"❌ Invalid query: {query_error}")
            logger.warning(f"Invalid query rejected: {query_error}")
            return None

    # =========================================================================
    # Initialize Components
    # =========================================================================

    config = Config()

    try:
        query_manager = QueryManager(config)
    except Exception as e:
        st.error(f"SYSTEM ERROR: Initialization failed - {e}")
        logger.error(f"Query manager initialization failed: {e}")
        return None

    if not query_manager.is_available():
        st.error("ALERT: Shodan connection unavailable. Verify API credentials.")
        return None

    # Validate template if using one
    if template:
        available = query_manager.get_available_templates()
        valid, template_error = validate_template(template, available)
        if not valid:
            st.error(f"❌ {template_error}")
            logger.warning(f"Invalid template rejected: {template}")
            return None

    # Record scan for rate limiting
    record_scan()
    logger.info(f"Starting scan: template={template}, query={query[:50] if query else None}, max_results={max_results}")

    scan_id = str(uuid.uuid4())
    start_time = time.time()

    # =========================================================================
    # Execute Scan
    # =========================================================================

    # Progress Display
    progress_container = st.container()
    with progress_container:
        st.markdown('<div class="scan-progress"></div>', unsafe_allow_html=True)
        status_text = st.empty()
        progress_bar = st.progress(0)

    try:
        # Display sanitized query/template (XSS prevention)
        if template:
            safe_template = sanitize_output(template)
            status_text.markdown(f"""
            ```
            ══════════════════════════════════════════════
            IMPERIAL SCAN INITIATED
            ══════════════════════════════════════════════
            TARGET TEMPLATE: {safe_template}
            STATUS: Connecting to Shodan network...
            ```
            """)
            all_results = query_manager.execute_template(template, max_results=max_results)
        else:
            # Truncate query for display
            display_query = query[:100] + "..." if len(query) > 100 else query
            safe_query = sanitize_output(display_query)
            status_text.markdown(f"""
            ```
            ══════════════════════════════════════════════
            IMPERIAL SCAN INITIATED
            ══════════════════════════════════════════════
            CUSTOM QUERY: {safe_query}
            STATUS: Connecting to Shodan network...
            ```
            """)
            all_results = query_manager.execute_query(query, max_results=max_results)
        progress_bar.progress(50)
    except Exception as e:
        st.error(f"SCAN FAILURE: {e}")
        logger.error(f"Scan execution failed: {e}", exc_info=True)
        progress_container.empty()
        return None

    status_text.markdown(f"""
    ```
    TARGETS ACQUIRED: {len(all_results)}
    STATUS: Processing intelligence data...
    ```
    """)
    aggregator = ResultAggregator()
    unique_results = aggregator.aggregate({'shodan': all_results})
    progress_bar.progress(70)

    status_text.markdown(f"""
    ```
    UNIQUE TARGETS: {len(unique_results)}
    STATUS: Running threat assessment...
    ```
    """)

    # Initialize ClawSec threat enricher if available
    from src.enrichment import ThreatEnricher
    clawsec_manager = get_clawsec_manager()
    threat_enricher = ThreatEnricher(clawsec_manager, config) if clawsec_manager else None

    assessor = VulnerabilityAssessor(
        config.get('vulnerability_checks', default={}),
        threat_enricher=threat_enricher
    )
    scorer = RiskScorer()

    for result in unique_results:
        # Use assess_with_intel if enricher available, otherwise standard assess
        if threat_enricher:
            vulns = assessor.assess_with_intel(result)
        else:
            vulns = assessor.assess(result)
        scorer.score_result(result, vulns)
    progress_bar.progress(90)

    duration = time.time() - start_time

    report = ScanReport.from_results(
        scan_id=scan_id,
        results=unique_results,
        engines=['shodan'],
        query=query,
        template_name=template,
        duration=duration
    )

    try:
        db = get_database()
        scan_record = db.create_scan(engines=['shodan'], query=query, template_name=template)
        db.add_findings(scan_record.scan_id, unique_results)
        db.update_scan(scan_record.scan_id, status='completed', total_results=len(unique_results), duration_seconds=duration)
    except Exception as e:
        st.warning(f"Database sync failed: {e}")

    progress_bar.progress(100)
    status_text.markdown(f"""
    ```
    ══════════════════════════════════════════════
    SCAN COMPLETE
    ══════════════════════════════════════════════
    DURATION: {duration:.2f} seconds
    TARGETS IDENTIFIED: {len(unique_results)}
    STATUS: Intelligence ready for review
    ```
    """)
    time.sleep(1.5)
    progress_container.empty()

    return report


def display_results(report):
    """Display scan results with Star Wars theme."""
    if not report:
        return

    # Success Banner
    render_html(f"""
    <div style="background: linear-gradient(90deg, rgba(57, 255, 20, 0.1), rgba(255, 232, 31, 0.1), rgba(57, 255, 20, 0.1));
                border: 2px solid rgba(57, 255, 20, 0.5); border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem;
                text-align: center; font-family: 'Orbitron', sans-serif;">
        <span style="color: #39FF14; font-size: 1.5rem;">⚡ SCAN COMPLETE ⚡</span><br>
        <span style="color: #FFE81F; font-size: 2rem; font-weight: 800;">{report.total_results}</span>
        <span style="color: #4BD5EE;"> targets acquired in </span>
        <span style="color: #FFE81F; font-size: 2rem; font-weight: 800;">{report.duration_seconds:.1f}s</span>
    </div>
    """)

    # Stats Cards
    st.markdown('<div class="section-header"><span>📊</span> THREAT ANALYSIS</div>', unsafe_allow_html=True)

    col1, col2, col3, col4, col5 = st.columns(5)

    stats_data = [
        (col1, "🎯", report.total_results, "TARGETS", "stat-info"),
        (col2, "💀", report.critical_findings, "CRITICAL", "stat-critical"),
        (col3, "⚠️", report.high_findings, "HIGH", "stat-high"),
        (col4, "📡", report.medium_findings, "MEDIUM", "stat-medium"),
        (col5, "📈", f"{report.average_risk_score:.1f}", "RISK AVG", "stat-info"),
    ]

    for col, icon, value, label, css_class in stats_data:
        with col:
            render_html(f"""
            <div class="stat-card {css_class}">
                <span class="stat-icon">{icon}</span>
                <div class="stat-value">{value}</div>
                <div class="stat-label">{label}</div>
            </div>
            """)

    if not report.findings:
        st.info("No threats detected in scan perimeter.")
        return

    st.markdown("<br>", unsafe_allow_html=True)

    # Charts
    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<div class="section-header"><span>🥧</span> THREAT DISTRIBUTION</div>', unsafe_allow_html=True)

        colors = ['#FF2D2D', '#FF6B35', '#FFE81F', '#39FF14']
        values = [report.critical_findings, report.high_findings, report.medium_findings, report.low_findings]

        fig = go.Figure(data=[go.Pie(
            labels=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            values=values,
            marker=dict(colors=colors, line=dict(color='#0a0a12', width=3)),
            hole=0.65,
            textinfo='label+value',
            textposition='outside',
            textfont=dict(size=12, color='#4BD5EE', family='Share Tech Mono')
        )])

        fig.update_layout(
            height=380,
            margin=dict(l=20, r=20, t=40, b=20),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            showlegend=False,
            annotations=[dict(
                text=f'<b>{sum(values)}</b><br>TOTAL',
                x=0.5, y=0.5,
                font=dict(size=24, color='#FFE81F', family='Orbitron'),
                showarrow=False
            )]
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.markdown('<div class="section-header"><span>📊</span> RISK SCORES</div>', unsafe_allow_html=True)

        scores = [f.get('risk_score', 0) for f in report.findings]

        fig = go.Figure(data=[go.Histogram(
            x=scores, nbinsx=10,
            marker=dict(color='rgba(75, 213, 238, 0.7)', line=dict(color='#FFE81F', width=2))
        )])

        fig.update_layout(
            height=380,
            margin=dict(l=20, r=20, t=40, b=40),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(
                title=dict(text='RISK LEVEL', font=dict(color='#FFE81F', family='Share Tech Mono')),
                gridcolor='rgba(75, 213, 238, 0.1)',
                tickfont=dict(color='#4BD5EE', family='Share Tech Mono')
            ),
            yaxis=dict(
                title=dict(text='FREQUENCY', font=dict(color='#FFE81F', family='Share Tech Mono')),
                gridcolor='rgba(75, 213, 238, 0.1)',
                tickfont=dict(color='#4BD5EE', family='Share Tech Mono')
            ),
            bargap=0.1
        )
        st.plotly_chart(fig, use_container_width=True)

    # World Map
    st.markdown('<div class="section-header"><span>🌍</span> GALACTIC THREAT MAP</div>', unsafe_allow_html=True)

    map_data = []
    country_counts = {}
    city_counts = {}

    for f in report.findings:
        metadata = f.get('metadata', {})
        location = metadata.get('location', {}) if isinstance(metadata, dict) else {}

        lat = location.get('latitude')
        lon = location.get('longitude')
        country = location.get('country') or 'Unknown'
        city = location.get('city') or 'Unknown'

        if country and country != 'Unknown':
            country_counts[country] = country_counts.get(country, 0) + 1
        if city and city != 'Unknown':
            city_counts[city] = city_counts.get(city, 0) + 1

        if lat and lon:
            risk_score = f.get('risk_score', 0)
            map_data.append({
                'lat': lat, 'lon': lon,
                'ip': f.get('ip', 'Unknown'),
                'port': f.get('port', 0),
                'risk_score': risk_score,
                'country': country, 'city': city,
                'service': f.get('service', 'Unknown'),
                'risk_class': get_risk_class(risk_score)
            })

    if map_data:
        # Geo Stats
        geo_col1, geo_col2, geo_col3, geo_col4 = st.columns(4)

        geo_stats = [
            (geo_col1, "🛰️", len(map_data), "LOCATED"),
            (geo_col2, "🌐", len(country_counts), "SYSTEMS"),
            (geo_col3, "🏙️", len(city_counts), "SECTORS"),
            (geo_col4, "⭐", max(country_counts.items(), key=lambda x: x[1])[0] if country_counts else "N/A", "HOTSPOT"),
        ]

        for col, icon, value, label in geo_stats:
            with col:
                render_html(f"""
                <div class="geo-stat">
                    <span class="geo-stat-icon">{icon}</span>
                    <div class="geo-stat-value">{value}</div>
                    <div class="geo-stat-label">{label}</div>
                </div>
                """)

        st.markdown("<br>", unsafe_allow_html=True)

        # Map visualization options
        map_col1, map_col2, map_col3 = st.columns([1, 1, 1])
        with map_col1:
            map_style = st.selectbox("🗺️ MAP STYLE", 
                ["3D Globe", "Flat Map", "Dark Matter", "Natural Earth"], 
                key="map_style")
        with map_col2:
            show_connections = st.checkbox("⚡ Show Threat Connections", value=False, key="connections")
        with map_col3:
            animate_markers = st.checkbox("💫 Animated Markers", value=True, key="animate")

        st.markdown("<br>", unsafe_allow_html=True)

        col1, col2 = st.columns([2, 1])

        with col1:
            df_map = pd.DataFrame(map_data)
            df_map['size'] = df_map['risk_score'].apply(lambda x: max(15, x * 5))
            
            # Enhanced hover text with more details
            df_map['hover_text'] = df_map.apply(
                lambda row: f"<b style='color:#FFE81F;font-size:14px'>{row['ip']}:{row['port']}</b><br>" +
                           f"<span style='color:#FF2D2D'>⚡ Risk: {row['risk_score']:.1f}/10</span><br>" +
                           f"<span style='color:#4BD5EE'>📍 {row['city']}, {row['country']}</span><br>" +
                           f"<span style='color:#39FF14'>🔧 {row['service']}</span>",
                axis=1
            )

            fig = go.Figure()

            # Add threat connections if enabled
            if show_connections and len(df_map) > 1:
                # Connect critical threats
                critical_threats = df_map[df_map['risk_class'] == 'critical']
                if len(critical_threats) > 1:
                    for i in range(len(critical_threats) - 1):
                        fig.add_trace(go.Scattergeo(
                            lon=[critical_threats.iloc[i]['lon'], critical_threats.iloc[i+1]['lon']],
                            lat=[critical_threats.iloc[i]['lat'], critical_threats.iloc[i+1]['lat']],
                            mode='lines',
                            line=dict(width=1, color='rgba(255, 45, 45, 0.3)', dash='dot'),
                            showlegend=False,
                            hoverinfo='skip'
                        ))

            # Add markers with enhanced styling
            for risk_class, color, name, symbol in [
                ('critical', '#FF2D2D', 'CRITICAL', 'diamond'),
                ('high', '#FF6B35', 'HIGH', 'square'),
                ('medium', '#FFE81F', 'MEDIUM', 'circle'),
                ('low', '#39FF14', 'LOW', 'circle')
            ]:
                df_filtered = df_map[df_map['risk_class'] == risk_class]
                if len(df_filtered) > 0:
                    fig.add_trace(go.Scattergeo(
                        lon=df_filtered['lon'], 
                        lat=df_filtered['lat'],
                        text=df_filtered['hover_text'], 
                        hoverinfo='text',
                        mode='markers',
                        marker=dict(
                            size=df_filtered['size'], 
                            color=color, 
                            opacity=0.85,
                            symbol=symbol,
                            line=dict(width=3, color='rgba(255,255,255,0.8)'),
                            sizemode='diameter'
                        ),
                        name=f'{name} ({len(df_filtered)})'
                    ))

            # Determine projection based on map style
            if map_style == "3D Globe":
                projection = 'orthographic'
                rotation = dict(lon=-40, lat=20, roll=0)
            elif map_style == "Flat Map":
                projection = 'natural earth'
                rotation = None
            elif map_style == "Dark Matter":
                projection = 'equirectangular'
                rotation = None
            else:  # Natural Earth
                projection = 'natural earth'
                rotation = None

            # Enhanced layout with better colors
            fig.update_layout(
                height=650,
                margin=dict(l=0, r=0, t=40, b=0),
                paper_bgcolor='rgba(0,0,0,0)',
                geo=dict(
                    showframe=False,
                    showcoastlines=True, 
                    coastlinecolor='#4BD5EE', 
                    coastlinewidth=2,
                    showland=True, 
                    landcolor='rgba(15, 25, 35, 0.95)',
                    showocean=True, 
                    oceancolor='rgba(5, 10, 20, 0.98)',
                    showcountries=True, 
                    countrycolor='rgba(75, 213, 238, 0.4)',
                    countrywidth=1,
                    showlakes=True,
                    lakecolor='rgba(10, 20, 30, 0.9)',
                    projection_type=projection,
                    projection_rotation=rotation if rotation else dict(lon=0, lat=0),
                    bgcolor='rgba(0,0,0,0)',
                    lataxis=dict(
                        showgrid=True, 
                        gridcolor='rgba(75, 213, 238, 0.15)',
                        gridwidth=1
                    ),
                    lonaxis=dict(
                        showgrid=True, 
                        gridcolor='rgba(75, 213, 238, 0.15)',
                        gridwidth=1
                    )
                ),
                legend=dict(
                    orientation='h', 
                    yanchor='bottom', 
                    y=1.02, 
                    xanchor='center', 
                    x=0.5,
                    font=dict(color='#FFE81F', size=12, family='Orbitron', weight='bold'),
                    bgcolor='rgba(10, 10, 20, 0.8)',
                    bordercolor='rgba(75, 213, 238, 0.5)',
                    borderwidth=2
                ),
                hoverlabel=dict(
                    bgcolor='rgba(10, 10, 20, 0.95)',
                    bordercolor='#FFE81F',
                    font=dict(family='Share Tech Mono', size=12, color='#fff')
                ),
                updatemenus=[dict(
                    type='buttons', 
                    showactive=False, 
                    y=0.05, 
                    x=0.5, 
                    xanchor='center',
                    bgcolor='rgba(10, 10, 20, 0.8)',
                    bordercolor='#FFE81F',
                    borderwidth=2,
                    buttons=[
                        dict(
                            label='🔄 AUTO ROTATE',
                            method='animate',
                            args=[None, dict(
                                frame=dict(duration=50, redraw=True), 
                                fromcurrent=True,
                                mode='immediate'
                            )]
                        ),
                        dict(
                            label='⏸️ PAUSE',
                            method='animate',
                            args=[[None], dict(
                                frame=dict(duration=0, redraw=False),
                                mode='immediate',
                                transition=dict(duration=0)
                            )]
                        )
                    ]
                )] if map_style == "3D Globe" else []
            )

            # Add animation frames for 3D globe
            if map_style == "3D Globe" and animate_markers:
                frames = [
                    go.Frame(
                        layout=dict(
                            geo=dict(
                                projection_rotation=dict(lon=i-180, lat=20, roll=0)
                            )
                        )
                    ) for i in range(0, 360, 3)
                ]
                fig.frames = frames

            st.plotly_chart(fig, use_container_width=True, config={
                'displayModeBar': True,
                'displaylogo': False,
                'modeBarButtonsToAdd': ['drawopenpath', 'eraseshape']
            })

        with col2:
            st.markdown("#### 🏴 TOP SYSTEMS")

            if country_counts:
                sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                max_count = sorted_countries[0][1]

                for country, count in sorted_countries:
                    pct = (count / max_count) * 100
                    render_html(f"""
                    <div class="country-item">
                        <div class="country-name">
                            <span style="color: #fff;">{country}</span>
                            <span style="color: #FFE81F; font-weight: bold;">{count}</span>
                        </div>
                        <div class="country-bar">
                            <div class="country-bar-fill" style="width: {pct}%;"></div>
                        </div>
                    </div>
                    """)
            
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("#### 🎯 THREAT DENSITY")
            
            # Create a mini heatmap
            if len(df_map) > 0:
                # Group by country and calculate average risk
                country_risk = df_map.groupby('country').agg({
                    'risk_score': 'mean',
                    'ip': 'count'
                }).reset_index()
                country_risk.columns = ['country', 'avg_risk', 'count']
                country_risk = country_risk.sort_values('avg_risk', ascending=False).head(8)
                
                fig_density = go.Figure(data=[go.Bar(
                    x=country_risk['avg_risk'],
                    y=country_risk['country'],
                    orientation='h',
                    marker=dict(
                        color=country_risk['avg_risk'],
                        colorscale=[
                            [0, '#39FF14'],
                            [0.4, '#FFE81F'],
                            [0.7, '#FF6B35'],
                            [1, '#FF2D2D']
                        ],
                        line=dict(color='#4BD5EE', width=2)
                    ),
                    text=country_risk['avg_risk'].round(1),
                    textposition='outside',
                    textfont=dict(color='#FFE81F', family='Orbitron', size=11),
                    hovertemplate='<b>%{y}</b><br>Avg Risk: %{x:.1f}<br><extra></extra>'
                )])
                
                fig_density.update_layout(
                    height=300,
                    margin=dict(l=0, r=40, t=10, b=0),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    xaxis=dict(
                        showgrid=True,
                        gridcolor='rgba(75, 213, 238, 0.1)',
                        title='',
                        tickfont=dict(color='#4BD5EE', size=9),
                        range=[0, 10]
                    ),
                    yaxis=dict(
                        showgrid=False,
                        tickfont=dict(color='#fff', size=10, family='Share Tech Mono')
                    ),
                    showlegend=False,
                    hoverlabel=dict(
                        bgcolor='rgba(10, 10, 20, 0.95)',
                        bordercolor='#FFE81F',
                        font=dict(family='Share Tech Mono', size=11)
                    )
                )
                
                st.plotly_chart(fig_density, use_container_width=True)

        # Additional visualization: Attack Surface Timeline
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown('<div class="section-header"><span>📡</span> THREAT SURFACE ANALYSIS</div>', unsafe_allow_html=True)
        
        viz_col1, viz_col2 = st.columns(2)
        
        with viz_col1:
            st.markdown("#### 🎯 PORT DISTRIBUTION")
            # Port analysis
            port_counts = df_map['port'].value_counts().head(10)
            
            fig_ports = go.Figure(data=[go.Bar(
                x=port_counts.index.astype(str),
                y=port_counts.values,
                marker=dict(
                    color=port_counts.values,
                    colorscale=[
                        [0, '#4BD5EE'],
                        [0.5, '#FFE81F'],
                        [1, '#FF2D2D']
                    ],
                    line=dict(color='#FFE81F', width=2)
                ),
                text=port_counts.values,
                textposition='outside',
                textfont=dict(color='#FFE81F', family='Orbitron', size=12),
                hovertemplate='<b>Port %{x}</b><br>Count: %{y}<br><extra></extra>'
            )])
            
            fig_ports.update_layout(
                height=300,
                margin=dict(l=20, r=20, t=20, b=40),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                xaxis=dict(
                    title=dict(text='PORT', font=dict(color='#4BD5EE', family='Share Tech Mono', size=11)),
                    showgrid=False,
                    tickfont=dict(color='#4BD5EE', size=10)
                ),
                yaxis=dict(
                    title=dict(text='TARGETS', font=dict(color='#4BD5EE', family='Share Tech Mono', size=11)),
                    showgrid=True,
                    gridcolor='rgba(75, 213, 238, 0.1)',
                    tickfont=dict(color='#4BD5EE', size=10)
                ),
                showlegend=False,
                hoverlabel=dict(
                    bgcolor='rgba(10, 10, 20, 0.95)',
                    bordercolor='#FFE81F',
                    font=dict(family='Share Tech Mono', size=11)
                )
            )
            
            st.plotly_chart(fig_ports, use_container_width=True)
        
        with viz_col2:
            st.markdown("#### 🔧 SERVICE BREAKDOWN")
            # Service analysis
            service_counts = df_map['service'].value_counts().head(8)
            
            fig_services = go.Figure(data=[go.Pie(
                labels=service_counts.index,
                values=service_counts.values,
                hole=0.6,
                marker=dict(
                    colors=['#FF2D2D', '#FF6B35', '#FFE81F', '#39FF14', '#4BD5EE', '#9D4EDD', '#FF2D2D', '#FFE81F'],
                    line=dict(color='#0a0a12', width=3)
                ),
                textinfo='label+percent',
                textposition='outside',
                textfont=dict(size=11, color='#fff', family='Share Tech Mono'),
                hovertemplate='<b>%{label}</b><br>Count: %{value}<br>%{percent}<br><extra></extra>'
            )])
            
            fig_services.update_layout(
                height=300,
                margin=dict(l=20, r=20, t=20, b=20),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                showlegend=False,
                annotations=[dict(
                    text=f'<b>{len(service_counts)}</b><br>SERVICES',
                    x=0.5, y=0.5,
                    font=dict(size=18, color='#FFE81F', family='Orbitron'),
                    showarrow=False
                )],
                hoverlabel=dict(
                    bgcolor='rgba(10, 10, 20, 0.95)',
                    bordercolor='#FFE81F',
                    font=dict(family='Share Tech Mono', size=11)
                )
            )
            
            st.plotly_chart(fig_services, use_container_width=True)

    else:
        st.info("No geolocation data available for current targets.")

    # Vulnerabilities
    st.markdown('<div class="section-header"><span>🔓</span> SECURITY BREACHES</div>', unsafe_allow_html=True)

    vuln_counts = {}
    for f in report.findings:
        for v in f.get('vulnerabilities', []):
            vuln_counts[v] = vuln_counts.get(v, 0) + 1

    if vuln_counts:
        top_vulns = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        cols = st.columns(4)
        for i, (vuln, count) in enumerate(top_vulns):
            with cols[i % 4]:
                render_html(f"""
                <div class="stat-card stat-critical" style="padding: 1rem;">
                    <div class="stat-value" style="font-size: 2rem;">{count}</div>
                    <div style="font-size: 0.7rem; color: #FF6B35; word-break: break-word;">{vuln}</div>
                </div>
                """)

    # Target List
    st.markdown('<div class="section-header"><span>📋</span> TARGET REGISTRY</div>', unsafe_allow_html=True)

    view_mode = st.radio("VIEW", ["HOLOGRAPHIC", "DATA MATRIX"], horizontal=True, label_visibility="collapsed")

    if view_mode == "HOLOGRAPHIC":
        def _as_float(value, default: float = 0.0) -> float:
            try:
                return float(value)
            except (TypeError, ValueError):
                return default

        sorted_findings = sorted(
            report.findings,
            key=lambda x: _as_float((x or {}).get('risk_score', 0)),
            reverse=True
        )

        for finding in sorted_findings[:15]:
            risk_score = _as_float(finding.get('risk_score', 0))
            risk_class = get_risk_class(risk_score)
            vulns = finding.get('vulnerabilities', [])

            # Separate ClawSec CVEs from regular vulnerabilities
            clawsec_vulns = [v for v in vulns if v.startswith('clawsec_')]
            regular_vulns = [v for v in vulns if not v.startswith('clawsec_')]

            vuln_html = ' '.join([f'<span class="vuln-tag">{_esc(v)}</span>' for v in regular_vulns[:6]])
            cve_html = ' '.join([
                f'<span class="cve-tag">🛡️ {_esc(v.replace("clawsec_", ""))}</span>'
                for v in clawsec_vulns[:3]
            ])

            # Check for ClawSec intel badge
            metadata = finding.get('metadata', {})
            clawsec_advisories = metadata.get('clawsec_advisories', [])
            intel_badge = '<span class="intel-badge"><span class="intel-indicator"></span>INTEL MATCH</span>' if clawsec_advisories else ''

            ip = _esc(finding.get('ip', 'Unknown'))
            port = _esc(finding.get('port', '?'))
            hostname = _esc(finding.get('hostname', '') or '')
            service = _esc(finding.get('service', 'Unknown'))

            # Build a cleaner meta line (avoid leading bullets when hostname missing)
            location = (metadata.get('location') or {}) if isinstance(metadata, dict) else {}
            city = (location.get('city') or '').strip()
            country = (location.get('country') or '').strip()
            if city and country:
                loc_text = f"{city}, {country}"
            else:
                loc_text = city or country
            meta_parts = [p for p in [hostname, loc_text, service] if p]
            # Escape meta parts (defense-in-depth against weird banners/titles)
            meta_text = " • ".join([_esc(p) for p in meta_parts]) if meta_parts else service

            severity_label = {
                'critical': 'CRITICAL',
                'high': 'HIGH',
                'medium': 'MEDIUM',
                'low': 'LOW'
            }.get(risk_class, str(risk_class).upper())

            card_html = f"""
            <div class="finding-card {risk_class}">
              <div style="display:flex;justify-content:space-between;align-items:center;">
                <div>
                  <span class="finding-ip">{ip}</span>
                  <span class="finding-port">:{port}</span>
                  {intel_badge}
                </div>
                <span class="risk-badge risk-{risk_class}">⚡ {_esc(severity_label)} {float(risk_score):.1f}</span>
              </div>
              <div class="finding-meta">{meta_text}</div>
              <div class="vuln-container">
                {cve_html}
                {vuln_html if regular_vulns else ('<span style="color:#39FF14;font-family:Share Tech Mono;">✓ SECURE</span>' if not clawsec_vulns else '')}
              </div>
            </div>
            """

            # Force single-line HTML so Markdown can't “break out” mid-block and show raw tags.
            card_html = " ".join(textwrap.dedent(card_html).strip().split())
            render_html(card_html)
    else:
        df = pd.DataFrame(report.findings)
        display_columns = ['ip', 'port', 'hostname', 'service', 'risk_score', 'vulnerabilities']
        available_cols = [c for c in display_columns if c in df.columns]
        df_display = df[available_cols].copy()

        if 'vulnerabilities' in df_display.columns:
            df_display['vulnerabilities'] = df_display['vulnerabilities'].apply(
                lambda x: ', '.join(x[:3]) if isinstance(x, list) else str(x)
            )
        if 'risk_score' in df_display.columns:
            df_display = df_display.sort_values('risk_score', ascending=False)

        st.dataframe(df_display, use_container_width=True, height=500)

    # Export
    st.markdown('<div class="section-header"><span>📥</span> DATA EXTRACTION</div>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.download_button("📄 JSON EXPORT", json.dumps(report.to_dict(), indent=2, default=str),
                          f"imperial_scan_{report.scan_id[:8]}.json", "application/json", use_container_width=True)
    with col2:
        df_export = pd.DataFrame(report.findings)
        if 'vulnerabilities' in df_export.columns:
            df_export['vulnerabilities'] = df_export['vulnerabilities'].apply(lambda x: '|'.join(x) if isinstance(x, list) else str(x))
        st.download_button("📊 CSV EXPORT", df_export.to_csv(index=False),
                          f"imperial_scan_{report.scan_id[:8]}.csv", "text/csv", use_container_width=True)
    with col3:
        st.download_button("📝 REPORT", f"IMPERIAL SCAN REPORT\n{'='*40}\nTargets: {report.total_results}\nCritical: {report.critical_findings}",
                          f"imperial_report_{report.scan_id[:8]}.txt", "text/plain", use_container_width=True)


def main_page():
    """Main scan page."""
    st.markdown('<p class="main-header">✦ AASRT ✦</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Imperial Security Reconnaissance System</p>', unsafe_allow_html=True)

    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = None

    with st.sidebar:
        st.markdown('<div class="sidebar-title">⚙️ COMMAND CENTER</div>', unsafe_allow_html=True)

        shodan_status = get_shodan_status()
        if shodan_status['configured']:
            st.markdown("""
            <div class="api-status connected">
                <span class="live-indicator"></span>
                <span style="color: #39FF14; font-weight: 700; font-size: 1.1rem;">SHODAN ONLINE</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="api-status disconnected">
                <span style="color: #FF2D2D; font-weight: 700;">❌ CONNECTION FAILED</span>
            </div>
            """, unsafe_allow_html=True)
            st.caption("Configure SHODAN_API_KEY in .env")

        # ClawSec Threat Intelligence Status
        clawsec_stats = get_clawsec_stats()
        if clawsec_stats and clawsec_stats.get('total_advisories', 0) > 0:
            render_html(f"""
            <div class="clawsec-status">
                <div style="display: flex; align-items: center;">
                    <span class="clawsec-indicator"></span>
                    <span style="color: #9D4EDD; font-weight: 700; font-size: 1rem;">CLAWSEC INTEL</span>
                </div>
                <div style="font-size: 0.8rem; color: #4BD5EE; margin-top: 8px; font-family: 'Share Tech Mono', monospace;">
                    📡 {clawsec_stats['total_advisories']} advisories<br>
                    💀 {clawsec_stats.get('critical_count', 0)} critical | ⚠️ {clawsec_stats.get('high_count', 0)} high
                </div>
            </div>
            """)

        st.markdown("---")

        scan_type = st.radio("MISSION TYPE", ["🎯 TEMPLATE", "✍️ CUSTOM"], horizontal=True)

        if "TEMPLATE" in scan_type:
            templates = get_templates()
            template_icons = {
                'autogpt_instances': '🤖', 'langchain_agents': '🔗', 'jupyter_notebooks': '📓',
                'clawdbot_instances': '🐾', 'exposed_env_files': '📁', 'clawsec_advisories': '🛡️',
            }
            selected_template = st.selectbox("SELECT TARGET",templates, index=0 if templates else None,
                format_func=lambda x: f"{template_icons.get(x, '📋')} {x.replace('_', ' ').title()}")
            custom_query = None
        else:
            selected_template = None
            custom_query = st.text_area("QUERY INPUT", placeholder='http.title:"Dashboard"', height=80)

        st.markdown("---")

        with st.expander("🔧 ADVANCED CONFIG"):
            max_results = st.slider("MAX TARGETS", 10, 500, 100, step=10)

        st.markdown("---")

        agreed = st.checkbox("I accept mission parameters", key="agreement")
        can_scan = agreed and shodan_status['configured'] and (selected_template or custom_query)

        if st.button("🚀 INITIATE SCAN", type="primary", disabled=not can_scan, use_container_width=True):
            report = run_scan(template=selected_template, query=custom_query, max_results=max_results)
            st.session_state.scan_results = report

    if st.session_state.scan_results:
        display_results(st.session_state.scan_results)
    else:
        st.markdown("""
        <div class="welcome-box">
            <span class="welcome-icon">🛸</span>
            <div class="welcome-title">AWAITING ORDERS</div>
            <div class="welcome-text">
                Imperial Security Scanner Standing By<br>
                Select target parameters and initiate reconnaissance<span class="cursor"></span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="section-header"><span>🎯</span> QUICK TARGETS</div>', unsafe_allow_html=True)

        templates = get_templates()
        template_data = {
            'autogpt_instances': ('🤖', 'AutoGPT', 'AI Agent Systems'),
            'langchain_agents': ('🔗', 'LangChain', 'Chain Protocols'),
            'jupyter_notebooks': ('📓', 'Jupyter', 'Research Stations'),
            'clawdbot_instances': ('🐾', 'Clawdbot', 'Control Panels'),
            'exposed_env_files': ('📁', 'ENV Files', 'Config Leaks'),
            'clawsec_advisories': ('🛡️', 'ClawSec', 'Threat Intel'),
        }

        cols = st.columns(5)
        for i, template in enumerate(templates[:5]):
            icon, name, desc = template_data.get(template, ('📋', template, 'Scan'))
            with cols[i]:
                render_html(f"""
                <div class="template-card">
                    <span class="template-icon">{icon}</span>
                    <div class="template-name">{name}</div>
                    <div class="template-desc">{desc}</div>
                </div>
                """)


def history_page():
    """Scan history page."""
    st.markdown('<p class="main-header">📜 MISSION LOG</p>', unsafe_allow_html=True)

    db = get_database()
    scans = db.get_recent_scans(limit=50)

    if not scans:
        st.markdown("""
        <div class="welcome-box">
            <span class="welcome-icon">📭</span>
            <div class="welcome-title">NO RECORDS</div>
            <div class="welcome-text">Mission database is empty</div>
        </div>
        """, unsafe_allow_html=True)
        return

    stats = db.get_statistics()

    col1, col2, col3, col4 = st.columns(4)
    for col, icon, value, label in [
        (col1, "🔍", stats['total_scans'], "MISSIONS"),
        (col2, "🎯", stats['total_findings'], "TARGETS"),
        (col3, "🌐", stats['unique_ips'], "UNIQUE IPS"),
        (col4, "💀", stats['risk_distribution']['critical'], "CRITICAL"),
    ]:
        with col:
            render_html(f"""
            <div class="stat-card">
                <span class="stat-icon">{icon}</span>
                <div class="stat-value stat-info">{value}</div>
                <div class="stat-label">{label}</div>
            </div>
            """)

    st.markdown("---")

    for scan in scans[:10]:
        d = scan.to_dict()
        with st.expander(f"🔍 Mission {d['scan_id'][:8]} • {d['timestamp'][:16] if d['timestamp'] else 'Unknown'}"):
            st.markdown(f"**Results:** {d['total_results']} | **Status:** {d['status']}")


def settings_page():
    """Settings page."""
    st.markdown('<p class="main-header">⚙️ SYSTEM CONFIG</p>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 🔑 API STATUS")
        shodan_status = get_shodan_status()
        if shodan_status['configured']:
            st.markdown("""<div class="api-status connected" style="padding: 1.5rem;">
                <span class="live-indicator"></span>
                <span style="color: #39FF14; font-weight: 700;">SHODAN CONNECTED</span>
            </div>""", unsafe_allow_html=True)
        else:
            st.error("API not configured")

    with col2:
        st.markdown("### 💾 DATABASE")
        db = get_database()
        stats = db.get_statistics()
        st.metric("Total Scans", stats['total_scans'])
        st.metric("Total Findings", stats['total_findings'])

        if st.button("🗑️ PURGE OLD DATA", use_container_width=True):
            deleted = db.cleanup_old_data(days=90)
            st.success(f"Purged {deleted} records")


# =============================================================================
# Health Check
# =============================================================================

def get_health_status() -> Dict[str, Any]:
    """
    Get application health status.

    Checks connectivity to all critical services and returns
    a summary of application health.

    Returns:
        Dictionary containing health status of all components:
        - healthy: Overall health status (bool)
        - shodan: Shodan API status
        - database: Database connectivity
        - clawsec: ClawSec integration status
        - rate_limiting: Rate limit status for current session
    """
    from src.utils.config import Config
    from src.storage.database import Database

    health = {
        'healthy': True,
        'timestamp': datetime.now().isoformat(),
        'components': {}
    }

    # Check Shodan API
    shodan_status = get_shodan_status()
    health['components']['shodan'] = {
        'healthy': shodan_status['configured'],
        'configured': shodan_status['configured'],
        'credits': shodan_status.get('credits')
    }
    if not shodan_status['configured']:
        health['healthy'] = False

    # Check Database
    try:
        config = Config()
        db = Database(config)
        db_health = db.health_check()
        health['components']['database'] = {
            'healthy': db_health.get('healthy', False),
            'type': db_health.get('database_type', 'unknown'),
            'latency_ms': db_health.get('latency_ms')
        }
        if not db_health.get('healthy'):
            health['healthy'] = False
    except Exception as e:
        health['components']['database'] = {
            'healthy': False,
            'error': str(e)
        }
        health['healthy'] = False

    # Check ClawSec
    clawsec = get_clawsec_manager()
    health['components']['clawsec'] = {
        'enabled': clawsec is not None,
        'healthy': clawsec is not None
    }

    # Rate limiting status
    allowed, msg = check_rate_limit()
    health['components']['rate_limiting'] = {
        'scans_allowed': allowed,
        'message': msg if not allowed else 'OK'
    }

    return health


# =============================================================================
# Main Application Entry Point
# =============================================================================

def main() -> None:
    """
    Main application entry point.

    Initializes the Streamlit application, renders the navigation sidebar,
    and dispatches to the appropriate page based on user selection.

    Pages:
        - Scanner: Main scan interface for security reconnaissance
        - History: View past scan results and statistics
        - Config: System settings and API status
    """
    with st.sidebar:
        st.markdown("""
        <div style="text-align: center; padding: 1.5rem 0;">
            <div style="font-size: 3rem; filter: drop-shadow(0 0 20px #FFE81F);">⭐</div>
            <div style="font-family: 'Orbitron'; font-size: 1.5rem; color: #FFE81F; text-shadow: 0 0 20px #FFE81F; letter-spacing: 4px;">AASRT</div>
            <div style="font-family: 'Share Tech Mono'; font-size: 0.7rem; color: #4BD5EE;">v1.0.0 IMPERIAL</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        page = st.radio("NAVIGATION", ["🔍 SCANNER", "📜 HISTORY", "⚙️ CONFIG"], label_visibility="collapsed")

    # Page routing
    if page == "🔍 SCANNER":
        main_page()
    elif page == "📜 HISTORY":
        history_page()
    else:
        settings_page()

    # Footer
    st.sidebar.markdown("---")
    st.sidebar.markdown("""
    <div style="text-align: center; font-size: 0.7rem; color: #4BD5EE;">
        <div>POWERED BY SHODAN</div>
        <div style="color: #FFE81F; margin-top: 5px;">MAY THE FORCE BE WITH YOU</div>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
