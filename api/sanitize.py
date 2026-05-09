"""
api/sanitize.py — kept for backward compatibility.
All logic has moved to stalker.py; this module re-exports from there.
"""
from stalker import sanitize_url, classify_stream_type, is_uncheckable

__all__ = ['sanitize_url', 'classify_stream_type', 'is_uncheckable']
