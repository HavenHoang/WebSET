from crawler.fetch import fetch_target
from crawler.forms import extract_forms
from crawler.param_discover import discover_request_targets
from crawler.tech_detect import (
    detect_tech_stack,
    detect_tech_stack_from_path,
    detect_tech_names,
    detect_tech_from_page,
)
from crawler.zip_reader import open_project_zip, list_zip_paths

__all__ = [
    "fetch_target",
    "extract_forms",
    "discover_request_targets",
    "detect_tech_stack",
    "detect_tech_stack_from_path",
    "detect_tech_names",
    "detect_tech_from_page",
    "open_project_zip",
    "list_zip_paths",
]
