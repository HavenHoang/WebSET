from crawl.fetch import fetch_target
from crawl.forms import extract_forms
from crawl.tech_detect import (detect_tech_stack, detect_tech_stack_from_path,
                               detect_tech_names, detect_tech_from_page)
from crawl.zip_reader import open_project_zip, list_zip_paths

__all__ = [
    "fetch_target",
    "extract_forms",
    "detect_tech_stack",
    "detect_tech_stack_from_path",
    "detect_tech_names",
    "detect_tech_from_page",
    "open_project_zip",
    "list_zip_paths",
]
