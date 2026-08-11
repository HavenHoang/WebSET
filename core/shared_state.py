class SharedState:
    """
    Session state for WebSET GUI.

    findings        → Start Scan only (may include CWE/OWASP/NIST/SANS).
    stack_findings  → Get Stack platform notes only (guidance; no standards mapping).
    tech_stacks     → Detected technologies from Get Stack.

    has_scan_data()  → True only after Start Scan (_start_scan_active).
    has_stack_data() → True if tech_stacks or stack_findings present.
    Get Stack must NEVER set _start_scan_active.

    active_test_finding → optional hand-off from Alerts → Payload
      (one finding target for a single-request Active Test).
    """

    current_url = None
    findings = []
    stack_findings = []
    case_name = None
    scan_type = None
    tech_stacks = []
    case_id = None
    scan_id = None
    current_user_id = None
    current_user_name = None
    # Start Scan pipeline only (Get Stack must NOT flip this)
    _start_scan_active = False
    # Alerts → Payload Active Test hand-off (not persisted)
    active_test_finding = None

    @classmethod
    def clear(cls):
        cls.current_url = None
        cls.findings = []
        cls.stack_findings = []
        cls.case_name = None
        cls.scan_type = None
        cls.tech_stacks = []
        cls.case_id = None
        cls.scan_id = None
        cls._start_scan_active = False
        cls.active_test_finding = None

    @classmethod
    def has_scan_data(cls) -> bool:
        return bool(cls._start_scan_active)

    @classmethod
    def has_stack_data(cls) -> bool:
        return bool(cls.tech_stacks) or bool(cls.stack_findings)

    @classmethod
    def is_signed_in(cls) -> bool:
        return cls.current_user_id is not None

    @classmethod
    def set_user(cls, user_id: int, display_name: str):
        cls.current_user_id = int(user_id)
        cls.current_user_name = display_name or f"User {user_id}"

    @classmethod
    def set_scan_result(
        cls,
        url,
        findings,
        scan_type="Dynamic",
        case_name=None,
        tech_stacks=None,
        case_id=None,
        scan_id=None,
    ):
        cls.current_url = url
        cls.findings = findings or []
        cls.scan_type = scan_type
        cls._start_scan_active = True
        # New Start Scan session clears any previous Active Test target
        cls.active_test_finding = None
        if case_name is not None:
            cls.case_name = case_name
        if tech_stacks is not None:
            cls.tech_stacks = tech_stacks
        if case_id is not None:
            cls.case_id = case_id
        if scan_id is not None:
            cls.scan_id = scan_id

    @classmethod
    def set_stack_result(
        cls,
        url=None,
        tech_stacks=None,
        stack_findings=None,
        case_name=None,
        case_id=None,
        scan_id=None,
    ):
        if url is not None:
            cls.current_url = url
        if tech_stacks is not None:
            cls.tech_stacks = tech_stacks or []
        if stack_findings is not None:
            cls.stack_findings = stack_findings or []
        if case_name is not None:
            cls.case_name = case_name
        if case_id is not None:
            cls.case_id = case_id
        if scan_id is not None:
            cls.scan_id = scan_id
        # intentionally do NOT set _start_scan_active
        # intentionally do NOT clear active_test_finding (Start Scan finding may still be valid)

    @classmethod
    def set_active_test_finding(cls, finding: dict | None):
        """
        Hand-off from Alerts → Payload.
        finding should include (when available):
          url/endpoint, method, param/input, param_location, context, vuln_type
        """
        cls.active_test_finding = dict(finding) if finding else None

    @classmethod
    def clear_active_test_finding(cls):
        cls.active_test_finding = None
