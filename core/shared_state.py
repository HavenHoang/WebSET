class SharedState:
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

    @classmethod
    def has_scan_data(cls) -> bool:
        return cls.current_url is not None

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
        if case_name is not None:
            cls.case_name = case_name
        if tech_stacks is not None:
            cls.tech_stacks = tech_stacks
        if case_id is not None:
            cls.case_id = case_id
        if scan_id is not None:
            cls.scan_id = scan_id

    @classmethod
    def set_stack_result(cls, url, tech_stacks=None, stack_findings=None, case_name=None):
        if url is not None:
            cls.current_url = url
        if tech_stacks is not None:
            cls.tech_stacks = tech_stacks or []
        if stack_findings is not None:
            cls.stack_findings = stack_findings or []
        if case_name is not None:
            cls.case_name = case_name
