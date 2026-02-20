from typing import List, Optional
from ninja import Schema, ModelSchema
from backend.core.models import *


class TargetIn(Schema):
    name: str
    type: Optional[str] = None
    platform: Optional[str] = None
    program_url: Optional[str] = None
    domains: List[str] = []

class TargetUpdate(Schema):
    name: Optional[str] = None
    type: Optional[str] = None
    platform: Optional[str] = None
    program_url: Optional[str] = None
    add_domains: Optional[List[str]] = None
    remove_domains: Optional[List[str]] = None

class ScanDomainIn(Schema):
    domain: str
    chunk_size: Optional[int] = None

class ScanUrlIn(Schema):
    url: str
    auth_headers: Optional[List[str]] = None
    logout: Optional[str] = None

class SubdomainAdd(Schema):
    hostname: str
    cname: Optional[str] = None
    ip: Optional[str] = None
    is_alive: bool = False

class SubdomainRemove(Schema):
    hostnames: List[str]

class WebAppAdd(Schema):
    url: str
    status_code: Optional[int] = None
    content_length: Optional[int] = None
    title: Optional[str] = None
    tech_stack: Optional[List[str]] = None
    location: Optional[str] = None

class WebAppRemove(Schema):
    urls: List[str]

# --- OUTPUT SCHEMAS ---

class DomainOut(ModelSchema):
    class Meta:
        model = Domain
        fields = ["hostname"]

class TargetOut(ModelSchema):
    domains: List[DomainOut] = []

    class Meta:
        model = Target
        fields = ["name", "type", "platform", "program_url"]

class SubdomainOut(ModelSchema):
    class Meta:
        model = Subdomain
        fields = ["hostname", "cname", "ip"]

class WebAppOut(ModelSchema):
    class Meta:
        model = WebApplication
        fields = ["status_code", "url", "content_length", "tech_stack", "location", "title"]

class VulnSubdomainOut(Schema):
    hostname: str

class VulnWebAppOut(Schema):
    url: str

class VulnerabilityOut(ModelSchema):
    subdomain: Optional[VulnSubdomainOut] = None
    web_app: Optional[VulnWebAppOut] = None

    class Meta:
        model = Vulnerability
        fields = ["name", "location", "severity", "type"]

class ParameterOut(ModelSchema):
    class Meta:
        model = Parameter
        fields = ["key", "value"]

class EndPointOut(ModelSchema):
    parameter: List[ParameterOut] = []

    class Meta:
        model = EndPoint
        fields = ["path", "status_code", "content_type", "content_length", "location_header"]

class ArchivedURLOut(ModelSchema):
    class Meta:
        model = ArchivedURLs
        fields = ["url", "source"]

# --- TASK SCHEMAS ---

class TaskStatusOut(Schema):
    task_id: str  # Kept this because it's a Celery UUID, not a database ID
    status: str