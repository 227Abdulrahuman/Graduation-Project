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

class WebAppCreateIn(Schema):
    url: str
    target_name: str

class WebAppCreateOut(Schema):
    message: str
    target: str
    domain: str
    subdomain: str
    webapp_url: str

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

class ArchivedURLOut(ModelSchema):
    class Meta:
        model = ArchivedURLs
        fields = ["url", "source"]


class TaskStatusOut(Schema):
    task_id: str
    status: str