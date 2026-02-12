from typing import List
from ninja import NinjaAPI, ModelSchema, Schema
from django.shortcuts import get_object_or_404

# Ensure this import points to where your models actually are
from backend.core.models import Target, Domain
from typing import Optional
api = NinjaAPI()


class TargetSchema(ModelSchema):
    class Meta:  # Changed from Config
        model = Target
        fields = ['id', 'name', 'platform', 'program_url']  # Changed from model_fields


class TargetIn(ModelSchema):
    class Meta:  # Changed from Config
        model = Target
        fields = ['name', 'platform', 'program_url']

class TargetPatch(Schema):
    name: Optional[str] = None
    platform: Optional[str] = None
    program_url: Optional[str] = None


class DomainSchema(ModelSchema):
    class Meta:
        model = Domain
        fields = ['id', 'hostname', 'target']


class DomainIn(Schema):
    target_id: int
    hostname: str


class DomainUpdate(Schema):
    target_id: int = None
    hostname: str = None



@api.post("/targets", response=TargetSchema)
def create_target(request, payload: TargetIn):
    target = Target.objects.create(**payload.dict())
    return target


@api.get("/targets", response=List[TargetSchema])
def list_targets(request):
    return Target.objects.all()


@api.get("/targets/{target_id}", response=TargetSchema)
def get_target(request, target_id: int):
    target = get_object_or_404(Target, id=target_id)
    return target


@api.patch("/targets/{target_id}", response=TargetSchema)
def update_target(request, target_id: int, payload: TargetPatch):
    target = get_object_or_404(Target, id=target_id)

    for attr, value in payload.dict(exclude_unset=True).items():
        setattr(target, attr, value)

    target.save()
    return target

@api.delete("/targets/{target_id}")
def delete_target(request, target_id: int):
    target = get_object_or_404(Target, id=target_id)
    target.delete()
    return {"success": True}



@api.post("/domains", response=DomainSchema)
def create_domain(request, payload: DomainIn):
    target = get_object_or_404(Target, id=payload.target_id)
    domain = Domain.objects.create(
        target=target,
        hostname=payload.hostname
    )
    return domain


@api.get("/domains", response=List[DomainSchema])
def list_domains(request):
    return Domain.objects.all()


@api.get("/domains/{domain_id}", response=DomainSchema)
def get_domain(request, domain_id: int):
    domain = get_object_or_404(Domain, id=domain_id)
    return domain


@api.put("/domains/{domain_id}", response=DomainSchema)
def update_domain(request, domain_id: int, payload: DomainUpdate):
    domain = get_object_or_404(Domain, id=domain_id)

    if payload.hostname:
        domain.hostname = payload.hostname

    if payload.target_id:
        target = get_object_or_404(Target, id=payload.target_id)
        domain.target = target

    domain.save()
    return domain


@api.delete("/domains/{domain_id}")
def delete_domain(request, domain_id: int):
    domain = get_object_or_404(Domain, id=domain_id)
    domain.delete()
    return {"success": True}


@api.get("/targets/{target_id}/domains", response=List[DomainSchema])
def list_target_domains(request, target_id: int):
    target = get_object_or_404(Target, id=target_id)
    # Ensure your Domain model has related_name="domains" in the ForeignKey
    return target.domains.all()