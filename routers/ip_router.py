from fastapi import APIRouter, Query, HTTPException
from services.ip_service import check_ip_reputation
from services.cve_enricher import fetch_cves_by_keyword
import ipaddress

router = APIRouter()

@router.get("/ip", summary="IP Reputation Check")
def ip_route(
    param: str = Query(
        ...,
        description="IPv4 or IPv6 address",
    )
):
    # Validate IP format
    try:
        ipaddress.ip_address(param)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid IP address format"
        )

    result = check_ip_reputation(param)

    return result
