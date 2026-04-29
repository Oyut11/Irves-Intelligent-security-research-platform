"""
IRVES — Network Proxy Routes (Phase 6)
Thin aggregator — includes sub-routers from this package.
"""

from fastapi import APIRouter

from routes.network.flows import router as flows_router
from routes.network.proxy import router as proxy_router
from routes.network.ssl import router as ssl_router
from routes.network.ai_audit import router as ai_audit_router
from routes.network.intercept import router as intercept_router
from routes.network.security import router as security_router
from routes.network.fritap import router as fritap_router

router = APIRouter()

# Include all sub-routers — they inherit the parent prefix (/api/network)
router.include_router(flows_router)
router.include_router(proxy_router)
router.include_router(ssl_router)
router.include_router(ai_audit_router)
router.include_router(intercept_router)
router.include_router(security_router)
router.include_router(fritap_router)
