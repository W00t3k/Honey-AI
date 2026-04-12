from .chat import router as chat_router
from .models import router as models_router
from .embeddings import router as embeddings_router
from .billing import router as billing_router
from .anthropic import router as anthropic_router
from .mcp import router as mcp_router
from .agentic import router as agentic_router
from .audio import router as audio_router
from .gemini import router as gemini_router
from .vectordb import router as vectordb_router
from .azure import router as azure_router
from .cohere import router as cohere_router
from .admin import router as admin_router, set_database

__all__ = [
    "chat_router",
    "models_router",
    "embeddings_router",
    "billing_router",
    "anthropic_router",
    "mcp_router",
    "agentic_router",
    "audio_router",
    "gemini_router",
    "vectordb_router",
    "azure_router",
    "cohere_router",
    "admin_router",
    "set_database",
]
