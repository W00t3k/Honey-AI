"""
Vector database API honeypot endpoints.

RAG (Retrieval-Augmented Generation) systems are a primary target for:
  - Data exfiltration: querying the vector store to reconstruct training/indexed data
  - RAG poisoning: upserting malicious vectors that inject content into future queries
  - Namespace enumeration: discovering what data is indexed
  - Embedding reconstruction: using query results to reverse-engineer embeddings

This module mimics three major vector DB APIs:

1. PINECONE — pinecone.io, auth via Api-Key header
   Paths: /query, /upsert, /delete, /fetch, /update, /describe_index_stats
   Key format: any hex string via 'Api-Key' header

2. CHROMA — chromadb, auth optional (often unauthenticated in self-hosted)
   Paths: /api/v1/collections, /api/v1/collections/{id}/query, /api/v1/collections/{id}/add
   Key format: Bearer token or none

3. WEAVIATE — weaviate.io, auth via Authorization: Bearer
   Paths: /v1/objects, /v1/graphql, /v1/schema, /v1/meta
   Also uses X-Openai-Api-Key header (for vectorizer config — exposes embedded API keys)
"""

import json
import random
import time
import uuid
import asyncio
from typing import Optional

from fastapi import APIRouter, Request, Response

from services import get_logger

router = APIRouter()


def _log_data(request, body_raw, body_parsed, response_body, status=200):
    async def _do():
        logger = get_logger()
        await logger.log_request(
            request=request,
            body_raw=body_raw,
            body_parsed=body_parsed,
            response_body=response_body,
            response_status=status,
            response_time_ms=random.uniform(5, 50),
        )
    return _do()


def _pinecone_headers():
    return {"content-type": "application/json"}


def _chroma_headers():
    return {"content-type": "application/json", "x-chroma-version": "0.5.20"}


def _weaviate_headers():
    return {"content-type": "application/json", "server": "Weaviate"}


def _fake_vector(dims=1536):
    return [round(random.gauss(0, 0.1), 8) for _ in range(dims)]


# ── PINECONE ───────────────────────────────────────────────────────────────────

@router.post("/query")
async def pinecone_query(request: Request):
    """
    Pinecone query — vector similarity search.

    PRIMARY RAG EXFIL VECTOR: attacker queries with a crafted vector
    to retrieve the nearest real documents from the index. Repeated
    querying with systematic vectors can reconstruct indexed content.
    Also captures: namespace enumeration, filter expressions (reveals schema),
    includeMetadata=true (shows what metadata is indexed).
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    await asyncio.sleep(random.uniform(0.02, 0.1))

    top_k = body_parsed.get("topK", body_parsed.get("top_k", 10))
    namespace = body_parsed.get("namespace", "")
    include_metadata = body_parsed.get("includeMetadata", body_parsed.get("include_metadata", False))

    # Generate fake matches with canary metadata
    matches = []
    for i in range(min(int(top_k), 10)):
        match = {
            "id": f"vec_{uuid.uuid4().hex[:16]}",
            "score": round(random.uniform(0.85, 0.99), 8),
            "values": _fake_vector(1536) if body_parsed.get("includeValues") else [],
        }
        if include_metadata:
            match["metadata"] = {
                "source": random.choice([
                    "customer_contracts.pdf",
                    "internal_policy.docx",
                    "employee_data.csv",
                    "api_documentation.md",
                    "system_prompts.json",
                ]),
                "page": random.randint(1, 50),
                "chunk": i,
                "canary_rag_result": True,
            }
        matches.append(match)

    response_data = {
        "matches": matches,
        "namespace": namespace,
        "usage": {"readUnits": random.randint(1, 5)},
    }
    response_body = json.dumps(response_data)

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=(time.time() - start_time) * 1000,
    )
    return Response(content=response_body, media_type="application/json", headers=_pinecone_headers())


@router.post("/upsert")
async def pinecone_upsert(request: Request):
    """
    Pinecone upsert — RAG POISONING ENTRY POINT.
    Attacker inserts malicious vectors with injected metadata/text
    that will be retrieved in future RAG queries, injecting into LLM context.
    Captures: vector count, namespace, metadata content (injection payload).
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    vectors = body_parsed.get("vectors", [])
    namespace = body_parsed.get("namespace", "")

    response_data = {"upsertedCount": len(vectors)}
    response_body = json.dumps(response_data)

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=(time.time() - start_time) * 1000,
    )
    return Response(content=response_body, media_type="application/json", headers=_pinecone_headers())


@router.get("/describe_index_stats")
@router.post("/describe_index_stats")
async def pinecone_describe_index_stats(request: Request):
    """Index stats — reveals dimension count, namespace names, vector counts."""
    body_raw = (await request.body()).decode("utf-8", errors="replace") if request.method == "POST" else None
    body_parsed = {"endpoint": "describe_index_stats"}

    response_data = {
        "namespaces": {
            "": {"vectorCount": random.randint(10000, 500000)},
            "production": {"vectorCount": random.randint(50000, 1000000)},
            "staging": {"vectorCount": random.randint(1000, 50000)},
            "documents": {"vectorCount": random.randint(5000, 100000)},
        },
        "dimension": 1536,
        "indexFullness": round(random.uniform(0.1, 0.8), 4),
        "totalVectorCount": random.randint(100000, 2000000),
    }
    response_body = json.dumps(response_data)

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=random.uniform(5, 30),
    )
    return Response(content=response_body, media_type="application/json", headers=_pinecone_headers())


@router.post("/fetch")
async def pinecone_fetch(request: Request):
    """Fetch specific vectors by ID — targeted extraction."""
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {}

    ids = body_parsed.get("ids", [])
    response_data = {
        "vectors": {
            vid: {
                "id": vid,
                "values": _fake_vector(1536),
                "metadata": {"source": "internal_doc.pdf", "canary": True},
            }
            for vid in ids[:50]
        },
        "namespace": body_parsed.get("namespace", ""),
    }
    response_body = json.dumps(response_data)

    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=body_raw, body_parsed=body_parsed,
        response_body=f"[{len(ids)} vectors fetched]",
        response_status=200, response_time_ms=random.uniform(5, 30),
    )
    return Response(content=response_body, media_type="application/json", headers=_pinecone_headers())


@router.post("/delete")
async def pinecone_delete(request: Request):
    """Vector deletion — attacker removing indexed data or canary markers."""
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {}

    response_body = json.dumps({})
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=body_raw, body_parsed=body_parsed,
        response_body=response_body, response_status=200, response_time_ms=10.0,
    )
    return Response(content=response_body, media_type="application/json", headers=_pinecone_headers())


# ── CHROMA ─────────────────────────────────────────────────────────────────────

@router.get("/api/v1/collections")
async def chroma_list_collections(request: Request):
    """
    Chroma collection listing.
    Self-hosted Chroma is often unauthenticated — attacker enumerates
    all collections to find RAG data stores.
    """
    response_data = [
        {"id": uuid.uuid4().hex, "name": name, "metadata": {}}
        for name in ["documents", "customer_support_kb", "internal_wiki", "product_docs", "code_embeddings"]
    ]
    response_body = json.dumps(response_data)

    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed={"endpoint": "chroma_list_collections"},
        response_body=response_body, response_status=200, response_time_ms=10.0,
    )
    return Response(content=response_body, media_type="application/json", headers=_chroma_headers())


@router.post("/api/v1/collections")
async def chroma_create_collection(request: Request):
    """Create a Chroma collection — RAG poisoning setup."""
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {}

    response_data = {
        "id": uuid.uuid4().hex,
        "name": body_parsed.get("name", "untitled"),
        "metadata": body_parsed.get("metadata", {}),
    }
    response_body = json.dumps(response_data)

    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=body_raw, body_parsed=body_parsed,
        response_body=response_body, response_status=200, response_time_ms=10.0,
    )
    return Response(content=response_body, media_type="application/json", headers=_chroma_headers())


@router.post("/api/v1/collections/{collection_id}/query")
async def chroma_query(collection_id: str, request: Request):
    """
    Chroma vector query — same exfil vector as Pinecone query.
    Captures: query embeddings, where filter (schema enumeration),
    include fields, n_results.
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {}

    n_results = body_parsed.get("n_results", 10)
    include = body_parsed.get("include", ["metadatas", "documents", "distances"])
    n = min(int(n_results), 20)

    response_data = {
        "ids": [[f"doc_{uuid.uuid4().hex[:8]}" for _ in range(n)]],
        "distances": [[round(random.uniform(0.01, 0.5), 8) for _ in range(n)]],
        "embeddings": None,
        "metadatas": [[{"source": f"document_{i}.pdf", "chunk": i, "canary_rag": True} for i in range(n)]] if "metadatas" in include else None,
        "documents": [[f"Document content chunk {i}. This is synthetic canary content." for i in range(n)]] if "documents" in include else None,
    }
    response_body = json.dumps(response_data)

    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=body_raw,
        body_parsed={**body_parsed, "collection_id": collection_id},
        response_body=f"[{n} results]",
        response_status=200, response_time_ms=(time.time() - start_time) * 1000,
    )
    return Response(content=response_body, media_type="application/json", headers=_chroma_headers())


@router.post("/api/v1/collections/{collection_id}/add")
async def chroma_add(collection_id: str, request: Request):
    """Chroma add — RAG poisoning injection point."""
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {}

    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=body_raw,
        body_parsed={**body_parsed, "collection_id": collection_id},
        response_body="true", response_status=201, response_time_ms=10.0,
    )
    return Response(content="true", media_type="application/json", headers=_chroma_headers())


@router.get("/api/v1/heartbeat")
async def chroma_heartbeat(request: Request):
    """Chroma health check — used to detect unauthenticated Chroma instances."""
    response_data = {"nanosecond heartbeat": time.time_ns()}
    response_body = json.dumps(response_data)
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed={"endpoint": "chroma_heartbeat"},
        response_body=response_body, response_status=200, response_time_ms=1.0,
    )
    return Response(content=response_body, media_type="application/json", headers=_chroma_headers())


# ── WEAVIATE ───────────────────────────────────────────────────────────────────

@router.get("/v1/meta")
async def weaviate_meta(request: Request):
    """
    Weaviate meta — version and module info.
    Also captures X-Openai-Api-Key header that Weaviate uses for its
    text2vec-openai vectorizer — a nested API key embedded in Weaviate config.
    """
    # CRITICAL: Weaviate passes OpenAI keys via X-Openai-Api-Key header
    openai_key = request.headers.get("x-openai-api-key") or request.headers.get("x-openai-apikey")
    cohere_key = request.headers.get("x-cohere-api-key")
    huggingface_key = request.headers.get("x-huggingface-api-key")

    body_parsed = {"endpoint": "weaviate_meta"}
    if openai_key:
        body_parsed["embedded_openai_key"] = openai_key
    if cohere_key:
        body_parsed["embedded_cohere_key"] = cohere_key
    if huggingface_key:
        body_parsed["embedded_huggingface_key"] = huggingface_key

    response_data = {
        "hostname": "weaviate://localhost",
        "modules": {
            "text2vec-openai": {"version": "v1", "wordCount": 1000},
            "generative-openai": {"version": "v1"},
            "qna-openai": {"version": "v1"},
        },
        "version": "1.26.1",
    }
    response_body = json.dumps(response_data)

    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed=body_parsed,
        response_body=response_body, response_status=200, response_time_ms=2.0,
    )
    return Response(content=response_body, media_type="application/json", headers=_weaviate_headers())


@router.get("/v1/schema")
async def weaviate_schema(request: Request):
    """
    Weaviate schema — reveals all collection/class names and their properties.
    High-value recon: tells attacker exactly what data is indexed.
    """
    classes = [
        {
            "class": name,
            "description": f"{name} collection",
            "properties": [
                {"name": "content", "dataType": ["text"]},
                {"name": "source", "dataType": ["text"]},
                {"name": "metadata", "dataType": ["object"]},
            ],
            "vectorizer": "text2vec-openai",
        }
        for name in ["Document", "CustomerRecord", "KnowledgeBase", "CodeSnippet", "InternalPolicy"]
    ]

    response_data = {"classes": classes}
    response_body = json.dumps(response_data)

    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed={"endpoint": "weaviate_schema"},
        response_body=response_body, response_status=200, response_time_ms=5.0,
    )
    return Response(content=response_body, media_type="application/json", headers=_weaviate_headers())


@router.post("/v1/graphql")
async def weaviate_graphql(request: Request):
    """
    Weaviate GraphQL — vector search and object retrieval.
    Captures: Get queries (enumeration), nearVector (extraction),
    nearText (semantic search), where filters (schema probing).
    GraphQL query text is logged in full.
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    openai_key = request.headers.get("x-openai-api-key")
    if openai_key:
        body_parsed["embedded_openai_key"] = openai_key

    response_data = {
        "data": {
            "Get": {
                "Document": [
                    {
                        "content": f"This is canary document content {i}.",
                        "source": f"document_{i}.pdf",
                        "_additional": {"id": uuid.uuid4().hex, "distance": round(random.uniform(0.01, 0.3), 8)},
                    }
                    for i in range(random.randint(2, 8))
                ]
            }
        }
    }
    response_body = json.dumps(response_data)

    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=body_raw, body_parsed=body_parsed,
        response_body=response_body, response_status=200,
        response_time_ms=(time.time() - start_time) * 1000,
    )
    return Response(content=response_body, media_type="application/json", headers=_weaviate_headers())


@router.post("/v1/objects")
async def weaviate_create_object(request: Request):
    """Create Weaviate object — RAG poisoning."""
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {}

    obj_id = uuid.uuid4().hex
    response_data = {**body_parsed, "id": obj_id, "creationTimeUnix": int(time.time() * 1000)}
    response_body = json.dumps(response_data)

    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=body_raw, body_parsed=body_parsed,
        response_body=response_body, response_status=200, response_time_ms=10.0,
    )
    return Response(content=response_body, media_type="application/json", headers=_weaviate_headers())


@router.get("/v1/objects")
async def weaviate_list_objects(request: Request):
    """List Weaviate objects — bulk enumeration."""
    openai_key = request.headers.get("x-openai-api-key")
    body_parsed = {"endpoint": "weaviate_list_objects"}
    if openai_key:
        body_parsed["embedded_openai_key"] = openai_key

    objects = [
        {
            "class": "Document",
            "id": uuid.uuid4().hex,
            "properties": {"content": f"Canary document {i}", "source": f"doc_{i}.pdf"},
        }
        for i in range(random.randint(3, 10))
    ]
    response_data = {"objects": objects, "totalResults": random.randint(1000, 50000)}
    response_body = json.dumps(response_data)

    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed=body_parsed,
        response_body=response_body, response_status=200, response_time_ms=15.0,
    )
    return Response(content=response_body, media_type="application/json", headers=_weaviate_headers())
