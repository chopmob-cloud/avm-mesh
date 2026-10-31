"""A2A SUT that serves the AlgoVoi settlement-evidence extension.

Derived from the TCK's generated reference SUT, differing in exactly two places:

  1. the agent card advertises our extension, built from avm_mesh.extension_descriptor();
  2. a `settlement-evidence-*` message id returns a real settlement receipt, converted
     from the dict avm_mesh.as_artifact() emits into the SDK's proto Part.

Everything else is the reference SUT, so a TCK comparison isolates our extension.
"""

import asyncio
import logging
import os

import grpc.aio
import uvicorn

from google.protobuf import json_format
from google.protobuf.struct_pb2 import Value

from starlette.applications import Starlette

import a2a.types.a2a_pb2_grpc as a2a_grpc

from a2a.helpers.proto_helpers import new_task_from_user_message
from a2a.server.agent_execution.agent_executor import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.events.event_queue import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.request_handlers.grpc_handler import GrpcHandler
from a2a.server.routes import (
    create_agent_card_routes,
    create_jsonrpc_routes,
    create_rest_routes,
)
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.server.tasks.task_updater import TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentExtension,
    AgentCard,
    AgentInterface,
    AgentProvider,
    AgentSkill,
    Part,
)
from a2a.utils.errors import A2AError

# --- this is the only reason this SUT exists -------------------------------
import hashlib
import json

from avm_mesh.a2a import ARTIFACT_NAME, as_artifact, extension_descriptor

REST_URL = '/a2a/rest'

_STREAMING_TIMEOUT_S = 2

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('TckSutAgent')


class TckAgentExecutor(AgentExecutor):
    """TCK agent executor with messageId-prefix routing."""

    async def execute(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        """Execute the agent's logic based on the messageId prefix."""
        task_id = context.task_id
        context_id = context.context_id
        if task_id is None or context_id is None:
            return

        updater = TaskUpdater(event_queue, task_id, context_id)
        message = context.message
        if message is None:
            await updater.complete(
                updater.new_agent_message([Part(text='No message provided')])
            )
            return

        if context.current_task is None:
            await event_queue.enqueue_event(new_task_from_user_message(message))

        message_id = message.message_id

        if message_id.startswith('tck-stream-artifact-chunked'):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(text="chunk-1 ")], append=True)
            await updater.add_artifact(parts=[Part(text="chunk-2")], append=True, last_chunk=True)
            await updater.complete()
            return

        if message_id.startswith('test-resubscribe-message-id'):
            await updater.start_work()
            await asyncio.sleep(4)
            await updater.complete()
            return

        if message_id.startswith('tck-stream-artifact-text'):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(text="Streamed text content")])
            await updater.complete()
            return

        if message_id.startswith('tck-stream-artifact-file'):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(raw=b'tck', media_type="text/plain", filename="output.txt")])
            await updater.complete()
            return

        if message_id.startswith('tck-stream-ordering-001'):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(text="Ordered output")])
            await updater.complete()
            return

        if message_id.startswith('tck-artifact-file-url'):
            await updater.add_artifact(parts=[Part(url="https://example.com/output.txt", media_type="text/plain", filename="output.txt")])
            await updater.complete()
            return

        if message_id.startswith('tck-delayed-complete'):
            await updater.start_work()
            await asyncio.sleep(2)
            await updater.complete(updater.new_agent_message([Part(text="Done after delay")]))
            return

        if message_id.startswith('tck-message-response'):
            await event_queue.enqueue_event(updater.new_agent_message([Part(text="Direct message response")]))
            return

        if message_id.startswith('tck-input-required'):
            await updater.requires_input()
            return

        if message_id.startswith('tck-complete-task'):
            await updater.complete(updater.new_agent_message([Part(text="Hello from TCK")]))
            return

        if message_id.startswith('tck-artifact-text'):
            await updater.add_artifact(parts=[Part(text="Generated text content")])
            await updater.complete()
            return

        if message_id.startswith('tck-artifact-file'):
            await updater.add_artifact(parts=[Part(raw=b'tck', media_type="text/plain", filename="output.txt")])
            await updater.complete()
            return

        if message_id.startswith('settlement-evidence'):
            await updater.start_work()
            # LEVEL 1 integrity over the exact bytes; no bundle is needed to seal,
            # and claiming a tier this SUT cannot anchor would be a lie.
            content = json.dumps(
                {"settlement": {"tx_id": "TCK-" + message_id, "chain": "voi",
                                "amount_microunits": "1000000"},
                 "issuer_did": "did:example:tck"},
                sort_keys=True, separators=(",", ":"),
            ).encode()
            receipt = {
                "canonical_bytes_b64": __import__("base64").b64encode(content).decode(),
                "content_hash": hashlib.sha256(content).hexdigest(),
                "evidence_uri": "file://proofpack.json",
            }
            artifact = as_artifact(receipt)
            # Convert OUR emitted part through the SDK's own proto parser. If the
            # part shape is wrong, this raises here rather than on the wire.
            parts = [json_format.Parse(json.dumps(p), Part()) for p in artifact["parts"]]
            await updater.add_artifact(parts=parts)
            await updater.complete()
            return

        if message_id.startswith('tck-artifact-data'):
            await updater.add_artifact(parts=[Part(data=json_format.Parse("{\"key\": \"value\", \"count\": 42}", Value()))])
            await updater.complete()
            return

        if message_id.startswith('tck-reject-task'):
            raise A2AError('rejected')

        if message_id.startswith('tck-stream-001'):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(text="Stream hello from TCK")])
            await updater.complete()
            return

        if message_id.startswith('tck-stream-002'):
            await updater.complete()
            return

        if message_id.startswith('tck-stream-003'):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(text="Stream task lifecycle")])
            await updater.complete()
            return

        # Default: complete the task with an echo response
        await updater.complete(
            updater.new_agent_message(
                [Part(text='Unhandled messageId prefix: ' + message_id)]
            )
        )

    async def cancel(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        """Cancel a task."""
        task_id = context.task_id
        context_id = context.context_id
        if task_id is None or context_id is None:
            return
        updater = TaskUpdater(event_queue, task_id, context_id)
        await updater.cancel()


def _get_env(name: str, default: str) -> str:
    value = os.environ.get(name, '')
    return value if value else default


async def main() -> None:
    """Start the TCK SUT agent with all three transports."""
    host = _get_env('SUT_HOST', 'localhost:9999')
    http_port = int(host.rsplit(':', 1)[-1]) if ':' in host else 9999
    grpc_port = int(_get_env('GRPC_PORT', str(http_port + 1)))

    agent_card = AgentCard(
        name='AlgoVoi settlement-evidence SUT',
        description='A2A SUT advertising the AlgoVoi settlement-evidence extension',
        version='1.0.0',
        provider=AgentProvider(
            organization='A2A Project',
            url='https://github.com/a2aproject',
        ),
        supported_interfaces=[
            AgentInterface(
                url=f'http://{host}',
                protocol_binding='JSONRPC',
                protocol_version='1.0',
            ),
            AgentInterface(
                url=f'http://{host}{REST_URL}',
                protocol_binding='HTTP+JSON',
                protocol_version='1.0',
            ),
            AgentInterface(
                url=f'{host.rsplit(":", 1)[0]}:{grpc_port}',
                protocol_binding='GRPC',
                protocol_version='1.0',
            ),
        ],
        capabilities=AgentCapabilities(
            streaming=True,
            push_notifications=False,
            extensions=[AgentExtension(
                uri=extension_descriptor()["uri"],
                description=extension_descriptor()["description"],
                required=extension_descriptor()["required"],
            )],
        ),
        default_input_modes=['text'],
        default_output_modes=['text'],
        skills=[
            AgentSkill(
                id='settlement-evidence',
                name='Settlement Evidence',
                description='Handles TCK conformance test messages',
                tags=['tck'],
            ),
        ],
    )

    task_store = InMemoryTaskStore()
    request_handler = DefaultRequestHandler(
        agent_executor=TckAgentExecutor(),
        task_store=task_store,
        agent_card=agent_card,
    )

    # JSON-RPC (mounted at root, matching the interface URL declared above)
    jsonrpc_routes = create_jsonrpc_routes(
        request_handler=request_handler,
        rpc_url='/',
    )
    # REST / HTTP+JSON
    rest_routes = create_rest_routes(
        request_handler=request_handler,
        path_prefix=REST_URL,
    )
    # Agent card discovery (/.well-known/agent-card.json)
    agent_card_routes = create_agent_card_routes(agent_card=agent_card)

    # NOTE: agent_card_routes must precede rest_routes — REST exposes a
    # catch-all Mount('/{tenant}', ...) that would otherwise swallow
    # /.well-known/agent-card.json before it's tried.
    # --- content-type gate -------------------------------------------------
    # A2A over JSON-RPC declares an unsupported media type by returning
    # ContentTypeNotSupportedError (-32005). Handing a text/plain body to the
    # SDK's JSON parser produces ParseError (-32700) instead, which is both the
    # wrong code and a misleading diagnosis. Reject at the HTTP layer with 415,
    # which HTTP defines for exactly this and which the TCK accepts as a valid
    # rejection (it skips rather than failing). Applies to the JSON-RPC and REST
    # surfaces only; the agent card is a GET and carries no body.
    from starlette.middleware import Middleware
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse

    class _ContentTypeGate(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if request.method in ("POST", "PUT", "PATCH"):
                raw = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
                if raw and raw not in ("application/json", "application/json-rpc"):
                    return JSONResponse(
                        {"jsonrpc": "2.0", "id": None,
                         "error": {"code": -32005,
                                   "message": "ContentTypeNotSupportedError: expected application/json"}},
                        status_code=415,
                    )
            return await call_next(request)

    main_app = Starlette(routes=[*jsonrpc_routes, *agent_card_routes, *rest_routes],
                         middleware=[Middleware(_ContentTypeGate)])

    config = uvicorn.Config(
        main_app, host='0.0.0.0', port=http_port, log_level='info'
    )
    uvicorn_server = uvicorn.Server(config)

    # gRPC
    grpc_server = grpc.aio.server()
    grpc_server.add_insecure_port(f'[::]:{grpc_port}')
    servicer = GrpcHandler(request_handler)
    a2a_grpc.add_A2AServiceServicer_to_server(servicer, grpc_server)

    logger.info(
        'Starting HTTP server on port %s and gRPC on port %s...',
        http_port,
        grpc_port,
    )

    await grpc_server.start()
    try:
        await asyncio.gather(
            uvicorn_server.serve(), grpc_server.wait_for_termination()
        )
    finally:
        await grpc_server.stop(0)


if __name__ == '__main__':
    asyncio.run(main())
