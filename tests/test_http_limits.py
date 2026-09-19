import asyncio

from fm10k_controlpanel.http_limits import BodyLimit


def test_chunked_body_is_bounded_before_application_reads_it():
    async def run():
        messages = iter([{"type": "http.request", "body": b"1234", "more_body": True},
                         {"type": "http.request", "body": b"5678", "more_body": True}])
        sent, called = [], []
        async def receive(): return next(messages)
        async def send(message): sent.append(message)
        async def app(*args): called.append(True)
        await BodyLimit(app, limit=6)({"type": "http"}, receive, send)
        assert not called and sent[0]["status"] == 413
    asyncio.run(run())


def test_fragmented_body_is_replayed_once_without_chunk_object_growth():
    async def run():
        chunks = iter([{"type": "http.request", "body": b"x", "more_body": True}] * 1000 +
                      [{"type": "http.request", "body": b"!", "more_body": False}])
        async def receive(): return next(chunks)
        async def app(scope, receive, send):
            message = await receive()
            assert message["body"] == b"x" * 1000 + b"!" and not message["more_body"]
        await BodyLimit(app, limit=1001)({"type": "http"}, receive, None)
    asyncio.run(run())
