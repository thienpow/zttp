import asyncio
import websockets

async def test_websocket():
    uri = "ws://localhost:8088/demos/websocket/hello"
    print(f"Connecting to {uri}...")
    try:
        async with websockets.connect(uri) as ws:
            print("Connection established.")
            message = "ping"
            print(f"Sending: {message}")
            await ws.send(message)
            print(f"Sent: {message}")
            try:
                response = await asyncio.wait_for(ws.recv(), timeout=10.0)
                print(f"Received: {response}")
                await ws.close(code=1000, reason="Normal closure")
                print("Sent close frame")
            except asyncio.TimeoutError:
                print("Timeout waiting for response.")
            except websockets.exceptions.ConnectionClosed as e:
                print(f"Connection closed: code={e.code}, reason='{e.reason}'")
            except Exception as e:
                print(f"Unexpected error: {e}")
    except Exception as e:
        print(f"Failed to connect: {e}")

asyncio.run(test_websocket())
