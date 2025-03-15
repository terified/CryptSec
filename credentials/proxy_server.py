from fastapi import FastAPI, Request, Response, HTTPException
import httpx
import logging

app = FastAPI()

# Настройка логирования
logging.basicConfig(level=logging.INFO)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logging.info(f"Request: {request.method} {request.url}")
    response = await call_next(request)
    logging.info(f"Response: {response.status_code}")
    return response

@app.post("/{path:path}")
async def proxy(request: Request, path: str):
    url = f"http://target.server/{path}"  # Замените на целевой сервер
    headers = dict(request.headers)
    data = await request.body()
    
    logging.info(f"Proxying request to {url} with headers {headers} and data {data}")

    try:
        async with httpx.AsyncClient() as client:
            proxy_response = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=data
            )
        logging.info(f"Received response with status {proxy_response.status_code} and content {proxy_response.content}")
    except httpx.RequestError as exc:
        logging.error(f"Request error: {exc}")
        raise HTTPException(status_code=500, detail="Internal server error")

    return Response(
        content=proxy_response.content,
        status_code=proxy_response.status_code,
        headers=dict(proxy_response.headers)
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)