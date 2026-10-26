from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from authz import Client, PythonCallableEvaluator, SqliteStorage

from examples.sample_app.routes import authz_admin, projects, tasks
from examples.sample_app.schema import ALL_NAMESPACES
from examples.sample_app.seed import seed


def is_active_contract(*, subject, resource, active):
    return active


@asynccontextmanager
async def lifespan(app: FastAPI):
    storage = SqliteStorage(":memory:")
    await storage.connect()
    client = Client(storage=storage, condition_evaluator=PythonCallableEvaluator())
    client.register_schema(*ALL_NAMESPACES)
    client.register_condition("is_active_contract", is_active_contract)
    app.state.authz_client = client
    await seed(client)
    yield
    await storage.close()


app = FastAPI(title="fastapi-auth sample: task tracker", lifespan=lifespan)
app.include_router(projects.router)
app.include_router(tasks.router)
app.include_router(authz_admin.router)


@app.exception_handler(ValueError)
async def invalid_reference(request: Request, exc: ValueError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": str(exc)})
