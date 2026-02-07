from contextlib import asynccontextmanager

class ForwardRefUser:
    def greet(self): return "Hello"

def some_function(user: "ForwardRefUser"): # Heuristic 1 target
    return user.greet()

@asynccontextmanager
async def lifespan(app):
    print("Startup")
    yield
    print("Shutdown")
    _teardown_helper() # Heuristic 2 target

def _teardown_helper():
    return "Cleanup complete"