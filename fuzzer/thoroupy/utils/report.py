from typing import Callable, Optional, TYPE_CHECKING
from typing_extensions import Protocol

if TYPE_CHECKING:
    try:
        from thoroupy.manager import UcsanManager
        from thoroupy.scheduler.seed import Seed
    except ImportError:
        pass

class ReportHandler(Protocol):
    def __call__(self, exit_status: int, seed: "Seed", label: int, result: int, addr: int, manager: "UcsanManager") -> None: ...

class ReportHandlerExternal(ReportHandler):
    """
    A report handler that is not defined in the Ucsan codebase.
    It is a function that takes the exit status, seed, label, result, addr, manager as arguments.
    All arguments are optional, and the function may have more arguments,
    arbitrary order, but they have to be the same name.
    """
    def __call__(self, exit_status: Optional[int], seed: Optional["Seed"], label: Optional[int], result: Optional[int], addr: Optional[int], manager: Optional["UcsanManager"]) -> None: ...

def decorator_report(func: Optional[ReportHandlerExternal] = None) -> Optional[ReportHandler]:
    """
    Decorator to report the result of the function to the external function.
    The arguments will be automatically guessed from the function signature.
    The external function may have the following signature:
    ```python
    def handler(exit_status, seed, label, result, addr, manager)
    ```
    Note that the arguments are optional, and the external function may have more arguments,
    arbitrary order, but they have to be the same name.
    The arguments will be passed to the external function if they are present in the local scope.
    """
    if func is None:
        return None
    
    taken_args = func.__code__.co_varnames
    def wrapper(exit_status, seed:"Seed", label, result, addr, manager:"UcsanManager"):
        kwargs = {}
        for arg in taken_args:
            if arg in locals():
                kwargs[arg] = locals()[arg]
        func(**kwargs)
        return None

    return wrapper
