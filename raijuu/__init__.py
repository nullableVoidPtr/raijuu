from .hook import dump_hook


def __getattr__(name):
    if name == "result":
        return dump_hook.result
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__ = ["dump_hook"]


def __dir__():
    return sorted(__all__ + ["result"])
