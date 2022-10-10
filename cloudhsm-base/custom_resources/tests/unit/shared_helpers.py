import importlib
import os


def module_loader(module_name: str, path: str):
    loader = importlib.machinery.SourceFileLoader(module_name, path)
    spec = importlib.util.spec_from_loader(module_name, loader)
    function = importlib.util.module_from_spec(spec)
    loader.exec_module(function)

    handler = function.handler
    return handler
