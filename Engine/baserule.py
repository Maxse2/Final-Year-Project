from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List
from Engine.alerts import Alert

class BaseRule(ABC):
    name: str = "unnamed"
    severity: str = "low"

    @abstractmethod
    def run(self, events):
        ...