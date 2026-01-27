from abc import ABC, abstractmethod

class BaseNormaliser(ABC):
    source_name = "unknown"
    
    @abstractmethod
    def normalise(self,lines):
        
        # Convert raw log lines into normalised events.
        
        pass