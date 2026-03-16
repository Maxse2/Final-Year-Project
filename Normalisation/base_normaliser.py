from abc import ABC, abstractmethod
# Base Structure for normaliser classes
class BaseNormaliser(ABC):
    source_name = "unknown"
    
    @abstractmethod
    def normalise(self,lines):
        
        # Convert raw log lines into normalised events.
        
        pass