from typing import Dict, Any, List, Optional

class ProcessNode:
    """Represents a process execution context."""
    def __init__(self, guid: str, image: str, command_line: str, parent_guid: str = ""):
        self.guid = guid
        self.image = image.lower()
        self.command_line = command_line.lower()
        self.parent_guid = parent_guid
        self.children: List[str] = []
        self.depth = 0
        self.is_malicious = False # To be populated by ML/Rules later

class ProcessTracker:
    """
    Lightweight, in-memory process relationship tracker.
    Builds execution trees by correlating ProcessGuid and ParentProcessGuid.
    """
    def __init__(self):
        # Maps ProcessGuid -> ProcessNode
        self.processes: Dict[str, ProcessNode] = {}
        
    def add_process(self, guid: str, image: str, command_line: str, parent_guid: str = "") -> ProcessNode:
        """Registers a process creation (EID 1)."""
        if not guid:
            # Fallback if telemetry is missing GUID
            guid = f"unknown-{image}-{command_line}"
            
        node = ProcessNode(guid, image, command_line, parent_guid)
        
        # Link to parent and calculate depth
        if parent_guid and parent_guid in self.processes:
            parent_node = self.processes[parent_guid]
            parent_node.children.append(guid)
            node.depth = parent_node.depth + 1
        else:
            node.depth = 1 # Root process (from our tracking perspective)
            
        self.processes[guid] = node
        return node
        
    def get_process(self, guid: str) -> Optional[ProcessNode]:
        """Retrieves process context by GUID."""
        return self.processes.get(guid)
        
    def get_process_depth(self, guid: str) -> float:
        """Returns the execution depth of a process."""
        node = self.get_process(guid)
        return float(node.depth) if node else 0.0
        
    def get_process_chain(self, guid: str) -> List[str]:
        """Returns the ancestor chain of images (e.g., ['explorer.exe', 'cmd.exe'])."""
        chain = []
        current = self.get_process(guid)
        while current:
            chain.append(current.image.split('\\')[-1])
            current = self.get_process(current.parent_guid)
        return chain[::-1] # Reverse to get root -> child
