from typing import Dict, Any, List

class ProcessLineageBuilder:
    """
    Reconstructs full process execution graphs (lineage) from disparate events 
    using ProcessGuid and ParentProcessGuid.
    """
    def __init__(self):
        # Maps ProcessGuid -> Event Dict
        self.process_cache = {}
        # Maps ParentProcessGuid -> List[ProcessGuid]
        self.children_map = {}

    def add_process_event(self, event: Dict[str, Any]):
        """Ingest a process creation (EID 1) event into the graph."""
        guid = event.get('process_guid')
        if not guid:
            return
            
        parent_guid = event.get('parent_guid')
        
        # Store process info
        self.process_cache[guid] = event
        
        # Link child to parent
        if parent_guid:
            if parent_guid not in self.children_map:
                self.children_map[parent_guid] = []
            if guid not in self.children_map[parent_guid]:
                self.children_map[parent_guid].append(guid)

    def build_lineage_tree(self, root_guid: str) -> Dict[str, Any]:
        """
        Recursively builds a structured JSON tree for a given root process.
        Perfect for future frontend UI rendering (D3.js / React trees).
        """
        if root_guid not in self.process_cache:
            # We might not have the parent event, just the GUID
            return {"process_guid": root_guid, "image": "Unknown (Not Cached)", "children": []}
            
        event = self.process_cache[root_guid]
        
        node = {
            "process_guid": root_guid,
            "image": event.get('image', '').split('\\')[-1],
            "command_line": event.get('command_line', ''),
            "timestamp": event.get('timestamp', ''),
            "children": []
        }
        
        # Recursively attach children
        if root_guid in self.children_map:
            for child_guid in self.children_map[root_guid]:
                node["children"].append(self.build_lineage_tree(child_guid))
                
        return node
        
    def get_ancestry_chain(self, leaf_guid: str) -> List[str]:
        """Returns a flat list tracing a process back up to its root."""
        chain = []
        current = leaf_guid
        
        while current in self.process_cache:
            event = self.process_cache[current]
            image = event.get('image', '').split('\\')[-1]
            chain.insert(0, image)
            
            parent_guid = event.get('parent_guid')
            if not parent_guid or parent_guid == current:
                break
            current = parent_guid
            
        return chain
