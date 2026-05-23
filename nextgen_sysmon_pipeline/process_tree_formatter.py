from typing import Dict, Any, List

class ProcessTreeFormatter:
    """
    Translates raw backend process graphs into lightweight, frontend-friendly 
    structures suitable for UI rendering (e.g., collapsible tree views).
    """
    
    @staticmethod
    def format_for_ui(raw_tree: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Flattens the nested tree into a list of nodes with depth markers.
        This is often easier to render in standard HTML/JS than a deep recursive object.
        """
        flat_list = []
        ProcessTreeFormatter._flatten(raw_tree, 0, flat_list)
        return flat_list

    @staticmethod
    def _flatten(node: Dict[str, Any], depth: int, flat_list: List[Dict[str, Any]]):
        if not node:
            return
            
        # Determine icon/color based on the executable name
        image = node.get('image', '').lower()
        icon = "fa-cogs" # Default process
        color = "text-secondary"
        
        if image in ['powershell.exe', 'cmd.exe', 'bash.exe']:
            icon = "fa-terminal"
            color = "text-danger"
        elif image in ['winword.exe', 'excel.exe', 'powerpnt.exe']:
            icon = "fa-file-word"
            color = "text-primary"
        elif image in ['chrome.exe', 'msedge.exe', 'firefox.exe']:
            icon = "fa-globe"
            color = "text-info"

        flat_list.append({
            "process_guid": node.get('process_guid'),
            "image": node.get('image'),
            "command_line": node.get('command_line'),
            "depth": depth,
            "icon": icon,
            "color_class": color,
            "padding_px": depth * 20 # UI hint for indentation
        })
        
        for child in node.get('children', []):
            ProcessTreeFormatter._flatten(child, depth + 1, flat_list)

    @staticmethod
    def format_d3_graph(raw_tree: Dict[str, Any]) -> Dict[str, Any]:
        """
        Alternative: Formats tree into a Node-Link JSON structure specifically 
        designed for D3.js or other graph visualization libraries.
        """
        nodes = []
        links = []
        
        def traverse(node):
            if not node: return
            
            nodes.append({
                "id": node.get('process_guid'),
                "label": node.get('image'),
                "group": 1 if 'powershell' in node.get('image', '').lower() else 0
            })
            
            for child in node.get('children', []):
                links.append({
                    "source": node.get('process_guid'),
                    "target": child.get('process_guid'),
                    "value": 1
                })
                traverse(child)
                
        traverse(raw_tree)
        return {"nodes": nodes, "links": links}
