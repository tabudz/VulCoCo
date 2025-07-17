"""
Joern Integration Module for MOVERY
Handles control and data dependency analysis using Joern - Edge-based approach
"""

import subprocess
import tempfile
import os
import json
from pathlib import Path
from typing import List, Dict, Set, Tuple

class JoernAnalyzer:
    def __init__(self, joern_path: str = "joern"):
        self.joern_path = joern_path
        self.temp_dir = Path("MOVERY-signatures/temp")
        self.temp_dir.mkdir(parents=True, exist_ok=True)
    
    def create_temp_c_file(self, function_code: str, filename: str = "temp.c") -> Path:
        """Create a temporary C file with the function code"""
        temp_file = self.temp_dir / filename
        
        # Wrap function in minimal C structure if needed
        if not function_code.strip().startswith('#include'):
            wrapped_code = f"""{function_code}"""
        else:
            wrapped_code = function_code
            
        with open(temp_file, 'w') as f:
            f.write(wrapped_code)
        
        return temp_file
    
    def run_joern_analysis(self, code_file: Path) -> Dict:
        """Run Joern analysis on a C file and extract edge information"""
        # Create Joern script for edge-based analysis
        joern_script = self.temp_dir / "edge_analysis.sc"

        # Updated Joern script to extract edges with source/target node information
        script_content = f"""
import scala.util.Try
import scala.reflect.runtime.universe._

def getNodeProperty[T](node: Any, propertyName: String): Option[T] = {{
  node match {{
    case nodeRef: overflowdb.NodeRef[_] =>
      propertyName match {{
        case "lineNumber" => Try(nodeRef.property("lineNumber").asInstanceOf[T]).toOption
        case "code" => Try(nodeRef.property("code").asInstanceOf[T]).toOption
        case "label" => Try(nodeRef.label.asInstanceOf[T]).toOption
        case "name" => Try(nodeRef.property("name").asInstanceOf[T]).toOption
        case "order" => Try(nodeRef.property("order").asInstanceOf[T]).toOption
        case "columnNumber" => Try(nodeRef.property("columnNumber").asInstanceOf[T]).toOption
        case _ => None
      }}
    case storedNode: io.shiftleft.codepropertygraph.generated.nodes.StoredNode =>
      // Use reflection for StoredNode since it doesn't have direct property accessors
      Try {{
        val runtimeMirror = scala.reflect.runtime.currentMirror
        val instanceMirror = runtimeMirror.reflect(storedNode)
        val methodName = TermName(propertyName)
        val symbol = instanceMirror.symbol.asClass.toType.member(methodName)
        if (symbol != NoSymbol && symbol.isMethod) {{
          val methodMirror = instanceMirror.reflectMethod(symbol.asMethod)
          methodMirror().asInstanceOf[T]
        }} else {{
          null.asInstanceOf[T]
        }}
      }}.toOption.filter(_ != null)
    case _ => None
  }}
}}

importCode.c("{code_file.absolute()}")

// Alternative: Direct property access that should work in scripts
def safeGetProperty(node: Any, propName: String): String = {{
  try {{
    propName match {{
      case "id" => node.asInstanceOf[{{def id: Long}}].id.toString
      case "label" => node.asInstanceOf[{{def label: String}}].label
      case "lineNumber" => 
        try {{
          val ln = node.asInstanceOf[{{def lineNumber: Option[Int]}}].lineNumber
          ln.map(_.toString).getOrElse("None")
        }} catch {{
          case _: Exception => "N/A"
        }}
      case "code" => 
        try {{
          node.asInstanceOf[{{def code: String}}].code
        }} catch {{
          case _: Exception => "N/A"
        }}
      case "name" => 
        try {{
          node.asInstanceOf[{{def name: String}}].name
        }} catch {{
          case _: Exception => "N/A"
        }}
      case _ => "Unknown"
    }}
  }} catch {{
    case _: Exception => "Error"
  }}
}}

// Helper function to filter out system/library nodes
def isUserCode(code: String, label: String): Boolean = {{
  // Filter out empty code, system headers, and library definitions
  if (code == "<empty>" || code == "N/A" || code == "Error") return false
  if (label == "NAMESPACE_BLOCK" || label == "TYPE_DECL") return false
  if (code.contains("typedef") && code.contains("struct")) return false
  if (code.contains("__") || code.contains("WINT_TYPE")) return false
  if (code.startsWith("int []") || code.startsWith("char []")) return false
  true
}}

// Get all edge data in the format expected by Python parser, filtered for user code
val astEdges = cpg.all.outE.hasLabel("AST").toList.map {{ edge =>
  val srcLine = safeGetProperty(edge.inNode, "lineNumber")
  val srcCode = safeGetProperty(edge.inNode, "code")
  val srcLabel = safeGetProperty(edge.inNode, "label")
  val tgtLine = safeGetProperty(edge.outNode, "lineNumber")
  val tgtCode = safeGetProperty(edge.outNode, "code")
  val tgtLabel = safeGetProperty(edge.outNode, "label")
  s"AST:$srcLine:$srcCode:$srcLabel:$tgtLine:$tgtCode:$tgtLabel"
}}.filter(edge => {{
  val parts = edge.split(":", 7)
  if (parts.length >= 7) {{
    val srcCode = parts(2)
    val srcLabel = parts(3)
    val tgtCode = parts(5)
    val tgtLabel = parts(6)
    isUserCode(srcCode, srcLabel) || isUserCode(tgtCode, tgtLabel)
  }} else false
}})

val cfgEdges = cpg.all.outE.hasLabel("CFG").toList.map {{ edge =>
  val srcLine = safeGetProperty(edge.inNode, "lineNumber")
  val srcCode = safeGetProperty(edge.inNode, "code")
  val srcLabel = safeGetProperty(edge.inNode, "label")
  val tgtLine = safeGetProperty(edge.outNode, "lineNumber")
  val tgtCode = safeGetProperty(edge.outNode, "code")
  val tgtLabel = safeGetProperty(edge.outNode, "label")
  s"CFG:$srcLine:$srcCode:$srcLabel:$tgtLine:$tgtCode:$tgtLabel"
}}.filter(edge => {{
  val parts = edge.split(":", 7)
  if (parts.length >= 7) {{
    val srcCode = parts(2)
    val srcLabel = parts(3)
    val tgtCode = parts(5)
    val tgtLabel = parts(6)
    isUserCode(srcCode, srcLabel) || isUserCode(tgtCode, tgtLabel)
  }} else false
}})

val refEdges = cpg.all.outE.hasLabel("REF").toList.map {{ edge =>
  val srcLine = safeGetProperty(edge.inNode, "lineNumber")
  val srcCode = safeGetProperty(edge.inNode, "code")
  val srcLabel = safeGetProperty(edge.inNode, "label")
  val tgtLine = safeGetProperty(edge.outNode, "lineNumber")
  val tgtCode = safeGetProperty(edge.outNode, "code")
  val tgtLabel = safeGetProperty(edge.outNode, "label")
  s"REF:$srcLine:$srcCode:$srcLabel:$tgtLine:$tgtCode:$tgtLabel"
}}.filter(edge => {{
  val parts = edge.split(":", 7)
  if (parts.length >= 7) {{
    val srcCode = parts(2)
    val srcLabel = parts(3)
    val tgtCode = parts(5)
    val tgtLabel = parts(6)
    isUserCode(srcCode, srcLabel) || isUserCode(tgtCode, tgtLabel)
  }} else false
}})

val callEdges = cpg.all.outE.hasLabel("CALL").toList.map {{ edge =>
  val srcLine = safeGetProperty(edge.inNode, "lineNumber")
  val srcCode = safeGetProperty(edge.inNode, "code")
  val srcLabel = safeGetProperty(edge.inNode, "label")
  val tgtLine = safeGetProperty(edge.outNode, "lineNumber")
  val tgtCode = safeGetProperty(edge.outNode, "code")
  val tgtLabel = safeGetProperty(edge.outNode, "label")
  s"CALL:$srcLine:$srcCode:$srcLabel:$tgtLine:$tgtCode:$tgtLabel"
}}.filter(edge => {{
  val parts = edge.split(":", 7)
  if (parts.length >= 7) {{
    val srcCode = parts(2)
    val srcLabel = parts(3)
    val tgtCode = parts(5)
    val tgtLabel = parts(6)
    isUserCode(srcCode, srcLabel) || isUserCode(tgtCode, tgtLabel)
  }} else false
}})

val reachingDefEdges = cpg.all.outE.hasLabel("REACHING_DEF").toList.map {{ edge =>
  val srcLine = safeGetProperty(edge.inNode, "lineNumber")
  val srcCode = safeGetProperty(edge.inNode, "code")
  val srcLabel = safeGetProperty(edge.inNode, "label")
  val tgtLine = safeGetProperty(edge.outNode, "lineNumber")
  val tgtCode = safeGetProperty(edge.outNode, "code")
  val tgtLabel = safeGetProperty(edge.outNode, "label")
  s"REACHING_DEF:$srcLine:$srcCode:$srcLabel:$tgtLine:$tgtCode:$tgtLabel"
}}.filter(edge => {{
  val parts = edge.split(":", 7)
  if (parts.length >= 7) {{
    val srcCode = parts(2)
    val srcLabel = parts(3)
    val tgtCode = parts(5)
    val tgtLabel = parts(6)
    isUserCode(srcCode, srcLabel) || isUserCode(tgtCode, tgtLabel)
  }} else false
}})

// Output all edges in the expected format
println("EDGES_START")
astEdges.foreach(println)
cfgEdges.foreach(println)
refEdges.foreach(println)
callEdges.foreach(println)
reachingDefEdges.foreach(println)
println("EDGES_END")

// Get basic node information in the expected format, filtered for user code
println("NODES_START")
cpg.all.toList.foreach {{ node =>
  val id = safeGetProperty(node, "id")
  val label = safeGetProperty(node, "label")
  val line = safeGetProperty(node, "lineNumber")
  val code = safeGetProperty(node, "code")
  if (isUserCode(code, label) && line != "None" && line != "N/A") {{
    println(s"NODE:$line:$label:$code")
  }}
}}
println("NODES_END")
"""
        
        with open(joern_script, 'w') as f:
            f.write(script_content)
        
        # Run Joern
        cmd = [self.joern_path, "--script", str(joern_script)]
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=60)
        except TypeError:
            # Handle older Python versions
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            result.stdout = result.stdout.decode('utf-8') if result.stdout else ''
            result.stderr = result.stderr.decode('utf-8') if result.stderr else ''
        # print(result)
        if result.returncode == 0:
            return self._parse_edge_output(result.stdout)
        else:
            # Provide detailed error information for debugging
            error_msg = f"Joern analysis failed (exit code: {result.returncode})"
            print(f"{error_msg}")
            print(f"Script used: {joern_script}")
            print(f"Script content:")
            print(script_content)
            print(f"Command: {' '.join(cmd)}")
            print(f"Stdout: {result.stdout}")
            print(f"Stderr: {result.stderr}")
            print(f"Code file: {code_file}")
            
            if code_file.exists():
                print(f"Code file content:")
                with open(code_file, 'r') as f:
                    content = f.read()
                    print(content[:500] + "..." if len(content) > 500 else content)
            
            raise RuntimeError(f"{error_msg}\\nStderr: {result.stderr}\\nStdout: {result.stdout}")
    
    def _parse_edge_output(self, output: str) -> Dict:
        """Parse the edge-based Joern output"""
        edges = {
            "AST": [],
            "CFG": [], 
            "REF": [],
            "CALL": [],
            "REACHING_DEF": []
        }
        nodes = []
        
        lines = output.split('\n')
        in_edges_section = False
        in_nodes_section = False
        
        for line in lines:
            line = line.strip()
            
            if line == "EDGES_START":
                in_edges_section = True
                continue
            elif line == "EDGES_END":
                in_edges_section = False
                continue
            elif line == "NODES_START":
                in_nodes_section = True
                continue
            elif line == "NODES_END":
                in_nodes_section = False
                continue
            
            if in_edges_section and line:
                # Parse edge format: EDGE_TYPE:srcLine:srcCode:srcLabel:tgtLine:tgtCode:tgtLabel
                # Use maxsplit to handle colons in code properly
                parts = line.split(':', 6)  # Split into max 7 parts
                if len(parts) == 7:
                    edge_type, src_line, src_code, src_label, tgt_line, tgt_code, tgt_label = parts
                    
                    # Skip edges with empty or system code
                    if self._is_system_code(src_code) and self._is_system_code(tgt_code):
                        continue
                        
                    if edge_type in edges:
                        # Convert line numbers safely
                        src_line_num = -1
                        tgt_line_num = -1
                        try:
                            if src_line != "None" and src_line != "N/A" and src_line.isdigit():
                                src_line_num = int(src_line)
                        except:
                            pass
                        try:
                            if tgt_line != "None" and tgt_line != "N/A" and tgt_line.isdigit():
                                tgt_line_num = int(tgt_line)
                        except:
                            pass
                            
                        edges[edge_type].append({
                            "edgeType": edge_type,
                            "sourceLineNumber": src_line_num,
                            "sourceCode": src_code,
                            "sourceLabel": src_label,
                            "targetLineNumber": tgt_line_num,
                            "targetCode": tgt_code,
                            "targetLabel": tgt_label
                        })
            
            if in_nodes_section and line:
                # Parse node format: NODE:line:nodeType:code
                parts = line.split(':', 3)  # Split into max 4 parts
                if len(parts) == 4:
                    _, node_line, node_type, node_code = parts
                    
                    # Skip system nodes
                    if self._is_system_code(node_code):
                        continue
                        
                    line_num = -1
                    try:
                        if node_line != "None" and node_line != "N/A" and node_line.isdigit():
                            line_num = int(node_line)
                    except:
                        pass
                        
                    nodes.append({
                        "lineNumber": line_num,
                        "nodeType": node_type,
                        "code": node_code
                    })
        
        return {
            "edges": edges,
            "nodes": nodes
        }
    
    def _is_system_code(self, code: str) -> bool:
        """Check if code is from system/library rather than user code"""
        if not code or code in ["<empty>", "N/A", "Error", "None"]:
            return True
        if code.strip() == "":
            return True
        if code in ["<global>", "RET", "p1", "p2"]:
            return True
        if code.startswith("typedef") or "__" in code:
            return True
        return False
    
    def get_edges_for_lines(self, function_code: str, target_lines: List[str]) -> Dict[str, List[Dict]]:
        """Get all edges related to specific lines of code"""
        temp_file = self.create_temp_c_file(function_code)
        
        try:
            analysis_result = self.run_joern_analysis(temp_file)
            related_edges = {
                "control_flow": [],
                "data_flow": [],
                "ast": [],
                "calls": []
            }
            
            # Find edges where source or target relates to target lines
            for target_line in target_lines:
                # Check CFG edges for control flow
                for edge in analysis_result["edges"]["CFG"]:
                    if (self._line_matches_code(target_line, edge["sourceCode"]) or 
                        self._line_matches_code(target_line, edge["targetCode"])):
                        related_edges["control_flow"].append(edge)
                
                # Check REF and REACHING_DEF edges for data flow
                for edge in analysis_result["edges"]["REF"]:
                    if (self._line_matches_code(target_line, edge["sourceCode"]) or 
                        self._line_matches_code(target_line, edge["targetCode"])):
                        related_edges["data_flow"].append(edge)
                
                for edge in analysis_result["edges"]["REACHING_DEF"]:
                    if (self._line_matches_code(target_line, edge["sourceCode"]) or 
                        self._line_matches_code(target_line, edge["targetCode"])):
                        related_edges["data_flow"].append(edge)
                
                # Check AST edges for structural relationships
                for edge in analysis_result["edges"]["AST"]:
                    if (self._line_matches_code(target_line, edge["sourceCode"]) or 
                        self._line_matches_code(target_line, edge["targetCode"])):
                        related_edges["ast"].append(edge)
                
                # Check CALL edges
                for edge in analysis_result["edges"]["CALL"]:
                    if (self._line_matches_code(target_line, edge["sourceCode"]) or 
                        self._line_matches_code(target_line, edge["targetCode"])):
                        related_edges["calls"].append(edge)
            
            # Remove duplicates
            for key in related_edges:
                related_edges[key] = self._remove_duplicate_edges(related_edges[key])
            
            return related_edges
            
        except Exception as e:
            print(f"[CRITICAL] Joern edge analysis failed for target lines: {target_lines}")
            raise RuntimeError(f"Joern edge analysis is required but failed: {e}")
        finally:
            if temp_file.exists():
                temp_file.unlink()
    
    def get_dependencies(self, function_code: str, target_lines: List[str]) -> Tuple[List[str], List[str]]:
        """Get control and data dependencies for target lines using edges"""
        edges_result = self.get_edges_for_lines(function_code, target_lines)
        
        control_deps = []
        data_deps = []
        
        # Extract unique source and target codes from control flow edges
        for edge in edges_result["control_flow"]:
            if edge["sourceCode"] and not self._is_system_code(edge["sourceCode"]):
                control_deps.append(edge["sourceCode"])
            if edge["targetCode"] and not self._is_system_code(edge["targetCode"]):
                control_deps.append(edge["targetCode"])
        
        # Extract unique source and target codes from data flow edges
        for edge in edges_result["data_flow"]:
            if edge["sourceCode"] and not self._is_system_code(edge["sourceCode"]):
                data_deps.append(edge["sourceCode"])
            if edge["targetCode"] and not self._is_system_code(edge["targetCode"]):
                data_deps.append(edge["targetCode"])
        
        # Remove duplicates and filter out target lines themselves
        control_deps = [dep for dep in list(set(control_deps)) 
                       if not any(self._line_matches_code(target, dep) for target in target_lines)]
        data_deps = [dep for dep in list(set(data_deps)) 
                    if not any(self._line_matches_code(target, dep) for target in target_lines)]
        
        return control_deps, data_deps
    
    def _line_matches_code(self, target_line: str, code: str) -> bool:
        """Check if target line matches the code from an edge"""
        if not target_line or not code:
            return False
            
        # Clean both strings for comparison
        clean_target = ''.join(target_line.split()).lower().strip("\\")
        clean_code = ''.join(code.split()).lower()
        
        # Check for containment in both directions
        return clean_target in clean_code or clean_code in clean_target
    
    def _remove_duplicate_edges(self, edges: List[Dict]) -> List[Dict]:
        """Remove duplicate edges based on source/target combination"""
        seen = set()
        unique_edges = []
        
        for edge in edges:
            key = (edge["sourceLineNumber"], edge["sourceCode"], edge["targetLineNumber"], edge["targetCode"])
            if key not in seen:
                seen.add(key)
                unique_edges.append(edge)
        
        return unique_edges
    
    def extract_control_flow_statements(self, function_code: str) -> List[str]:
        """Extract all control flow statements from function using CFG edges"""
        temp_file = self.create_temp_c_file(function_code)
        
        try:
            analysis_result = self.run_joern_analysis(temp_file)
            control_statements = set()
            
            # Get all unique source and target codes from CFG edges
            for edge in analysis_result["edges"]["CFG"]:
                if edge["sourceCode"] and not self._is_system_code(edge["sourceCode"]):
                    control_statements.add(edge["sourceCode"])
                if edge["targetCode"] and not self._is_system_code(edge["targetCode"]):
                    control_statements.add(edge["targetCode"])
            
            # Also check AST edges for control structures
            for edge in analysis_result["edges"]["AST"]:
                if edge["sourceLabel"] == "CONTROL_STRUCTURE" and not self._is_system_code(edge["sourceCode"]):
                    control_statements.add(edge["sourceCode"])
                if edge["targetLabel"] == "CONTROL_STRUCTURE" and not self._is_system_code(edge["targetCode"]):
                    control_statements.add(edge["targetCode"])
            
            return list(control_statements)
            
        except Exception as e:
            print(f"[CRITICAL] Joern control flow extraction failed")
            raise RuntimeError(f"Joern control flow analysis is required but failed: {e}")
        finally:
            if temp_file.exists():
                temp_file.unlink()

def test_joern_integration():
    """Test the Joern integration with edge-based analysis"""
    analyzer = JoernAnalyzer()
    
    test_code = """
int test_function(int x, int y) {
    if (x > 0) {
        int z = x + y;
        return z;
    }
    return 0;
}
"""
    
    print("[TEST] Testing Joern edge-based integration...")
    
    # Test edge extraction
    edges = analyzer.get_edges_for_lines(test_code, ["if (x > 0)", "int z = x + y"])
    print(f"[INFO] Related edges found:")
    for edge_type, edge_list in edges.items():
        print(f"  {edge_type}: {len(edge_list)} edges")
        for edge in edge_list[:3]:  # Show first 3 edges of each type
            print(f"    {edge['sourceCode']} -> {edge['targetCode']}")
    
    # Test dependency extraction
    control_deps, data_deps = analyzer.get_dependencies(test_code, ["if (x > 0)"])
    print(f"[INFO] Control dependencies: {control_deps}")
    print(f"[INFO] Data dependencies: {data_deps}")
    
    # Test control flow extraction
    control_flow = analyzer.extract_control_flow_statements(test_code)
    print(f"[INFO] Control flow statements: {control_flow}")

if __name__ == "__main__":
    test_joern_integration()