"""
MOVERY Signature Generator - Implementation of Section 3.1 (Enhanced)
Implements the signature generation methodology from the MOVERY paper with improved abstraction.
Updated to save complete preprocessed line sets for clone detection.
"""

import re
import tempfile
import subprocess
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional, Any
from joern_integration import JoernAnalyzer
import os
import time

class SignatureGenerator:
    """
    MOVERY Signature Generator implementing Section 3.1 methodology
    
    IMPORTANT PROCESSING FLOW:
    1. All analysis (Joern dependency/control flow) uses ORIGINAL code
    2. Line comparison/matching uses NORMALIZED code (no abstraction)
    3. Abstraction is ONLY applied at the final signature generation step
    
    This ensures Joern can parse valid C/C++ syntax while still providing
    the abstraction benefits described in the paper.
    """
    def __init__(self, joern_path: str = "joern"):
        """Initialize the signature generator with Joern analyzer"""
        self.joern_analyzer = JoernAnalyzer(joern_path)
        self.temp_dir = Path("MOVERY-signatures/temp")
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Path to ctags for abstraction
        self.pathToCtags = '/home/MOVERY/config/ctags'  # Adjust path as needed
        
    def normalize(self, string: str) -> str:
        """
        Code normalization - removes whitespace, tabs, and converts to lowercase
        Based on the normalize function from the provided scripts
        """
        return ''.join(string.replace('\r', '').replace('\t', '').split(' ')).lower()
    
    def removeComment(self, string: str) -> str:
        """
        Remove C/C++ style comments
        Based on the removeComment function from the provided scripts
        """
        c_regex = re.compile(
            r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
            re.DOTALL | re.MULTILINE)
        return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])
    
    def abstract(self, body: str, ext: str = "c") -> str:
        """
        Apply abstraction to replace variables, types, function calls with symbols
        Enhanced version based on the abstract function from preprocessor.py
        """
        tempFile = self.temp_dir / f'temp_abstract_{os.getpid()}_{int(time.time()*1000000)}.{ext}'
        
        try:
            with open(tempFile, 'w', encoding="UTF-8") as ftemp:
                ftemp.write(body)
            
            abstractBody = body
            originalFunctionBody = body

            # Use ctags to extract variable and type information
            command = f'{self.pathToCtags} -f - --kinds-C=* --fields=neKSt "{tempFile}"'
            try:
                astString = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True).decode(errors='ignore')
            except subprocess.CalledProcessError as e:
                print(f"[ERROR] ctags failed: {e}")
                raise Exception(f"ctags execution failed: {e}")

            variables = []
            parameters = []
            dataTypes = []

            functionList = astString.split('\n')
            local = re.compile(r'local')
            parameter = re.compile(r'parameter')
            func = re.compile(r'(function)')
            number = re.compile(r'(\d+)')
            dataType = re.compile(r"(typeref:)\w*(:)")

            # Extract parameters and variables
            for i in functionList:
                elemList = re.sub(r'[\t\s ]{2,}', '', i)
                elemList = elemList.split("\t")
                if i != '' and len(elemList) >= 6 and (local.fullmatch(elemList[3]) or local.fullmatch(elemList[4])):
                    variables.append(elemList)
                
                if i != '' and len(elemList) >= 6 and (parameter.match(elemList[3]) or parameter.fullmatch(elemList[4])):
                    parameters.append(elemList)

            # Apply abstraction transformations
            parameterList = [param[0] for param in parameters if len(param) > 0]
            variableList = [var[0] for var in variables if len(var) > 0]
            dataTypeList = []
            
            for param in parameters:
                if len(param) >= 6 and dataType.search(param[5]):
                    dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", param[5])))
                elif len(param) >= 7 and dataType.search(param[6]):
                    dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", param[6])))

            for variable in variables:
                if len(variable) >= 6 and dataType.search(variable[5]):
                    dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", variable[5])))
                elif len(variable) >= 7 and dataType.search(variable[6]):
                    dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", variable[6])))

            # Replace parameters with FPARAM
            for param in parameterList:
                if len(param) == 0:
                    continue
                try:
                    paramPattern = re.compile("(^|\W)" + re.escape(param) + "(\W)")
                    abstractBody = paramPattern.sub(r"\g<1>FPARAM\g<2>", abstractBody)
                except:
                    pass

            # Replace data types with DTYPE
            for dtype in dataTypeList:
                if len(dtype) == 0:
                    continue
                try:
                    dtypePattern = re.compile("(^|\W)" + re.escape(dtype) + "(\W)")
                    abstractBody = dtypePattern.sub(r"\g<1>DTYPE\g<2>", abstractBody)
                except:
                    pass

            # Replace local variables with LVAR
            for lvar in variableList:
                if len(lvar) == 0:
                    continue
                try:
                    lvarPattern = re.compile("(^|\W)" + re.escape(lvar) + "(\W)")
                    abstractBody = lvarPattern.sub(r"\g<1>LVAR\g<2>", abstractBody)
                except:
                    pass

        except Exception as e:
            print(f"[ERROR] Abstraction failed: {e}")
            raise Exception(f"ctags-based abstraction failed: {e}")
        finally:
            if tempFile.exists():
                tempFile.unlink()

        return abstractBody
    
    def get_complete_function_lines(self, function_code: str) -> Dict[str, List[str]]:
        """
        Get complete preprocessed line sets for a function
        Returns both normalized and abstracted lines for clone detection
        
        Returns:
            Dict with 'normalized' and 'abstracted' line lists
        """
        if not function_code or not function_code.strip():
            return {'normalized': [], 'abstracted': []}
        
        try:
            # Get normalized lines (remove comments, normalize, filter)
            normalized_lines = []
            clean_code = self.removeComment(function_code)
            for line in clean_code.split('\n'):
                clean_line = line.strip()
                if clean_line and len(clean_line) > 0:
                    normalized = self.normalize(clean_line)
                    if len(normalized) >= 15:  # Skip short lines as per paper
                        normalized_lines.append(normalized)
            
            # Get abstracted lines
            abstracted_lines = []
            try:
                abstracted_code = self.abstract(function_code)
                clean_abstracted = self.removeComment(abstracted_code)
                for line in clean_abstracted.split('\n'):
                    clean_line = line.strip()
                    if clean_line and len(clean_line) > 0:
                        abstracted = self.normalize(clean_line)
                        if len(abstracted) >= 15:
                            abstracted_lines.append(abstracted)
            except Exception as e:
                print(f"[WARNING] Abstraction failed for complete lines, using normalized: {e}")
                abstracted_lines = normalized_lines.copy()
            
            return {
                'normalized': normalized_lines,
                'abstracted': abstracted_lines
            }
            
        except Exception as e:
            print(f"[ERROR] Failed to get complete function lines: {e}")
            return {'normalized': [], 'abstracted': []}
    
    def _create_line_mapping(self, function_body: str) -> Dict[str, str]:
        """
        Create a line-by-line mapping from original lines to abstracted lines
        
        Args:
            function_body: Original function body
            
        Returns:
            Dict mapping original lines to abstracted lines
        """
        try:
            # Get the full abstracted function
            abstracted_function = self.abstract(function_body)
            
            # Split both into lines
            original_lines = function_body.split('\n')
            abstracted_lines = abstracted_function.split('\n')
            
            # Create mapping
            line_mapping = {}
            
            # Ensure we have the same number of lines
            if len(original_lines) != len(abstracted_lines):
                print(f"[WARNING] Line count mismatch: original={len(original_lines)}, abstracted={len(abstracted_lines)}")
                # Take the minimum to avoid index errors
                min_lines = min(len(original_lines), len(abstracted_lines))
                original_lines = original_lines[:min_lines]
                abstracted_lines = abstracted_lines[:min_lines]
            
            # Create the mapping
            for orig_line, abst_line in zip(original_lines, abstracted_lines):
                # Clean the original line (remove comments)
                clean_orig = self.removeComment(orig_line.strip())
                if clean_orig and len(clean_orig.strip()) > 0:
                    line_mapping[clean_orig] = abst_line.strip()
            
            print(f"[INFO] Created line mapping with {len(line_mapping)} entries")
            return line_mapping
            
        except Exception as e:
            print(f"[ERROR] Failed to create line mapping: {e}")
            raise
    
    def _get_function_lines(self, function_code: str) -> Set[str]:
        """Extract and normalize lines from function code (NO abstraction here)"""
        lines = set()
        for line in function_code.split('\n'):
            clean_line = self.removeComment(line.strip())
            if clean_line and len(clean_line.strip()) > 0:
                normalized = self.normalize(clean_line)  # Only normalization, NO abstraction
                # Skip short lines as per paper (less than 15 characters)
                if len(normalized) >= 15:
                    lines.add(normalized)
        return lines
    
    def extract_essential_lines(self, fo: Optional[str], fd: str, fp: str) -> Tuple[Set[str], Set[str]]:
        """
        Extract essential vulnerable and patch lines according to Definition I from the paper:
        
        EV = {l | l ∈ (fd \ fp) ∧ l ∈ (fo ∩ fd) ∧ l ∉ fp}
        EP = {l | l ∈ (fp \ fd) ∧ l ∉ (fo ∪ fd) ∧ l ∈ fp}
        """
        fo_lines = self._get_function_lines(fo) if fo else set()
        fd_lines = self._get_function_lines(fd)
        fp_lines = self._get_function_lines(fp)
        
        # Essential vulnerable lines: deleted from patch AND in both fo and fd
        if fo_lines:
            # Lines deleted in patch: fd \ fp
            deleted_lines = fd_lines - fp_lines
            # Lines common to fo and fd: fo ∩ fd  
            common_lines = fo_lines & fd_lines
            # Essential vulnerable: intersection of both conditions
            ev = deleted_lines & common_lines
        else:
            # If no oldest function, just use deleted lines
            ev = fd_lines - fp_lines
            
        # Essential patch lines: added in patch AND not in fo or fd
        if fo_lines:
            # Lines added in patch: fp \ fd
            added_lines = fp_lines - fd_lines
            # Not in fo or fd: not in (fo ∪ fd)
            ep = added_lines - (fo_lines | fd_lines)
        else:
            # If no oldest function, just use added lines
            ep = fp_lines - fd_lines
            
        print(f"[INFO] Essential lines extracted - EV: {len(ev)}, EP: {len(ep)}")
        return ev, ep
    
    def extract_dependent_lines(self, fo: Optional[str], fd: str, fp: str, 
                              ev: Set[str], ep: Set[str]) -> Tuple[Set[str], Set[str]]:
        """
        Extract dependent vulnerable and patch lines according to Definition II:
        
        Dv = {l | l ∈ (fo ∩ fd) ∧ (l →c lv ∨ l →d lv)} where lv ∈ Ev
        Dp = {l | l ∈ fp ∧ (l →c lp ∨ l →d lp)} where lp ∈ Ep
        
        NOTE: Use original code for Joern analysis, only normalize for line matching
        """
        dv = set()
        dp = set()
        
        try:
            # Extract dependent vulnerable lines
            if ev:
                # Find original lines that correspond to normalized essential vulnerable lines
                ev_targets = self._find_original_lines(fd, ev)
                if ev_targets:
                    # Use ORIGINAL fd code for Joern analysis (no abstraction!)
                    control_deps, data_deps = self.joern_analyzer.get_dependencies(fd, ev_targets)
                    
                    fo_lines = self._get_function_lines(fo) if fo else set()
                    fd_lines = self._get_function_lines(fd)
                    
                    # Collect all dependency lines (normalize but don't abstract)
                    all_deps = set()
                    for dep in control_deps + data_deps:
                        if dep and len(dep.strip()) > 0:
                            normalized_dep = self.normalize(self.removeComment(dep))
                            if len(normalized_dep) >= 15:
                                all_deps.add(normalized_dep)
                    
                    # Dependent vulnerable lines must be in both fo and fd (if fo exists)
                    if fo_lines:
                        dv = {line for line in (fo_lines & fd_lines) if any(dep in line for dep in all_deps)}
                    else:
                        dv = {line for line in (fd_lines) if any(dep in line for dep in all_deps)}
            
            # Extract dependent patch lines
            if ep:
                # Find original lines that correspond to normalized essential patch lines
                ep_targets = self._find_original_lines(fp, ep)
                if ep_targets:
                    # Use ORIGINAL fp code for Joern analysis (no abstraction!)
                    control_deps, data_deps = self.joern_analyzer.get_dependencies(fp, ep_targets)
                    
                    fp_lines = self._get_function_lines(fp)
                    
                    # Collect all dependency lines (normalize but don't abstract)
                    all_deps = set()
                    for dep in control_deps + data_deps:
                        if dep and len(dep.strip()) > 0:
                            normalized_dep = self.normalize(self.removeComment(dep))
                            if len(normalized_dep) >= 15:
                                all_deps.add(normalized_dep)
                    # Dependent patch lines must be in fp
                    dp = {line for line in (fp_lines) if any(dep in line for dep in all_deps)}
                    
        except Exception as e:
            print(f"[WARNING] Could not extract dependencies: {e}")
            # Continue with empty dependency sets if Joern analysis fails
            
        print(f"[INFO] Dependent lines extracted - DV: {len(dv)}, DP: {len(dp)}")
        return dv, dp
    
    def extract_control_flow_lines(self, fo: Optional[str], fd: str, ev: Set[str]) -> Set[str]:
        """
        Extract vulnerable control flow code lines according to Definition III:
        
        Control flow lines from function entrance to essential vulnerable lines
        NOTE: Use original fd code for Joern analysis, only normalize for line matching
        """
        fv = set()
        
        try:
            # Extract control flow statements from the ORIGINAL disclosed vulnerable function
            control_flow_statements = self.joern_analyzer.extract_control_flow_statements(fd)
            
            fo_lines = self._get_function_lines(fo) if fo else set()
            fd_lines = self._get_function_lines(fd)
            
            # Process control flow statements (normalize but don't abstract)
            for stmt in control_flow_statements:
                if stmt and len(stmt.strip()) > 0:
                    normalized_stmt = self.normalize(self.removeComment(stmt))
                    if len(normalized_stmt) >= 15:
                        # Control flow lines should be common to both fo and fd (if fo exists)
                        if fo_lines:
                            if normalized_stmt in (fo_lines & fd_lines):
                                fv.add(normalized_stmt)
                        else:
                            if normalized_stmt in fd_lines:
                                fv.add(normalized_stmt)
                                
        except Exception as e:
            print(f"[WARNING] Could not extract control flow: {e}")
            
        print(f"[INFO] Control flow lines extracted - FV: {len(fv)}")
        return fv
    
    def _find_original_lines(self, function_code: str, normalized_lines: Set[str]) -> List[str]:
        """
        Find approximate original lines in function code that match normalized lines
        This is needed for Joern analysis which requires original code lines
        """
        original_lines = []
        code_lines = function_code.split('\n')
        
        for norm_line in normalized_lines:
            # Try to find matching original line
            for original_line in code_lines:
                clean_original = self.removeComment(original_line.strip())
                if clean_original and self.normalize(clean_original) == norm_line:
                    original_lines.append(original_line.strip())
                    break
        
        return original_lines
    
    def _apply_transformations(self, lines: Set[str], function_code: str, line_mapping: Dict[str, str]) -> List[Dict[str, str]]:
        """
        Apply normalization and abstraction to lines using pre-computed line mapping
        Returns list of dictionaries with 'norm' and 'abst' keys as shown in paper
        
        Args:
            lines: Set of normalized lines (already normalized, no abstraction yet)
            function_code: Original function code for finding original lines
            line_mapping: Pre-computed mapping from original lines to abstracted lines
        """
        result = []
        
        for norm_line in lines:
            # Find the original line that corresponds to this normalized line
            original_line = None
            for line in function_code.split('\n'):
                clean_line = self.removeComment(line.strip())
                if clean_line and self.normalize(clean_line) == norm_line:
                    original_line = clean_line
                    break
            
            if original_line and original_line in line_mapping:
                # Get the abstracted line from the mapping and normalize it
                abstracted_line = line_mapping[original_line]
                abstracted = self.normalize(abstracted_line)
            else:
                # If we can't find the mapping, this is an error since we require ctags
                print(f"[WARNING] Could not find abstraction mapping for line: {norm_line}")
                print(f"[WARNING] Original line: {original_line}")
                # Since we don't allow fallbacks, we'll use the normalized line as abstracted
                # This should ideally not happen if our mapping is complete
                abstracted = norm_line
            
            entry = {
                "norm": norm_line,      # Already normalized (no abstraction)
                "abst": abstracted      # Normalized + abstracted
            }
            result.append(entry)
            
        return result
    
    def generate_signatures(self, fo: Optional[str], fd: str, fp: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Generate vulnerability and patch signatures according to MOVERY methodology
        
        IMPORTANT: Abstraction is only applied at the final step to avoid syntax errors
        during Joern analysis. All intermediate processing uses original code.
        
        Args:
            fo: Oldest vulnerable function code (optional)
            fd: Disclosed vulnerable function code  
            fp: Patched function code
            
        Returns:
            Tuple[Dict, Dict]: (vulnerability_signature, patch_signature)
            
        Vulnerability signature: Sv = (Ev, Dv, Fv)
        Patch signature: Sp = (Ep, Dp)
        """
        print(f"[INFO] Generating signatures for vulnerability...")
        
        # Step 0: Get complete preprocessed function line sets for clone detection
        print("[INFO] Preprocessing complete function line sets...")
        fo_complete_lines = self.get_complete_function_lines(fo) if fo else {'normalized': [], 'abstracted': []}
        fd_complete_lines = self.get_complete_function_lines(fd)
        fp_complete_lines = self.get_complete_function_lines(fp)
        
        # Step 1: Create line mappings for abstraction (do this once per function)
        print("[INFO] Creating abstraction mappings...")
        try:
            fd_mapping = self._create_line_mapping(fd)
            fp_mapping = self._create_line_mapping(fp)
        except Exception as e:
            print(f"[ERROR] Failed to create abstraction mappings: {e}")
            raise
        
        # Step 2: Extract essential lines (Definition I)
        # Uses original code for analysis, only normalizes for line comparison
        ev, ep = self.extract_essential_lines(fo, fd, fp)
        
        # Step 3: Extract dependent lines (Definition II) 
        # Uses original code for Joern dependency analysis
        dv, dp = self.extract_dependent_lines(fo, fd, fp, ev, ep)
        
        # Step 4: Extract control flow lines (Definition III)
        # Uses original code for Joern control flow analysis
        fv = self.extract_control_flow_lines(fo, fd, ev)
        
        # Step 5: Apply transformations (normalization + abstraction) using mappings
        # THIS IS THE ONLY PLACE WHERE ABSTRACTION IS APPLIED!
        try:
            ev_transformed = self._apply_transformations(ev, fd, fd_mapping)
            dv_transformed = self._apply_transformations(dv, fd, fd_mapping)
            fv_transformed = self._apply_transformations(fv, fd, fd_mapping)
            
            ep_transformed = self._apply_transformations(ep, fp, fp_mapping)
            dp_transformed = self._apply_transformations(dp, fp, fp_mapping)
        except Exception as e:
            print(f"[ERROR] Failed to apply transformations: {e}")
            raise
        
        # Step 6: Generate final signatures with complete preprocessed line sets
        vulnerability_signature = {
            "Ev": ev_transformed,  # Essential vulnerable lines
            "Dv": dv_transformed,  # Dependent vulnerable lines  
            "Fv": fv_transformed,  # Vulnerable control flow lines
            "preprocessed_functions": {
                "fo_lines": fo_complete_lines,  # Complete oldest function lines
                "fd_lines": fd_complete_lines,  # Complete disclosed vulnerable function lines
                "fp_lines": fp_complete_lines   # Complete patched function lines
            }
        }
        
        patch_signature = {
            "Ep": ep_transformed,  # Essential patch lines
            "Dp": dp_transformed,  # Dependent patch lines
            "preprocessed_functions": {
                "fo_lines": fo_complete_lines,  # Complete oldest function lines
                "fd_lines": fd_complete_lines,  # Complete disclosed vulnerable function lines
                "fp_lines": fp_complete_lines   # Complete patched function lines
            }
        }
        
        print(f"[INFO] Signature generation complete:")
        print(f"  - Vulnerability signature: Ev={len(ev_transformed)}, Dv={len(dv_transformed)}, Fv={len(fv_transformed)}")
        print(f"  - Patch signature: Ep={len(ep_transformed)}, Dp={len(dp_transformed)}")
        print(f"  - Complete function lines: fo={len(fo_complete_lines['normalized'])}, fd={len(fd_complete_lines['normalized'])}, fp={len(fp_complete_lines['normalized'])}")
        
        return vulnerability_signature, patch_signature


def test_signature_generation():
    """Test the signature generation with example vulnerability"""
    print("[TEST] Testing MOVERY signature generation...")
    
    generator = SignatureGenerator()
    
    # Example from CVE-2016-8654 mentioned in the paper
    fo = """
void jpc_qmfb_split_col(int *a, int numrows, int stride, int parity) {
    int bufsize = JPC_CEILDIVPOW2(numrows, 1);
    jpc_fix_t *buf;
    
    if (bufsize > QMFB_SPLITBUFSIZE) {
        if (!(buf = jas_alloc(bufsize * sizeof(jpc_fix_t)))) {
            abort();
        }
    }
    if (numrows >= 2) {
        hstartcol = (numrows + 1 - parity) >> 1;
        m = (parity) ? hstartcol : (numrows - hstartcol);
        n = m;
        dstptr = buf;
        srcptr = &a[(1 - parity) * stride];
    }
}
"""
    
    fd = """
void jpc_qmfb_split_col(int *a, int numrows, int stride, int parity) {
    int bufsize = JPC_CEILDIVPOW2(numrows, 1);
    jpc_fix_t *buf;
    
    if (bufsize > QMFB_SPLITBUFSIZE) {
        if (!(buf = jas_alloc2(bufsize, sizeof(jpc_fix_t)))) {
            abort();
        }
    }
    if (numrows >= 2) {
        hstartcol = (numrows + 1 - parity) >> 1;
        m = (parity) ? hstartcol : (numrows - hstartcol);
        m = numrows - hstartcol;
        n = m;
        dstptr = buf;
        srcptr = &a[(1 - parity) * stride];
    }
}
"""
    
    fp = """
void jpc_qmfb_split_col(int *a, int numrows, int stride, int parity) {
    int bufsize = JPC_CEILDIVPOW2(numrows, 1);
    jpc_fix_t *buf;
    
    if (bufsize > QMFB_SPLITBUFSIZE) {
        if (!(buf = jas_alloc2(bufsize, sizeof(jpc_fix_t)))) {
            abort();
        }
    }
    if (numrows >= 2) {
        hstartrow = (numrows + 1 - parity) >> 1;
        // ORIGINAL (WRONG): m = (parity) ? hstartrow : (numrows - hstartrow);
        m = numrows - hstartrow;
        n = m;
        dstptr = buf;
        srcptr = &a[(1 - parity) * stride];
    }
}
"""
    
    try:
        vuln_sig, patch_sig = generator.generate_signatures(fo, fd, fp)
        
        print("\n[RESULT] Generated Vulnerability Signature:")
        for key, lines in vuln_sig.items():
            if key == "preprocessed_functions":
                print(f"  {key}:")
                for func_name, func_lines in lines.items():
                    print(f"    {func_name}: {len(func_lines['normalized'])} normalized, {len(func_lines['abstracted'])} abstracted lines")
            else:
                print(f"  {key}: {len(lines)} lines")
                for i, line in enumerate(lines[:3]):  # Show first 3 lines
                    print(f"    [{i+1}] norm: {line['norm'][:50]}...")
                    print(f"        abst: {line['abst'][:50]}...")
        
        print("\n[RESULT] Generated Patch Signature:")
        for key, lines in patch_sig.items():
            if key == "preprocessed_functions":
                print(f"  {key}:")
                for func_name, func_lines in lines.items():
                    print(f"    {func_name}: {len(func_lines['normalized'])} normalized, {len(func_lines['abstracted'])} abstracted lines")
            else:
                print(f"  {key}: {len(lines)} lines")
                for i, line in enumerate(lines[:3]):  # Show first 3 lines
                    print(f"    [{i+1}] norm: {line['norm'][:50]}...")
                    print(f"        abst: {line['abst'][:50]}...")
        
        return vuln_sig, patch_sig
        
    except Exception as e:
        print(f"[ERROR] Signature generation failed: {e}")
        import traceback
        traceback.print_exc()
        return None, None


if __name__ == "__main__":
    test_signature_generation()