#!/usr/bin/env python3
"""
Script to analyze vulnerable code clones using Claude API
"""

import json
import jsonlines
import requests
import time
from pathlib import Path
from typing import Dict, List, Any
import argparse
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def remove_comments(code):
    """
    Remove single-line and multi-line comments from code.
    Handles C-style (//, /**/), Python-style (#), and other common comment patterns.
    """
    # Remove single-line comments (// and #)
    code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
    code = re.sub(r'#.*?$', '', code, flags=re.MULTILINE)
    
    # Remove multi-line comments (/* */)
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    
    # Remove Python docstrings (triple quotes)
    code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)
    code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)
    
    return code


def standardize_whitespace(code):
    """
    Standardize whitespace in code:
    - Remove excessive whitespace
    - Standardize indentation to 4 spaces
    - Remove trailing whitespace
    """
    # Split into lines for processing
    lines = code.split('\n')
    processed_lines = []
    
    for line in lines:
        # Remove trailing whitespace
        line = line.rstrip()
        
        # Skip empty lines
        if not line.strip():
            processed_lines.append('')
            continue
            
        # Count leading whitespace and convert tabs to spaces
        leading_whitespace = len(line) - len(line.lstrip())
        content = line.lstrip()
        
        # Convert tabs to 4 spaces in leading whitespace
        line_with_spaces = line.expandtabs(4)
        new_leading = len(line_with_spaces) - len(line_with_spaces.lstrip())
        
        # Standardize to 4-space indentation
        indent_level = new_leading // 4 if new_leading > 0 else 0
        standardized_line = '    ' * indent_level + content
        
        processed_lines.append(standardized_line)
    
    # Join lines and remove excessive blank lines (more than 2 consecutive)
    result = '\n'.join(processed_lines)
    result = re.sub(r'\n\s*\n\s*\n+', '\n\n', result)
    
    return result.strip()


def normalize_case(code):
    """
    Normalize case for keywords and common patterns.
    This is a basic implementation - you may want to customize based on your languages.
    """
    # Common programming keywords to normalize (extend as needed)
    keywords = {
        # Python keywords
        'IF', 'ELSE', 'ELIF', 'FOR', 'WHILE', 'DEF', 'CLASS', 'IMPORT', 'FROM', 'RETURN',
        'TRY', 'EXCEPT', 'FINALLY', 'WITH', 'AS', 'LAMBDA', 'AND', 'OR', 'NOT', 'IN', 'IS',
        # C/C++/Java keywords
        'INT', 'CHAR', 'FLOAT', 'DOUBLE', 'VOID', 'BOOL', 'STRING', 'PUBLIC', 'PRIVATE',
        'PROTECTED', 'STATIC', 'CONST', 'FINAL', 'ABSTRACT', 'VIRTUAL', 'OVERRIDE',
        # JavaScript keywords
        'FUNCTION', 'VAR', 'LET', 'CONST', 'THIS', 'NEW', 'TYPEOF', 'INSTANCEOF'
    }
    
    # Normalize keywords to lowercase (but preserve within strings)
    # This is a simplified approach - a more robust solution would use proper parsing
    for keyword in keywords:
        # Use word boundaries to avoid replacing parts of identifiers
        pattern = r'\b' + keyword + r'\b'
        code = re.sub(pattern, keyword.lower(), code, flags=re.IGNORECASE)
    
    return code


def preprocess_code(code):
    """
    Apply all preprocessing steps to code.
    """
    if not code or not isinstance(code, str):
        return code
    
    # Step 1: Remove comments
    code = remove_comments(code)
    
    # Step 2: Standardize whitespace
    code = standardize_whitespace(code)
    
    # Step 3: Normalize case
    code = normalize_case(code)
    
    return code

PROMPT_TEMPLATE = """
Analyze the following code functions to determine if the cloned function contains the same vulnerability as the original function:

ORIGINAL FUNCTION (Known vulnerable):
{original_function}

FIXED FUNCTION (Patched version):
{fixed_function}

CLONED FUNCTION (To be assessed):
{cloned_function}

Please assess whether the cloned function is vulnerable to the same issue that was fixed in the original function.
NOTE: A function that merely CALLS the original vulnerable function should NOT be considered a vulnerable clone unless it also IMPLEMENTS similar vulnerable logic itself. Focus on whether the cloned function contains similar vulnerable code patterns, not just whether it uses the vulnerable function.
IMPORTANT: Respond ONLY with valid JSON in the exact format below. Do not include any explanatory text before or after the JSON.

=== JSON RESPONSE ===
{{
  "is_vulnerable": true/false,
  "confidence_level": 1-5,
  "justification": "Detailed explanation of why the clone is or is not vulnerable. For vulnerable cases, explain what specific vulnerability pattern is present. For non-vulnerable cases, explain what protections/fixes are already in place that prevent the vulnerability."
}}
=== END JSON ===
"""

# PROMPT_TEMPLATE = """
# Analyze the following code functions to determine if the cloned function contains the same vulnerability as the original function:

# ORIGINAL FUNCTION (Known vulnerable):
# {original_function}

# FIXED FUNCTION (Patched version):
# {fixed_function}

# CLONED FUNCTION (To be assessed):
# {cloned_function}

# Please assess whether the cloned function is vulnerable to the same issue that was fixed in the original function.

# IMPORTANT NOTE: A function that merely CALLS the original vulnerable function should NOT be considered a vulnerable clone unless it also IMPLEMENTS similar vulnerable logic itself. Focus on whether the cloned function contains similar vulnerable code patterns, not just whether it uses the vulnerable function.

# IMPORTANT: Respond ONLY with valid JSON in the exact format below. Do not include any explanatory text before or after the JSON.

# === JSON RESPONSE ===
# {{
#   "is_vulnerable": true/false,
#   "confidence_level": 1-5,
#   "justification": "Detailed explanation of why the clone is or is not vulnerable. For vulnerable cases, explain what specific vulnerability pattern is present. For non-vulnerable cases, explain what protections/fixes are already in place that prevent the vulnerability."
# }}
# === END JSON ===
# """

class ClaudeAnalyzer:
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514", response_dir: str = None):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.anthropic.com/v1/messages"
        self.response_dir = response_dir
        self.headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01"
        }
        
        # Create response directory if specified
        if self.response_dir:
            Path(self.response_dir).mkdir(parents=True, exist_ok=True)
    
    def clean_json_response(self, text: str) -> str:
        """Clean and extract JSON from Claude's response"""
        # First try to find JSON between the specified delimiters
        json_start_marker = "=== JSON RESPONSE ==="
        json_end_marker = "=== END JSON ==="
        
        start_idx = text.find(json_start_marker)
        end_idx = text.find(json_end_marker)
        
        if start_idx != -1 and end_idx != -1:
            # Extract text between markers
            start_idx += len(json_start_marker)
            json_text = text[start_idx:end_idx].strip()
        else:
            # Fallback: look for JSON boundaries
            json_start = text.find('{')
            json_end = text.rfind('}') + 1
            
            if json_start != -1 and json_end != -1:
                json_text = text[json_start:json_end]
            else:
                return ""
        
        # Remove common markdown formatting
        json_text = json_text.replace("```json", "").replace("```", "")
        
        # Fix common JSON issues
        # json_text = json_text.replace("'", '"')  # Replace single quotes
        json_text = json_text.replace('True', 'true').replace('False', 'false')  # Python booleans
        json_text = json_text.replace('None', 'null')  # Python None
        
        return json_text.strip()
    
    def analyze_clone(self, original_func: str, fixed_func: str, cloned_func: str, 
                     commit_message: str, cve_id: str, cve_desc: str, cwe: List[str], id: int, 
                     clone_identifier: str = None) -> Dict[str, Any]:
        """Analyze a single clone using Claude"""
        
        prompt = PROMPT_TEMPLATE.format(
            original_function=original_func,
            fixed_function=fixed_func,
            cloned_function=cloned_func,
            commit_message=commit_message or "No commit message available",
            cve_id=cve_id or "Not specified",
            cve_desc=cve_desc or "Not specified",
            cwe=", ".join(cwe) if cwe else "Not specified"
        )
        
        data = {
            "model": self.model,
            "max_tokens": 4000,
            "temperature": 0,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }
        
        try:
            response = requests.post(self.base_url, headers=self.headers, json=data)
            response.raise_for_status()
            
            result = response.json()
            content = result["content"][0]["text"]
            
            # Save raw response if directory specified
            if self.response_dir and clone_identifier:
                # print(id)
                response_file = Path(self.response_dir) / f"{id}_response.txt"
                with open(response_file, 'w', encoding='utf-8') as f:
                    f.write(f"=== RAW CLAUDE RESPONSE ===\n")
                    f.write(content)
                    f.write(f"\n\n=== METADATA ===\n")
                    f.write(f"Clone ID: {clone_identifier}\n")
                    f.write(f"CVE: {cve_id}\n")
                    f.write(f"Model: {self.model}\n")
            
            # Clean and parse JSON
            cleaned_json = self.clean_json_response(content)
            
            if not cleaned_json:
                logger.warning("No JSON found in Claude response")
                return {
                    "error": "No JSON found in response", 
                    "raw_response": content,
                    "clone_id": clone_identifier
                }
            
            try:
                parsed_result = json.loads(cleaned_json)
                
                # Validate required fields
                required_fields = ["is_vulnerable", "confidence_level", "justification"]
                for field in required_fields:
                    if field not in parsed_result:
                        logger.warning(f"Missing required field '{field}' in Claude response")
                        parsed_result[field] = None
                
                # Save successful parse if directory specified
                if self.response_dir and clone_identifier:
                    success_file = Path(self.response_dir) / f"{id}_parsed.json"
                    with open(success_file, 'w', encoding='utf-8') as f:
                        json.dump(parsed_result, f, indent=2)
                
                return parsed_result
                
            except json.JSONDecodeError as e:
                logger.error(f"JSON parsing failed for clone {clone_identifier}: {e}")
                
                # Save failed parse for debugging
                if self.response_dir and clone_identifier:
                    error_file = Path(self.response_dir) / f"{id}_error.txt"
                    with open(error_file, 'w', encoding='utf-8') as f:
                        f.write(f"=== JSON PARSE ERROR ===\n")
                        f.write(f"Error: {str(e)}\n")
                        f.write(f"Clone ID: {clone_identifier}\n\n")
                        f.write(f"=== CLEANED JSON ATTEMPT ===\n")
                        f.write(cleaned_json)
                        f.write(f"\n\n=== ORIGINAL RESPONSE ===\n")
                        f.write(content)
                
                return {
                    "error": f"JSON parsing failed: {str(e)}", 
                    "raw_response": content,
                    "cleaned_json": cleaned_json,
                    "clone_id": clone_identifier
                }
                
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            return {"error": f"API request failed: {str(e)}", "clone_id": clone_identifier}
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return {"error": f"Unexpected error: {str(e)}", "clone_id": clone_identifier}

def load_source_functions(jsonl_path: str) -> Dict[str, Dict[str, Any]]:
    """Load source functions from JSONL file"""
    functions = {}
    
    with jsonlines.open(jsonl_path) as reader:
        for obj in reader:
            func_hash = obj.get('func', obj.get('function', obj.get('vuln_func')))
            functions[func_hash] = obj
    
    return functions

def load_results(results_path: str) -> Dict[str, Any]:
    """Load clone detection results"""
    with open(results_path, 'r') as f:
        return json.load(f)

def extract_clone_code_from_path(clone_path: str, clone_code_fallback: str = None) -> str:
    """
    Extract clone code from the provided path.
    If the file cannot be read, fall back to the clone code from the JSON key.
    """
    if not clone_path:
        if clone_code_fallback:
            logger.info("No path provided, using clone code from JSON key")
            return clone_code_fallback
        else:
            return "// No clone code available"
    
    try:
        # Try to read from the file path
        with open(clone_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        if content.strip():
            logger.debug(f"Successfully read clone code from: {clone_path}")
            return content
        else:
            logger.warning(f"File is empty: {clone_path}")
            return clone_code_fallback or "// Empty file"
            
    except FileNotFoundError:
        logger.warning(f"File not found: {clone_path}")
        if clone_code_fallback:
            logger.info("Using clone code from JSON key as fallback")
            return clone_code_fallback
        else:
            return f"// File not found: {clone_path}"
            
    except PermissionError:
        logger.warning(f"Permission denied: {clone_path}")
        if clone_code_fallback:
            logger.info("Using clone code from JSON key as fallback")
            return clone_code_fallback
        else:
            return f"// Permission denied: {clone_path}"
            
    except Exception as e:
        logger.error(f"Error reading file {clone_path}: {e}")
        if clone_code_fallback:
            logger.info("Using clone code from JSON key as fallback")
            return clone_code_fallback
        else:
            return f"// Error reading file: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description="Analyze vulnerable code clones with Claude")
    parser.add_argument("--results", required=True, help="Path to clone detection results JSON")
    parser.add_argument("--sources", required=True, help="Path to source functions JSONL")
    parser.add_argument("--api-key", required=True, help="Claude API key")
    parser.add_argument("--output", required=True, help="Output path for analysis results")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between API calls (seconds)")
    parser.add_argument("--limit", type=int, help="Limit number of clones to analyze (for testing)")
    parser.add_argument("--responses-dir", help="Directory to save Claude responses for debugging")
    
    args = parser.parse_args()
    
    # Create responses directory if specified
    if args.responses_dir:
        Path(args.responses_dir).mkdir(parents=True, exist_ok=True)
        logger.info(f"Saving responses to: {args.responses_dir}")
    
    # Load data
    logger.info("Loading source functions...")
    source_functions = load_source_functions(args.sources)
    
    logger.info("Loading clone detection results...")
    results = load_results(args.results)
    
    # Initialize Claude analyzer
    analyzer = ClaudeAnalyzer(args.api_key, response_dir=args.responses_dir)
    
    # Process results
    analysis_results = {}
    total_clones = 0
    processed = 0
    
    # Count total clones for progress tracking
    for source_func_hash, clones in results["results"].items():
        total_clones += len(clones)
    
    if args.limit:
        total_clones = min(total_clones, args.limit)
    
    logger.info(f"Starting analysis of {total_clones} clones...")
    
    for source_func_hash, clones in results["results"].items():
        if args.limit and processed >= args.limit:
            break
            
        # Get source function details
        source_func_data = source_functions.get(source_func_hash)
        if not source_func_data:
            logger.warning(f"Source function {source_func_hash} not found in JSONL")
            continue
        
        analysis_results[source_func_hash] = {}
        
        for clone_code, clone_info in clones.items():
            if args.limit and processed >= args.limit:
                break
                
            processed += 1
            query_path = clone_info.get('path')
            query_id = clone_info.get('commit_url')
            
            logger.info(f"Analyzing clone {processed}/{total_clones}")
            logger.debug(f"Clone path: {query_path}")
            logger.debug(f"Clone commit: {query_id}")
            
            # The clone_code is already available as the key
            # Try to read from file first, fall back to the clone_code key
            final_clone_code = extract_clone_code_from_path(
                query_path, 
                clone_code_fallback=clone_code
            )
            
            # Use a more manageable clone identifier for storage
            clone_identifier = f"clone_{processed}"
            
            # Analyze with Claude
            analysis = analyzer.analyze_clone(
                original_func=source_func_data.get("func", source_func_data.get("function", source_func_data.get("vuln_func"))),
                fixed_func=source_func_data.get("fix_func", ""),
                cloned_func=final_clone_code,
                commit_message=source_func_data.get("commit_message", ""),
                cve_id=source_func_data.get("cve", ""),
                cve_desc=source_func_data.get("cve_desc", ""),
                cwe=source_func_data.get("cwe", []),
                id=processed,
                clone_identifier=clone_identifier,
            )
            
            # Add metadata to analysis
            analysis["clone_info"] = clone_info
            analysis["clone_path"] = query_path
            analysis["clone_commit_url"] = query_id
            
            # Modified: Use original clone_code as key instead of clone_identifier
            analysis_results[source_func_hash][clone_code] = analysis
            
            # Rate limiting
            time.sleep(args.delay)
    
    # Save results
    logger.info(f"Saving results to {args.output}")
    with open(args.output, 'w') as f:
        json.dump(analysis_results, f, indent=2)
    
    # Print summary
    vulnerable_count = 0
    high_confidence_vulnerable = 0
    error_count = 0
    
    for source_results in analysis_results.values():
        for clone_analysis in source_results.values():
            if clone_analysis.get("error"):
                error_count += 1
            elif clone_analysis.get("is_vulnerable", False):
                vulnerable_count += 1
                if clone_analysis.get("confidence_level", 0) >= 4:
                    high_confidence_vulnerable += 1
    
    logger.info(f"Analysis complete!")
    logger.info(f"Total clones analyzed: {processed}")
    logger.info(f"Vulnerable clones found: {vulnerable_count}")
    logger.info(f"High confidence vulnerable (4-5): {high_confidence_vulnerable}")
    logger.info(f"Errors encountered: {error_count}")
    if args.responses_dir:
        logger.info(f"Responses saved to: {args.responses_dir}")
    logger.info(f"Results saved to: {args.output}")

if __name__ == "__main__":
    main()