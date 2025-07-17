#!/usr/bin/env python3
"""
Code Clone Detector for C/C++ code using hash-based matching

This script:
1. Reads code entries from a JSONL file with the specified format
2. Normalizes code by replacing identifiers with placeholders
3. Generates hashes of normalized code for comparison
4. Only focuses on <original, X> pairs within the same label group
5. <original, 1/2/3/4> pairs are considered true clones
6. <original, fix> pairs are not considered clones
7. Calculates precision, recall, and F1 score based on these rules

Format of each entry in the JSONL file:
{
    "label": <group_id>,    # Numeric identifier for clone group
    "index": <index>,       # Index within the file
    "code": <source_code>,  # The C/C++ code
    "type": <type>          # "original", "fix", "1", "2", "3", "4", etc.
}

Evaluation metrics:
- True Positive: Detected <original, numeric> pairs (same hash)
- False Positive: Detected <original, fix> pairs (same hash)
- False Negative: Undetected <original, numeric> pairs (different hash)
- True Negative: Undetected <original, fix> pairs (different hash)
"""

import json
import re
import hashlib
import sys
from collections import defaultdict
import argparse

# C/C++ keywords and special identifiers
CPP_KEYWORDS = [
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", 
    "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", 
    "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct", 
    "switch", "typedef", "union", "unsigned", "void", "volatile", "while", "_Bool", 
    "_Complex", "_Imaginary", "bool", "catch", "class", "constexpr", "const_cast", 
    "delete", "dynamic_cast", "explicit", "export", "false", "friend", "mutable", 
    "namespace", "new", "nullptr", "operator", "private", "protected", "public", 
    "reinterpret_cast", "static_assert", "static_cast", "template", "this", "throw", 
    "true", "try", "typeid", "typename", "using", "virtual", "wchar_t"
]

CPP_SPECIAL_IDS = [
    "main", "printf", "scanf", "malloc", "free", "realloc", "calloc", "memcpy", 
    "memset", "strlen", "strcmp", "strcpy", "strcat", "fopen", "fclose", "fread", 
    "fwrite", "fprintf", "fscanf", "FILE", "NULL", "size_t", "ptrdiff_t", "time_t", 
    "clock_t", "va_list", "jmp_buf", "std", "string", "vector", "map", "set", 
    "list", "queue", "stack", "deque", "array", "bitset", "iostream", "istream", 
    "ostream", "cin", "cout", "cerr", "clog", "stringstream", "fstream", "ifstream", 
    "ofstream", "algorithm", "iterator", "exception", "thread", "mutex", "chrono"
]

def remove_comments_and_docstrings(source):
    """Remove comments and normalize whitespace from C/C++ code."""
    def replacer(match):
        s = match.group(0)
        if s.startswith('//') or s.startswith('/*'):
            return " "
        else:
            return s
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )
    # Replace comments with spaces
    result = re.sub(pattern, replacer, source)
    
    # Normalize whitespace
    lines = []
    for line in result.split('\n'):
        line = line.strip()
        if line:
            lines.append(line)
    return '\n'.join(lines)

def is_valid_variable_cpp(name):
    """Check if a name is a valid C/C++ identifier and not a keyword or special identifier."""
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        return False
    elif name in CPP_KEYWORDS:
        return False
    elif name in CPP_SPECIAL_IDS:
        return False
    return True

def replace_identifiers_with_index(function_code):
    """
    Replace user-defined identifiers in C/C++ code with indexed placeholders (a1, a2, ...).
    
    This is a simplified version using regex instead of a full parser.
    """
    # Clean up the function code first
    function_code = remove_comments_and_docstrings(function_code)
    
    # Extract all potential identifiers using regex
    # This pattern matches valid C/C++ identifiers
    identifier_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b'
    
    # Find all matches
    matches = re.finditer(identifier_pattern, function_code)
    
    # Collect unique identifiers
    identifiers = {}
    index = 1
    
    for match in matches:
        identifier = match.group(0)
        if identifier not in identifiers and is_valid_variable_cpp(identifier):
            identifiers[identifier] = f"a{index}"
            index += 1
    
    # Replace all occurrences of each identifier
    normalized_code = function_code
    for original, replacement in identifiers.items():
        # Use word boundaries to ensure we're replacing whole identifiers
        pattern = r'\b' + re.escape(original) + r'\b'
        normalized_code = re.sub(pattern, replacement, normalized_code)
    
    return normalized_code

def generate_function_hash(func_code):
    """
    Generate a hash for a normalized function.
    
    1. Remove comments and normalize whitespace
    2. Replace identifiers with indexed placeholders
    3. Generate MD5 hash
    """
    # Clean and normalize the code
    normalized_code = replace_identifiers_with_index(func_code)
    
    # Generate MD5 hash
    return hashlib.md5(normalized_code.encode()).hexdigest()

def read_jsonl_file(file_path):
    """Read data from a JSONL file."""
    data = []
    with open(file_path, 'r') as f:
        for line_number, line in enumerate(f, 1):
            try:
                entry = json.loads(line)
                # Add line number for reference
                entry['line_number'] = line_number
                data.append(entry)
            except json.JSONDecodeError:
                print(f"Warning: Skipping invalid JSON at line {line_number}")
    return data

def is_original_type(entry_type):
    """Check if an entry type is 'original'."""
    return entry_type == "original"

def is_fix_type(entry_type):
    """Check if an entry type is a fix."""
    return entry_type == "fix"

def is_numeric_type(entry_type):
    """Check if an entry type is a numeric variant (1, 2, 3, 4, etc.)."""
    try:
        int(entry_type)
        return True
    except (ValueError, TypeError):
        return False

def detect_clones(data_entries):
    """
    Detect code clones from the provided data entries.
    
    Rules:
    1. Only match <original, X> pairs within the same label group
    2. <original, numeric> pairs are considered true clones
    3. <original, fix> pairs are not considered clones
    """
    # Group entries by their label
    entries_by_label = defaultdict(list)
    for entry in data_entries:
        if 'label' in entry:
            entries_by_label[entry['label']].append(entry)
    
    # Generate hashes for all code entries
    entry_hashes = {}
    for entry in data_entries:
        if 'code' in entry:
            entry_hashes[entry['line_number']] = generate_function_hash(entry['code'])
    
    # Initialize counters
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negatives = 0
    total_potential_clones = 0
    total_non_clones = 0
    detected_clones = []
    
    # Process each label group
    for label, entries in entries_by_label.items():
        # Find original entries in this group
        original_entries = [e for e in entries if is_original_type(e.get('type', ''))]
        
        if not original_entries:
            continue  # Skip if no original entries in this group
        
        # Process each original entry
        for original_entry in original_entries:
            original_hash = entry_hashes.get(original_entry['line_number'])
            if not original_hash:
                continue
            
            # Examine pairs with each non-original entry
            for other_entry in entries:
                if other_entry['line_number'] == original_entry['line_number']:
                    continue  # Skip self
                
                other_hash = entry_hashes.get(other_entry['line_number'])
                if not other_hash:
                    continue
                
                other_type = other_entry.get('type', '')
                
                # Handle <original, numeric> pairs (true clones)
                if is_numeric_type(other_type):
                    total_potential_clones += 1
                    
                    if original_hash == other_hash:
                        # Detected true clone
                        true_positives += 1
                        detected_clones.append(original_entry)
                        detected_clones.append(other_entry)
                    else:
                        # Undetected true clone
                        false_negatives += 1
                
                # Handle <original, fix> pairs (not clones)
                elif is_fix_type(other_type):
                    total_non_clones += 1
                    
                    if original_hash == other_hash:
                        # Incorrectly detected as clone
                        false_positives += 1
                        detected_clones.append(original_entry)
                        detected_clones.append(other_entry)
                    else:
                        # Correctly not detected as clone
                        true_negatives += 1
    
    # Remove duplicates from detected_clones
    unique_detected_clones = []
    seen_line_numbers = set()
    for clone in detected_clones:
        if clone['line_number'] not in seen_line_numbers:
            unique_detected_clones.append(clone)
            seen_line_numbers.add(clone['line_number'])
    
    # Calculate precision, recall, and F1 score
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 1.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'true_positives': true_positives,
        'false_positives': false_positives,
        'false_negatives': false_negatives,
        'true_negatives': true_negatives,
        'detected_clones': unique_detected_clones,
        'total_potential_clones': total_potential_clones,
        'total_non_clones': total_non_clones
    }

def print_results(results):
    """Print the evaluation results in a readable format."""
    print("\n" + "="*50)
    print("CODE CLONE DETECTION RESULTS")
    print("="*50)
    print(f"Precision: {results['precision']:.4f}")
    print(f"Recall: {results['recall']:.4f}")
    print(f"F1 Score: {results['f1']:.4f}")
    print("-"*50)
    print(f"True Positives: {results['true_positives']}")
    print(f"False Positives: {results['false_positives']}")
    print(f"False Negatives: {results['false_negatives']}")
    print(f"True Negatives: {results['true_negatives']}")
    print("-"*50)
    print(f"Total True Clone Pairs: {results['total_potential_clones']}")
    print(f"Total Non-Clone Pairs: {results['total_non_clones']}")
    print(f"Total Detected Clones: {len(results['detected_clones'])}")
    print("="*50)

def save_detailed_results(results, output_path):
    """Save detailed results to a JSON file."""
    # Create a serializable version of results
    serializable_results = {
        'precision': results['precision'],
        'recall': results['recall'],
        'f1': results['f1'],
        'true_positives': results['true_positives'],
        'false_positives': results['false_positives'],
        'false_negatives': results['false_negatives'],
        'true_negatives': results['true_negatives'],
        'total_potential_clones': results['total_potential_clones'],
        'total_non_clones': results['total_non_clones'],
        'detected_clone_count': len(results['detected_clones']),
        'detected_clones': [
            {k: v for k, v in clone.items() if k != 'code'} 
            for clone in results['detected_clones']
        ]
    }
    
    with open(output_path, 'w') as f:
        json.dump(serializable_results, f, indent=2)
    
    print(f"Detailed results saved to {output_path}")

def main():
    parser = argparse.ArgumentParser(description='Code Clone Detection for C/C++ using hash matching')
    parser.add_argument('input_file', help='Input JSONL file containing code entries')
    parser.add_argument('-o', '--output', default='clone_detection_results.json', 
                        help='Output file for detailed results (default: clone_detection_results.json)')
    args = parser.parse_args()
    
    print(f"Reading code entries from {args.input_file}...")
    data = read_jsonl_file(args.input_file)
    print(f"Read {len(data)} entries.")
    
    print("Running code clone detection...")
    results = detect_clones(data)
    
    print_results(results)
    
    if args.output:
        save_detailed_results(results, args.output)

if __name__ == "__main__":
    main()