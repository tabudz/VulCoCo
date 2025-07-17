import hashlib
import re
from tree_sitter import Language, Parser
from collections import defaultdict
import json
from tqdm import tqdm
import os
import sys

sys.setrecursionlimit(1500)

# Load the Tree-sitter parser for C, C++, and Java
Language.build_library(
    'build/my-languages.so',
    ['/raid/data/yindusu/titan_code_clone/tree-sitter/tree-sitter-c',
     '/raid/data/yindusu/titan_code_clone/tree-sitter/tree-sitter-cpp',
     '/raid/data/yindusu/titan_code_clone/tree-sitter/tree-sitter-java',]
)

# Initialize parsers for each language
C_LANGUAGE = Language('build/my-languages.so', 'c')
CPP_LANGUAGE = Language('build/my-languages.so', 'cpp')
JAVA_LANGUAGE = Language('build/my-languages.so', 'java')

parsers = {
    'c': Parser(),
    'cpp': Parser(),
    'java': Parser()
}

parsers['c'].set_language(C_LANGUAGE)
parsers['cpp'].set_language(CPP_LANGUAGE)
parsers['java'].set_language(JAVA_LANGUAGE)

# Language-specific keywords and standard functions
c_keywords = ["auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum",
              "extern", "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return",
              "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void",
              "volatile", "while", "_Bool", "_Complex", "_Imaginary", "_Alignas", "_Alignof", "_Atomic",
              "_Static_assert", "_Noreturn", "_Thread_local", "_Generic", "true", "false", "NULL"]

cpp_keywords = c_keywords + ["class", "namespace", "using", "template", "typename", "public", "private", "protected",
                            "virtual", "override", "final", "new", "delete", "this", "operator", "friend", "explicit",
                            "mutable", "constexpr", "decltype", "auto", "nullptr", "thread_local", "alignas", "alignof",
                            "static_assert", "noexcept", "try", "catch", "throw", "typeid", "dynamic_cast", "static_cast",
                            "const_cast", "reinterpret_cast"]

java_keywords = ["abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const",
                "continue", "default", "do", "double", "else", "enum", "extends", "final", "finally", "float",
                "for", "goto", "if", "implements", "import", "instanceof", "int", "interface", "long", "native",
                "new", "package", "private", "protected", "public", "return", "short", "static", "strictfp",
                "super", "switch", "synchronized", "this", "throw", "throws", "transient", "try", "void",
                "volatile", "while", "true", "false", "null"]

# Language-specific standard types
c_standard_types = ["void", "char", "short", "int", "long", "float", "double", "signed", "unsigned",
                   "_Bool", "_Complex", "_Imaginary", "size_t", "ptrdiff_t", "wchar_t", "wint_t",
                   "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
                   "intptr_t", "uintptr_t", "time_t", "clock_t", "FILE", "DIR"]

cpp_standard_types = c_standard_types + ["string", "vector", "map", "set", "list", "queue", "stack", "pair",
                                        "shared_ptr", "unique_ptr", "weak_ptr", "array", "unordered_map",
                                        "unordered_set", "deque", "priority_queue", "bitset", "tuple",
                                        "function", "thread", "mutex", "condition_variable"]

java_standard_types = ["boolean", "byte", "char", "short", "int", "long", "float", "double", "String",
                      "Object", "Integer", "Double", "Float", "Boolean", "Character", "Byte", "Short", "Long",
                      "ArrayList", "HashMap", "HashSet", "TreeMap", "TreeSet", "LinkedList", "Vector",
                      "Stack", "Queue", "PriorityQueue", "Properties", "Date", "Calendar", "Thread",
                      "Runnable", "Exception", "RuntimeException"]

# Language-specific standard functions
c_standard_functions = ["printf", "scanf", "malloc", "free", "calloc", "realloc", "strlen", "strcpy", "strcat",
                       "strcmp", "strncmp", "strstr", "memcpy", "memset", "memmove", "fopen", "fclose", "fread",
                       "fwrite", "fprintf", "fscanf", "fgets", "fputs", "exit", "abort", "atexit", "system",
                       "getenv", "qsort", "bsearch", "abs", "labs", "div", "ldiv", "rand", "srand", "atoi",
                       "atol", "atof", "strtol", "strtoul", "strtod", "isalpha", "isdigit", "isalnum", "isspace",
                       "tolower", "toupper", "sin", "cos", "tan", "log", "exp", "sqrt", "pow", "ceil", "floor"]

cpp_standard_functions = c_standard_functions + ["cout", "cin", "endl", "begin", "end", "size", "empty", "push_back",
                                                "pop_back", "insert", "erase", "find", "clear", "sort", "reverse",
                                                "max", "min", "swap", "make_pair", "make_shared", "make_unique",
                                                "get", "move", "forward", "thread", "join", "detach", "lock", "unlock"]

java_standard_functions = ["println", "print", "length", "charAt", "substring", "indexOf", "toLowerCase", "toUpperCase",
                          "trim", "replace", "split", "equals", "compareTo", "hashCode", "toString", "valueOf",
                          "parseInt", "parseDouble", "add", "remove", "get", "set", "size", "isEmpty", "contains",
                          "clear", "iterator", "hasNext", "next", "put", "keySet", "values", "entrySet",
                          "start", "run", "sleep", "wait", "notify", "notifyAll", "currentTimeMillis"]

# Language-specific modifiers
c_modifiers = ["static", "extern", "register", "auto", "const", "volatile", "restrict", "inline",
               "unsigned", "signed", "_Thread_local", "_Atomic"]

cpp_modifiers = c_modifiers + ["public", "private", "protected", "virtual", "explicit", "mutable", "constexpr",
                              "thread_local", "alignas", "noexcept"]

java_modifiers = ["public", "private", "protected", "static", "final", "abstract", "synchronized", "volatile",
                 "transient", "native", "strictfp"]

def get_language_config(language):
    """Get language-specific configuration"""
    configs = {
        'c': {
            'keywords': c_keywords,
            'standard_types': c_standard_types,
            'standard_functions': c_standard_functions,
            'modifiers': c_modifiers
        },
        'cpp': {
            'keywords': cpp_keywords,
            'standard_types': cpp_standard_types,
            'standard_functions': cpp_standard_functions,
            'modifiers': cpp_modifiers
        },
        'java': {
            'keywords': java_keywords,
            'standard_types': java_standard_types,
            'standard_functions': java_standard_functions,
            'modifiers': java_modifiers
        }
    }
    return configs.get(language, configs['c'])

def detect_language_from_path(file_path):
    """Detect programming language based on file path extension"""
    ext = file_path.lower().split('.')[-1]
    if ext == 'c':
        return 'c'
    elif ext in ['cpp', 'cc', 'cxx', 'c++']:
        return 'cpp'
    elif ext == 'java':
        return 'java'
    else:
        return 'c'  # Default to C

def detect_language(filename):
    """Detect programming language based on file extension (backward compatibility)"""
    ext = filename.lower().split('.')[-1]
    if ext == 'c':
        return 'c'
    elif ext in ['cpp', 'cc', 'cxx', 'c++']:
        return 'cpp'
    elif ext == 'java':
        return 'java'
    else:
        return 'c'  # Default to C

def remove_comments_and_docstrings(source, language='c'):
    """Remove comments based on language"""
    if language == 'java':
        # Java-style comments (same as C/C++)
        pattern = re.compile(
            r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
            re.DOTALL | re.MULTILINE
        )
    else:
        # C/C++ style comments
        pattern = re.compile(
            r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
            re.DOTALL | re.MULTILINE
        )
    
    def replacer(match):
        s = match.group(0)
        if s.startswith('/') or s.startswith('/*'):
            return " "
        else:
            return s
    
    temp = []
    for x in re.sub(pattern, replacer, source).split('\n'):
        if x.strip() != "":
            temp.append(x)
    return '\n'.join(temp)

def tree_to_token_index(root_node):
    if (len(root_node.children) == 0 or root_node.type == 'string') and root_node.type != 'comment':
        return [(root_node.start_point, root_node.end_point, root_node.type)]
    else:
        code_tokens = []
        for child in root_node.children:
            code_tokens += tree_to_token_index(child)
        return code_tokens
    
def index_to_code_token(index, code):
    start_point = index[0]
    end_point = index[1]
    if start_point[0] == end_point[0]:
        s = code[start_point[0]][start_point[1]:end_point[1]]
    else:
        s = ""
        s += code[start_point[0]][start_point[1]:]
        for i in range(start_point[0]+1, end_point[0]):
            s += code[i]
        s += code[end_point[0]][:end_point[1]]
    return s

def get_formal_parameters(root_node, language):
    """Extract formal parameters from function definition"""
    parameters = set()
    
    def traverse_for_params(node):
        if language == 'java':
            if node.type == "method_declaration":
                for child in node.children:
                    if child.type == "formal_parameters":
                        for param in child.children:
                            if param.type == "formal_parameter":
                                for param_part in param.children:
                                    if param_part.type == "identifier":
                                        parameters.add(param_part.text.decode())
        else:  # C/C++
            if node.type == "function_definition":
                for child in node.children:
                    if child.type == "function_declarator":
                        for param_child in child.children:
                            if param_child.type == "parameter_list":
                                for param in param_child.children:
                                    if param.type == "parameter_declaration":
                                        for param_part in param.children:
                                            if param_part.type == "identifier":
                                                parameters.add(param_part.text.decode())
        
        for child in node.children:
            traverse_for_params(child)
    
    traverse_for_params(root_node)
    return parameters

def get_local_variables(root_node, formal_params, language):
    """Extract local variables (excluding formal parameters)"""
    local_vars = set()
    
    def traverse_for_vars(node):
        if language == 'java':
            # Java variable declarations
            if node.type == "local_variable_declaration":
                for child in node.children:
                    if child.type == "variable_declarator":
                        for var_child in child.children:
                            if var_child.type == "identifier":
                                var_name = var_child.text.decode()
                                if var_name not in formal_params:
                                    local_vars.add(var_name)
        else:  # C/C++
            # Variable declarations
            if node.type == "declaration":
                for child in node.children:
                    if child.type == "init_declarator":
                        for init_child in child.children:
                            if init_child.type == "identifier":
                                var_name = init_child.text.decode()
                                if var_name not in formal_params:
                                    local_vars.add(var_name)
            
            # Simple declarators
            elif node.type == "declarator" and node.parent and node.parent.type == "declaration":
                for child in node.children:
                    if child.type == "identifier":
                        var_name = child.text.decode()
                        if var_name not in formal_params:
                            local_vars.add(var_name)
        
        for child in node.children:
            traverse_for_vars(child)
    
    traverse_for_vars(root_node)
    return local_vars

def get_data_types(root_node, language, config):
    """Extract data types (standard and user-defined, but not modifiers)"""
    data_types = set()
    
    def traverse_for_types(node):
        if language == 'java':
            # Java type identifiers
            if node.type == "type_identifier":
                type_name = node.text.decode()
                if type_name not in config['modifiers']:
                    data_types.add(type_name)
            elif node.type in ["integral_type", "floating_point_type", "boolean_type"]:
                type_name = node.text.decode()
                if type_name not in config['modifiers']:
                    data_types.add(type_name)
        else:  # C/C++
            # Standard primitive types
            if node.type == "primitive_type":
                type_name = node.text.decode()
                if type_name not in config['modifiers']:
                    data_types.add(type_name)
            
            # User-defined types
            elif node.type == "type_identifier":
                type_name = node.text.decode()
                if type_name not in config['modifiers']:
                    data_types.add(type_name)
            
            # Struct/union/enum specifiers
            elif node.type in ["struct_specifier", "union_specifier", "enum_specifier"]:
                for child in node.children:
                    if child.type == "type_identifier":
                        data_types.add(child.text.decode())
        
        for child in node.children:
            traverse_for_types(child)
    
    traverse_for_types(root_node)
    return data_types

def get_function_calls(root_node, language, config):
    """Extract function calls (excluding standard library functions)"""
    function_calls = set()
    
    def traverse_for_calls(node):
        if language == 'java':
            if node.type == "method_invocation":
                for child in node.children:
                    if child.type == "identifier":
                        func_name = child.text.decode()
                        if func_name not in config['standard_functions']:
                            function_calls.add(func_name)
                        break
        else:  # C/C++
            if node.type == "call_expression":
                for child in node.children:
                    if child.type == "identifier":
                        func_name = child.text.decode()
                        if func_name not in config['standard_functions']:
                            function_calls.add(func_name)
                        break
        
        for child in node.children:
            traverse_for_calls(child)
    
    traverse_for_calls(root_node)
    return function_calls

def vuddy_level4_abstraction(function: str, language: str) -> str:
    """
    VUDDY Level 4 abstraction for multiple languages:
    - Level 1: Formal parameters → FPARAM
    - Level 2: Local variables → LVAR  
    - Level 3: Data types → DTYPE
    - Level 4: Function calls → FUNCCALL
    """
    parser = parsers[language]
    config = get_language_config(language)
    
    tree = parser.parse(bytes(function, "utf8"))
    root_node = tree.root_node

    # Extract different categories of identifiers
    formal_params = get_formal_parameters(root_node, language)
    local_vars = get_local_variables(root_node, formal_params, language)
    data_types = get_data_types(root_node, language, config)
    function_calls = get_function_calls(root_node, language, config)
    
    # Build replacement mapping
    replacements = {}
    
    def traverse_and_collect(node):
        node_text = node.text.decode()
        
        # Level 4: Function calls
        if language == 'java':
            if node.type == "identifier" and node.parent and node.parent.type == "method_invocation":
                if node_text in function_calls:
                    replacements[node_text] = "FUNCCALL"
        else:  # C/C++
            if node.type == "identifier" and node.parent and node.parent.type == "call_expression":
                if node_text in function_calls:
                    replacements[node_text] = "FUNCCALL"
        
        # Level 3: Data types
        if language == 'java':
            if node.type in ["type_identifier", "integral_type", "floating_point_type", "boolean_type"]:
                if node_text in data_types:
                    replacements[node_text] = "DTYPE"
        else:  # C/C++
            if node.type in ["primitive_type", "type_identifier"]:
                if node_text in data_types:
                    replacements[node_text] = "DTYPE"
        
        # Level 1: Formal parameters
        if node.type == "identifier" and node_text in formal_params:
            replacements[node_text] = "FPARAM"
        
        # Level 2: Local variables
        elif node.type == "identifier" and node_text in local_vars:
            replacements[node_text] = "LVAR"

        for child in node.children:
            traverse_and_collect(child)

    # Collect all replacements
    traverse_and_collect(root_node)
    tokens_index = tree_to_token_index(root_node)

    function_lines = function.split("\n")
    code_tokens = [index_to_code_token(x, function_lines) for x in tokens_index]

    replace_pos = {}
    for idx, code_token in enumerate(code_tokens):
        if code_token in replacements:
            substitute = replacements[code_token]
            try:
                replace_pos[tokens_index[idx][0][0]].append((tokens_index[idx][0][1], tokens_index[idx][1][1]))
            except KeyError:
                replace_pos[tokens_index[idx][0][0]] = [(tokens_index[idx][0][1], tokens_index[idx][1][1])]

    diff = {}
    for line in sorted(replace_pos.keys()):
        diff[line] = 0
        for index, pos in enumerate(replace_pos[line]):
            start = pos[0] + diff[line]
            end = pos[1] + diff[line]
            substitute = replacements[function_lines[line][start:end]]
            function_lines[line] = (
                function_lines[line][:start] + substitute + function_lines[line][end:]
            )
            diff[line] += len(substitute) - (end - start)

    return "\n".join(function_lines)


def generate_md5_hash(content: str) -> str:
    """
    Generate an MD5 hash ID for the given content.
    """
    return hashlib.md5(content.encode("utf-8")).hexdigest()


def hash_based_clone_detection(
    functions: list, known_vulnerable_hashes: list, hash_dict: dict
) -> list:
    """
    Detect recurring vulnerabilities based on hash-based matching with VUDDY Level 4 abstraction.
    """
    matches = []

    for i, line in tqdm(enumerate(functions), desc="Checking for clones"):
        function = remove_comments_and_docstrings(line.get('function', ''), line.get('language', 'c'))
        try:
            processed_function = vuddy_level4_abstraction(function, line.get('language', 'c'))
        except RecursionError:
            continue
        except Exception as e:
            print(f"Error processing function from {line.get('filename', 'unknown')}: {e}")
            continue
            
        # Remove ALL whitespace characters (spaces, tabs, newlines, etc.)
        processed_function = re.sub(r'\s+', '', processed_function)
        function_hash = generate_md5_hash(processed_function)

        for j, known_hash in enumerate(known_vulnerable_hashes):
            if function_hash == known_hash:
                matches.append({
                    "original_commit": hash_dict[known_hash]['commit_id'],
                    "clone_filename": line['filename'],
                    "clone_path": line['path'],
                    "clone_repo": line.get('repo', 'unknown'),
                    "clone_language": line.get('language', 'unknown'),
                    "json_file": line.get('json_file', 'unknown'),
                })

    return matches


def load_functions_from_json_files(funcs_dir):
    """Load functions from {repo}_functions.json files in the directory"""
    print(f"Loading functions from JSON files in {funcs_dir}...")
    
    all_functions = []
    json_files = [f for f in os.listdir(funcs_dir) if f.endswith('_functions.json')]
    
    print(f"Found {len(json_files)} JSON function files")
    
    for json_file in tqdm(json_files, desc="Loading JSON files"):
        json_path = os.path.join(funcs_dir, json_file)
        repo_name = json_file.replace('_functions.json', '')
        
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                functions_data = json.load(f)
            
            print(f"Processing {len(functions_data)} functions from {json_file}")
            
            for func_entry in functions_data:
                # Extract information from JSON entry
                function_code = func_entry.get('function', '')
                file_path = func_entry.get('path', '')
                
                # Skip empty functions or functions with too few lines
                if not function_code or function_code.replace('\n\n','\n').count('\n') <= 2:
                    continue
                
                # Detect language from the file path in the JSON entry
                language = detect_language_from_path(file_path)
                
                all_functions.append({
                    'function': function_code,
                    'path': file_path,
                    'filename': os.path.basename(file_path),
                    'repo': repo_name,
                    'language': language,
                    'json_file': json_file
                })
                
        except Exception as e:
            print(f"Error loading {json_file}: {e}")
            continue
    
    print(f"Loaded {len(all_functions)} functions from {len(json_files)} JSON files")
    
    # Print language distribution for verification
    language_counts = {}
    for func in all_functions:
        lang = func['language']
        language_counts[lang] = language_counts.get(lang, 0) + 1
    
    print("Language distribution:")
    for lang, count in language_counts.items():
        print(f"  {lang}: {count} functions")
    
    return all_functions

def process_source_files(funcs_dir, vuln_file, output_dir):
    # Load known vulnerable functions from JSONL file
    print("Loading known vulnerable functions...")
    with open(vuln_file, 'r') as f:
        lines = f.readlines()
        all_entries = [json.loads(x) for x in lines]
    
    # Filter for target == 1 (vulnerable functions) and sufficient lines
    known_vulnerable_functions = [
        entry for entry in all_entries
        if entry.get('func', entry.get('vuln_func', entry.get('function', ''))).replace('\n\n','\n').count('\n') > 2
    ]
    
    print(f"Found {len(known_vulnerable_functions)} vulnerable functions with target=1")

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    hash_dict = {}
    known_vulnerable_hashes = []
    
    # Process known vulnerable functions (assume they are C/C++ for now)
    print("Processing vulnerable functions...")
    for line in tqdm(known_vulnerable_functions): 
        func = remove_comments_and_docstrings(line.get('func', ''), 'c')
        try:
            processed_function = vuddy_level4_abstraction(func, 'c')
        except RecursionError:
            continue
        # Remove ALL whitespace characters (spaces, tabs, newlines, etc.)
        processed_function = re.sub(r'\s+', '', processed_function)
        function_hash = generate_md5_hash(processed_function)
        known_vulnerable_hashes.append(function_hash)
        hash_dict[function_hash] = line
    
    print(f"Successfully processed {len(known_vulnerable_hashes)} vulnerable function hashes")
    
    # Load functions from JSON files
    all_functions = load_functions_from_json_files(funcs_dir)
    
    if not all_functions:
        print("No functions found in JSON files!")
        return
    
    # Process functions in batches for better memory management
    batch_size = 1000
    all_matches = []
    
    for i in tqdm(range(0, len(all_functions), batch_size), desc="Processing function batches"):
        batch_functions = all_functions[i:i+batch_size]
        
        print(f"Processing batch {i//batch_size + 1} with {len(batch_functions)} functions...")
        batch_matches = hash_based_clone_detection(batch_functions, known_vulnerable_hashes, hash_dict)
        all_matches.extend(batch_matches)
        
        if batch_matches:
            print(f"Found {len(batch_matches)} matches in this batch")

    # Save all matches to output JSONL file
    output_path = os.path.join(output_dir, "hash_based_clones_final.jsonl")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    print(f"Saving {len(all_matches)} total matches to {output_path}")
    with open(output_path, 'w') as f:
        for match in all_matches:
            f.write(json.dumps(match) + '\n')
    
    print(f"Clone detection complete! Found {len(all_matches)} potential clones.")

if __name__ == "__main__":
    # Paths to input and output directories
    funcs_dir = '/mnt/sun-data/ngoctanbui/code_clone/final_funcs'
    vuln_file = '/raid/data/yindusu/titan_code_clone/datasets/final_src.jsonl'
    output_dir = '/mnt/sun-data/ngoctanbui/code_clone/final_clones/hash_based'

    # Process source files
    process_source_files(funcs_dir, vuln_file, output_dir)