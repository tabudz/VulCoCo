import hashlib
import re
from tree_sitter import Language, Parser
from collections import defaultdict

# Load the Tree-sitter parser for C/C++
Language.build_library(
    'build/my-languages.so',
    ['/raid/data/yindusu/titan_code_clone/tree-sitter/tree-sitter-c', 
     '/raid/data/yindusu/titan_code_clone/tree-sitter/tree-sitter-cpp']  # Add both C and C++ parsers
)
C_LANGUAGE = Language('build/my-languages.so', 'c')
CPP_LANGUAGE = Language('build/my-languages.so', 'cpp')
parser = Parser()

# C/C++ keywords and special identifiers
cpp_keywords = [
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

cpp_special_ids = [
    "main", "printf", "scanf", "malloc", "free", "realloc", "calloc", "memcpy", 
    "memset", "strlen", "strcmp", "strcpy", "strcat", "fopen", "fclose", "fread", 
    "fwrite", "fprintf", "fscanf", "FILE", "NULL", "size_t", "ptrdiff_t", "time_t", 
    "clock_t", "va_list", "jmp_buf", "std", "string", "vector", "map", "set", 
    "list", "queue", "stack", "deque", "array", "bitset", "iostream", "istream", 
    "ostream", "cin", "cout", "cerr", "clog", "stringstream", "fstream", "ifstream", 
    "ofstream", "algorithm", "iterator", "exception", "thread", "mutex", "chrono"
]

def remove_comments_and_docstrings(source):
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
    temp = []
    for x in re.sub(pattern, replacer, source).split('\n'):
        if x.strip() != "":
            temp.append(x)
    return '\n'.join(temp)

def is_valid_variable_cpp(name: str) -> bool:
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        return False
    elif name in cpp_keywords:
        return False
    elif name in cpp_special_ids:
        return False
    return True

def tree_to_token_index(root_node):
    if (len(root_node.children) == 0 or root_node.type == 'string_literal') and root_node.type != 'comment':
        return [(root_node.start_point, root_node.end_point)]
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

def replace_identifiers_with_index(function: str, lang: str = "cpp") -> str:
    """
    Parse the C/C++ function using Tree-sitter and replace identifiers
    with indexed placeholders (a1, a2, ...). Same identifiers are replaced
    consistently within the same function, leaving keywords and literals untouched.
    """
    # Set appropriate language for parsing
    if lang.lower() == "c":
        parser.set_language(C_LANGUAGE)
    else:  # Default to C++
        parser.set_language(CPP_LANGUAGE)

    # Parse the function using Tree-sitter
    tree = parser.parse(bytes(function, "utf8"))
    root_node = tree.root_node

    # Initialize state
    identifiers = {}
    index = 1

    def traverse_and_collect(node):
        """
        Traverse the tree recursively to collect identifiers and assign placeholders.
        """
        nonlocal index
        if node.type == "identifier":
            identifier = node.text.decode()
            if identifier not in identifiers and is_valid_variable_cpp(identifier):
                identifiers[identifier] = f"a{index}"
                index += 1

        for child in node.children:
            traverse_and_collect(child)

    # Step 1: Collect identifiers
    traverse_and_collect(root_node)

    # Step 2: Replace identifiers in the original function
    tokens_index = tree_to_token_index(root_node)
    function_lines = function.split("\n")
    code_tokens = [index_to_code_token(x, function_lines) for x in tokens_index]

    replace_pos = {}
    for idx, code_token in enumerate(code_tokens):
        if code_token in identifiers:
            substitute = identifiers[code_token]
            try:
                replace_pos[tokens_index[idx][0][0]].append((tokens_index[idx][0][1], tokens_index[idx][1][1]))
            except KeyError:
                replace_pos[tokens_index[idx][0][0]] = [(tokens_index[idx][0][1], tokens_index[idx][1][1])]

    diff = {}
    for line in sorted(replace_pos.keys()):  # Sort by line number for consistent replacements
        diff[line] = 0
        for index, pos in enumerate(replace_pos[line]):
            start = pos[0] + diff[line]
            end = pos[1] + diff[line]
            try:
                substitute = identifiers[function_lines[line][start:end]]
                function_lines[line] = (
                    function_lines[line][:start] + substitute + function_lines[line][end:]
                )
                diff[line] += len(substitute) - (end - start)
            except:
                # Handle potential indexing errors gracefully
                pass

    return "\n".join(function_lines)


if __name__ == "__main__":
    # Example known vulnerable C++ functions
    known_vulnerable_functions = [
        """
        void vulnerableFunction(char* userInput) {
            char buffer[10];
            strcpy(buffer, userInput);  // Buffer overflow vulnerability
            printf("Input: %s\\n", buffer);
        }
        """,
        """
        bool checkAccess(const std::string& userInput) {
            if (userInput == "admin") {
                std::cout << "Access granted!" << std::endl;
                return true;
            }
            return false;
        }
        """
    ]
    
    for func in known_vulnerable_functions:
        func = remove_comments_and_docstrings(func)
        print("Original function:")
        print(func)
        print("\nFunction with replaced identifiers:")
        print(replace_identifiers_with_index(func))
        print("\n" + "-"*50 + "\n")