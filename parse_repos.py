import os
import json
from tree_sitter import Parser, Language
import tree_sitter_c_sharp as tscsharp  # Pre-built binding for C#
import tree_sitter_java as tsjava  # Pre-built binding for Java
import tree_sitter_javascript as tsjavascript  # Pre-built binding for JavaScript
import tree_sitter_c as ts_c  # Pre-built binding for C
import tree_sitter_cpp as ts_cpp  # Pre-built binding for C++
import sys
sys.setrecursionlimit(2000)

# Constants
REPOS_DIR = "/mnt/sun-data/ngoctanbui/code_clone/final_repos"  # Directory with cloned repositories
FUNCTIONS_DIR = "/mnt/sun-data/ngoctanbui/code_clone/final_funcs"  # Directory to save parsed functions
LANGUAGES = ["c", "cpp", "java"]  # Languages to parse

# Load Tree-sitter parsers
JAVA_LANGUAGE = Language(tsjava.language())
JAVASCRIPT_LANGUAGE = Language(tsjavascript.language())
JAVA_PARSER = Parser(JAVA_LANGUAGE)
JAVASCRIPT_PARSER = Parser(JAVASCRIPT_LANGUAGE)
CSHARP_LANGUAGE = Language(tscsharp.language())
CSHARP_PARSER = Parser(CSHARP_LANGUAGE)
C_LANGUAGE = Language(ts_c.language())
C_PARSER = Parser(C_LANGUAGE)
CPP_LANGUAGE = Language(ts_cpp.language())
CPP_PARSER = Parser(CPP_LANGUAGE)


def parse_functions_with_tree_sitter(file_path, file_extension):
    """
    Parse the source file using Tree-sitter to extract functions.
    """
    functions = []
    try:
        # Select the appropriate language parser
        if file_extension in [".c"]:  # C source and header files
            parser = C_PARSER
        elif file_extension in [".cpp", ".cc"]:  # C++ source and header
            parser = CPP_PARSER
        elif file_extension in [".java"]:  # C++ source and header
            parser = JAVA_PARSER
        else:
            return functions

        # Read the source code
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                code = file.read().encode()
                # print(code)
        except:
            try:
                with open(file_path, 'r', encoding = "CP949") as file:
                    code = file.read().encode()
            except:
                try:
                    with open(file_path, 'r', encoding = "euc-kr") as file:
                        code = file.read().encode()
                except:
                    pass

        # Parse the code with Tree-sitter
        tree = parser.parse(code)
        # print(tree)
        if not tree:
            print(f"Tree-sitter returned an empty tree for: {file_path}")
            return []

        root_node = tree.root_node

        # Traverse AST and find function nodes
        def traverse_tree(node):
            # print(node.type)
            if node.type in ("method_declaration", "function_declaration", "arrow_function", "function_definition"):
                start_byte = node.start_byte
                end_byte = node.end_byte
                function_content = code[start_byte:end_byte].decode("utf-8")
                functions.append({'path': file_path, 'function': function_content})

            for child in node.children:
                traverse_tree(child)

        traverse_tree(root_node)

    except Exception as e:
        print(f"Error parsing {file_path}: {e}")

    return functions


def process_repository(repo_path, file_extensions):
    """
    Process all source files in a repository to extract functions.
    """
    functions = []
    for root, _, files in os.walk(repo_path):
        for file in files:
            if any(file.endswith(ext) for ext in file_extensions):
                # print(f"Processing: {file}")
                file_path = os.path.join(root, file)
                file_extension = os.path.splitext(file)[1]
                functions.extend(parse_functions_with_tree_sitter(file_path, file_extension))
    return functions


def parse_repositories(repos_dir, functions_dir):
    """
    Parse all cloned repositories and save extracted functions as JSON.
    """
    os.makedirs(functions_dir, exist_ok=True)

    # language_functions_dir = os.path.join(functions_dir, language)
    # os.makedirs(language_functions_dir, exist_ok=True)

    repos = [repo for repo in os.listdir(repos_dir) if os.path.isdir(os.path.join(repos_dir, repo))]
    total_repos = len(repos)

    for index, repo_name in enumerate(repos, start=1):
        repo_path = os.path.join(repos_dir, repo_name)
        json_save_path = os.path.join(functions_dir, f"{repo_name}_functions.json")

        if os.path.exists(json_save_path):
            print(f"Skipping repository {index}/{total_repos}: {repo_name} (already processed)")
            continue

        # Display current repository index and total repositories
        print(f"\nProcessing repository {index}/{total_repos}: {repo_name}")

        functions = process_repository(repo_path, ["java", "c", "cpp"])

        # Save extracted functions to JSON
        with open(json_save_path, "w", encoding="utf-8") as json_file:
            json.dump(functions, json_file, indent=4)
        print(f"Saved {len(functions)} functions from {repo_name} to {json_save_path}")


if __name__ == "__main__":
    parse_repositories(
        repos_dir=REPOS_DIR,
        functions_dir=FUNCTIONS_DIR,
    )
