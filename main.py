import argparse
import json
import glob
import os
import numpy as np
from collections import defaultdict
from pathlib import Path
import faiss
from sentence_transformers import SentenceTransformer
from accelerate import Accelerator
import logging
import pickle
import torch
import re
from tqdm import tqdm
from movery_signature_generator import SignatureGenerator


class AbstractionProcessor:
    """
    Handles code abstraction using MOVERY technique for clone detection
    """
    
    def __init__(self, use_abstraction=True):
        """Initialize the abstraction processor"""
        self.use_abstraction = use_abstraction
        self.signature_generator = SignatureGenerator() if SignatureGenerator and use_abstraction else None
        self.abstraction_cache = {}  # Cache to avoid re-abstracting same code
    
    def abstract_function_code(self, function_code: str) -> str:
        """
        Abstract a single function using MOVERY technique
        Returns the abstracted code as a string
        """
        if not self.use_abstraction or not self.signature_generator:
            return function_code
            
        if not function_code or not function_code.strip():
            return ""
        
        # Check cache first (use hash of code as key)
        code_hash = hash(function_code)
        if code_hash in self.abstraction_cache:
            return self.abstraction_cache[code_hash]
        
        try:
            # Apply MOVERY abstraction
            abstracted_code = self.signature_generator.abstract(function_code)
            
            # Remove comments and clean up
            clean_abstracted = self.signature_generator.removeComment(abstracted_code)
            
            # Cache the result
            self.abstraction_cache[code_hash] = clean_abstracted
            
            return clean_abstracted
            
        except Exception as e:
            print(f"[WARNING] MOVERY abstraction failed for function: {e}")
            # Fallback to original code with comment removal
            if self.signature_generator:
                clean_original = self.signature_generator.removeComment(function_code)
            else:
                clean_original = remove_comments(function_code)
            self.abstraction_cache[code_hash] = clean_original
            return clean_original
    
    def batch_abstract_functions(self, function_codes: list, show_progress: bool = True) -> list:
        """
        Abstract a batch of function codes
        Returns list of abstracted codes
        """
        if not self.use_abstraction:
            return function_codes
            
        abstracted_codes = []
        total = len(function_codes)
        
        for i, code in enumerate(function_codes):
            if show_progress and i % 100 == 0:
                print(f"[INFO] Abstracting functions: {i}/{total} ({i/total*100:.1f}%)")
            
            abstracted = self.abstract_function_code(code)
            abstracted_codes.append(abstracted)
        
        if show_progress:
            print(f"[INFO] Abstraction complete: {total} functions processed")
            print(f"[INFO] Cache size: {len(self.abstraction_cache)} unique functions")
        
        return abstracted_codes


def setup_logger(log_file, logger_name="CombinedCloneDetectionLogger"):
    """
    Sets up a logger to log messages to both stdout and a file.
    """
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter("%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file, mode="w")
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(console_formatter)
        logger.addHandler(file_handler)

    return logger


def load_embedding_model_safely(model_name="jinaai/jina-embeddings-v3", logger=None):
    """
    Safely load the embedding model with error handling and cache clearing if needed.
    """
    try:
        if logger:
            logger.info(f"Attempting to load model: {model_name}")
        
        # Try loading with force_download first to bypass cache issues
        embedder = SentenceTransformer(model_name, trust_remote_code=True)
        
        if logger:
            logger.info(f"Successfully loaded model: {model_name}")
        return embedder
        
    except Exception as e:
        if logger:
            logger.warning(f"Failed to load with force_download: {e}")
            logger.info("Trying to clear cache and reload...")
        
        # Clear the specific model cache
        import shutil
        cache_dir = Path.home() / ".cache" / "huggingface" / "hub"
        model_cache_dirs = list(cache_dir.glob(f"*{model_name.replace('/', '--')}*"))
        
        for cache_path in model_cache_dirs:
            try:
                if logger:
                    logger.info(f"Removing cache directory: {cache_path}")
                shutil.rmtree(cache_path)
            except Exception as cache_error:
                if logger:
                    logger.warning(f"Failed to remove cache directory {cache_path}: {cache_error}")
        
        # Also clear transformers modules cache
        transformers_cache = Path.home() / ".cache" / "huggingface" / "modules" / "transformers_modules"
        jina_cache_dirs = list(transformers_cache.glob("*jina*"))
        
        for cache_path in jina_cache_dirs:
            try:
                if logger:
                    logger.info(f"Removing transformers cache: {cache_path}")
                shutil.rmtree(cache_path)
            except Exception as cache_error:
                if logger:
                    logger.warning(f"Failed to remove transformers cache {cache_path}: {cache_error}")
        
        # Try loading again after cache clear
        try:
            embedder = SentenceTransformer(model_name, trust_remote_code=True)
            if logger:
                logger.info(f"Successfully loaded model after cache clear: {model_name}")
            return embedder
        except Exception as e2:
            if logger:
                logger.error(f"Failed to load model even after cache clear: {e2}")
                logger.info("Trying fallback model...")
            
            # Try a fallback model
            fallback_models = [
                "sentence-transformers/all-MiniLM-L6-v2",
                "sentence-transformers/all-mpnet-base-v2", 
                "jinaai/jina-embeddings-v2-base-en"
            ]
            
            for fallback in fallback_models:
                try:
                    if logger:
                        logger.info(f"Trying fallback model: {fallback}")
                    embedder = SentenceTransformer(fallback, trust_remote_code=True)
                    if logger:
                        logger.info(f"Successfully loaded fallback model: {fallback}")
                    return embedder
                except Exception as fallback_error:
                    if logger:
                        logger.warning(f"Fallback model {fallback} failed: {fallback_error}")
                    continue
            
            # If all fallbacks fail, raise the original error
            raise e2


# ===== CODE PREPROCESSING FUNCTIONS =====

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


def preprocess_code(code, abstraction_processor=None):
    """
    Apply all preprocessing steps to code, including optional MOVERY abstraction.
    """
    if not code or not isinstance(code, str):
        return code
    
    # Step 1: Apply MOVERY abstraction if enabled (this includes comment removal)
    if abstraction_processor and abstraction_processor.use_abstraction:
        code = abstraction_processor.abstract_function_code(code)
    else:
        # Step 1a: Remove comments (if not using MOVERY abstraction)
        code = remove_comments(code)
    
    # Step 2: Standardize whitespace
    code = standardize_whitespace(code)
    
    # Step 3: Normalize case
    code = normalize_case(code)
    
    return code


def preprocess_code_batch(code_list, abstraction_processor=None):
    """
    Apply preprocessing to a batch of code snippets.
    """
    if abstraction_processor and abstraction_processor.use_abstraction:
        # Use batch abstraction for efficiency
        abstracted_codes = abstraction_processor.batch_abstract_functions(code_list, show_progress=False)
        # Then apply remaining preprocessing steps
        return [preprocess_code(code, abstraction_processor=None) for code in abstracted_codes]
    else:
        return [preprocess_code(code, abstraction_processor) for code in code_list]


# ===== CLONE DETECTION FUNCTIONS =====

def load_corpus(corpus_path, abstraction_processor=None):
    """
    Load the source data (corpus) from all.json and preprocess it.
    """
    corpus = []
    with open(corpus_path, "r", encoding="utf-8") as f:
        for line in f:
            data = json.loads(line)
            corpus.append(data)
    
    # Extract functions and preprocess them
    raw_corpus = [func.get('function', func.get('vuln_func', func.get('func'))) for func in corpus]
    preprocessed_corpus = preprocess_code_batch(raw_corpus, abstraction_processor)
    
    return preprocessed_corpus


def build_faiss_index(embeddings):
    """
    Builds a Faiss index for fast similarity search.
    """
    dimension = embeddings.shape[1]
    index = faiss.IndexFlatIP(dimension)  # Inner product for cosine similarity
    faiss.normalize_L2(embeddings)       # Ensure embeddings are normalized for cosine similarity
    index.add(embeddings)
    return index


def batch_process_queries_faiss(queries, embedder, faiss_index, corpus, batch_size, top_k, threshold, abstraction_processor=None):
    """
    Process queries for clone detection using Faiss.
    """
    results = defaultdict(dict)
    # Extract and preprocess query functions
    raw_queries = [q.get('function', q.get('vuln_func')) for q in queries]
    preprocessed_queries = preprocess_code_batch(raw_queries, abstraction_processor)
    
    for i in range(0, len(preprocessed_queries), batch_size):
        query_batch = preprocessed_queries[i:i + batch_size]
        query_embeddings = embedder.encode(query_batch, convert_to_numpy=True)
        faiss.normalize_L2(query_embeddings)  # Normalize queries for cosine similarity

        # Search in Faiss
        distances, indices = faiss_index.search(query_embeddings, k=top_k)
        for j, (query, dists, idxs) in enumerate(zip(query_batch, distances, indices)):
            original_query = raw_queries[i + j]  # Use original query as key
            for dist, idx in zip(dists, idxs):
                if dist < threshold:
                    continue
                doc = corpus[idx]
                results[doc][original_query] = float(dist)

    return results


def process_repository_detection(repo_path, embedder, faiss_index, corpus, batch_size, top_k, threshold, abstraction_processor=None):
    """
    Process a single repository for clone detection. Returns results in memory.
    """
    with open(repo_path, "r", encoding="utf-8") as f:
        queries = json.load(f)

    # Perform clone detection
    results = batch_process_queries_faiss(
        queries, embedder, faiss_index, corpus, batch_size, top_k, threshold, abstraction_processor
    )

    return results, queries


# ===== CLONE FILTERING FUNCTIONS =====

def cosine_similarity(embedding1, embedding2):
    """Calculate cosine similarity between two embeddings."""
    return np.dot(embedding1, embedding2) / (np.linalg.norm(embedding1) * np.linalg.norm(embedding2))


def filter_clones(results, vuln_to_fix, embedder, batch_size, logger, abstraction_processor=None, vuln_embeddings_cache=None, fix_embeddings_cache=None):
    """Process results and filter out clones with higher similarity to fix than to vuln."""
    
    filtered_results = {}
    total_vulns = 0
    total_clones = 0
    removed_clones = 0
    
    # Process each vulnerability
    for vuln_func, clones in results.items():
        total_vulns += 1
        total_clones += len(clones)
        
        # Initialize filtered clones for this vulnerability
        filtered_results[vuln_func] = {}
        
        # Find the fix for the vulnerable function
        if vuln_func in vuln_to_fix:
            fix_func = vuln_to_fix[vuln_func]
        else:
            # Try to find a match based on function signature
            found_match = False
            for v_func in vuln_to_fix:
                # Compare function signatures (first line typically contains the function signature)
                if vuln_func.split('\n')[0].strip() == v_func.split('\n')[0].strip():
                    fix_func = vuln_to_fix[v_func]
                    # logger.info(f"Found fix based on function signature match")
                    found_match = True
                    break
            
            if not found_match:
                # logger.warning(f"No fix found for vulnerable function. Keeping all clones.")
                filtered_results[vuln_func] = clones
                continue
        
        # Preprocess functions before embedding (including abstraction if enabled)
        preprocessed_vuln = preprocess_code(vuln_func, abstraction_processor)
        preprocessed_fix = preprocess_code(fix_func, abstraction_processor)
        
        # Get embeddings for the vulnerable and fixed functions (use cache if available)
        if vuln_embeddings_cache and preprocessed_vuln in vuln_embeddings_cache:
            vuln_embedding = vuln_embeddings_cache[preprocessed_vuln]
        else:
            vuln_embedding = embedder.encode(preprocessed_vuln, convert_to_numpy=True)
        
        if fix_embeddings_cache and preprocessed_fix in fix_embeddings_cache:
            fix_embedding = fix_embeddings_cache[preprocessed_fix]
        else:
            fix_embedding = embedder.encode(preprocessed_fix, convert_to_numpy=True)
        
        # Calculate similarity between vulnerable function and fix
        vuln_fix_similarity = cosine_similarity(vuln_embedding, fix_embedding)
        
        # Process clones in batches to avoid memory issues
        clone_list = list(clones.keys())
        for i in tqdm(range(0, len(clone_list), batch_size)):
            batch_clones = clone_list[i:i+batch_size]
            
            # Preprocess and encode all clones in the batch (including abstraction if enabled)
            preprocessed_batch = preprocess_code_batch(batch_clones, abstraction_processor)
            batch_embeddings = embedder.encode(preprocessed_batch, convert_to_numpy=True, batch_size=batch_size)
            
            # For each clone in the batch
            for j, clone in enumerate(batch_clones):
                clone_info = clones[clone]
                
                # Handle both old format (just similarity float) and new format (dict with similarity)
                if isinstance(clone_info, dict):
                    original_similarity = clone_info.get("similarity", clone_info)
                else:
                    original_similarity = clone_info
                
                # Calculate similarity between clone and vulnerable function using embeddings
                clone_vuln_similarity = cosine_similarity(batch_embeddings[j], vuln_embedding)
                
                # Calculate similarity between clone and fix
                clone_fix_similarity = cosine_similarity(batch_embeddings[j], fix_embedding)
                
                # Keep clone if: similarity(target, fix) < similarity(target, vuln) OR similarity(target, fix) < similarity(vuln, fix)
                if clone_fix_similarity < clone_vuln_similarity:
                    filtered_results[vuln_func][clone] = original_similarity
                else:
                    removed_clones += 1
                    logger.debug(f"Removing clone with target-vuln similarity {clone_vuln_similarity:.4f}, target-fix similarity {clone_fix_similarity:.4f}, vuln-fix similarity {vuln_fix_similarity:.4f}")
    
    logger.info(f"Filtering completed: Processed {total_vulns} vulnerabilities with {total_clones} clones total. Removed {removed_clones} clones.")
    return filtered_results


# ===== POST-PROCESSING FUNCTIONS =====

def add_path_and_cve_info(results, queries, function_to_cve, logger):
    """Add CVE and path information to results."""
    
    # Create a mapping of function body to path from queries
    function_to_path = {entry["function"]: entry["path"] for entry in queries}
    
    # Modify the results structure
    updated_results = {}
    for function, clones in results.items():
        updated_clones = {}
        for clone_function, similarity in clones.items():
            # Retrieve the CVE and path for the clone function
            cve = function_to_cve.get(function.strip(), None)
            path = function_to_path.get(clone_function, None)
            
            if path:
                updated_clones[clone_function] = {
                    "similarity": similarity,
                    "path": path,
                    "commit_url": cve
                }
        
        updated_results[function] = updated_clones
    
    return updated_results


# ===== EMBEDDING CACHE FUNCTIONS =====

def compute_and_cache_fix_embeddings(all_movery_data, embedder, cache_dir, batch_size, logger, abstraction_processor=None, cache_suffix=""):
    """
    Compute and cache embeddings for fix functions.
    Returns dictionaries mapping vulnerable functions to their embeddings and fix functions to their embeddings.
    """
    fix_cache_path = cache_dir / f"fix_embeddings{cache_suffix}.pkl"
    vuln_cache_path = cache_dir / f"vuln_embeddings{cache_suffix}.pkl"
    
    # Check if fix embeddings are cached
    if fix_cache_path.exists() and vuln_cache_path.exists():
        logger.info("Loading cached fix and vulnerable function embeddings...")
        with open(fix_cache_path, "rb") as f:
            fix_embeddings_cache = pickle.load(f)
        with open(vuln_cache_path, "rb") as f:
            vuln_embeddings_cache = pickle.load(f)
        logger.info(f"Loaded cached embeddings for {len(fix_embeddings_cache)} fix functions and {len(vuln_embeddings_cache)} vulnerable functions.")
        return vuln_embeddings_cache, fix_embeddings_cache
    
    logger.info("Computing fix and vulnerable function embeddings...")
    
    # Collect unique vulnerable and fix functions
    vuln_functions = set()
    fix_functions = set()
    
    for entry in all_movery_data:
        vuln_func = entry.get("function", entry.get("vuln_func", entry.get("func")))
        fix_func = entry.get("fix_func")
        
        if vuln_func and fix_func:
            vuln_functions.add(vuln_func)
            fix_functions.add(fix_func)
    
    logger.info(f"Found {len(vuln_functions)} unique vulnerable functions and {len(fix_functions)} unique fix functions.")
    
    # Preprocess functions before embedding (including abstraction if enabled)
    vuln_functions_list = list(vuln_functions)
    preprocessed_vuln_functions = preprocess_code_batch(vuln_functions_list, abstraction_processor)
    
    fix_functions_list = list(fix_functions)
    preprocessed_fix_functions = preprocess_code_batch(fix_functions_list, abstraction_processor)
    
    # Compute embeddings for vulnerable functions
    vuln_embeddings = embedder.encode(
        preprocessed_vuln_functions, 
        convert_to_numpy=True, 
        batch_size=batch_size, 
        show_progress_bar=True
    )
    
    # Create mapping from preprocessed function to embedding
    vuln_embeddings_cache = {
        preprocess_code(func, abstraction_processor): embedding for func, embedding in zip(vuln_functions_list, vuln_embeddings)
    }
    
    # Compute embeddings for fix functions
    fix_embeddings = embedder.encode(
        preprocessed_fix_functions, 
        convert_to_numpy=True, 
        batch_size=batch_size, 
        show_progress_bar=True
    )
    
    # Create mapping from preprocessed function to embedding
    fix_embeddings_cache = {
        preprocess_code(func, abstraction_processor): embedding for func, embedding in zip(fix_functions_list, fix_embeddings)
    }
    
    # Cache the embeddings
    logger.info("Caching fix and vulnerable function embeddings...")
    with open(fix_cache_path, "wb") as f:
        pickle.dump(fix_embeddings_cache, f)
    with open(vuln_cache_path, "wb") as f:
        pickle.dump(vuln_embeddings_cache, f)
    
    logger.info("Fix and vulnerable function embeddings cached successfully.")
    return vuln_embeddings_cache, fix_embeddings_cache


# ===== MAIN PROCESSING FUNCTION =====

def process_single_repository(repo_path, embedder, faiss_index, corpus, all_movery_data, function_to_cve, 
                             vuln_to_fix, batch_size, top_k, threshold, enable_filtering, logger,
                             abstraction_processor=None, vuln_embeddings_cache=None, fix_embeddings_cache=None):
    """
    Process a single repository through the entire pipeline.
    """
    repo_name = repo_path.stem
    logger.info(f"Processing repository: {repo_name}")
    
    # Phase 1: Clone Detection
    results, queries = process_repository_detection(
        repo_path, embedder, faiss_index, corpus, batch_size, top_k, threshold, abstraction_processor
    )
    
    if not results:
        logger.warning(f"No results found for {repo_name}. Skipping.")
        return None
    
    logger.info(f"Found {len(results)} vulnerable functions with clones")
    
    # Phase 2: Clone Filtering (optional)
    if enable_filtering:
        logger.info("Applying clone filtering...")
        results = filter_clones(results, vuln_to_fix, embedder, batch_size, logger, abstraction_processor,
                              vuln_embeddings_cache, fix_embeddings_cache)
    else:
        logger.info("Skipping clone filtering.")
    
    # Phase 3: Post-processing - Add path and CVE info
    logger.info("Adding path and CVE information...")
    final_results = add_path_and_cve_info(results, queries, function_to_cve, logger)
    
    return {"results": final_results}


def run_clone_detection_pipeline(all_json_path, funcs_dir, clones_dir, batch_size, top_k, threshold, enable_filtering, use_abstraction, logger):
    """
    Main function to run the entire clone detection pipeline.
    """
    accelerator = Accelerator()

    # Initialize abstraction processor
    abstraction_processor = AbstractionProcessor(use_abstraction=use_abstraction)
    
    # Define cache path (different for abstracted vs non-abstracted)
    cache_dir = Path(clones_dir) / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    
    cache_suffix = "_abstracted" if use_abstraction else "_original"
    cache_path = cache_dir / f"corpus_embeddings{cache_suffix}.pkl"

    # Load the source corpus (now with preprocessing and optional abstraction)
    logger.info("Loading and preprocessing corpus from all.json...")
    if use_abstraction:
        logger.info("MOVERY abstraction is ENABLED")
    else:
        logger.info("MOVERY abstraction is DISABLED")
        
    corpus = load_corpus(all_json_path, abstraction_processor)
    logger.info(f"Loaded and preprocessed corpus with {len(corpus)} functions.")

    # Load embedding model with error handling
    logger.info("Loading embedding model...")
    embedder = load_embedding_model_safely(logger=logger)
    embedder.to(accelerator.device)

    # Check if embeddings are cached
    if cache_path.exists():
        logger.info("Loading cached corpus embeddings...")
        with open(cache_path, "rb") as f:
            corpus_embeddings = pickle.load(f)
        logger.info(f"Loaded cached embeddings for {len(corpus_embeddings)} functions.")
    else:
        # Compute corpus embeddings (corpus is already preprocessed)
        logger.info("Computing corpus embeddings...")
        corpus_embeddings = embedder.encode(
            corpus, convert_to_numpy=True, batch_size=batch_size, show_progress_bar=True
        )
        logger.info("Saving corpus embeddings to cache...")
        with open(cache_path, "wb") as f:
            pickle.dump(corpus_embeddings, f)
        logger.info("Corpus embeddings cached successfully.")
    
    logger.info("Building Faiss index...")
    faiss_index = build_faiss_index(corpus_embeddings)

    # Load data for post-processing
    logger.info("Loading data for post-processing...")
    with open(all_json_path, "r", encoding="utf-8") as file:
        all_movery_data = [json.loads(line) for line in file]

    # Create mappings
    function_to_cve = {}
    vuln_to_fix = {}
    for entry in all_movery_data:
        function_body = preprocess_code(entry.get('function', entry.get('vuln_func', entry.get('func'))).strip(), abstraction_processor)
        cve = entry["commit_url"]
        function_to_cve[function_body] = cve
        
        # For filtering
        if enable_filtering:
            vuln_func = entry.get("function", entry.get("vuln_func", entry.get("func")))
            fix_func = entry.get("fix_func")
            if vuln_func and fix_func:
                vuln_to_fix[vuln_func] = fix_func

    logger.info(f"Loaded {len(function_to_cve)} CVE mappings.")
    if enable_filtering:
        logger.info(f"Loaded {len(vuln_to_fix)} vulnerable-fix function pairs.")

    # Compute and cache fix function embeddings if filtering is enabled
    vuln_embeddings_cache = None
    fix_embeddings_cache = None
    if enable_filtering:
        vuln_embeddings_cache, fix_embeddings_cache = compute_and_cache_fix_embeddings(
            all_movery_data, embedder, cache_dir, batch_size, logger, abstraction_processor, cache_suffix
        )

    # Find all function JSON files in the directory
    funcs_dir = Path(funcs_dir)
    clones_dir = Path(clones_dir)
    function_files = list(funcs_dir.rglob("*.json"))
    logger.info(f"Found {len(function_files)} function JSON files.")

    # Filter out already processed files
    remaining_files = []
    for repo_path in function_files:
        relative_path = repo_path.relative_to(funcs_dir)
        output_path = clones_dir / f"{relative_path.stem}_final{cache_suffix}.json"
        if not output_path.exists():
            remaining_files.append(repo_path)

    logger.info(f"{len(remaining_files)} files remaining to process.")

    # Distribute processing across GPUs
    with accelerator.split_between_processes(remaining_files) as split_files:
        total_files = len(split_files)
        processed_files = 0

        for repo_path in split_files:
            processed_files += 1
            relative_path = repo_path.relative_to(funcs_dir)
            output_path = clones_dir / f"{relative_path.stem}_final{cache_suffix}.json"

            logger.info(f"Processing file {processed_files}/{total_files}: {repo_path}")

            final_results = process_single_repository(
                repo_path, embedder, faiss_index, corpus, all_movery_data, 
                function_to_cve, vuln_to_fix, batch_size, top_k, threshold, 
                enable_filtering, logger, abstraction_processor, vuln_embeddings_cache, fix_embeddings_cache
            )
            
            if final_results:
                # Save final results
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Add metadata about abstraction
                final_results["metadata"] = {
                    "abstraction_enabled": use_abstraction,
                    "threshold": threshold,
                    "top_k": top_k,
                    "filtering_enabled": enable_filtering
                }
                
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(final_results, f, indent=4)
                
                num_results = len(final_results["results"])
                logger.info(f"Saved {num_results} final results to {output_path}. ({processed_files}/{total_files} files processed)")
            else:
                logger.info(f"No results to save for {repo_path}. ({processed_files}/{total_files} files processed)")

    logger.info("Clone detection pipeline completed.")


# ===== MAIN FUNCTION =====

def main():
    parser = argparse.ArgumentParser(description="Enhanced Clone Detection Pipeline with MOVERY Abstraction")
    
    # Input/output arguments
    parser.add_argument("--all_json_path", type=str, 
                       default="/raid/data/yindusu/titan_code_clone/tosem_vulclonebench/funcs/vuln.jsonl", 
                       help="Path to the all.json file.")
    parser.add_argument("--funcs_dir", type=str, 
                       default="/raid/data/yindusu/titan_code_clone/tosem_vulclonebench/funcs", 
                       help="Path to the directory with function JSON files.")
    parser.add_argument("--clones_dir", type=str, 
                       default="/raid/data/yindusu/titan_code_clone/tosem_vulclonebench/results/jina_abst_", 
                       help="Path to the output directory for clone results.")
    
    # Processing arguments
    parser.add_argument("--batch_size", type=int, default=4, 
                       help="Batch size for processing queries.")
    parser.add_argument("--top_k", type=int, default=1, 
                       help="Number of top matches to retrieve.")
    parser.add_argument("--threshold", type=float, default=0.5, 
                       help="Similarity threshold for clone detection.")
    
    # Pipeline control arguments
    parser.add_argument("--disable_filtering", action="store_true", 
                       help="Disable clone filtering based on fix similarity")
    
    # MOVERY abstraction control
    parser.add_argument("--use_abstraction", action="store_true", default=True,
                       help="Enable MOVERY abstraction (default: True)")
    parser.add_argument("--no_abstraction", action="store_true",
                       help="Disable MOVERY abstraction (use original code with basic preprocessing)")
    
    # Logging
    parser.add_argument("--log_file", type=str, 
                       default=None,
                       help="Path to save the log file")

    args = parser.parse_args()

    # Handle abstraction flag
    use_abstraction = args.use_abstraction and not args.no_abstraction
    
    # Check if MOVERY SignatureGenerator is available
    if use_abstraction and SignatureGenerator is None:
        print("[ERROR] MOVERY abstraction requested but SignatureGenerator not available.")
        print("Please ensure the MOVERY signature generator script is available.")
        print("Falling back to basic preprocessing without abstraction.")
        use_abstraction = False

    # Setup logging
    abstraction_suffix = "_abstracted" if use_abstraction else "_original"
    log_file = args.log_file or os.path.join(args.clones_dir, f"clone_detection_pipeline{abstraction_suffix}.log")
    logger = setup_logger(log_file)

    enable_filtering = not args.disable_filtering

    logger.info("Starting enhanced clone detection pipeline...")
    logger.info(f"Arguments: {vars(args)}")
    logger.info(f"MOVERY abstraction: {'ENABLED' if use_abstraction else 'DISABLED'}")
    logger.info(f"Clone filtering: {'ENABLED' if enable_filtering else 'DISABLED'}")

    try:
        run_clone_detection_pipeline(
            args.all_json_path,
            args.funcs_dir,
            args.clones_dir,
            args.batch_size,
            args.top_k,
            args.threshold,
            enable_filtering,
            use_abstraction,
            logger
        )

        logger.info("=" * 50)
        logger.info("Enhanced pipeline completed successfully!")
        logger.info("=" * 50)

    except Exception as e:
        logger.error(f"Pipeline failed with error: {str(e)}")
        raise


if __name__ == "__main__":
    main()