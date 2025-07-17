#!/usr/bin/env python3
"""
MOVERY Vulnerable Code Clone Detector
Detects vulnerable code clones using MOVERY signatures based on the three conditions:
1. Contains all vulnerability signature lines (Sv)
2. Does not contain patch signature lines (Sp) 
3. Has sufficient syntax similarity to original vulnerable functions

Uses proper Jaccard similarity calculation with complete preprocessed function line sets.
Supports parallel processing with streaming results for real-time feedback.

Modified to read functions from JSON file with "func" and "path" attributes.
"""

import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict
import re
import tempfile
import subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count, Lock
import time
import threading
from datetime import datetime

# Import from your signature generator script for preprocessing
try:
    from movery_signature_generator import SignatureGenerator
except ImportError:
    try:
        from signature_generator import SignatureGenerator  
    except ImportError:
        print("[ERROR] Could not import SignatureGenerator for preprocessing.")
        print("Please ensure the updated signature generator script is available.")
        sys.exit(1)


class ProgressTracker:
    """Thread-safe progress tracking with detailed statistics"""
    
    def __init__(self, total_signatures: int, total_functions: int):
        self.total_signatures = total_signatures
        self.total_functions = total_functions
        self.total_comparisons = total_signatures * total_functions
        self.lock = threading.Lock()
        self.completed_comparisons = 0
        self.completed_signatures = 0
        self.clones_found = 0
        self.start_time = time.time()
        self.last_update = time.time()
        
    def update_progress(self, comparisons_done: int = 0, signatures_done: int = 0, clones_found: int = 0):
        """Update progress counters"""
        with self.lock:
            self.completed_comparisons += comparisons_done
            self.completed_signatures += signatures_done
            self.clones_found += clones_found
            
            current_time = time.time()
            # Print progress every 10 seconds or when significant progress is made
            if current_time - self.last_update >= 10 or signatures_done > 0:
                self._print_progress()
                self.last_update = current_time
    
    def _print_progress(self):
        """Print current progress (called with lock held)"""
        elapsed = time.time() - self.start_time
        
        # Calculate percentages
        sig_progress = (self.completed_signatures / self.total_signatures) * 100 if self.total_signatures > 0 else 0
        comp_progress = (self.completed_comparisons / self.total_comparisons) * 100 if self.total_comparisons > 0 else 0
        
        # Calculate rates
        sig_rate = self.completed_signatures / elapsed if elapsed > 0 else 0
        comp_rate = self.completed_comparisons / elapsed if elapsed > 0 else 0
        
        # Estimate time remaining
        if sig_rate > 0:
            remaining_signatures = self.total_signatures - self.completed_signatures
            eta_seconds = remaining_signatures / sig_rate
            eta_str = f"{eta_seconds/60:.1f}m" if eta_seconds > 60 else f"{eta_seconds:.0f}s"
        else:
            eta_str = "unknown"
        
        print(f"[PROGRESS] Signatures: {self.completed_signatures}/{self.total_signatures} ({sig_progress:.1f}%) | "
              f"Comparisons: {self.completed_comparisons:,}/{self.total_comparisons:,} ({comp_progress:.1f}%) | "
              f"Clones: {self.clones_found} | "
              f"Rate: {sig_rate:.1f} sig/s, {comp_rate:.0f} comp/s | "
              f"ETA: {eta_str}")
    
    def print_final_summary(self):
        """Print final progress summary"""
        with self.lock:
            elapsed = time.time() - self.start_time
            print(f"\n[FINAL] Completed {self.completed_signatures}/{self.total_signatures} signatures")
            print(f"[FINAL] Performed {self.completed_comparisons:,} comparisons in {elapsed:.1f}s")
            print(f"[FINAL] Found {self.clones_found} vulnerable clones")
            if elapsed > 0:
                print(f"[FINAL] Average rate: {self.completed_comparisons/elapsed:.0f} comparisons/second")


class StreamingResultWriter:
    """Thread-safe streaming result writer"""
    
    def __init__(self, output_file: str):
        self.output_file = output_file
        self.lock = threading.Lock()
        self.total_written = 0
        
        # Create/truncate the output file
        with open(output_file, 'w', encoding='utf-8') as f:
            pass  # Just create empty file
    
    def write_result(self, result: Dict):
        """Write a single result to the output file"""
        with self.lock:
            try:
                with open(self.output_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(result) + '\n')
                    f.flush()  # Ensure immediate write
                self.total_written += 1
            except Exception as e:
                print(f"[ERROR] Failed to write result: {e}")
    
    def get_total_written(self) -> int:
        """Get total number of results written"""
        with self.lock:
            return self.total_written


class VulnerableCloneDetector:
    """
    MOVERY Vulnerable Code Clone Detector
    Implements the three-condition detection methodology from the paper
    """
    
    def __init__(self, similarity_threshold: float = 0.5, parallel_workers: int = None, 
                 result_writer: StreamingResultWriter = None, progress_tracker: ProgressTracker = None):
        """
        Initialize the clone detector
        
        Args:
            similarity_threshold: Jaccard similarity threshold (θ) for Condition 3
            parallel_workers: Number of parallel workers (default: CPU count)
            result_writer: Streaming result writer for immediate output
            progress_tracker: Progress tracker for real-time updates
        """
        self.similarity_threshold = similarity_threshold
        self.parallel_workers = parallel_workers or cpu_count()
        self.signature_generator = SignatureGenerator()
        self.result_writer = result_writer
        self.progress_tracker = progress_tracker
        self.stats = {
            'total_signatures': 0,
            'total_functions_scanned': 0,
            'total_clones_found': 0,
            'condition_stats': {
                'cond1_passed': 0,
                'cond2_passed': 0, 
                'cond3_passed': 0,
                'all_conditions_passed': 0
            },
            'processing_time': 0.0
        }
    
    def load_signatures(self, signatures_file: str) -> List[Dict]:
        """Load vulnerability signatures from JSONL file"""
        signatures = []
        
        try:
            with open(signatures_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line:
                        try:
                            record = json.loads(line)
                            # Only process successful signature generations
                            if record.get('processing_status') == 'success':
                                signatures.append(record)
                            elif record.get('processing_status') == 'failed':
                                print(f"[INFO] Skipping failed signature on line {line_num}")
                        except json.JSONDecodeError as e:
                            print(f"[WARNING] Invalid JSON on line {line_num}: {e}")
                            continue
                            
            print(f"[INFO] Loaded {len(signatures)} successful signatures")
            self.stats['total_signatures'] = len(signatures)
            return signatures
            
        except FileNotFoundError:
            print(f"[ERROR] Signatures file not found: {signatures_file}")
            raise
        except Exception as e:
            print(f"[ERROR] Failed to load signatures: {e}")
            raise
    
    def load_target_functions(self, functions_json_file: str) -> List[Tuple[str, str]]:
        """
        Load target functions from JSON file
        Expected format: [{"func": "function_code", "path": "file_path"}, ...]
        Returns list of (path, function_code) tuples
        """
        functions = []
        
        try:
            with open(functions_json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                raise ValueError("JSON file must contain an array of function objects")
            
            print(f"[INFO] Loading {len(data)} functions from {functions_json_file}")
            
            for i, func_obj in enumerate(data):
                if not isinstance(func_obj, dict):
                    print(f"[WARNING] Skipping non-object item at index {i}")
                    continue
                
                if 'function' not in func_obj or 'path' not in func_obj:
                    print(f"[WARNING] Skipping item at index {i}: missing 'function' or 'path' attribute")
                    continue
                
                func_code = func_obj['function']
                path = func_obj['path']
                
                if not isinstance(func_code, str) or not isinstance(path, str):
                    print(f"[WARNING] Skipping item at index {i}: 'function' and 'path' must be strings")
                    continue
                
                if func_code.strip():  # Skip empty functions
                    functions.append((path, func_code))
                else:
                    print(f"[WARNING] Skipping empty function at path: {path}")
            
            print(f"[INFO] Successfully loaded {len(functions)} valid functions")
            self.stats['total_functions_scanned'] = len(functions)
            return functions
            
        except FileNotFoundError:
            print(f"[ERROR] Functions JSON file not found: {functions_json_file}")
            raise
        except json.JSONDecodeError as e:
            print(f"[ERROR] Invalid JSON in functions file: {e}")
            raise
        except Exception as e:
            print(f"[ERROR] Failed to load functions: {e}")
            raise
    
    def preprocess_function(self, function_code: str) -> Tuple[Set[str], Set[str]]:
        """
        Preprocess function code to extract normalized and abstracted line sets separately
        Returns (normalized_lines, abstracted_lines)
        """
        try:
            # Use the same preprocessing as signature generation
            complete_lines = self.signature_generator.get_complete_function_lines(function_code)
            
            # Keep normalized and abstracted lines separate
            normalized_lines = set(complete_lines.get('normalized', []))
            abstracted_lines = set(complete_lines.get('abstracted', []))
            
            return normalized_lines, abstracted_lines
            
        except Exception as e:
            print(f"[ERROR] Preprocessing failed: {e}")
            return set(), set()
    
    def extract_signature_lines(self, signature: Dict) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
        """
        Extract line sets from vulnerability and patch signatures
        Returns (sv_norm_lines, sv_abst_lines, sp_norm_lines, sp_abst_lines)
        """
        sv_norm_lines = set()  # Vulnerability signature normalized lines
        sv_abst_lines = set()  # Vulnerability signature abstracted lines
        sp_norm_lines = set()  # Patch signature normalized lines
        sp_abst_lines = set()  # Patch signature abstracted lines
        
        # Extract vulnerability signature lines (Ev, Dv, Fv)
        vuln_sig = signature.get('vulnerability_signature', {})
        for component in ['Ev', 'Dv', 'Fv']:
            lines = vuln_sig.get(component, [])
            for line_obj in lines:
                if isinstance(line_obj, dict):
                    if 'norm' in line_obj:
                        sv_norm_lines.add(line_obj['norm'])
                    if 'abst' in line_obj:
                        sv_abst_lines.add(line_obj['abst'])
        
        # Extract patch signature lines (Ep, Dp)
        patch_sig = signature.get('patch_signature', {})
        for component in ['Ep']:
            lines = patch_sig.get(component, [])
            for line_obj in lines:
                if isinstance(line_obj, dict):
                    if 'norm' in line_obj:
                        sp_norm_lines.add(line_obj['norm'])
                    if 'abst' in line_obj:
                        sp_abst_lines.add(line_obj['abst'])
        
        return sv_norm_lines, sv_abst_lines, sp_norm_lines, sp_abst_lines
    
    def get_reference_function_lines(self, signature: Dict) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
        """
        Extract complete preprocessed line sets for fo and fd from signature
        Returns (fo_norm_lines, fo_abst_lines, fd_norm_lines, fd_abst_lines) for Jaccard similarity calculation
        """
        # Get preprocessed functions from either vulnerability or patch signature
        vuln_sig = signature.get('vulnerability_signature', {})
        patch_sig = signature.get('patch_signature', {})
        
        # Try vulnerability signature first
        preprocessed = vuln_sig.get('preprocessed_functions', {})
        if not preprocessed:
            # Fallback to patch signature
            preprocessed = patch_sig.get('preprocessed_functions', {})
        
        fo_norm_lines = set()
        fo_abst_lines = set()
        fd_norm_lines = set()
        fd_abst_lines = set()
        
        if preprocessed:
            # Get fo lines (oldest function)
            fo_data = preprocessed.get('fo_lines', {})
            if fo_data:
                fo_norm_lines.update(fo_data.get('normalized', []))
                fo_abst_lines.update(fo_data.get('abstracted', []))
            
            # Get fd lines (disclosed vulnerable function)
            fd_data = preprocessed.get('fd_lines', {})
            if fd_data:
                fd_norm_lines.update(fd_data.get('normalized', []))
                fd_abst_lines.update(fd_data.get('abstracted', []))
        
        return fo_norm_lines, fo_abst_lines, fd_norm_lines, fd_abst_lines
    
    def jaccard_similarity(self, set1: Set[str], set2: Set[str]) -> float:
        """Calculate Jaccard similarity between two sets"""
        if not set1 and not set2:
            return 1.0
        if not set1 or not set2:
            return 0.0
        
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union if union > 0 else 0.0
    
    def check_condition1(self, function_lines: Set[str], sv_lines: Set[str]) -> bool:
        """
        Condition 1: Function should contain ALL code lines in Sv
        ∀l∈Sv .(l ∈ f)
        """
        if not sv_lines:  # If no vulnerability lines, condition is satisfied
            return True
        
        return sv_lines.issubset(function_lines)
    
    def check_condition2(self, function_lines: Set[str], sp_lines: Set[str]) -> bool:
        """
        Condition 2: Function should NOT contain ANY code lines in Sp
        ∀l∈Sp .(l ∉ f)
        """
        if not sp_lines:  # If no patch lines, condition is satisfied
            return True
        
        return sp_lines.isdisjoint(function_lines)
    
    def check_condition3(self, target_norm_lines: Set[str], target_abst_lines: Set[str], 
                        fo_norm_lines: Set[str], fo_abst_lines: Set[str], 
                        fd_norm_lines: Set[str], fd_abst_lines: Set[str]) -> Tuple[bool, float]:
        """
        Condition 3: Syntax similarity should be ≥ threshold
        (Sim(f, fo) ≥ θ) ∨ (Sim(f, fd) ≥ θ)
        
        Uses proper Jaccard similarity with abstracted lines for generalization:
        |f_abst ∩ fo_abst| / |f_abst ∪ fo_abst| and |f_abst ∩ fd_abst| / |f_abst ∪ fd_abst|
        """
        # Calculate Jaccard similarity with fo (oldest function) using abstracted lines
        sim_fo = 0.0
        if fo_abst_lines:
            sim_fo = self.jaccard_similarity(target_abst_lines, fo_abst_lines)
        
        # Calculate Jaccard similarity with fd (disclosed vulnerable function) using abstracted lines
        sim_fd = 0.0
        if fd_abst_lines:
            sim_fd = self.jaccard_similarity(target_abst_lines, fd_abst_lines)
        
        # Check if either similarity meets threshold
        max_similarity = max(sim_fo, sim_fd)
        condition_passed = max_similarity >= self.similarity_threshold
        
        return condition_passed, max_similarity
    
    def detect_clones_for_signature(self, signature: Dict, target_functions: List[Tuple[str, str]]) -> int:
        """
        Detect vulnerable clones for a single signature across all target functions
        Returns number of clones found (writes results immediately if result_writer provided)
        """
        clones_found = 0
        sv_norm_lines, sv_abst_lines, sp_norm_lines, sp_abst_lines = self.extract_signature_lines(signature)
        fo_norm_lines, fo_abst_lines, fd_norm_lines, fd_abst_lines = self.get_reference_function_lines(signature)
        
        # Remove vulnerability lines from patch lines to avoid conflicts
        sp_norm_lines = sp_norm_lines - sv_norm_lines
        sp_abst_lines = sp_abst_lines - sv_abst_lines
        
        metadata = signature.get('metadata', {})
        cve = metadata.get('cve', 'Unknown')
        project = metadata.get('project', 'Unknown')
        
        print(f"[INFO] Checking signature for {project} - {cve}")
        print(f"  Vulnerability lines: norm={len(sv_norm_lines)}, abst={len(sv_abst_lines)}")
        print(f"  Patch lines: norm={len(sp_norm_lines)}, abst={len(sp_abst_lines)}")
        print(f"  Reference lines: fo_abst={len(fo_abst_lines)}, fd_abst={len(fd_abst_lines)}")
        
        # Special cases as mentioned in the paper
        use_only_vuln_sig = len(sp_abst_lines) == 0  # No patch lines added
        use_only_patch_sig = len(sv_abst_lines) == 0  # No vulnerability lines deleted
        
        if use_only_vuln_sig:
            print(f"  [SPECIAL] Using only vulnerability signature (no patch lines)")
        elif use_only_patch_sig:
            print(f"  [SPECIAL] Using only patch signature (no vuln lines)")
        
        functions_processed = 0
        for function_path, function_code in target_functions:
            functions_processed += 1
            
            # Update progress
            if self.progress_tracker:
                self.progress_tracker.update_progress(comparisons_done=1)
            
            # Preprocess the target function
            target_norm_lines, target_abst_lines = self.preprocess_function(function_code)
            
            if not target_abst_lines:  # Need abstracted lines for matching
                continue
            
            # Check conditions using ABSTRACTED lines for generalization
            cond1_passed = False
            cond2_passed = False  
            cond3_passed = False
            similarity_score = 0.0
            
            if not use_only_patch_sig:
                # Condition 1: Match abstracted signature lines with abstracted target lines
                cond1_passed = self.check_condition1(target_abst_lines, sv_abst_lines)
                self.stats['condition_stats']['cond1_passed'] += int(cond1_passed)
            else:
                cond1_passed = True  # Skip condition 1 if using only patch signature
            
            if not use_only_vuln_sig:
                # Condition 2: Match abstracted signature lines with abstracted target lines
                cond2_passed = self.check_condition2(target_abst_lines, sp_abst_lines)
                self.stats['condition_stats']['cond2_passed'] += int(cond2_passed)
            else:
                cond2_passed = True  # Skip condition 2 if using only vulnerability signature
            
            # Condition 3: Use abstracted lines for similarity calculation
            cond3_passed, similarity_score = self.check_condition3(
                target_norm_lines, target_abst_lines, 
                fo_norm_lines, fo_abst_lines, 
                fd_norm_lines, fd_abst_lines
            )
            self.stats['condition_stats']['cond3_passed'] += int(cond3_passed)
            
            # Determine if this is a vulnerable clone
            is_vulnerable_clone = False
            
            if use_only_vuln_sig:
                # Only conditions 1 and 3
                is_vulnerable_clone = cond1_passed and cond3_passed
            elif use_only_patch_sig:
                # Only conditions 2 and 3  
                is_vulnerable_clone = cond2_passed and cond3_passed
            else:
                # All three conditions
                is_vulnerable_clone = cond1_passed and cond2_passed and cond3_passed
            
            if is_vulnerable_clone:
                self.stats['condition_stats']['all_conditions_passed'] += 1
                clones_found += 1
                
                clone_info = {
                    'function_path': function_path,
                    'function_code': function_code,  # Include the actual function code
                    'signature_metadata': metadata,
                    'conditions': {
                        'condition1_passed': cond1_passed,
                        'condition2_passed': cond2_passed,
                        'condition3_passed': cond3_passed,
                        'similarity_score': similarity_score
                    },
                    'signature_stats': signature.get('signature_stats', {}),
                    'special_mode': {
                        'use_only_vuln_sig': use_only_vuln_sig,
                        'use_only_patch_sig': use_only_patch_sig
                    },
                    'line_matches': {
                        'sv_abst_lines_matched': len(sv_abst_lines & target_abst_lines) if sv_abst_lines else 0,
                        'sp_abst_lines_found': len(sp_abst_lines & target_abst_lines) if sp_abst_lines else 0,
                        'total_target_abst_lines': len(target_abst_lines),
                        'total_sv_abst_lines': len(sv_abst_lines),
                        'total_sp_abst_lines': len(sp_abst_lines)
                    },
                    'detection_timestamp': time.time()
                }
                
                # Write result immediately if writer is available
                if self.result_writer:
                    self.result_writer.write_result(clone_info)
                
                # Update progress tracker
                if self.progress_tracker:
                    self.progress_tracker.update_progress(clones_found=1)
                
                print(f"  [CLONE FOUND] {Path(function_path).name} - Similarity: {similarity_score:.3f}")
        
        # Update progress tracker for completed signature
        if self.progress_tracker:
            self.progress_tracker.update_progress(signatures_done=1)
        
        return clones_found


def detect_signature_batch(args: Tuple[List[Dict], List[Tuple[str, str]], float, str, int, int]) -> Tuple[int, str]:
    """
    Process a batch of signatures in parallel with streaming results
    This function will be called by worker processes
    """
    signatures_batch, target_functions, similarity_threshold, output_file, total_signatures, total_functions = args
    
    # Create a new detector instance and result writer for this worker
    worker_output_file = f"{output_file}.worker_{os.getpid()}"
    result_writer = StreamingResultWriter(worker_output_file)
    
    # Create progress tracker for this worker
    progress_tracker = ProgressTracker(len(signatures_batch), len(target_functions))
    
    detector = VulnerableCloneDetector(
        similarity_threshold, 
        result_writer=result_writer,
        progress_tracker=progress_tracker
    )
    
    total_clones = 0
    for i, signature in enumerate(signatures_batch):
        print(f"[WORKER {os.getpid()}] Processing signature {i+1}/{len(signatures_batch)}")
        clones = detector.detect_clones_for_signature(signature, target_functions)
        total_clones += clones
    
    progress_tracker.print_final_summary()
    return total_clones, worker_output_file


class ParallelVulnerableCloneDetector(VulnerableCloneDetector):
    """
    Parallel version of the VulnerableCloneDetector with streaming results
    """
    
    def detect_all_clones_parallel(self, signatures: List[Dict], target_functions: List[Tuple[str, str]], output_file: str) -> int:
        """Detect vulnerable clones for all signatures using parallel processing with streaming results"""
        start_time = time.time()
        
        print(f"\n[INFO] Starting parallel clone detection for {len(signatures)} signatures...")
        print(f"[INFO] Using {self.parallel_workers} parallel workers")
        print(f"[INFO] Results will be written to {output_file} in real-time")
        print(f"[INFO] Total comparisons to perform: {len(signatures) * len(target_functions):,}")
        
        # Initialize global progress tracker
        global_progress = ProgressTracker(len(signatures), len(target_functions))
        
        # Split signatures into batches for parallel processing
        batch_size = max(1, len(signatures) // self.parallel_workers)
        signature_batches = [
            signatures[i:i + batch_size] 
            for i in range(0, len(signatures), batch_size)
        ]
        
        print(f"[INFO] Split into {len(signature_batches)} batches (batch size: {batch_size})")
        
        total_clones = 0
        worker_files = []
        
        # Process batches in parallel
        with ProcessPoolExecutor(max_workers=self.parallel_workers) as executor:
            # Submit all batches
            future_to_batch = {
                executor.submit(
                    detect_signature_batch, 
                    (batch, target_functions, self.similarity_threshold, output_file, len(signatures), len(target_functions))
                ): i 
                for i, batch in enumerate(signature_batches)
            }
            
            # Collect results as they complete
            completed_batches = 0
            for future in as_completed(future_to_batch):
                batch_idx = future_to_batch[future]
                try:
                    batch_clones, worker_file = future.result()
                    total_clones += batch_clones
                    worker_files.append(worker_file)
                    completed_batches += 1
                    
                    print(f"[INFO] Completed batch {completed_batches}/{len(signature_batches)} "
                          f"(batch {batch_idx + 1}) - Found {batch_clones} clones")
                    
                except Exception as e:
                    print(f"[ERROR] Batch {batch_idx + 1} failed: {e}")
        
        # Merge worker files into final output
        print(f"[INFO] Merging results from {len(worker_files)} worker files...")
        self._merge_worker_files(worker_files, output_file)
        
        end_time = time.time()
        self.stats['processing_time'] = end_time - start_time
        self.stats['total_clones_found'] = total_clones
        
        print(f"\n[INFO] Parallel processing completed in {self.stats['processing_time']:.2f} seconds")
        return total_clones
    
    def _merge_worker_files(self, worker_files: List[str], final_output: str):
        """Merge worker output files into final result file"""
        try:
            total_merged = 0
            with open(final_output, 'w', encoding='utf-8') as outfile:
                for i, worker_file in enumerate(worker_files):
                    if os.path.exists(worker_file):
                        file_lines = 0
                        with open(worker_file, 'r', encoding='utf-8') as infile:
                            for line in infile:
                                outfile.write(line)
                                file_lines += 1
                        total_merged += file_lines
                        print(f"[INFO] Merged {file_lines} results from worker file {i+1}")
                        # Clean up worker file
                        os.remove(worker_file)
            
            print(f"[INFO] Successfully merged {total_merged} total results to {final_output}")
                        
        except Exception as e:
            print(f"[ERROR] Failed to merge worker files: {e}")
            # If merge fails, at least preserve worker files
            print(f"[INFO] Worker files preserved: {worker_files}")
    
    def print_summary(self):
        """Print detection summary statistics"""
        print("\n" + "=" * 60)
        print("VULNERABLE CODE CLONE DETECTION SUMMARY")
        print("=" * 60)
        
        print(f"Signatures processed: {self.stats['total_signatures']}")
        print(f"Target functions scanned: {self.stats['total_functions_scanned']}")
        print(f"Vulnerable clones found: {self.stats['total_clones_found']}")
        print(f"Processing time: {self.stats['processing_time']:.2f} seconds")
        print(f"Parallel workers used: {self.parallel_workers}")
        
        if self.stats['total_functions_scanned'] > 0:
            clone_rate = self.stats['total_clones_found'] / self.stats['total_functions_scanned'] * 100
            print(f"Clone detection rate: {clone_rate:.2f}%")
        
        if self.stats['processing_time'] > 0:
            throughput = self.stats['total_functions_scanned'] * self.stats['total_signatures'] / self.stats['processing_time']
            print(f"Throughput: {throughput:.0f} function-signature comparisons per second")


def main():
    """Main entry point"""
    if len(sys.argv) < 4:
        print("MOVERY Vulnerable Code Clone Detector")
        print("=" * 40)
        print("\nUsage:")
        print("  python detect_clones.py <signatures.jsonl> <functions.json> <output.jsonl> [threshold] [workers]")
        print("\nArguments:")
        print("  signatures.jsonl : JSONL file with MOVERY signatures")
        print("  functions.json   : JSON file with array of {\"func\": \"code\", \"path\": \"path\"} objects")
        print("  output.jsonl     : Output file for clone detection results")
        print("  threshold        : Optional similarity threshold (default: 0.5)")
        print("  workers          : Optional number of parallel workers (default: CPU count)")
        print("\nInput JSON format:")
        print("  [{\"func\": \"function_code\", \"path\": \"file/path\"}, ...]")
        print("\nExample:")
        print("  python detect_clones.py signatures.jsonl functions.json clones.jsonl 0.5 8")
        print("\nNote: Results are written to output file in real-time as clones are detected.")
        sys.exit(1)
    
    signatures_file = sys.argv[1]
    functions_json_file = sys.argv[2]
    output_file = sys.argv[3]
    threshold = float(sys.argv[4]) if len(sys.argv) > 4 else 0.5
    workers = int(sys.argv[5]) if len(sys.argv) > 5 else cpu_count()
    
    # Validate inputs
    if not Path(signatures_file).exists():
        print(f"[ERROR] Signatures file not found: {signatures_file}")
        sys.exit(1)
    
    if not Path(functions_json_file).exists():
        print(f"[ERROR] Functions JSON file not found: {functions_json_file}")
        sys.exit(1)
    
    # Create output directory if needed
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    
    print("MOVERY Vulnerable Code Clone Detection")
    print("=" * 50)
    print(f"Signatures: {signatures_file}")
    print(f"Functions: {functions_json_file}")
    print(f"Output: {output_file}")
    print(f"Similarity threshold: {threshold}")
    print(f"Parallel workers: {workers}")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # Initialize parallel detector
        detector = ParallelVulnerableCloneDetector(
            similarity_threshold=threshold, 
            parallel_workers=workers
        )
        
        # Load data
        print(f"\n[STEP 1] Loading signatures...")
        signatures = detector.load_signatures(signatures_file)
        
        print(f"\n[STEP 2] Loading target functions...")
        target_functions = detector.load_target_functions(functions_json_file)
        
        if not signatures:
            print("[ERROR] No valid signatures found")
            sys.exit(1)
        
        if not target_functions:
            print("[ERROR] No target functions found")
            sys.exit(1)
        
        # Detect clones with streaming results
        print(f"\n[STEP 3] Detecting vulnerable clones...")
        print(f"[INFO] Will perform {len(signatures) * len(target_functions):,} total comparisons")
        
        total_clones = detector.detect_all_clones_parallel(signatures, target_functions, output_file)
        
        # Print summary
        detector.print_summary()
        
        print(f"\nDetection complete! {total_clones} clones found and saved to: {output_file}")
        print(f"Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    except KeyboardInterrupt:
        print("\n[INFO] Detection interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Detection failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()