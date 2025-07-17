#!/usr/bin/env python3
"""
Vulnerability Signature Processor
Processes JSONL files containing vulnerability-fix pairs and introducing code,
then generates MOVERY signatures using the SignatureGenerator.

Logic for oldest function (fo):
- If introducing code is available for a commit: fo = introducing_func_code
- If no introducing code available: fo = fd (current vulnerable function)

This ensures all vulnerabilities can be processed even when historical data is incomplete.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict

# Import from your signature generator script
# Adjust the import name based on your script filename
try:
    from movery_signature_generator import SignatureGenerator
except ImportError:
    # Alternative import paths
    try:
        from signature_generator import SignatureGenerator  
    except ImportError:
        print("[ERROR] Could not import SignatureGenerator. Please ensure the signature generator script is available.")
        print("Expected import paths: 'movery_signature_generator' or 'signature_generator'")
        sys.exit(1)


def load_jsonl(filepath: str) -> List[Dict]:
    """Load JSONL file and return list of records"""
    records = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        print(f"[WARNING] Invalid JSON on line {line_num}: {e}")
                        continue
        print(f"[INFO] Successfully loaded {len(records)} records from {filepath}")
        return records
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        raise
    except Exception as e:
        print(f"[ERROR] Failed to load {filepath}: {e}")
        raise


def find_vuln_fix_pairs(vuln_fix_records: List[Dict]) -> List[Tuple[Dict, Dict]]:
    """
    Find vulnerability-fix pairs based on commit_id.
    Pairs should have same commit_id, with target=1 (vuln) and target=0 (fix).
    """
    pairs = []
    commit_groups = defaultdict(list)
    
    # Track filtering statistics
    records_without_commit_id = 0
    commits_without_vuln = 0
    commits_without_fix = 0
    
    # Group records by commit_id
    for record in vuln_fix_records:
        commit_id = record.get('commit_id')
        if commit_id:
            commit_groups[commit_id].append(record)
        else:
            records_without_commit_id += 1
            print(f"[WARNING] Record {record.get('idx', 'unknown')} missing commit_id")
    
    print(f"[INFO] Found {len(commit_groups)} unique commits from {len(vuln_fix_records)} records")
    if records_without_commit_id > 0:
        print(f"[WARNING] Skipped {records_without_commit_id} records without commit_id")
    
    # Find pairs within each commit group
    for commit_id, records in commit_groups.items():
        vuln_records = [r for r in records if r.get('target') == 1]
        fix_records = [r for r in records if r.get('target') == 0]
        
        if not vuln_records:
            commits_without_vuln += 1
            print(f"[WARNING] Commit {commit_id[:8]} has no vulnerability records (target=1)")
            continue
            
        if not fix_records:
            commits_without_fix += 1
            print(f"[WARNING] Commit {commit_id[:8]} has no fix records (target=0)")
            continue
            
        # Match vulnerability with corresponding fix by same commit_id
        commit_pairs_found = 0
        for vuln in vuln_records:
            for fix in fix_records:
                # Simple matching: just same commit_id with target=1 and target=0
                pairs.append((vuln, fix))
                commit_pairs_found += 1
                break  # Take first fix for each vuln (assuming 1:1 mapping)
        
        if commit_pairs_found == 0:
            print(f"[WARNING] Commit {commit_id[:8]} has {len(vuln_records)} vuln and {len(fix_records)} fix records but no pairs created")
    
    print(f"[INFO] Pairing statistics:")
    print(f"  Total records: {len(vuln_fix_records)}")
    print(f"  Records without commit_id: {records_without_commit_id}")
    print(f"  Unique commits: {len(commit_groups)}")
    print(f"  Commits without vuln records: {commits_without_vuln}")
    print(f"  Commits without fix records: {commits_without_fix}")
    print(f"  Final vulnerability-fix pairs: {len(pairs)}")
    
    return pairs


def match_with_introducing_code(pairs: List[Tuple[Dict, Dict]], 
                               introducing_records: List[Dict]) -> List[Tuple[str, str, str, str, Dict]]:
    """
    Match vulnerability pairs with introducing code records by commit_id.
    If no introducing code is found, use the current vulnerable function as the oldest.
    Returns tuples of (fo, fd, fp, commit_id, metadata)
    """
    # Create lookup for introducing records by commit_id
    introducing_lookup = {}
    for record in introducing_records:
        commit_id = record.get('commit_id')
        if commit_id:
            introducing_lookup[commit_id] = record
    
    print(f"[INFO] Found introducing code for {len(introducing_lookup)} commits")
    
    matched_data = []
    pairs_with_introducing = 0
    pairs_without_introducing = 0
    pairs_missing_func_code = 0
    
    for vuln_record, fix_record in pairs:
        commit_id = vuln_record.get('commit_id')
        
        # Get function codes
        fd = vuln_record.get('func')  # disclosed vulnerable function
        fp = fix_record.get('func')   # patched function
        
        if not fd or not fp:
            pairs_missing_func_code += 1
            print(f"[WARNING] Missing function code for commit {commit_id[:8] if commit_id else 'unknown'}")
            print(f"  Vuln record {vuln_record.get('idx', 'unknown')}: func present = {bool(fd)}")
            print(f"  Fix record {fix_record.get('idx', 'unknown')}: func present = {bool(fp)}")
            continue
        
        # Try to find introducing code (oldest vulnerable)
        fo = None
        has_introducing_code = False
        
        if commit_id in introducing_lookup:
            fo = introducing_lookup[commit_id].get('introducing_func_code')
            if fo and fo.strip():  # Make sure it's not empty
                has_introducing_code = True
                pairs_with_introducing += 1
            else:
                fo = None
        
        # If no introducing code found, use current vulnerable function as oldest
        if fo is None:
            fo = fd  # Current vulnerable function becomes the oldest
            pairs_without_introducing += 1
            print(f"[INFO] No introducing code for {commit_id[:8]}, using current vuln func as oldest")
        
        # Collect metadata for tracking
        metadata = {
            'commit_id': commit_id,
            'project': vuln_record.get('project'),
            'cve': vuln_record.get('cve'),
            'cwe': vuln_record.get('cwe', []),
            'cve_desc': vuln_record.get('cve_desc'),
            'vuln_idx': vuln_record.get('idx'),
            'fix_idx': fix_record.get('idx'),
            'has_introducing_code': has_introducing_code,
            'oldest_func_source': 'introducing_code' if has_introducing_code else 'current_vuln'
        }
        
        matched_data.append((fo, fd, fp, commit_id, metadata))
    
    print(f"[INFO] Function code matching statistics:")
    print(f"  Input pairs: {len(pairs)}")
    print(f"  Pairs missing function code: {pairs_missing_func_code}")
    print(f"  Valid pairs processed: {len(matched_data)}")
    print(f"  Pairs with introducing code: {pairs_with_introducing}")
    print(f"  Pairs using current vuln as oldest: {pairs_without_introducing}")
    
    return matched_data


def process_vulnerabilities(vuln_fix_file: str, introducing_file: str, output_file: str):
    """Main processing function to generate signatures for all vulnerabilities"""
    
    print("=" * 60)
    print("MOVERY Vulnerability Signature Processing")
    print("=" * 60)
    
    # Load input files
    print(f"\n[STEP 1] Loading vulnerability-fix pairs from {vuln_fix_file}")
    vuln_fix_records = load_jsonl(vuln_fix_file)
    
    print(f"\n[STEP 2] Loading introducing code records from {introducing_file}")
    introducing_records = load_jsonl(introducing_file)
    
    # Process data
    print(f"\n[STEP 3] Finding vulnerability-fix pairs from {len(vuln_fix_records)} records...")
    pairs = find_vuln_fix_pairs(vuln_fix_records)
    
    if not pairs:
        print("[ERROR] No vulnerability-fix pairs found. Check your data format.")
        return
    
    # Show where pairs might have been lost
    print(f"\n[FILTERING SUMMARY]")
    print(f"  Input JSONL records: {len(vuln_fix_records)}")
    print(f"  Expected pairs (records/2): {len(vuln_fix_records)//2}")
    print(f"  Actual pairs found: {len(pairs)}")
    print(f"  Pairs lost: {len(vuln_fix_records)//2 - len(pairs)}")
    if len(vuln_fix_records)//2 != len(pairs):
        print(f"  → Check the detailed warnings above to see why pairs were filtered out")
    
    print(f"\n[STEP 4] Matching with introducing code...")
    matched_data = match_with_introducing_code(pairs, introducing_records)
    
    if not matched_data:
        print("[ERROR] No matched data found.")
        return
    
    # Initialize signature generator
    print(f"\n[STEP 5] Initializing MOVERY signature generator...")
    try:
        generator = SignatureGenerator()
        print("[INFO] SignatureGenerator initialized successfully")
    except Exception as e:
        print(f"[ERROR] Failed to initialize SignatureGenerator: {e}")
        return
    
    # Process each vulnerability
    print(f"\n[STEP 6] Processing {len(matched_data)} vulnerabilities...")
    results = []
    successful = 0
    failed = 0
    
    for i, (fo, fd, fp, commit_id, metadata) in enumerate(matched_data):
        print(f"\n[{i+1}/{len(matched_data)}] Processing {metadata['project']} - {commit_id[:8]}...")
        print(f"  CVE: {metadata['cve']}, CWE: {metadata['cwe']}")
        
        try:
            # Generate signatures using MOVERY methodology
            vuln_sig, patch_sig = generator.generate_signatures(fo, fd, fp)
            
            # Calculate signature statistics
            signature_stats = {
                'vuln_essential_lines': len(vuln_sig['Ev']),
                'vuln_dependent_lines': len(vuln_sig['Dv']),
                'vuln_control_flow_lines': len(vuln_sig['Fv']),
                'patch_essential_lines': len(patch_sig['Ep']),
                'patch_dependent_lines': len(patch_sig['Dp']),
                'total_vuln_lines': len(vuln_sig['Ev']) + len(vuln_sig['Dv']) + len(vuln_sig['Fv']),
                'total_patch_lines': len(patch_sig['Ep']) + len(patch_sig['Dp'])
            }
            
            # Prepare result record
            result = {
                'metadata': metadata,
                'vulnerability_signature': vuln_sig,
                'patch_signature': patch_sig,
                'signature_stats': signature_stats,
                'processing_status': 'success'
            }
            
            results.append(result)
            successful += 1
            
            print(f"  [SUCCESS] Signatures generated:")
            print(f"    Vulnerability: Ev={signature_stats['vuln_essential_lines']}, "
                  f"Dv={signature_stats['vuln_dependent_lines']}, "
                  f"Fv={signature_stats['vuln_control_flow_lines']}")
            print(f"    Patch: Ep={signature_stats['patch_essential_lines']}, "
                  f"Dp={signature_stats['patch_dependent_lines']}")
            
        except Exception as e:
            print(f"  [ERROR] Failed to process: {e}")
            failed += 1
            
            # Still save the metadata for failed cases
            error_result = {
                'metadata': metadata,
                'vulnerability_signature': None,
                'patch_signature': None,
                'signature_stats': None,
                'processing_status': 'failed',
                'error': str(e)
            }
            results.append(error_result)
            continue
    
    # Save results
    print(f"\n[STEP 7] Saving results to {output_file}")
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for result in results:
                f.write(json.dumps(result) + '\n')
        print(f"[INFO] Results saved successfully")
    except Exception as e:
        print(f"[ERROR] Failed to save results: {e}")
        return
    
    # Print comprehensive summary
    print("\n" + "=" * 60)
    print("PROCESSING SUMMARY")
    print("=" * 60)
    
    print(f"Total vulnerabilities processed: {len(matched_data)}")
    print(f"Successful signature generation: {successful}")
    print(f"Failed signature generation: {failed}")
    print(f"Success rate: {successful/len(matched_data)*100:.1f}%")
    
    # Calculate aggregate statistics for successful cases
    success_results = [r for r in results if r['processing_status'] == 'success']
    
    if success_results:
        total_ev = sum(r['signature_stats']['vuln_essential_lines'] for r in success_results)
        total_dv = sum(r['signature_stats']['vuln_dependent_lines'] for r in success_results)
        total_fv = sum(r['signature_stats']['vuln_control_flow_lines'] for r in success_results)
        total_ep = sum(r['signature_stats']['patch_essential_lines'] for r in success_results)
        total_dp = sum(r['signature_stats']['patch_dependent_lines'] for r in success_results)
        
        print(f"\nSignature Statistics (successful cases):")
        print(f"  Essential vulnerable lines (Ev): {total_ev}")
        print(f"  Dependent vulnerable lines (Dv): {total_dv}")
        print(f"  Control flow vulnerable lines (Fv): {total_fv}")
        print(f"  Essential patch lines (Ep): {total_ep}")
        print(f"  Dependent patch lines (Dp): {total_dp}")
        
        with_introducing = sum(1 for r in success_results if r['metadata']['has_introducing_code'])
        with_current_as_oldest = sum(1 for r in success_results if not r['metadata']['has_introducing_code'])
        
        print(f"\nOldest function source breakdown:")
        print(f"  With actual introducing code: {with_introducing}/{len(success_results)} "
              f"({with_introducing/len(success_results)*100:.1f}%)")
        print(f"  Using current vuln as oldest: {with_current_as_oldest}/{len(success_results)} "
              f"({with_current_as_oldest/len(success_results)*100:.1f}%)")
        
        # Project breakdown
        project_counts = defaultdict(int)
        for r in success_results:
            project_counts[r['metadata']['project']] += 1
        
        print(f"\nProject breakdown:")
        for project, count in sorted(project_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {project}: {count}")
    
    print(f"\nResults saved to: {output_file}")
    print("Processing complete!")


def main():
    """Main entry point"""
    if len(sys.argv) != 4:
        print("MOVERY Vulnerability Signature Processor")
        print("=" * 40)
        print("\nUsage:")
        print("  python process_vulnerabilities.py <vuln_fix_file.jsonl> <introducing_file.jsonl> <output_file.jsonl>")
        print("\nArguments:")
        print("  vuln_fix_file.jsonl    : JSONL file with vulnerability-fix pairs (target 0/1)")
        print("  introducing_file.jsonl : JSONL file with introducing code records")
        print("  output_file.jsonl      : Output file for generated signatures")
        print("\nExample:")
        print("  python process_vulnerabilities.py vuln_fix_pairs.jsonl introducing_code.jsonl signatures.jsonl")
        sys.exit(1)
    
    vuln_fix_file = sys.argv[1]
    introducing_file = sys.argv[2] 
    output_file = sys.argv[3]
    
    # Validate input files exist
    if not Path(vuln_fix_file).exists():
        print(f"[ERROR] Vulnerability-fix file not found: {vuln_fix_file}")
        sys.exit(1)
        
    if not Path(introducing_file).exists():
        print(f"[ERROR] Introducing code file not found: {introducing_file}")
        sys.exit(1)
    
    # Create output directory if needed
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        process_vulnerabilities(vuln_fix_file, introducing_file, output_file)
    except KeyboardInterrupt:
        print("\n[INFO] Processing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Processing failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()