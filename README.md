# VulCoCo

VulCoCo is a tool for vulnerable code clone detection that combines retrieval-based methods with LLM validation to identify code clones in software repositories.

## Prerequisites

- Python 3.8+
- Conda package manager
- Anthropic API key (for LLM validation step)

## Installation

1. **Setup Environment**
   ```bash
   conda env create -f environment.yml
   conda activate vulcoco
   ```

2. **Download Source Dataset**
   
   Download the source dataset from [Google Drive](https://drive.google.com/file/d/1QKVNr5vtXMEB6jq-oDKD2gf-upVvUrc1/view?usp=sharing) and extract it to your preferred location.

## Usage

### Step 1: Fetch and Clone Repositories
```bash
python get_top_repos.py
```
This script fetches and clones the top repositories for analysis.

### Step 2: Parse Source Files
```bash
python parse_repos.py
```
Parses the cloned repositories to extract function-level code segments.

### Step 3: Retrieval-based Clone Detection
```bash
python3 main.py --all_json_path 'path/to/source/data.jsonl' \
                --funcs_dir 'path/to/function/json/files' \
                --clones_dir 'path/to/output/directory' \
                --threshold 0.7
```

**Parameters:**
- `--all_json_path`: Path to the JSONL source dataset
- `--funcs_dir`: Directory containing function JSON files from Step 2
- `--clones_dir`: Output directory for clone detection results
- `--threshold`: Similarity threshold for clone detection (default: 0.7)

### Step 4: LLM Validation
```bash
python3 llm.py --results 'path/to/clone/results.json' \
               --sources 'path/to/source/data.jsonl' \
               --api-key 'your-anthropic-api-key' \
               --output 'path/to/validated/output.json' \
               --responses-dir 'path/to/llm/responses'
```

**Parameters:**
- `--results`: JSON file containing clone detection results from Step 3
- `--sources`: Path to the original JSONL source dataset
- `--api-key`: Your Anthropic API key for LLM validation
- `--output`: Output path for validated results
- `--responses-dir`: Directory to save raw LLM responses

## Output

The tool generates:
- Clone detection results in JSON format
- LLM validation responses
- Final validated clone pairs with confidence scores
