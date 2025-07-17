# VulCoCo

## Workflow

### Step 1: Setup Environment
conda env create -f environment.yml

### Step 2: Download Source Dataset
Download source dataset from https://drive.google.com/file/d/1QKVNr5vtXMEB6jq-oDKD2gf-upVvUrc1/view?usp=sharing

### Step 3: Fetch and Clone Repositories
python get_top_repos.py

### Step 4: Parse Source Files
python parse_repos.py

### Step 5: Retrieval-based Clone Detection
python3 main.py --all_json_path 'path to the jsonl source data' \ 
                --funcs_dir 'path to the directory with function JSON files' \
                --clones_dir 'Path to the output directory for clone results' \
                --threshold 0.7 

### Step 6: LLM Validation
python3 llm.py --results 'path to json result file from previous step' 
               --sources 'path to the jsonl source data' 
               --api-key 'anthropic API key'
               --output 'output path'
               --responses-dir 'path to save LLM responses'