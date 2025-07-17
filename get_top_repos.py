import os
import time
import requests
import json
import subprocess
from datetime import datetime, timedelta
from tqdm import tqdm

# Constants
PER_PAGE = 100
OUTPUT_DIR = "/mnt/sun-data/ngoctanbui/code_clone/final_repos"
LANGUAGES_REPOS = {
    'c': 100,
    'cpp': 100,
    'java': 100
}
GITHUB_TOKEN = "github token here"  # Replace with your GitHub token
MAX_RETRIES = 3
DAYS_THRESHOLD = 300  # Exclude repos with no commits in the last 300 days
MIN_PR_MERGE_RATE = 0.10  # Exclude repos with PR merge rate < 10%


def make_github_request(url, params=None, token=None):
    """
    Make a GitHub API request with rate limiting and retry logic.
    """
    retries = 0
    while retries < MAX_RETRIES:
        headers = {'Authorization': f'token {token}'} if token else {}
        response = requests.get(url, params=params, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            reset_time = int(response.headers.get('X-RateLimit-Reset', time.time() + 60))
            wait_time = reset_time - int(time.time())
            if wait_time > 0:
                print(f"Rate limit exceeded. Waiting for {wait_time} seconds...")
                time.sleep(wait_time + 1)
        elif response.status_code == 404:
            print(f"Resource not found: {url}")
            return None
        else:
            print(f"API request failed. Status code: {response.status_code}")
            retries += 1
            time.sleep(2 ** retries)  # Exponential backoff
    
    print(f"Failed to make request after {MAX_RETRIES} retries: {url}")
    return None


def has_recent_commits(owner, repo_name, token):
    """
    Check if the repository has commits within the last DAYS_THRESHOLD days.
    """
    cutoff_date = datetime.now() - timedelta(days=DAYS_THRESHOLD)
    url = f'https://api.github.com/repos/{owner}/{repo_name}/commits'
    params = {
        'since': cutoff_date.isoformat(),
        'per_page': 1
    }
    
    result = make_github_request(url, params, token)
    if result is None:
        return False  # If we can't fetch commits, exclude the repo
    
    return len(result) > 0


def get_pr_merge_rate(owner, repo_name, token):
    """
    Calculate the PR merge rate for the repository.
    Returns the merge rate as a float between 0 and 1.
    """
    url = f'https://api.github.com/repos/{owner}/{repo_name}/pulls'
    params = {
        'state': 'all',
        'per_page': 100  # Get a sample of recent PRs
    }
    
    result = make_github_request(url, params, token)
    if result is None or len(result) == 0:
        return 0.0  # If no PRs or can't fetch, return 0% merge rate
    
    total_prs = len(result)
    merged_prs = sum(1 for pr in result if pr.get('merged_at') is not None)
    
    return merged_prs / total_prs if total_prs > 0 else 0.0


def is_repo_active(owner, repo_name, token):
    """
    Check if repository meets activity criteria:
    1. Has commits within the last DAYS_THRESHOLD days
    2. Has PR merge rate >= MIN_PR_MERGE_RATE
    """
    print(f"  Checking activity for {owner}/{repo_name}...")
    
    # Check recent commits
    if not has_recent_commits(owner, repo_name, token):
        print(f"  ❌ {owner}/{repo_name}: No commits in last {DAYS_THRESHOLD} days")
        return False
    
    # Check PR merge rate
    merge_rate = get_pr_merge_rate(owner, repo_name, token)
    if merge_rate < MIN_PR_MERGE_RATE:
        print(f"  ❌ {owner}/{repo_name}: PR merge rate {merge_rate:.1%} < {MIN_PR_MERGE_RATE:.1%}")
        return False
    
    print(f"  ✅ {owner}/{repo_name}: Active (PR merge rate: {merge_rate:.1%})")
    return True


def extract_owner_repo(html_url):
    """
    Extract owner and repo name from GitHub HTML URL.
    """
    # URL format: https://github.com/owner/repo
    parts = html_url.rstrip('/').split('/')
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return None, None


def fetch_repos(language, star_range, token):
    """
    Fetch a batch of repositories for a specific language and star range.
    """
    url = 'https://api.github.com/search/repositories'
    params = {
        'q': f'language:{language} stars:{star_range}',
        'sort': 'stars',
        'order': 'desc',
        'per_page': PER_PAGE,
        'page': 1,
    }
    
    result = make_github_request(url, params, token)
    if result is None:
        return []
    
    repos = result.get('items', [])
    return [
        {
            "name": repo.get('name'),
            "url": repo.get('html_url'),
            "stars": repo.get('stargazers_count'),
            "owner": repo.get('owner', {}).get('login')
        }
        for repo in repos
    ]


def filter_active_repos(repos, token):
    """
    Filter repositories based on activity criteria.
    """
    active_repos = []
    
    print(f"Filtering {len(repos)} repositories for activity...")
    for repo in tqdm(repos, desc="Checking repo activity"):
        owner = repo.get('owner')
        repo_name = repo.get('name')
        
        if not owner or not repo_name:
            print(f"  ❌ Skipping repo with missing owner/name: {repo}")
            continue
        
        if is_repo_active(owner, repo_name, token):
            active_repos.append(repo)
        
        # Small delay to be respectful to the API
        time.sleep(0.1)
    
    print(f"Found {len(active_repos)} active repositories out of {len(repos)}")
    return active_repos


def clone_repo(repo_url, repo_name, base_path, progress_bar):
    """
    Clone a GitHub repository using its URL.
    """
    repo_path = os.path.join(base_path, repo_name)
    if os.path.exists(repo_path):
        progress_bar.set_description(f"Already exists: {repo_name}")
        return

    try:
        subprocess.run(['git', 'clone', repo_url, repo_path], check=True, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        progress_bar.set_description(f"Cloned: {repo_name}")
    except subprocess.CalledProcessError as e:
        progress_bar.set_description(f"Failed: {repo_name}")
        print(f"Failed to clone {repo_name}: {e}")


def fetch_and_clone(language, total_repos, token):
    """
    Fetch and clone repositories for a language, respecting GitHub's API limits
    and filtering for active repositories.
    """
    fetched_repos = 0
    star_range = ">=0"
    all_repos = []
    all_active_repos = []

    language_dir = os.path.join(OUTPUT_DIR, language)
    os.makedirs(language_dir, exist_ok=True)

    metadata_file = os.path.join(OUTPUT_DIR, f"{language}_metadata.json")
    active_metadata_file = os.path.join(OUTPUT_DIR, f"{language}_active_metadata.json")

    print(f"Processing {total_repos} repositories for {language}...")

    while fetched_repos < total_repos:
        # Fetch repositories for the current star range
        repos = fetch_repos(language, star_range, token)
        if not repos:
            print("No more repositories available in the current star range.")
            break

        # Filter for active repositories
        active_repos = filter_active_repos(repos, token)

        # Clone active repositories with progress bar
        if active_repos:
            with tqdm(active_repos, desc=f"Cloning active {language} repos") as progress_bar:
                for repo in active_repos:
                    if repo['url']:
                        clone_repo(repo['url'], repo['name'], language_dir, progress_bar)
                    progress_bar.update(1)

        # Save metadata incrementally
        all_repos.extend(repos)
        all_active_repos.extend(active_repos)
        
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(all_repos, f, indent=4)
        
        with open(active_metadata_file, 'w', encoding='utf-8') as f:
            json.dump(all_active_repos, f, indent=4)

        fetched_repos += len(repos)

        # Adjust the star range for the next query
        if len(repos) > 0:
            lowest_star = repos[-1]['stars']
            star_range = f"<{lowest_star}"
        else:
            print("No repositories found in the current range. Ending fetch.")
            break

        # Stop if fewer than PER_PAGE repositories were fetched (no more data)
        if len(repos) < PER_PAGE:
            print(f"Fewer than {PER_PAGE} repos fetched. Stopping for {language}.")
            break

    print(f"Summary for {language}:")
    print(f"  Total repositories found: {len(all_repos)}")
    print(f"  Active repositories: {len(all_active_repos)}")
    print(f"  Filtered out: {len(all_repos) - len(all_active_repos)}")


if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print(f"Activity filters:")
    print(f"  - Excluding repos with no commits in last {DAYS_THRESHOLD} days")
    print(f"  - Excluding repos with PR merge rate < {MIN_PR_MERGE_RATE:.1%}")
    print()

    for lang, total in LANGUAGES_REPOS.items():
        try:
            fetch_and_clone(lang, total, GITHUB_TOKEN)
            print(f"Completed processing {lang}\n")
        except Exception as e:
            print(f"Error processing {lang}: {e}")