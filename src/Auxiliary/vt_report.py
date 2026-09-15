from typing import Any, Dict, List, Tuple
import time
import requests


def submit_binary_to_cape(file_path: str) -> int:
  """Submits a binary file to the local CAPEv2 instance and returns the task ID."""
  url = "http://localhost:8000/apiv2/tasks/create/file/"

  with open(file_path, "rb") as f:
    files = {"file": (file_path, f)}
    response = requests.post(url, files=files)

  if response.status_code != 200:
    raise Exception(
        f"Failed to submit file: {response.status_code} - {response.text}"
    )

  data = response.json()

  # Safely parse task ID from various CAPEv2 response structures
  task_id = None
  if isinstance(data, dict):
    if "task_id" in data:
      task_id = data["task_id"]
    elif "task_ids" in data:
      ids = data["task_ids"]
      if isinstance(ids, list) and len(ids) > 0:
        task_id = ids[0]
    elif "data" in data:
      inner_data = data["data"]
      if isinstance(inner_data, dict):
        if "task_id" in inner_data:
          task_id = inner_data["task_id"]
        elif "task_ids" in inner_data:
          ids = inner_data["task_ids"]
          if isinstance(ids, list) and len(ids) > 0:
            task_id = ids[0]

  if task_id is None:
    raise Exception(f"Could not extract task ID from CAPE response: {data}")

  print(f"[*] Submitted {file_path} -> Task ID: {task_id}")
  return task_id

def wait_for_report(task_id: int, timeout: int = 300, poll_interval: int = 10) -> Dict[str, Any]:
    """Polls the local CAPE instance until the analysis report is ready and fetched."""
    view_url = f"http://localhost:8000/apiv2/tasks/view/{task_id}/"
    report_url = f"http://localhost:8000/apiv2/tasks/get/report/{task_id}/"
    
    start_time = time.time()
    print(f"[*] Waiting for Task {task_id} execution to complete...")
    
    while time.time() - start_time < timeout:
        try:
            response = requests.get(view_url)
            if response.status_code == 200:
                data = response.json()
                task_info = data.get("data", {})
                status = task_info.get("status")
                print(f"[*] Task {task_id} status: {status}")
                
                if status == "reported":
                    print(f"[*] Fetching JSON report for Task {task_id}...")
                    report_res = requests.get(report_url)
                    print(f"[*] Report endpoint HTTP status: {report_res.status_code}")
                    
                    if report_res.status_code == 200:
                        return report_res.json()
        except Exception as e:
            print(f"[!] Exception during polling: {e}")
            
        time.sleep(poll_interval)
        
    raise TimeoutError(f"Task {task_id} did not finish within {timeout} seconds.")


def extract_api_sequence(report_data: Dict[str, Any]) -> List[str]:
    """Extracts the sequence of API calls from a CAPE JSON report."""
    api_sequence = []
    
    # CAPE standard path: report -> behavior -> processes -> calls -> api
    behavior = report_data.get("behavior", {})
    processes = behavior.get("processes", [])
    
    if not processes:
        # Check alternative common paths
        processes = report_data.get("processes", [])
        
    for process in processes:
        calls = process.get("calls", [])
        for call in calls:
            # CAPE typically stores the API function name under 'api'
            api_name = call.get("api") or call.get("function")
            if api_name:
                api_sequence.append(api_name)
                
    # Debug print if no sequences were found
    if not api_sequence:
        print(f"[!] Warning: No API calls found. Report keys available: {list(report_data.keys())}")
        if "behavior" in report_data:
            print(f"[!] Behavior keys available: {list(report_data['behavior'].keys())}")
            
    return api_sequence

def compute_lcs(seq1: List[str], seq2: List[str]) -> Tuple[int, float, List[str]]:
    """Computes the Longest Common Subsequence (LCS) and normalized similarity score."""
    m, n = len(seq1), len(seq2)
    if m == 0 or n == 0:
        return 0, 0.0, []

    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if seq1[i - 1] == seq2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

    lcs_length = dp[m][n]
    normalized_score = lcs_length / max(m, n)

    # Backtracking to reconstruct the matching API trace sequence
    lcs_sequence = []
    i, j = m, n
    while i > 0 and j > 0:
        if seq1[i - 1] == seq2[j - 1]:
            lcs_sequence.append(seq1[i - 1])
            i -= 1
            j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            i -= 1
        else:
            j -= 1
            
    lcs_sequence.reverse()
    return lcs_length, normalized_score, lcs_sequence

if __name__ == "__main__":
    # Replace with the actual file paths of your binaries
    binary_a = "original.exe"
    binary_b = "control_flow.exe"

    try:
        # Step 1: Submit samples to your local sandbox
        task_a = submit_binary_to_cape(binary_a)
        task_b = submit_binary_to_cape(binary_b)

        # Step 2: Poll and fetch structured JSON reports once sandbox execution finishes
        report_a = wait_for_report(task_a)
        print("ERROR:", report_a.get("error"))
        print("ERROR_VALUE:", report_a.get("error_value"))
        report_b = wait_for_report(task_b)

        # Step 3: Extract sequential execution calls
        seq_a = extract_api_sequence(report_a)
        seq_b = extract_api_sequence(report_b)

        print(f"\n[*] Sequence A Length: {len(seq_a)}")
        print(f"[*] Sequence B Length: {len(seq_b)}")

        # Step 4: Compute LCS metric
        lcs_len, sim_score, common_calls = compute_lcs(seq_a, seq_b)

        print("\n--- Behavioral Verification Results ---")
        print(f"LCS Count           : {lcs_len}")
        print(f"Similarity Score    : {sim_score:.4f}")
        print(f"Common Sequence Snippet: {common_calls[:10]}")

        # Step 5: Decision threshold check
        if sim_score >= 0.96:
            print("\n[+] SUCCESS: Variant satisfies behavioral preservation threshold (>= 0.96).")
        else:
            print("\n[-] FAILED: High behavioral drift detected (< 0.96).")

    except Exception as e:
        print(f"[!] Pipeline execution error: {e}")
