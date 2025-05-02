import google.generativeai as genai
import os
import sys
import argparse
import re
import html
import datetime
import json # Import the json module

# --- Configuration ---

API_KEY = os.getenv("GEMINI_API_KEY")

# --- MODIFIED: Removed .xml, .json, .css as per previous request ---
# List of code/config file extensions to process
CODE_EXTENSIONS = {
    # Programming Languages
    '.py', '.js', '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.go',
    '.rb', '.php', '.swift', '.kt', '.ts',
    # Web Frontend (HTML can contain JS)
    '.html',
    # Shell Scripting
    '.sh',
    # Configuration / Infrastructure-as-Code
    '.yaml', '.yml', '.tf',
}
# --- End Modification ---

# Severity mapping and colors (inspired by the image)
SEVERITY_MAP = {
    "critical": {"color": "#dc3545", "level": 5},
    "high": {"color": "#fd7e14", "level": 4},
    "medium": {"color": "#ffc107", "level": 3},
    "low": {"color": "#0dcaf0", "level": 2},
    "informational": {"color": "#adb5bd", "level": 1}
}

# --- Gemini Interaction ---

def configure_gemini():
    """Configures the Generative AI client."""
    if not API_KEY:
        print("Error: GEMINI_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)
    try:
        genai.configure(api_key=API_KEY)
        print("Gemini AI configured successfully.")
    except Exception as e:
        print(f"Error configuring Gemini AI: {e}", file=sys.stderr)
        sys.exit(1)

# --- MODIFIED get_gemini_review: Added Vulnerability Title to prompt, kept temperature=0 ---
def get_gemini_review(file_path, code_content):
    """Sends code content to Gemini for secure code review."""
    if not code_content.strip():
        return "Skipped: File is empty.", None # Return None for content if skipped

    model = genai.GenerativeModel('gemini-1.5-flash-latest')

    # Using the enhanced prompt for precision and added Vulnerability Title field
    prompt = f"""
    Act as a **meticulous, highly accurate, and conservative expert security code reviewer**. Your primary goal is **maximum precision and the avoidance of hallucinations, speculation, or false positives**. You must base your findings **strictly and solely** on the provided code snippet and well-established, verifiable secure coding principles and vulnerability patterns.

    **CRITICAL Instructions for Analysis & Reporting:**
    1.  **Evidence is Key:** Only report findings where there is clear, direct evidence within the provided code. Do not infer vulnerabilities based on missing context or assumptions about external systems or libraries unless explicitly shown in the code.
    2.  **Prioritize Accuracy:** If you are uncertain about whether something constitutes a genuine security vulnerability (as opposed to a style issue, best practice suggestion, or potential bug with no clear security impact), **DO NOT report it as a security finding**. You may assign 'Informational' severity ONLY if providing context, but clearly state the uncertainty.
    3.  **Minimize Noise:** Focus on identifying **concrete, exploitable security weaknesses** or **clear deviations from essential security practices**. Avoid purely stylistic suggestions or low-impact, theoretical risks without a clear attack vector demonstrated in the code.
    4.  **No Hallucination:** Do not invent vulnerabilities, code snippets, or CVE connections that are not directly supported by the provided text.
    5.  **Be Specific:** All parts of your finding description (Risk, Snippet, Remediation) must be specific and directly related to the code provided.

    For each **confirmed and verifiable** security vulnerability or significant risk you identify based *only* on the code below, provide ONLY the following information in this exact format, starting each item on a new line:

    Vulnerability Title: [Provide a concise name for the vulnerability type, e.g., SQL Injection, Cross-Site Scripting, Hardcoded API Key]
    Risk Description: [**Accurately, concisely, and factually** describe the specific security issue and its potential impact, avoiding exaggeration.]
    Code Snippet/Location: [Specify the **exact** relevant line number(s) or precise code snippet that demonstrates the vulnerability. Use line numbers (e.g., 'Line(s) X-Y:') whenever possible.]
    Severity: [Assign ONE severity level based on demonstrable potential impact: Critical, High, Medium, Low, or Informational. **Be conservative:** If impact isn't clear or requires many external factors, lean towards a lower severity or Informational.]
    CVE ID: [Mention CVE ID(s) ONLY if the code pattern **directly and unambiguously** matches a well-known CVE entry AND the vulnerable pattern is clearly present. Otherwise, state "N/A". **DO NOT GUESS CVEs.** State the relevant CWE if applicable and certain.]
    Remediation Steps: [Provide **at least three distinct, clear, actionable, specific, and secure** remediation suggestions to fix the vulnerability or mitigate the risk in the context of the provided code. Please format them as a numbered or bulleted list. If fewer than three distinct, high-quality options are genuinely applicable, provide only those that are relevant.]

    ---
    **Output Formatting Rules:**
    * Use the exact field names ("Vulnerability Title:", "Risk Description:", etc.) followed by a colon and a space.
    * Start each field on a new line.
    * If multiple distinct vulnerabilities are found, separate each complete finding block (Vulnerability Title to Remediation Steps) with a line containing exactly '---FINDING SEPARATOR---'.
    * **If, after meticulous analysis based *only* on the provided code, you find NO concrete security vulnerabilities meeting these strict criteria, output ONLY the exact phrase:** "No significant security vulnerabilities identified in this file."
    ---

    **Analyze only the code below:**
    --- CODE START ---
    ```
    {code_content}
    ```
    --- CODE END ---
    """

    print(f"Sending '{file_path}' to Gemini for review...")
    try:
        # Set temperature to 0 for more deterministic output
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(temperature=0.0), # Keep temperature=0
            request_options={'timeout': 600}
        )

        if not response.candidates:
            review_text = "Review failed: No response candidates received (potentially due to safety filters or API issues)."
            raw_content = review_text
        else:
            if response.parts:
                 review_text = "".join(part.text for part in response.parts if hasattr(part, 'text'))
                 raw_content = review_text
            else:
                 review_text = "Review failed: Response received but no text parts found."
                 raw_content = review_text

        return review_text, raw_content

    except Exception as e:
        error_message = f"Review failed for {file_path}: An error occurred during the API call: {e}"
        print(error_message, file=sys.stderr)
        return error_message, error_message
# --- End MODIFIED get_gemini_review ---

# --- MODIFIED Parsing Gemini's Response: Added title extraction, removed summary ---
def parse_gemini_response(response_text, filename):
    """
    Parses the Gemini response text to extract structured vulnerability findings.
    Now extracts explicit Vulnerability Title.
    """
    findings = []
    if not response_text or "No significant security vulnerabilities identified" in response_text:
        return findings
    if response_text.startswith("Review failed"):
        return findings # Let calling function handle review failures

    finding_blocks = response_text.split('---FINDING SEPARATOR---')
    finding_id_counter = 1

    for block in finding_blocks:
        block = block.strip()
        if not block:
            continue

        finding = {"filename": filename}
        raw_finding_data = block

        try:
            # Regex for Title
            title_match = re.search(r"^Vulnerability Title:\s*(.*?)(?=\n^Risk Description:|\Z)", block, re.MULTILINE | re.DOTALL)
            # Other regex
            desc_match = re.search(r"^Risk Description:\s*(.*?)(?=\n^Code Snippet/Location:|\n^Severity:|\Z)", block, re.MULTILINE | re.DOTALL)
            snippet_match = re.search(r"^Code Snippet/Location:\s*(.*?)(?=\n^Severity:|\n^CVE ID:|\Z)", block, re.MULTILINE | re.DOTALL)
            severity_match = re.search(r"^Severity:\s*(\w+)", block, re.MULTILINE)
            cve_match = re.search(r"^CVE ID:\s*(.*?)(?=\n^Remediation Steps:|\Z)", block, re.MULTILINE | re.DOTALL)
            remediation_match = re.search(r"^Remediation Steps:\s*(.*)", block, re.MULTILINE | re.DOTALL)

            # Store the title, provide default
            vulnerability_title = title_match.group(1).strip() if title_match else "Unnamed Finding"
            # Store others
            risk_description = desc_match.group(1).strip() if desc_match else "N/A"
            code_snippet = snippet_match.group(1).strip() if snippet_match else "N/A"
            raw_severity = severity_match.group(1).strip().lower() if severity_match else "informational"
            severity = raw_severity.capitalize() if raw_severity in SEVERITY_MAP else "Informational"
            cve_id = cve_match.group(1).strip() if cve_match else "N/A"
            remediation = remediation_match.group(1).strip() if remediation_match else "N/A"

            if risk_description != "N/A" and severity != "Informational":
                line_info = ""
                line_match_snippet = re.search(r"Line(?:s)?\s*(\d+(?:[,-]\s*\d+)*)", code_snippet, re.IGNORECASE)
                if line_match_snippet:
                    line_info = line_match_snippet.group(1)

                # Removed old issue_summary calculation

                findings.append({
                    "filename": filename,
                    "line_info": line_info,
                    "severity": severity,
                    "vulnerability_title": vulnerability_title, # Add the new title field
                    "risk_description": risk_description,
                    "code_snippet": code_snippet,
                    "remediation": remediation,
                    "cve_id": cve_id
                })
                finding_id_counter += 1
            elif block:
                 print(f"Warning: Could not fully parse finding block in {filename}.", file=sys.stderr)

        except Exception as e:
            print(f"Error parsing finding block in {filename}: {e}\nBlock:\n{block}", file=sys.stderr)

    return findings
# --- End MODIFIED parse_gemini_response ---

# --- File System Interaction & Data Collection ---
# (review_folder function remains the same as previous full version)
def review_folder(folder_path):
    """
    Traverses folder, gets reviews, parses them, and returns structured scan data.
    """
    if not os.path.isdir(folder_path):
        print(f"Error: Folder not found: {folder_path}", file=sys.stderr)
        return None

    print(f"\n--- Starting Security Code Review for Folder: {folder_path} ---")

    all_findings = []
    files_analyzed = 0
    files_with_errors = 0
    file_processing_errors = [] # List to store files that failed reading/review

    for root, _, files in os.walk(folder_path):
        if any(part.startswith('.') for part in root.split(os.sep)):
             continue

        for filename in files:
             _, extension = os.path.splitext(filename)
             if extension.lower() in CODE_EXTENSIONS:
                files_analyzed += 1
                file_path = os.path.join(root, filename)
                print(f"\n--- Reviewing File: {file_path} ---")
                content = None
                file_read_error = False
                try:
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                    except UnicodeDecodeError:
                        print(f"Warning: UTF-8 decoding failed for {file_path}. Trying 'latin-1'.")
                        try:
                             with open(file_path, 'r', encoding='latin-1') as f:
                                content = f.read()
                        except Exception as enc_err:
                             print(f"Error reading file {file_path} with multiple encodings: {enc_err}", file=sys.stderr)
                             files_with_errors += 1
                             file_processing_errors.append({"filename": file_path, "error": str(enc_err)})
                             file_read_error = True

                    if file_read_error or content is None: continue

                    review_result_text, _ = get_gemini_review(file_path, content)

                    if review_result_text.startswith("Review failed"):
                         print(review_result_text, file=sys.stderr)
                         files_with_errors += 1
                         file_processing_errors.append({"filename": file_path, "error": review_result_text})
                    elif "Skipped: File is empty." in review_result_text:
                        print(f"Skipped empty file: {file_path}")
                    else:
                        parsed = parse_gemini_response(review_result_text, file_path)
                        if parsed:
                             all_findings.extend(parsed)
                             print(f"Found {len(parsed)} potential finding(s) in {file_path}")
                        else:
                            print(f"No findings reported or parsed for {file_path}.")

                except FileNotFoundError:
                    err_msg = f"Error: File disappeared during processing: {file_path}"
                    print(err_msg, file=sys.stderr)
                    files_with_errors += 1
                    file_processing_errors.append({"filename": file_path, "error": err_msg})
                except PermissionError:
                     err_msg = f"Error: Permission denied reading file: {file_path}"
                     print(err_msg, file=sys.stderr)
                     files_with_errors += 1
                     file_processing_errors.append({"filename": file_path, "error": err_msg})
                except Exception as e:
                    err_msg = f"An unexpected error occurred processing {file_path}: {e}"
                    print(err_msg, file=sys.stderr)
                    files_with_errors += 1
                    file_processing_errors.append({"filename": file_path, "error": err_msg})

    print("\n--- Review Processing Complete ---")

    total_findings = len(all_findings)
    severity_counts = {sev.capitalize(): 0 for sev in SEVERITY_MAP.keys()}
    for finding in all_findings:
        sev = finding.get('severity', 'Informational')
        if sev in severity_counts:
            severity_counts[sev] += 1

    for i, finding in enumerate(all_findings):
        finding['id'] = f"finding-{i+1}"

    scan_data = {
        "scan_metadata": {
            "scanned_path": folder_path,
            "report_generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "files_analyzed": files_analyzed,
            "files_with_errors": files_with_errors,
            "file_processing_errors": file_processing_errors,
            "total_findings": total_findings
        },
        "severity_summary": {sev: count for sev, count in severity_counts.items() if count > 0},
        "findings": all_findings
    }

    return scan_data

# --- MODIFIED HTML Report Generation: Uses Vulnerability Title in header ---
def generate_html_report(scan_data, report_filename):
    """Generates an HTML report from the structured scan data with severity filters."""

    metadata = scan_data.get("scan_metadata", {})
    severity_summary = scan_data.get("severity_summary", {})
    findings = scan_data.get("findings", [])
    scanned_path = metadata.get("scanned_path", "N/A")
    generation_time = metadata.get("report_generated_at", datetime.datetime.now(datetime.timezone.utc).isoformat())
    try:
        display_time = datetime.datetime.fromisoformat(generation_time).strftime("%Y-%m-%d %H:%M:%S %Z")
    except:
        display_time = generation_time

    # --- Generate dynamic parts FIRST ---
    severity_css_list = []
    for sev, props in SEVERITY_MAP.items():
        severity_css_list.append(f".severity-{sev} {{ background-color: {props['color']}; }}")
        severity_css_list.append(f".summary-box .sev-label-{sev} {{ background-color: {props['color']}; }}")
        severity_css_list.append(f".filter-btn[data-filter='{sev.capitalize()}'] {{ border-left: 5px solid {props['color']}; }}")
        severity_css_list.append(f".filter-btn.active[data-filter='{sev.capitalize()}'] {{ background-color: {props['color']}; color: white; }}")
    severity_css = "\n        ".join(severity_css_list)

    severity_summary_list = []
    sorted_severities = sorted(severity_summary.keys(), key=lambda s: SEVERITY_MAP.get(s.lower(), {"level": 0})['level'], reverse=True)
    for sev in sorted_severities:
        count = severity_summary[sev]
        severity_summary_list.append(f'<li><span class="sev-label-{sev.lower()}">{sev}</span> <span>{count}</span></li>')
    severity_summary_html = "\n                    ".join(severity_summary_list) if severity_summary_list else "<li><span>No findings.</span></li>"

    files_with_errors_html = ""
    processing_errors = metadata.get("file_processing_errors", [])
    if processing_errors:
        error_list_items = [f"<li>{html.escape(err['filename'])}: <small>{html.escape(err['error'][:100])}...</small></li>" for err in processing_errors]
        files_with_errors_html = f"""
            <div class="summary-box">
                <h3>Files With Errors ({len(processing_errors)})</h3>
                <ul style="max-height: 100px; overflow-y: auto;">{''.join(error_list_items)}</ul>
            </div>"""

    total_findings_count = metadata.get("total_findings", 0)
    filter_buttons_html_list = [f'<button class="filter-btn active" data-filter="All">All ({total_findings_count})</button>']
    for sev in sorted_severities:
        count = severity_summary[sev]
        filter_buttons_html_list.append(f'<button class="filter-btn" data-filter="{sev}">{sev} ({count})</button>')
    filter_buttons_html = "\n                        ".join(filter_buttons_html_list)

    findings_html_list = []
    findings.sort(key=lambda x: (SEVERITY_MAP.get(x['severity'].lower(), {"level": 0})['level'], x['filename']), reverse=True)
    for finding in findings:
        finding_id = html.escape(finding['id'])
        severity = html.escape(finding['severity'])
        severity_lower = severity.lower()
        severity_class = f"severity-{severity_lower}" if severity_lower in SEVERITY_MAP else "severity-informational"
        # Use vulnerability_title here
        esc_title = html.escape(finding.get('vulnerability_title', 'Unnamed Finding'))
        esc_file = html.escape(finding['filename'])
        line_info = html.escape(finding.get('line_info', ''))
        file_display = f"{esc_file}{f':{line_info}' if line_info else ''}"
        esc_risk = html.escape(finding['risk_description']).replace('\n', '<br>')
        esc_snippet = html.escape(finding['code_snippet'])
        esc_remediation = html.escape(finding['remediation']).replace('\n', '<br>')
        esc_cve = html.escape(finding.get('cve_id', 'N/A'))

        findings_html_list.append(f"""
            <div class="finding-entry" id="{finding_id}" data-severity="{severity}">
                <div class="finding-header">
                    <span class="severity {severity_class}">{severity}</span>
                    <span class="issue">{esc_title}</span>
                    <span class="file-info">{file_display}</span>
                    <span class="toggle-icon">&#9660;</span>
                </div>
                <div class="finding-details">
                    <div class="detail-block">
                        <h4>Risk Description</h4>
                        <p>{esc_risk}</p>
                    </div>
                     <div class="detail-block">
                        <h4>Context / Snippet</h4>
                        <pre><code>{esc_snippet}</code></pre>
                    </div>
                    <div class="detail-block">
                        <h4>Remediation</h4>
                        <p>{esc_remediation}</p>
                    </div>
                    <div class="detail-block">
                        <h4>CVE ID</h4>
                        <p>{esc_cve}</p>
                    </div>
                </div>
            </div>
        """)
    findings_html = "\n            ".join(findings_html_list) if findings_html_list else "<p>No findings details to display.</p>"

    # --- Define the HTML Template String ---
    # (HTML structure, CSS, JS remains the same as previous version)
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gemini Security Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f7fc; color: #333; }}
        .container {{ background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); max-width: 1200px; margin: auto; }}
        h1, h2, h3 {{ color: #1a2a4d; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-bottom: 20px;}}
        h1 {{ text-align: center; font-size: 1.8em; }}
        h2 {{ font-size: 1.4em;}}
        h3 {{ font-size: 1.1em; border-bottom: none; margin-bottom: 10px;}}
        .header-info {{ font-size: 0.9em; color: #666; text-align: center; margin-bottom: 30px; }}

        .summary-section {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #eee; }}
        .summary-box {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; border: 1px solid #dee2e6; }}
        .summary-box h3 {{ margin-top: 0; color: #495057; }}
        .summary-box ul {{ list-style: none; padding: 0; margin: 0; }}
        .summary-box li {{ display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 0.95em; border-bottom: 1px dashed #eee; padding-bottom: 5px; }}
        .summary-box li:last-child {{ border-bottom: none; }}
        .summary-box li span:last-child {{ font-weight: bold; background-color: #e9ecef; padding: 2px 6px; border-radius: 3px;}}
        .severity-breakdown li span:first-child {{ display: inline-block; padding: 3px 10px; border-radius: 4px; color: white; font-size: 0.9em; text-align: center; min-width: 80px; font-weight: bold; }}

        .filter-controls {{ margin-bottom: 20px; padding-bottom: 20px; border-bottom: 1px solid #eee; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }}
        .filter-label {{ margin-right: 10px; font-weight: bold; color: #495057; }}
        .filter-btn {{ padding: 8px 15px; font-size: 0.95em; border: 1px solid #ccc; border-radius: 4px; background-color: #f8f9fa; color: #495057; cursor: pointer; transition: background-color 0.2s, color 0.2s, border-color 0.2s; border-left: 5px solid transparent; }}
        .filter-btn:hover {{ background-color: #e9ecef; border-color: #bbb; }}
        .filter-btn.active {{ border-color: #333; font-weight: bold; }}
        .filter-btn.active[data-filter='All'] {{ background-color: #6c757d; color: white; border-color: #5a6268;}}
        .filter-btn.active[data-filter='All']:hover {{ background-color: #5a6268; }}

        .findings-section h2 {{ border-bottom: 1px solid #eee; padding-bottom: 10px; margin-bottom: 20px; }}
        .finding-entry {{ border: 1px solid #e9ecef; border-radius: 5px; margin-bottom: 15px; background-color: #fff; box-shadow: 0 1px 4px rgba(0,0,0,0.07); overflow: hidden; transition: opacity 0.3s ease-out; }}
        .finding-entry.finding-hidden {{ display: none; }}

        .finding-header {{ padding: 12px 18px; background-color: #f8f9fa; border-bottom: 1px solid #e9ecef; cursor: pointer; display: grid; grid-template-columns: auto 1fr auto auto; align-items: center; gap: 15px; }}
        .finding-header:hover {{ background-color: #eef2f7; }}
        .finding-header .severity {{ font-weight: bold; padding: 4px 10px; border-radius: 4px; color: white; font-size: 0.9em; }}
        .finding-header .issue {{ font-weight: bold; color: #343a40; }} /* Title styling */
        .finding-header .file-info {{ font-size: 0.9em; color: #6c757d; text-align: right; white-space: nowrap; }}
        .finding-header .toggle-icon {{ font-size: 1.1em; transition: transform 0.2s; color: #6c757d; justify-self: end; }}
        .finding-header.collapsed .toggle-icon {{ transform: rotate(-90deg); }}

        .finding-details {{ padding: 20px; border-top: 1px solid #e9ecef; background-color: #ffffff; display: none; }}
        .finding-details.visible {{ display: block; }}
        .finding-details h4 {{ margin-top: 0; margin-bottom: 8px; color: #1a2a4d; font-size: 1.05em; }}
        .finding-details pre {{ background-color: #282c34; color: #abb2bf; padding: 15px; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word; font-family: 'Courier New', Courier, monospace; font-size: 0.9em; border: 1px solid #ced4da; max-height: 300px; overflow-y: auto; }}
        .finding-details p {{ margin-top: 0; margin-bottom: 10px; font-size: 0.95em; line-height: 1.6; }}
        .detail-block {{ margin-bottom: 20px; }}

        /* Severity Colors */
        {severity_css}
    </style>
</head>
<body>
    <div class="container">
        <h1>AI Enhanced Secure Code Review Scan Report</h1>
        <div class="header-info">
            Generated on: {display_time} | Scanned Path: {scanned_path_escaped}
        </div>

        <h2>Executive Summary</h2>
        <div class="summary-section">
            <div class="summary-box">
                <h3>Scan Overview</h3>
                <ul>
                    <li><span>Files Analyzed:</span> <span>{files_analyzed}</span></li>
                    <li><span>Files with Errors:</span> <span>{files_with_errors}</span></li>
                    <li><span>Total Findings:</span> <span>{total_findings}</span></li>
                </ul>
            </div>
            <div class="summary-box">
                <h3>Severity Breakdown</h3>
                <ul class="severity-breakdown">
                    {severity_summary_html}
                </ul>
            </div>
            {files_with_errors_html}
        </div>

        <div class="filter-controls">
             <span class="filter-label">Filter by Severity:</span>
             {filter_buttons_html}
        </div>

        <h2>Detailed Findings ({total_findings})</h2>
        <div class="findings-section">
            {findings_html}
        </div>

    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const findingHeaders = document.querySelectorAll('.finding-header');
            findingHeaders.forEach(header => {{
                header.classList.add('collapsed');
                const details = header.nextElementSibling;
                const icon = header.querySelector('.toggle-icon');
                if (details && details.classList.contains('finding-details')) {{
                    header.addEventListener('click', (event) => {{
                        if (event.target.tagName === 'BUTTON') return;
                        const isVisible = details.classList.contains('visible');
                        details.classList.toggle('visible', !isVisible);
                        header.classList.toggle('collapsed', isVisible);
                    }});
                }} else {{
                     if (icon) icon.style.display = 'none';
                }}
            }});

            const filterButtons = document.querySelectorAll('.filter-btn');
            const findingEntries = document.querySelectorAll('.finding-entry');
            filterButtons.forEach(button => {{
                button.addEventListener('click', () => {{
                    const filterValue = button.getAttribute('data-filter');
                    filterButtons.forEach(btn => btn.classList.remove('active'));
                    button.classList.add('active');
                    findingEntries.forEach(entry => {{
                        const severity = entry.getAttribute('data-severity');
                        if (filterValue === 'All' || severity === filterValue) {{
                            entry.classList.remove('finding-hidden');
                        }} else {{
                            entry.classList.add('finding-hidden');
                        }}
                    }});
                }});
            }});
        }});
    </script>
</body>
</html>
"""

    # --- Assemble the final HTML using .format() ---
    final_html = html_content.format(
        display_time=display_time,
        scanned_path_escaped=html.escape(scanned_path),
        files_analyzed=metadata.get('files_analyzed', 0),
        files_with_errors=metadata.get('files_with_errors', 0),
        total_findings=metadata.get('total_findings', 0),
        severity_css=severity_css,
        severity_summary_html=severity_summary_html,
        files_with_errors_html=files_with_errors_html,
        filter_buttons_html=filter_buttons_html,
        findings_html=findings_html
    )

    # --- Write to file ---
    try:
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(final_html)
        print(f"\nHTML report generated: {report_filename}")
    except IOError as e:
        print(f"\nError writing HTML report to {report_filename}: {e}", file=sys.stderr)


# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Perform AI-powered secure code review using Gemini, generate JSON data and an HTML report.")
    parser.add_argument("folder_path", help="The path to the folder containing the code to review.")
    parser.add_argument("-o", "--output", default="gemini_security_report.html", help="Output HTML report filename (default: gemini_security_report.html)")
    parser.add_argument("--json-output", help="Optional: Filename to save the intermediate JSON results.")
    args = parser.parse_args()

    # 1. Configure Gemini API access
    configure_gemini()

    # 2. Perform review and get structured data
    scan_data = review_folder(args.folder_path)

    if scan_data is None:
        sys.exit(1) # Exit if folder review failed early

    # 3. Save JSON output if requested
    if args.json_output:
        try:
            with open(args.json_output, 'w', encoding='utf-8') as f:
                json.dump(scan_data, f, indent=4)
            print(f"JSON results saved to: {args.json_output}")
        except IOError as e:
            print(f"Error writing JSON output to {args.json_output}: {e}", file=sys.stderr)
        except TypeError as e:
             print(f"Error serializing data to JSON: {e}", file=sys.stderr)

    # 4. Generate the HTML report from the structured data
    generate_html_report(scan_data, args.output)

    print("\n--- Security Code Review Finished ---")