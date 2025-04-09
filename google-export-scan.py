import os
import sys
import re
import time
import mailbox
from email import policy
from email.parser import BytesParser

def sanitize_filename(filename):
    sanitized = re.sub(r'[\\/]', '_', filename)
    return sanitized

def extract_attachments(mbox_file, extract_dir):
    if not os.path.exists(extract_dir):
        os.makedirs(extract_dir)
    print(f"[DEBUG] Opening mbox file: {mbox_file}")
    mbox = mailbox.mbox(mbox_file)
    print(f"[DEBUG] Successfully opened mbox file: {mbox_file}")
    total_messages = len(mbox)
    print(f"Total messages to scan: {total_messages}")
    for idx, message in enumerate(mbox, start=1):
        print(f"[DEBUG] Processing message {idx}/{total_messages}")
        found_attachment = False
        parsed_message = BytesParser(policy=policy.default).parsebytes(message.as_bytes())
        for part in parsed_message.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            content_disposition = part.get("Content-Disposition")
            if content_disposition and "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    sanitized_filename = sanitize_filename(filename)
                    filepath = os.path.join(extract_dir, sanitized_filename)
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            with open(filepath, 'wb') as fp:
                                fp.write(payload)
                            print(f'Extracted: {filepath}')
                            found_attachment = True
                        except Exception as e:
                            print(f"Failed to write {filepath}: {e}")
                    else:
                        print(f"Warning: Failed to decode payload for {sanitized_filename} in message {idx}")
        if not found_attachment:
            print(f"[DEBUG] No attachments found in message {idx}")
        print(f'Scanned {idx}/{total_messages} messages', end='\r')
    print(f'\nCompleted scanning {total_messages} messages.')

import subprocess

def scan_path(path):
    infected = []
    scanned_count = 0
    for root, dirs, files in os.walk(path):
        for file in files:
            full_path = os.path.join(root, file)
            if file.endswith('.mbox'):
                print(f"[SKIP] Skipping .mbox file: {full_path}")
                continue
            print(f"Scanning: {full_path}")
            scanned_count += 1
            try:
                result = subprocess.run(['clamscan', '--no-summary', full_path], capture_output=True, text=True)
                output = result.stdout.strip()
                if output and "FOUND" in output:
                    # Example output: /path/to/file: Eicar-Test-Signature FOUND
                    parts = output.split(':', 1)
                    if len(parts) == 2:
                        _, rest = parts
                        malware_name = rest.strip().replace('FOUND', '').strip()
                        infected.append((full_path, malware_name))
                        print(f"[INFECTED] {full_path} - {malware_name}")
            except Exception as e:
                print(f"[ERROR] clamscan failed on {full_path}: {e}")
    return infected, scanned_count

def extract_user_mbox_attachments(user_path):
    import re
    found_mbox = False
    mail_dir = os.path.join(user_path, 'Mail')
    if not os.path.isdir(mail_dir):
        print(f"[WARNING] No Mail folder found in {user_path}, skipping mbox extraction.")
        return
    print(f"[INFO] Searching for .mbox files in {mail_dir} ...")
    for dirpath, _, filenames in os.walk(mail_dir):
        for filename in filenames:
            print(f"[DEBUG] Found file: {filename}")
            if filename.lower().endswith('.mbox'):
                found_mbox = True
                mbox_path = os.path.join(dirpath, filename)
                # Create a sanitized directory name based on the mbox filename (without extension)
                base_name = os.path.splitext(filename)[0]
                safe_name = re.sub(r'[\\/]', '_', base_name)
                mbox_extract_dir = os.path.join(dirpath, f"{safe_name}_attachments")
                print(f"[INFO] Extracting attachments from {mbox_path} to {mbox_extract_dir}")
                try:
                    extract_attachments(mbox_path, mbox_extract_dir)
                except Exception as e:
                    print(f"[ERROR] Failed to extract from {mbox_path}: {e}")
    if not found_mbox:
        print(f"[INFO] No .mbox files found in {user_path}")
    else:
        print(f"[INFO] Completed extraction for {user_path}")

def scan_user_export(user_path, root_export_dir):
    start_time = time.time()
    user_infected = []
    user_name = os.path.basename(user_path)
    attachments_dir = os.path.join(user_path, f'attachments_{user_name}')

    # YARA scan using CLI
    yara_rules_path = 'yara-rules-full.yar'
    print(f"[INFO] Preparing to scan user folder with YARA CLI: {user_path}")
    if not os.path.isfile(yara_rules_path):
        print(f"[ERROR] YARA rules file not found: {yara_rules_path}")
    else:
        yara_results = []
        yara_match_count = 0
        file_count = 0

        yara_cmd = ['yara', '-r', yara_rules_path, user_path]
        print(f"[INFO] Running YARA command: {' '.join(yara_cmd)}")

        try:
            result = subprocess.run(yara_cmd, capture_output=True, text=True)
            if result.stderr:
                print(f"[YARA STDERR] {result.stderr.strip()}")

            # Parse YARA output (format: "rule_name file_path")
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split(maxsplit=1)
                    if len(parts) == 2:
                        rule_name, file_path = parts
                        # Skip .mbox files
                        if file_path.endswith('.mbox'):
                            continue
                        yara_match_count += 1
                        details = f"YARA:{rule_name}"
                        yara_results.append((file_path, details))
                        print(f"[YARA DETECT] {file_path} - {rule_name}")
                        file_count += 1
            if yara_match_count == 0:
                print("[INFO] No YARA matches found.")
        except Exception as e:
            print(f"[ERROR] YARA scan failed: {e}")

    # ClamAV scan
    print(f"[INFO] Scanning user folder with ClamAV: {user_path}")
    infected1, count1 = scan_path(user_path)
    user_infected += infected1
    file_count += count1
    if os.path.exists(attachments_dir):
        print(f"[INFO] Scanning extracted attachments with ClamAV: {attachments_dir}")
        infected2, count2 = scan_path(attachments_dir)
        user_infected += infected2
        file_count += count2


    print(f"\n----- {user_name} YARA scan complete: {yara_match_count} matches -----")
    print(f"----- {user_name} ClamAV scan complete: {len(user_infected)} detections -----\n")

    # Combine results
    rel_infected = []
    for full_path, malware in user_infected:
        rel_path = os.path.relpath(full_path, root_export_dir)
        rel_infected.append((rel_path, malware))
    for full_path, details in yara_results:
        rel_path = os.path.relpath(full_path, root_export_dir)
        rel_infected.append((rel_path, details))

    end_time = time.time()

    # Save Markdown report in root export dir
    md_report_path = os.path.join(root_export_dir, f'{user_name}_scan_report.md')
    try:
        with open(md_report_path, 'w') as f:
            f.write(f"# Malware Scan Report for {user_name}\n\n")
            f.write(f"**Scan started:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}\n\n")
            f.write(f"**Scan finished:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))}\n\n")
            f.write(f"**Duration:** {end_time - start_time:.2f} seconds\n\n")
            f.write(f"**Total files scanned:** {file_count}\n\n")
            f.write(f"**ClamAV detections:** {len(user_infected)}\n\n")
            f.write(f"**YARA detections:** {yara_match_count}\n\n")
            if rel_infected:
                f.write("## Detected Threats\n\n")
                f.write("| File Path | Detection |\n")
                f.write("|-----------|-----------|\n")
                for rel_path, malware in rel_infected:
                    f.write(f"| {rel_path} | {malware} |\n")
            else:
                f.write("No infected files found.\n")
        print(f"[INFO] User Markdown scan report saved to {md_report_path}")
    except Exception as e:
        print(f"[ERROR] Failed to write Markdown report for {user_name}: {e}")

    return rel_infected

def main():
    if len(sys.argv) != 2:
        print("Usage: python google-export-scan.py <root_export_folder>")
        sys.exit(1)

    root_export_dir = sys.argv[1]
    if not os.path.isdir(root_export_dir):
        print(f"Error: {root_export_dir} is not a directory")
        sys.exit(1)

    # ClamAV daemon connection removed, using clamscan CLI

    # No YARA rules compilation needed, using CLI directly

    report = {}

    print(f"[DEBUG] Root export directory provided: {root_export_dir}")
    mail_check = os.path.join(root_export_dir, 'Mail')
    if os.path.isdir(mail_check):
        # Single user export
        entry = os.path.basename(root_export_dir.rstrip('/'))
        print(f"[DEBUG] Detected single user export (Mail folder found in root).")
        print(f"\n========== Starting Extraction for {entry} ==========")
        extract_user_mbox_attachments(root_export_dir)
        print(f"\n========== Starting YARA Scan for {entry} ==========")
        print(f"\n========== Starting ClamAV Scan for {entry} ==========")
        infected_files = scan_user_export(root_export_dir, root_export_dir)
        if infected_files:
            report[entry] = infected_files
    else:
        # Multi-user export root
        print(f"[DEBUG] Detected multi-user export (no Mail folder in root).")
        for entry in os.listdir(root_export_dir):
            user_path = os.path.join(root_export_dir, entry)
            if not os.path.isdir(user_path):
                continue
            mail_subdir = os.path.join(user_path, 'Mail')
            if not os.path.isdir(mail_subdir):
                print(f"[WARNING] No Mail folder found in {user_path}, skipping extraction.")
            else:
                print(f"\n========== Starting Extraction for {entry} ==========")
                extract_user_mbox_attachments(user_path)
            print(f"\n========== Starting YARA Scan for {entry} ==========")
            print(f"\n========== Starting ClamAV Scan for {entry} ==========")
            infected_files = scan_user_export(user_path, root_export_dir)
            if infected_files:
                report[entry] = infected_files

    # Write global Markdown report
    report_path = os.path.join(root_export_dir, 'malware_scan_report.md')
    with open(report_path, 'w') as f:
        f.write("# Consolidated Malware Scan Report\n\n")
        f.write(f"**Scan completed:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n\n")
        total_detections = sum(len(files) for files in report.values())
        f.write(f"**Total infected files detected:** {total_detections}\n\n")
        if total_detections > 0:
            f.write("## Detected Threats\n\n")
            f.write("| User | File Path | Detection |\n")
            f.write("|-------|-----------|-----------|\n")
            for user, files in report.items():
                for rel_path, malware in files:
                    f.write(f"| {user} | {rel_path} | {malware} |\n")
        else:
            f.write("No infected files found across all exports.\n")
    print(f"[INFO] Malware scan complete. Global Markdown report saved to {report_path}")

if __name__ == "__main__":
    main()
