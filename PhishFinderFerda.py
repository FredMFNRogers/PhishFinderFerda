#!/usr/bin/env python3

import os
import sys
import re
import shlex
import logging
import subprocess
import email
import email.policy
import email.parser
import shutil

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def check_dependencies():
    needed = ["eioc.py", "oledump.py", "pdf-parser.py"]
    for tool in needed:
        if shutil.which(tool) is None and not os.path.exists(tool):
            logging.error(f"{tool} not found in PATH or current folder.")
            sys.exit(1)

def run_command(cmd, capture_output=True):
    try:
        args = shlex.split(cmd)
        result = subprocess.run(args, capture_output=capture_output, text=True)
        if capture_output and result.returncode == 0:
            return result.stdout.strip()
        elif capture_output:
            logging.error(f"Command failed: {result.stderr}")
    except Exception as e:
        logging.error(f"Error running command: {cmd}\n{e}")
    return None

def sanitize_filename(name):
    return re.sub(r'[\\/:"*?<>|]+', '_', name)

def extract_subject(eml_path):
    try:
        with open(eml_path, 'rb') as fp:
            msg = email.message_from_binary_file(fp, policy=email.policy.default)
        sub = msg.get('Subject') or 'No_Subject'
        return sanitize_filename(sub)
    except Exception as e:
        logging.error(f"Error extracting subject from {eml_path}: {e}")
        return "No_Subject"

def create_output_directory(path):
    try:
        os.makedirs(path, exist_ok=True)
        return path
    except Exception as e:
        logging.error(f"Failed creating directory {path}: {e}")
        return None

def extract_attachments_with_python(eml_path, attach_dir):
    try:
        with open(eml_path, 'rb') as fp:
            msg = email.message_from_binary_file(fp, policy=email.policy.default)
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            filename = part.get_filename()
            if filename:
                filename = sanitize_filename(filename)
                out_path = os.path.join(attach_dir, filename)
                with open(out_path, 'wb') as out_f:
                    payload = part.get_payload(decode=True)
                    if payload:
                        out_f.write(payload)
    except Exception as e:
        logging.error(f"Error extracting attachments: {e}")

def run_eioc(eml_path):
    cmd = f"python3 eioc.py '{eml_path}'"
    return run_command(cmd)

def parse_eioc_for_attachments(eioc_output):
    pat = r'Filename:\s+(.+)'
    return re.findall(pat, eioc_output or "")

def extract_macros(office_file):
    cmd = f"python3 oledump.py '{office_file}'"
    out = run_command(cmd)
    if not out:
        logging.info(f"No macros found in {office_file} (empty oledump output).")
        return []
    results = []
    for line in out.splitlines():
        if (' M ' in line or ' m ' in line) and ':' in line:
            left = line.split(':', 1)[0].strip()
            if left.isdigit():
                results.append(left)
    return results

def dump_macro(office_file, stream_id, out_dir):
    macro_name = f"{os.path.basename(office_file)}_{stream_id}.vba"
    macro_path = os.path.join(out_dir, macro_name)
    cmd = f"python3 oledump.py '{office_file}' -s {stream_id} --vbadecompresscorrupt > '{macro_path}'"
    subprocess.run(shlex.split(cmd))
    return macro_path

def parse_pdf_objects(pdf_file, raw_data, out_dir):
    if not raw_data:
        return (
            "No IP addresses found.\n"
            "No URLs found.\n"
            "Extracted Object Numbers and Types:\n"
            "No JS, JavaScript, OpenAction, Launch, or EmbeddedFile objects found.\n"
            "No strings found.\n"
        )
    ip_pat = r'([0-9]{1,3}\.){3}[0-9]{1,3}'
    url_pat = r'URI \([^\)]+\)'
    obj_pat = r'obj (\d+) 0[^<]*<<[^<]*\/Type (\/EmbeddedFile|\/JS|\/JavaScript|\/OpenAction|\/Launch)'
    str_pat = r'"[^"]*"'
    ips = re.findall(ip_pat, raw_data)
    urls = re.findall(url_pat, raw_data)
    objs = re.findall(obj_pat, raw_data, re.DOTALL)
    obj_info = [(m[0], m[1]) for m in objs] if objs else []
    strs = re.findall(str_pat, raw_data)
    lines = []
    if ips:
        lines.append("IP addresses found:")
        lines.extend(ips)
    else:
        lines.append("No IP addresses found.")
    if urls:
        lines.append("URLs found:")
        lines.extend(urls)
    else:
        lines.append("No URLs found.")
    lines.append("Extracted Object Numbers and Types:")
    if obj_info:
        for onum, otype in obj_info:
            lines.append(f"Object Number: {onum}, Object Type: {otype}")
            out_file = os.path.join(out_dir, f"{os.path.basename(pdf_file)}_obj{onum}.bin")
            c = f"python3 pdf-parser.py '{pdf_file}' --object {onum} --raw --filter"
            c += f" > '{out_file}'"
            subprocess.run(shlex.split(c))
    else:
        lines.append("No JS, JavaScript, OpenAction, Launch, or EmbeddedFile objects found.")
    if strs:
        lines.append("Extracted Strings:")
        lines.extend(strs)
    else:
        lines.append("No strings found.")
    return "\n".join(lines)

def process_office(office_file, out_dir, report_file):
    with open(report_file, 'a', encoding='utf-8') as rf:
        rf.write(f"\nOffice Document analysis: {os.path.basename(office_file)}\n")
        rf.write("="*30 + "\n")
    macros = extract_macros(office_file)
    if not macros:
        with open(report_file, 'a', encoding='utf-8') as rf:
            rf.write(f"No macros found in {os.path.basename(office_file)}.\n")
        return
    for m_id in macros:
        macro_path = dump_macro(office_file, m_id, out_dir)
        with open(report_file, 'a', encoding='utf-8') as rf:
            rf.write(f"Extracted macro: {macro_path}\n")

def process_pdf(pdf_file, out_dir, report_file):
    with open(report_file, 'a', encoding='utf-8') as rf:
        rf.write(f"\nPDF Analysis: {os.path.basename(pdf_file)}\n")
        rf.write("="*30 + "\n")
    cmd = f"python3 pdf-parser.py '{pdf_file}' --raw"
    raw = run_command(cmd)
    parsed = parse_pdf_objects(pdf_file, raw, out_dir)
    with open(report_file, 'a', encoding='utf-8') as rf:
        rf.write(parsed + "\n")

def append_eioc_full(eml_path, report_file):
    out = run_eioc(eml_path)
    if out:
        with open(report_file, 'a', encoding='utf-8') as rf:
            rf.write("\n=== EIOC Full Output ===\n")
            rf.write(out + "\n")

def process_eml(eml_path, out_dir):
    base = os.path.basename(eml_path)
    attachments_dir = os.path.join(out_dir, "attachments")
    os.makedirs(attachments_dir, exist_ok=True)
    eioc_output = run_eioc(eml_path)
    attachments_list = parse_eioc_for_attachments(eioc_output)
    extract_attachments_with_python(eml_path, attachments_dir)
    report_file = os.path.join(out_dir, f"{base}_output.txt")
    with open(report_file, 'w', encoding='utf-8') as rf:
        rf.write("EIOC Attachments Found:\n=======================\n")
        if attachments_list:
            for a in attachments_list:
                rf.write(f" - {a}\n")
        else:
            rf.write("No attachments found by EIOC.\n")
    for f_name in os.listdir(attachments_dir):
        lf = f_name.lower()
        full_path = os.path.join(attachments_dir, f_name)
        if lf.endswith('.pdf'):
            process_pdf(full_path, attachments_dir, report_file)
        elif lf.endswith(('.doc', '.docx', '.xls', '.ppt', '.xlsm', '.pptm', '.docm')):
            process_office(full_path, attachments_dir, report_file)
    append_eioc_full(eml_path, report_file)

def main():
    check_dependencies()
    if len(sys.argv) < 2:
        print("Usage: python3 script.py <input_file> [output_directory]")
        sys.exit(1)
    inp = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "output"
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    exts_office = ('.doc', '.docx', '.xls', '.ppt', '.xlsm', '.pptm', '.docm')
    if inp.lower().endswith('.eml'):
        subject = extract_subject(inp)
        subdir = os.path.join(out_dir, subject)
        if not create_output_directory(subdir):
            logging.error("Failed to create output directory.")
            sys.exit(1)
        process_eml(inp, subdir)
    elif inp.lower().endswith('.pdf'):
        pdf_report = os.path.join(out_dir, f"{os.path.basename(inp)}_report.txt")
        with open(pdf_report, 'w', encoding='utf-8') as rf:
            rf.write("PDF Processing Report\n=====================\n")
            rf.write(f"File: {os.path.basename(inp)}\n\n")
        process_pdf(inp, out_dir, pdf_report)
    elif inp.lower().endswith(exts_office):
        doc_report = os.path.join(out_dir, f"{os.path.basename(inp)}_report.txt")
        process_office(inp, out_dir, doc_report)
    else:
        logging.error("Unsupported file type. Only .eml, .pdf, or Office docs.")
        sys.exit(1)

if __name__ == "__main__":
    main()

