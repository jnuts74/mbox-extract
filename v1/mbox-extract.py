import mailbox
import os
import re
from email import policy
from email.parser import BytesParser

def sanitize_filename(filename):
    # Replace any '/' or '\' with an underscore
    sanitized = re.sub(r'[\\/]', '_', filename)
    return sanitized

def extract_attachments(mbox_file, extract_dir):
    if not os.path.exists(extract_dir):
        os.makedirs(extract_dir)

    mbox = mailbox.mbox(mbox_file)
    
    total_messages = len(mbox)
    print(f"Total messages to scan: {total_messages}")

    for idx, message in enumerate(mbox, start=1):
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
                    if payload:  # Ensure the payload is not None
                        try:
                            with open(filepath, 'wb') as fp:
                                fp.write(payload)
                            print(f'Extracted: {filepath}')
                        except Exception as e:
                            print(f"Failed to write {filepath}: {e}")
                    else:
                        print(f"Warning: Failed to decode payload for {sanitized_filename} in message {idx}")

        print(f'Scanned {idx}/{total_messages} messages', end='\r')
        
    print(f'\nCompleted scanning {total_messages} messages.')

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print("Usage: python takeout-extract.py <mbox_file> <output_directory>")
    else:
        mbox_file = sys.argv[1]
        extract_dir = sys.argv[2]
        extract_attachments(mbox_file, extract_dir)
