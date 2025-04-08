
---

# MBOX Attachment Extractor

This project provides a Python script to extract attachments from MBOX files, such as those provided by Google Takeout. The script parses the MBOX format and extracts email attachments into a specified directory.

## Features

- Parses MBOX files to extract email attachments.
- Supports output of extracted attachments to a specified directory.
- Prints real-time progress of the scanning operation.
- Handles filename sanitation to prevent directory traversal issues.
- Does not require any external Python libraries beyond the standard library.

## Prerequisites

- Python 3.x

## Setup

1. **Clone the Repository**

   ```bash
   git clone https://github.com/jnuts74/mbox-extract.git
   cd mbox-extract
   ```

## Usage

To run the script, use the following command format:

```bash
python3 mbox-extract.py <mbox_file> <output_directory>
```

- `<mbox_file>`: The path to the MBOX file you want to process.
- `<output_directory>`: The directory where you want to save the extracted attachments.

### Example

Here's an example of how to use the script:

```bash
python3 mbox-extract.py mymail.mbox extracted-files
```

In this example, the script will process `mymail.mbox` and save the extracted attachments into the `extracted-files` folder.

## How It Works

- The script reads the MBOX file and iterates through each email message.
- It checks each part of the message to determine if it's an attachment.
- If an attachment is found, the filename is sanitized and saved to the specified output directory.
- Progress is printed to the console as each message is processed.

## Contributing

If you'd like to contribute to this project, please fork the repository and use a feature branch. Pull requests are warmly welcome.

## License

This project is licensed under the MIT License. 
