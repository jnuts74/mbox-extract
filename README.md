# MBOX Attachment Extractor

This project provides a Python script to extract attachments from MBOX files, such as those provided by Google Takeout. The script parses the MBOX format and extracts email attachments into a specified directory.

## Features

- Parses MBOX files to extract email attachments.
- Supports output of extracted attachments to a specified directory.
- Prints real-time progress of the scanning operation.
- Handles filename sanitation to prevent directory traversal issues.

## Prerequisites

- Python 3.x
- Virtual Environment (optional but recommended)

## Setup

1. **Clone the Repository**

   ```bash
   git clone https://github.com/jnuts74/mbox-extract.git
   cd mbox-extract
