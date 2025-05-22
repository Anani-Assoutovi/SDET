#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May 22 15:27:13 2025

@author: Anani A. Assoutovi
"""

import os
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from tqdm import tqdm
from requests.adapters import HTTPAdapter, Retry
from zipfile import ZipFile

# Set up session with retries
session = requests.Session()
retries = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
session.mount('https://', HTTPAdapter(max_retries=retries))
HEADERS = {'User-Agent': 'Mozilla/5.0'}


def fetch_page(url):
    """Fetch the HTML content from a URL."""
    try:
        response = session.get(url, headers=HEADERS)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"[ERROR] Failed to fetch page: {e}")
        return None


def extract_pdf_links(html, base_url):
    """Extract all .pdf links from the HTML content."""
    soup = BeautifulSoup(html, 'html.parser')
    links = soup.find_all('a', href=True)
    return [
        urljoin(base_url, link['href'])
        for link in links
        if link['href'].lower().endswith('.pdf')
    ]


def download_pdf(url, save_dir, skip_existing=True):
    """Download a PDF file to the specified directory."""
    filename = os.path.basename(url)
    filepath = os.path.join(save_dir, filename)

    if skip_existing and os.path.exists(filepath):
        return filepath

    try:
        response = session.get(url, headers=HEADERS, stream=True)
        response.raise_for_status()
        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return filepath
    except requests.RequestException as e:
        print(f"[ERROR] Failed to download {url}: {e}")
        return None


def zip_downloaded_pdfs(pdf_paths, zip_name):
    """Zip all downloaded PDF files into a single archive."""
    with ZipFile(zip_name, 'w') as zipf:
        for file_path in pdf_paths:
            if file_path and os.path.exists(file_path):
                arcname = os.path.basename(file_path)
                zipf.write(file_path, arcname)
    print(f"[ZIP] Created archive: {zip_name}")


def main(url, output_dir, skip_existing=True, zip_result=False):
    """Main scraper logic."""
    os.makedirs(output_dir, exist_ok=True)

    print(f"[INFO] Fetching: {url}")
    html = fetch_page(url)
    if not html:
        return

    print("[INFO] Extracting PDF links...")
    pdf_links = extract_pdf_links(html, url)
    print(f"[INFO] Found {len(pdf_links)} PDF file(s).")

    downloaded_files = []
    for pdf_url in tqdm(pdf_links, desc="Downloading PDFs", unit="file", colour='green'):
        path = download_pdf(pdf_url, output_dir, skip_existing=skip_existing)
        if path:
            downloaded_files.append(path)

    print(f"[DONE] Downloaded {len(downloaded_files)} PDF(s) to '{output_dir}'")

    if zip_result and downloaded_files:
        #zip_path = os.path.join(output_dir, 'jfk_pdfs.zip')
        zip_path = f"{os.path.basename(output_dir.rstrip('/'))}.zip"
        zip_downloaded_pdfs(downloaded_files, zip_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PDF Scraper CLI Tool')
    parser.add_argument('--url', type=str, required=True, help='Web page URL to scrape PDFs from')
    parser.add_argument('--out', type=str, default='pdfs', help='Output directory for PDF files')
    parser.add_argument('--force', action='store_true', help='Force re-download of existing files')
    parser.add_argument('--zip', action='store_true', help='Zip all downloaded PDFs after download')

    args = parser.parse_args()
    main(args.url, args.out, skip_existing=not args.force, zip_result=args.zip)