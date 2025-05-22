#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May 22 15:01:27 2025

@author: Anani A. Assoutovi
"""

"""
    Our goal here is to:
	1.	Fetches the HTML from the JFK Archives release page.
	2.	Extracts all links to .pdf files.
	3.	Downloads the PDFs using a robust setup (retries, user-agent, progress bar).
	4.	And then save them to a local folder in order to avoid re-downloading existing files.
"""


"""
Now, here is why we use the below libraries:
	•	os – for creating directories and handling file paths
	•	requests – for making HTTP requests
	•	BeautifulSoup – for parsing HTML and extracting links
	•	urljoin – to ensures relative URLs are converted to full URLs
	•	tqdm – to shows a progress bar for downloads
	•	Retry/HTTPAdapter – to add retry logic to failed HTTP requests
"""

import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from tqdm import tqdm
from requests.adapters import HTTPAdapter, Retry


"""
Next, we define:
	•	our target page
	•	the output directory
	•	 and then our User-Agent to avoid getting blocked by the server for using a script

"""
# Constants
BASE_URL = 'https://www.archives.gov/research/jfk/release-2025'
SAVE_DIR = 'jfk_pdfs'
HEADERS = {'User-Agent': 'Mozilla/5.0'}


"""
Here we:
    •	creates a requests.Session() with retry logic
	•	Retries up to 5 times
	•	Waits between retries (exponential backoff)
	•	Only retries on specific status codes (e.g., server errors or too many requests)

"""
# Set up session with retries
session = requests.Session()
retries = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
session.mount('https://', HTTPAdapter(max_retries=retries))


"""
Now, we make a GET request to download the HTML page. If successful, it returns 
the HTML content as a string. If it fails, it logs the error and returns None.

"""
def fetch_page(url):
    """Fetch the HTML content of the page."""
    try:
        response = session.get(url, headers=HEADERS)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching page: {e}")
        return None

"""
Here, we use BeautifulSoup to find all <a> tags with href attributes that end 
in .pdf. Then we use urljoin() to create absolute URLs.

"""
def extract_pdf_links(html, base_url):
    """Extract and return all PDF URLs from the HTML content."""
    soup = BeautifulSoup(html, 'html.parser')
    links = soup.find_all('a', href=True)
    return [
        urljoin(base_url, link['href'])
        for link in links
        if link['href'].lower().endswith('.pdf')
    ]


"""
We download an individual PDF:
	•	Extracts the file name from the URL
	•	Skips the download if the file already exists
	•	Streams the file to disk in chunks for memory-efficiency
	•	Handles download failures with try/except

"""
def download_pdf(url, save_dir):
    filename = os.path.basename(url)
    filepath = os.path.join(save_dir, filename)

    if os.path.exists(filepath):
        return  # Skip existing file

    try:
        response = session.get(url, headers=HEADERS, stream=True)
        response.raise_for_status()
        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
    except requests.RequestException as e:
        print(f"Failed to download {url}: {e}")


"""
Then, we write the Main execution flow:
	1.	We create output directory
	2.	Fetches page HTML
	3.	Extract all PDF URLs
	4.	Loop through each link with a tqdm progress bar
	5.	Download each file via download_pdf()
"""
def main():
    os.makedirs(SAVE_DIR, exist_ok=True)

    print("Fetching page...")
    html = fetch_page(BASE_URL)
    if not html:
        return

    print("Extracting PDF links...")
    pdf_links = extract_pdf_links(html, BASE_URL)
    print(f"Found {len(pdf_links)} PDF files.")

    print("Downloading PDFs...")
    for url in tqdm(pdf_links, desc="Downloading", unit="file"):
        download_pdf(url, SAVE_DIR)

    print(f"Download complete. Files saved in '{SAVE_DIR}'")


if __name__ == '__main__':
    main()