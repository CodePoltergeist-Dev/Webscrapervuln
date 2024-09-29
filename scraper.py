import requests

# Function to scrape vulnerability data from the NVD CVE API
def scrape_nvd_vulnerabilities(results_per_page=2000, start_index=0):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={results_per_page}&startIndex={start_index}"
    
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        
        vulnerabilities = []
        
        # Extract relevant details from the response
        for item in data.get('vulnerabilities', []):
            vulnerability = {
                'id': item['cve']['id'],
                'sourceIdentifier': item['cve']['sourceIdentifier'],
                'published': item['cve']['published'],
                'lastModified': item['cve']['lastModified'],
                'vulnStatus': item['cve']['vulnStatus'],
                'descriptions': item['cve']['descriptions'],
                'metrics': {
                    'cvssMetricV2': {
                        'baseScore': item.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('baseScore'),
                        'baseSeverity': item.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('baseSeverity')
                    }
                },
                'references': [ref['url'] for ref in item['cve'].get('references', [])]
            }
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    else:
        print(f"Error fetching data: {response.status_code}")
        return []

# Example usage
if __name__ == "__main__":
    vulnerabilities = scrape_nvd_vulnerabilities()
    for vuln in vulnerabilities:
        print(vuln)  # Print each vulnerability for confirmation

