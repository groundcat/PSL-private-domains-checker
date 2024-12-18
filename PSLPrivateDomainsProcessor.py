import datetime
import json
import time
import requests
import random
import pandas as pd
import whois as whois_fallback
import whoisdomain as whois
import dns.message
import dns.query
import dns.rdatatype
import dns.rdataclass

try:
    from datetime import UTC  # Python 3.9+
except ImportError:
    UTC = datetime.timezone.utc  # Python 3.2+

def check_dns_status(domain):
    """
    Checks the DNS status of a domain.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        str: The DNS status of the domain ("NXDOMAIN", "ok", or "ERROR")
    """
    def make_request():
        response = make_dns_request(domain, "NS")
        if response is None:
            return "ERROR"
            
        if response.get("Status") == 3:
            return "NXDOMAIN"
        return "ok"
    
    for _ in range(3):  # Reduced retries since we're using a more reliable method
        dns_status = make_request()
        print(f"Attempt {_ + 1}, DNS Status: {dns_status}")
        if dns_status != "ERROR":
            return dns_status
        time.sleep(1)
    return "ERROR"

def make_dns_request(domain, record_type):
    """
    Makes DNS request.
    
    Args:
        domain (str): The domain to query
        record_type (str): The type of DNS record to query
        
    Returns:
        dict: A dictionary containing the parsed DNS response
    """
    dns_servers = [
        ['8.8.8.8', '8.8.4.4'],
        ['1.1.1.1', '1.0.0.1'],
        ['208.67.222.222', '208.67.220.220']
    ]
    selected_group = random.choice(dns_servers)
    selected_dns = random.choice(selected_group)
    dns_servers.remove(selected_group)

    try:
        # Use the selected DNS server as the resolver
        q = dns.message.make_query(dns.name.from_text(domain), dns.rdatatype.from_text(record_type))
        r = dns.query.udp(q, selected_dns, timeout=5)

        # Parse the response
        ## Response log
        print(f"DNS Query for {domain} using {selected_dns} with record type {record_type}: \n\t{r.to_text().replace('\n','\n\t')}")
            
        # Check for empty response (NXDOMAIN or no records)
        if not r.answer:
            # Run another query to check if it's for sure NXDOMAIN
            r = dns.query.udp(q, random.choice(random.choice(dns_servers)), timeout=5)
            if not r.answer:
                return {"Status": 3}
            
        # Parse the dig output
        answer = []
        for record in r.answer:
            if record.rdtype == dns.rdatatype.TXT:
                for txt_record in record:
                    answer.append({"data": txt_record.to_text().strip('"').strip("'")})
            else:
                answer.append({"data": record.to_text()})
                        
        return {"Answer": answer}
        
    except dns.exception.Timeout:
        print(f"dns request timed out for {domain}")
        return None
    except Exception as e:
        print(f"Error executing dig command for {domain}: {e}")
        return None


def check_psl_txt_record(domain):
    """
    Checks the _psl TXT record for a domain.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        str: The _psl TXT record status of the domain
    """
    # Prepare the domain for the TXT check
    domain = domain.lstrip('*.').lstrip('!').encode('idna').decode('ascii')
    psl_domain = f"_psl.{domain}"
    
    def make_request():
        response = make_dns_request(psl_domain, "TXT")
        if response is None:
            return "ERROR"
            
        if response.get("Status") == 3:
            print(f"NXDOMAIN for {psl_domain}")
            return "invalid"
            
        txt_records = [record.get("data", "") for record in response.get("Answer", [])]
        print(f"TXT Records for {psl_domain}: {txt_records}")
        
        for record in txt_records:
            if "github.com/publicsuffix/list/pull/" in record:
                print(f"Found valid PSL record: {record}")
                return "valid"
                
        print(f"No valid PSL record found in: {txt_records}")
        return "invalid"
    
    for _ in range(3):
        psl_txt_status = make_request()
        print(f"{psl_domain} Attempt {_ + 1}, PSL TXT Status: {psl_txt_status}")
        if psl_txt_status != "ERROR":
            return psl_txt_status
        time.sleep(1)
    return "ERROR"

def get_whois_data(domain):
    """
    Retrieves WHOIS data for a domain using the whoisdomain package.
    Falls back to python-whois if whoisdomain fails.

    Args:
        domain (str): The domain to query.

    Returns:
        tuple: A tuple containing WHOIS domain status, expiry date, registration date, and WHOIS status.
    """
    try:
        d = whois.query(domain)
        whois_domain_status = d.statuses
        whois_expiry = d.expiration_date
        whois_registration = d.creation_date
        whois_status = "ok"
    except Exception as e:
        print(f"whoisdomain Exception: {e}")
        try:
            w = whois_fallback.whois(domain)
            whois_domain_status = w.status
            whois_expiry = w.expiration_date
            whois_registration = w.creation_date
            if isinstance(whois_expiry, list):
                whois_expiry = whois_expiry[0]
            if isinstance(whois_registration, list):
                whois_registration = whois_registration[0]
            whois_status = "ok"
        except Exception as fallback_e:
            print(f"python-whois Exception: {fallback_e}")
            whois_domain_status = None
            whois_expiry = None
            whois_registration = None
            whois_status = "ERROR"
    return whois_domain_status, whois_expiry, whois_registration, whois_status


class PSLPrivateDomainsProcessor:
    """
    A class to process PSL private section domains, check their status, and save the results.
    """

    def __init__(self):
        """
        Initializes the PSLPrivateDomainsProcessor with default values and settings.
        """
        self.psl_url = "https://publicsuffix.org/list/public_suffix_list.dat"
        self.psl_icann_marker = "// ===BEGIN ICANN DOMAINS==="
        self.psl_private_marker = "// ===BEGIN PRIVATE DOMAINS==="
        self.columns = [
            "psl_entry",
            "top_level_domain",
            "dns_status",
            "whois_status",
            "whois_domain_expiry_date",
            "whois_domain_registration_date",
            "whois_domain_status",
            "psl_txt_status",
            "expiry_check_status"
        ]
        self.df = pd.DataFrame(columns=self.columns)
        self.icann_domains = set()

    def fetch_psl_data(self):
        """
        Fetches the PSL data from the specified URL.

        Returns:
            str: The raw PSL data.
        """
        print("Fetching PSL data from URL...")
        response = requests.get(self.psl_url)
        psl_data = response.text
        print("PSL data fetched.")
        return psl_data

    def parse_domain(self, domain):
        """
        Parses and normalizes a domain.

        Args:
            domain (str): The domain to parse.

        Returns:
            str: The normalized domain.

        Raises:
            ValueError: If no valid top-level domain is found.
        """
        domain = domain.lstrip('*.')  # wildcards (*)
        domain = domain.lstrip('!')  # bangs (!)

        parts = domain.split('.')

        for i in range(len(parts)):
            candidate = '.'.join(parts[i:])
            if candidate in self.icann_domains:
                continue
            elif '.'.join(parts[i + 1:]) in self.icann_domains:
                return candidate.encode('idna').decode('ascii')

        raise ValueError(f"No valid top-level domain found in the provided domain: {domain}")

    def parse_psl_data(self, psl_data):
        """
        Parses the fetched PSL data and separates ICANN and private domains.

        Args:
            psl_data (str): The raw PSL data.

        Returns:
            tuple: A tuple containing the unparsed private domains and the parsed private domains.
        """
        print("Parsing PSL data...")

        lines = psl_data.splitlines()
        process_icann = False
        process_private = False
        private_domains = {}

        for line in lines:
            stripped_line = line.strip()
            if stripped_line == self.psl_icann_marker:
                process_icann = True
                process_private = False
                continue
            elif stripped_line == self.psl_private_marker:
                process_icann = False
                process_private = True
                continue

            if stripped_line.startswith('//') or not stripped_line:
                continue

            if process_icann:
                self.icann_domains.add(stripped_line)
            elif process_private:
                private_domains[self.parse_domain(stripped_line)] = stripped_line

        print(f"Private domains to be processed: {len(private_domains)}\n"
              f"ICANN domains: {len(self.icann_domains)}")

        print("Private domains in the publicly registrable name space: ", len(private_domains))

        return private_domains.values(), private_domains.keys()

    def process_domains(self, raw_domains, domains):
        """
        Processes each domain, performing DNS, WHOIS, and _psl TXT record checks.

        Args:
            raw_domains (list): A list of unparsed domains to process.
            domains (list): A list of domains to process.
        """
        data = []
        # Get current date in UTC, time component zeroed out
        current_date = datetime.datetime.now(UTC).date()
        expiry_threshold = current_date + datetime.timedelta(days=365 * 2)

        for raw_domain, domain in zip(raw_domains, domains):
            whois_domain_status, whois_expiry, whois_registration, whois_status = get_whois_data(domain)
            dns_status = check_dns_status(domain)
            psl_txt_status = check_psl_txt_record(raw_domain)

            if whois_status == "ERROR":
                expiry_check_status = "ERROR"
            else:
                # Convert expiry datetime to date only for comparison
                expiry_date = whois_expiry.date() if whois_expiry else None
                expiry_check_status = "ok" if expiry_date and expiry_date >= expiry_threshold else "FAIL_2Y"

            print(
                f"{domain} - DNS Status: {dns_status}, "
                f"Expiry: {expiry_date if whois_expiry else None}, "
                f"Registration: {whois_registration.date() if whois_registration else None}, "
                f"PSL TXT Status: {psl_txt_status}, "
                f"Expiry Check: {expiry_check_status}")

            data.append({
                "psl_entry": domain,
                "top_level_domain": domain,
                "whois_domain_status": json.dumps(whois_domain_status),
                "whois_domain_expiry_date": expiry_date if whois_expiry else None,
                "whois_domain_registration_date": whois_registration.date() if whois_registration else None,
                "whois_status": whois_status,
                "dns_status": dns_status,
                "psl_txt_status": psl_txt_status,
                "expiry_check_status": expiry_check_status
            })

        self.df = pd.DataFrame(data, columns=self.columns)

    def save_results(self):
        """
        Saves all processed domain data to data/all.csv.
        """
        sorted_df = self.df.sort_values(by="psl_entry")
        sorted_df.to_csv("data/all.csv", index=False)

    def save_invalid_results(self):
        """
        Saves domains with invalid DNS or expired WHOIS data to data/nxdomain.csv and data/expired.csv.
        """
        nxdomain_df = self.df[self.df["dns_status"] != "ok"].sort_values(by="psl_entry")
        nxdomain_df.to_csv("data/nxdomain.csv", index=False)

        current_date = datetime.datetime.now(UTC).date()
        expired_df = self.df[
            self.df["whois_domain_expiry_date"].notnull() &
            (self.df["whois_domain_expiry_date"] < current_date)
        ].sort_values(by="psl_entry")
        expired_df.to_csv("data/expired.csv", index=False)

    def save_hold_results(self):
        """
        Saves domains with WHOIS status containing any form of "hold" to data/hold.csv.
        """
        hold_df = self.df[
            self.df["whois_domain_status"].str.contains("hold", case=False, na=False)
        ].sort_values(by="psl_entry")
        hold_df.to_csv("data/hold.csv", index=False)

    def save_missing_psl_txt_results(self):
        """
        Saves domains with invalid _psl TXT records to data/missing_psl_txt.csv.
        """
        missing_psl_txt_df = self.df[self.df["psl_txt_status"] == "invalid"].sort_values(by="psl_entry")
        missing_psl_txt_df.to_csv("data/missing_psl_txt.csv", index=False)

    def save_expiry_less_than_2yrs_results(self):
        """
        Saves domains with WHOIS expiry date less than 2 years from now to data/expiry_less_than_2yrs.csv.
        """
        expiry_less_than_2yrs_df = self.df[self.df["expiry_check_status"] == "FAIL_2Y"].sort_values(by="psl_entry")
        expiry_less_than_2yrs_df.to_csv("data/expiry_less_than_2yrs.csv", index=False)

    def run(self):
        """
        Executes the entire processing pipeline.
        """
        psl_data = self.fetch_psl_data()
        raw_domains, domains = self.parse_psl_data(psl_data)
        self.process_domains(raw_domains, domains)
        self.save_results()
        self.save_invalid_results()
        self.save_hold_results()
        self.save_missing_psl_txt_results()
        self.save_expiry_less_than_2yrs_results()


if __name__ == "__main__":
    processor = PSLPrivateDomainsProcessor()
    processor.run()
