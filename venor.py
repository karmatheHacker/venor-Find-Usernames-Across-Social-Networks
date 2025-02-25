"""
Venor: Find Usernames Across Social Networks
Developed by Rabin
"""

import csv
import os
import platform
import re
import sys
import time
import random
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from time import monotonic

import requests
from requests_futures.sessions import FuturesSession
from torrequest import TorRequest
from result import QueryStatus
from result import QueryResult
from notify import QueryNotifyPrint
from sites import SitesInformation

module_name = "Venor: Find Usernames Across Social Networks"
__version__ = "1.0.0"

# List of user agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
]


class VenorFuturesSession(FuturesSession):
    def request(self, method, url, hooks={}, *args, **kwargs):
        """Request URL with response time measurement."""
        start = monotonic()

        def response_time(resp, *args, **kwargs):
            """Measure response time."""
            resp.elapsed = monotonic() - start
            return

        try:
            if isinstance(hooks['response'], list):
                hooks['response'].insert(0, response_time)
            elif isinstance(hooks['response'], tuple):
                hooks['response'] = list(hooks['response'])
                hooks['response'].insert(0, response_time)
            else:
                hooks['response'] = [response_time, hooks['response']]
        except KeyError:
            hooks['response'] = [response_time]

        return super(VenorFuturesSession, self).request(method, url, hooks=hooks, *args, **kwargs)


def get_response(request_future, error_type, social_network):
    """Handle response from an asynchronous request."""
    response = None
    error_context = "General Unknown Error"
    exception_text = None

    try:
        response = request_future.result()
        if response.status_code:
            error_context = None
    except requests.exceptions.HTTPError as errh:
        error_context = "HTTP Error"
        exception_text = str(errh)
    except requests.exceptions.ProxyError as errp:
        error_context = "Proxy Error"
        exception_text = str(errp)
    except requests.exceptions.ConnectionError as errc:
        error_context = "Error Connecting"
        exception_text = str(errc)
    except requests.exceptions.Timeout as errt:
        error_context = "Timeout Error"
        exception_text = str(errt)
    except requests.exceptions.RequestException as err:
        error_context = "Unknown Error"
        exception_text = str(err)

    return response, error_context, exception_text


def venor(username, site_data, query_notify, tor=False, unique_tor=False, proxy=None, timeout=None):
    """Run Venor analysis for a username."""
    query_notify.start(username)

    if tor or unique_tor:
        underlying_request = TorRequest()
        underlying_session = underlying_request.session
    else:
        underlying_session = requests.session()
        underlying_request = requests.Request()

    max_workers = min(20, len(site_data))
    session = VenorFuturesSession(max_workers=max_workers, session=underlying_session)

    results_total = {}

    for social_network, net_info in site_data.items():
        results_site = {}
        results_site['url_main'] = net_info.get("urlMain")

        headers = {
            'User-Agent': random.choice(USER_AGENTS),
        }
        if "headers" in net_info:
            headers.update(net_info["headers"])

        url = net_info["url"].format(username)
        regex_check = net_info.get("regexCheck")
        if regex_check and re.search(regex_check, username) is None:
            results_site['status'] = QueryResult(username, social_network, url, QueryStatus.ILLEGAL)
            results_site["url_user"] = ""
            results_site['http_status'] = ""
            results_site['response_text'] = ""
            query_notify.update(results_site['status'])
        else:
            results_site["url_user"] = url
            url_probe = net_info.get("urlProbe", url)

            if net_info["errorType"] == 'status_code' and net_info.get("request_head_only", True):
                request_method = session.head
            else:
                request_method = session.get

            allow_redirects = net_info["errorType"] != "response_url"

            if proxy:
                proxies = {"http": proxy, "https": proxy}
                future = request_method(url=url_probe, headers=headers, proxies=proxies, allow_redirects=allow_redirects, timeout=timeout)
            else:
                future = request_method(url=url_probe, headers=headers, allow_redirects=allow_redirects, timeout=timeout)

            net_info["request_future"] = future

            if unique_tor:
                underlying_request.reset_identity()

        results_total[social_network] = results_site

    for social_network, net_info in site_data.items():
        results_site = results_total.get(social_network)
        url = results_site.get("url_user")
        status = results_site.get("status")
        if status is not None:
            continue

        error_type = net_info["errorType"]
        future = net_info["request_future"]
        r, error_text, exception_text = get_response(future, error_type, social_network)

        try:
            response_time = r.elapsed
        except AttributeError:
            response_time = None

        try:
            http_status = r.status_code
        except:
            http_status = "?"
        try:
            response_text = r.text.encode(r.encoding)
        except:
            response_text = ""

        if error_text:
            result = QueryResult(username, social_network, url, QueryStatus.UNKNOWN, query_time=response_time, context=error_text)
        elif error_type == "message":
            error_flag = True
            errors = net_info.get("errorMsg")
            if isinstance(errors, str):
                if errors in r.text:
                    error_flag = False
            else:
                for error in errors:
                    if error in r.text:
                        error_flag = False
                        break
            if error_flag:
                result = QueryResult(username, social_network, url, QueryStatus.CLAIMED, query_time=response_time)
            else:
                result = QueryResult(username, social_network, url, QueryStatus.AVAILABLE, query_time=response_time)
        elif error_type == "status_code":
            if 200 <= r.status_code < 300:
                result = QueryResult(username, social_network, url, QueryStatus.CLAIMED, query_time=response_time)
            else:
                result = QueryResult(username, social_network, url, QueryStatus.AVAILABLE, query_time=response_time)
        elif error_type == "response_url":
            if 200 <= r.status_code < 300:
                result = QueryResult(username, social_network, url, QueryStatus.CLAIMED, query_time=response_time)
            else:
                result = QueryResult(username, social_network, url, QueryStatus.AVAILABLE, query_time=response_time)
        else:
            raise ValueError(f"Unknown Error Type '{error_type}' for site '{social_network}'")

        query_notify.update(result)
        results_site['status'] = result
        results_site['http_status'] = http_status
        results_site['response_text'] = response_text
        results_total[social_network] = results_site

    query_notify.finish()
    return results_total


def timeout_check(value):
    """Validate timeout argument."""
    try:
        timeout = float(value)
    except:
        raise ValueError(f"Timeout '{value}' must be a number.")
    if timeout <= 0:
        raise ValueError(f"Timeout '{value}' must be greater than 0.0s.")
    return timeout


def main():
    version_string = f"%(prog)s {__version__}\n" + \
                     f"Python:  {platform.python_version()}"

    parser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter,
                            description=f"{module_name} (Version {__version__})")
    parser.add_argument("--version", action="version", version=version_string, help="Display version information.")
    parser.add_argument("--verbose", "-v", action="store_true", dest="verbose", default=False, help="Display extra debugging information.")
    parser.add_argument("--folderoutput", "-fo", dest="folderoutput", help="Save results to a folder.")
    parser.add_argument("--output", "-o", dest="output", help="Save results to a file.")
    parser.add_argument("--tor", "-t", action="store_true", dest="tor", default=False, help="Make requests over Tor.")
    parser.add_argument("--unique-tor", "-u", action="store_true", dest="unique_tor", default=False, help="Use a new Tor circuit for each request.")
    parser.add_argument("--csv", action="store_true", dest="csv", default=False, help="Save results in CSV format.")
    parser.add_argument("--site", action="append", metavar='SITE_NAME', dest="site_list", default=None, help="Limit analysis to specific sites.")
    parser.add_argument("--proxy", "-p", metavar='PROXY_URL', action="store", dest="proxy", default=None, help="Make requests over a proxy.")
    parser.add_argument("--timeout", action="store", metavar='TIMEOUT', dest="timeout", type=timeout_check, default=None, help="Timeout for requests.")
    parser.add_argument("--print-all", action="store_true", dest="print_all", help="Output all results.")
    parser.add_argument("--no-color", action="store_true", dest="no_color", default=False, help="Disable colored output.")
    parser.add_argument("username", nargs='+', metavar='USERNAMES', action="store", help="One or more usernames to check.")
    parser.add_argument("--local", "-l", action="store_true", default=False, help="Use local data.json file.")

    args = parser.parse_args()

    if args.tor and args.proxy:
        raise Exception("Tor and Proxy cannot be used simultaneously.")

    if args.output and args.folderoutput:
        print("Error: Use either --output or --folderoutput, not both.")
        sys.exit(1)

    try:
        if args.local:
            sites = SitesInformation(os.path.join(os.path.dirname(__file__), 'resources/data.json'))
        else:
            sites = SitesInformation(args.json_file)
    except Exception as error:
        print(f"ERROR:  {error}")
        sys.exit(1)

    site_data_all = {site.name: site.information for site in sites}

    if args.site_list:
        site_data = {}
        site_missing = []
        for site in args.site_list:
            counter = 0
            for existing_site in site_data_all:
                if site.lower() == existing_site.lower():
                    site_data[existing_site] = site_data_all[existing_site]
                    counter += 1
            if counter == 0:
                site_missing.append(f"'{site}'")
        if site_missing:
            print(f"Error: Sites not found: {', '.join(site_missing)}.")
        if not site_data:
            sys.exit(1)
    else:
        site_data = site_data_all

    query_notify = QueryNotifyPrint(result=None, verbose=args.verbose, print_all=args.print_all, color=not args.no_color)

    for username in args.username:
        results = venor(username, site_data, query_notify, tor=args.tor, unique_tor=args.unique_tor, proxy=args.proxy, timeout=args.timeout)

        if args.output:
            result_file = args.output
        elif args.folderoutput:
            os.makedirs(args.folderoutput, exist_ok=True)
            result_file = os.path.join(args.folderoutput, f"{username}.txt")
        else:
            result_file = f"{username}.txt"

        with open(result_file, "w", encoding="utf-8") as file:
            exists_counter = 0
            for website_name in results:
                dictionary = results[website_name]
                if dictionary.get("status").status == QueryStatus.CLAIMED:
                    exists_counter += 1
                    file.write(dictionary["url_user"] + "\n")
            file.write(f"Total Websites Username Detected On : {exists_counter}\n")

        if args.csv:
            with open(username + ".csv", "w", newline='', encoding="utf-8") as csv_report:
                writer = csv.writer(csv_report)
                writer.writerow(['username', 'name', 'url_main', 'url_user', 'exists', 'http_status', 'response_time_s'])
                for site in results:
                    response_time_s = results[site]['status'].query_time
                    if response_time_s is None:
                        response_time_s = ""
                    writer.writerow([username, site, results[site]['url_main'], results[site]['url_user'], str(results[site]['status'].status), results[site]['http_status'], response_time_s])

        print()


if __name__ == "__main__":
    main()
