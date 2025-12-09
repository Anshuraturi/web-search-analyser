#!/usr/bin/env python3
"""
Browser History Analyzer - Advanced Cybersecurity Tool
=====================================================
Analyzes browser history from Chrome, Firefox, Edge, and Safari
to detect security threats, suspicious activities, and generate
comprehensive forensic reports.
"""

import os
import sqlite3
import json
import csv
from datetime import datetime, timedelta
import urllib.parse
import re
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional
import platform
import shutil


class BrowserHistoryAnalyzer:
    def __init__(self):
        self.system = platform.system()
        self.supported_browsers = ['Chrome', 'Firefox', 'Edge', 'Safari']

        # Known suspicious domains and patterns
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'malware-site.tk', 'phishing-bank.ml', 'suspicious.ga',
            'free-download.tk', 'urgent-update.cf'
        ]

        self.suspicious_keywords = [
            'hack', 'crack', 'pirate', 'torrent', 'warez',
            'adult', 'casino', 'gambling', 'pharmacy',
            'free-download', 'keygen', 'serial'
        ]

        # Get browser paths for current OS
        self.browser_paths = self._get_browser_paths()
        self.setup_output_directory()

    def setup_output_directory(self):
        """Create output directory for analysis reports"""
        self.output_dir = "browser_analysis_reports"
        os.makedirs(self.output_dir, exist_ok=True)
        print(f"📁 Output directory: {self.output_dir}")

    def _get_browser_paths(self) -> Dict[str, str]:
        """Get browser database paths for different operating systems"""
        system = platform.system()
        home = os.path.expanduser("~")

        if system == "Windows":
            return {
                'Chrome': os.path.join(home, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "History"),
                'Edge': os.path.join(home, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "History"),
                'Firefox': self._find_firefox_profile(home, "AppData/Roaming/Mozilla/Firefox/Profiles")
            }
        elif system == "Darwin":  # macOS
            return {
                'Chrome': os.path.join(home, "Library", "Application Support", "Google", "Chrome", "Default",
                                       "History"),
                'Safari': os.path.join(home, "Library", "Safari", "History.db"),
                'Firefox': self._find_firefox_profile(home, "Library/Application Support/Firefox/Profiles")
            }
        else:  # Linux
            return {
                'Chrome': os.path.join(home, ".config", "google-chrome", "Default", "History"),
                'Firefox': self._find_firefox_profile(home, ".mozilla/firefox")
            }

    def _find_firefox_profile(self, home: str, relative_path: str) -> Optional[str]:
        """Find Firefox profile database"""
        try:
            firefox_dir = os.path.join(home, *relative_path.split('/'))
            if os.path.exists(firefox_dir):
                profiles = [d for d in os.listdir(firefox_dir) if '.default' in d]
                if profiles:
                    return os.path.join(firefox_dir, profiles, "places.sqlite")
        except:
            pass
        return None

    def extract_chrome_history(self, db_path: str) -> List[Dict]:
        """Extract history from Chrome/Edge SQLite database"""
        history_data = []

        if not os.path.exists(db_path):
            return history_data

        try:
            # Create temporary copy to avoid locking issues
            temp_db = db_path + "_temp"
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            # Query Chrome history database
            query = """
                SELECT url, title, visit_count, last_visit_time
                FROM urls 
                WHERE visit_count > 0
                ORDER BY last_visit_time DESC
                LIMIT 10000
            """

            cursor.execute(query)
            rows = cursor.fetchall()

            for row in rows:
                url, title, visit_count, last_visit_time = row

                # Convert Chrome timestamp (microseconds since 1601-01-01)
                if last_visit_time > 0:
                    timestamp = datetime(1601, 1, 1) + timedelta(microseconds=last_visit_time)
                else:
                    timestamp = datetime.now()

                history_data.append({
                    'url': url,
                    'title': title or 'No Title',
                    'visit_count': visit_count,
                    'timestamp': timestamp,
                    'domain': urllib.parse.urlparse(url).netloc
                })

            conn.close()
            os.remove(temp_db)

        except Exception as e:
            print(f"❌ Error reading Chrome history: {str(e)}")

        return history_data

    def extract_firefox_history(self, db_path: str) -> List[Dict]:
        """Extract history from Firefox SQLite database"""
        history_data = []

        if not os.path.exists(db_path):
            return history_data

        try:
            temp_db = db_path + "_temp"
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            # Query Firefox history database
            query = """
                SELECT h.url, h.title, h.visit_count, h.last_visit_date
                FROM moz_places h
                WHERE h.visit_count > 0
                ORDER BY h.last_visit_date DESC
                LIMIT 10000
            """

            cursor.execute(query)
            rows = cursor.fetchall()

            for row in rows:
                url, title, visit_count, last_visit_date = row

                # Convert Firefox timestamp (microseconds since Unix epoch)
                if last_visit_date:
                    timestamp = datetime.fromtimestamp(last_visit_date / 1000000)
                else:
                    timestamp = datetime.now()

                history_data.append({
                    'url': url,
                    'title': title or 'No Title',
                    'visit_count': visit_count,
                    'timestamp': timestamp,
                    'domain': urllib.parse.urlparse(url).netloc
                })

            conn.close()
            os.remove(temp_db)

        except Exception as e:
            print(f"❌ Error reading Firefox history: {str(e)}")

        return history_data

    def analyze_browsing_patterns(self, history_data: List[Dict]) -> Dict:
        """Analyze browsing patterns and extract behavioral insights"""

        if not history_data:
            return {}

        analysis = {
            'total_entries': len(history_data),
            'date_range': {
                'earliest': min(entry['timestamp'] for entry in history_data),
                'latest': max(entry['timestamp'] for entry in history_data)
            },
            'top_domains': Counter(entry['domain'] for entry in history_data).most_common(20),
            'suspicious_domains': [],
            'suspicious_keywords': [],
            'browsing_times': defaultdict(int),
            'daily_activity': defaultdict(int),
            'most_visited': sorted(history_data, key=lambda x: x['visit_count'], reverse=True)[:20]
        }

        # Detect suspicious domains
        for entry in history_data:
            domain = entry['domain'].lower()
            for sus_domain in self.suspicious_domains:
                if sus_domain in domain:
                    analysis['suspicious_domains'].append({
                        'url': entry['url'],
                        'domain': domain,
                        'title': entry['title'],
                        'timestamp': entry['timestamp'],
                        'reason': f'Contains suspicious domain: {sus_domain}'
                    })

        # Detect suspicious keywords in URLs and titles
        for entry in history_data:
            url_lower = entry['url'].lower()
            title_lower = entry['title'].lower()

            for keyword in self.suspicious_keywords:
                if keyword in url_lower or keyword in title_lower:
                    analysis['suspicious_keywords'].append({
                        'url': entry['url'],
                        'title': entry['title'],
                        'timestamp': entry['timestamp'],
                        'keyword': keyword
                    })

        # Analyze browsing times (hourly distribution)
        for entry in history_data:
            hour = entry['timestamp'].hour
            analysis['browsing_times'][hour] += 1

        # Analyze daily activity
        for entry in history_data:
            date = entry['timestamp'].date()
            analysis['daily_activity'][date] += 1

        return analysis

    def detect_security_issues(self, history_data: List[Dict]) -> Dict:
        """Detect potential security threats in browsing history"""

        security_issues = {
            'http_sites': [],  # Insecure HTTP sites
            'suspicious_downloads': [],  # Potentially malicious downloads
            'potential_phishing': [],  # Phishing site patterns
            'privacy_concerns': [],  # Tracking and analytics
            'malware_domains': [],  # Known malicious domains
            'social_engineering': []  # Social engineering attempts
        }

        for entry in history_data:
            url = entry['url']
            domain = entry['domain']
            title = entry['title']

            # Check for insecure HTTP sites
            if url.startswith('http://') and not url.startswith('https://'):
                if not any(local in domain for local in ['localhost', '127.0.0.1', '192.168.']):
                    security_issues['http_sites'].append({
                        'url': url,
                        'title': title,
                        'timestamp': entry['timestamp']
                    })

            # Check for suspicious file downloads
            suspicious_extensions = ['.exe', '.scr', '.bat', '.com', '.pif', '.zip', '.rar']
            if any(ext in url.lower() for ext in suspicious_extensions):
                security_issues['suspicious_downloads'].append({
                    'url': url,
                    'title': title,
                    'timestamp': entry['timestamp']
                })

            # Check for phishing patterns
            phishing_patterns = [
                'secure-update', 'verify-account', 'suspended-account',
                'urgent-action', 'confirm-identity', 'account-locked',
                'payment-failed', 'security-alert'
            ]

            if any(pattern in url.lower() or pattern in title.lower() for pattern in phishing_patterns):
                matched_pattern = next(p for p in phishing_patterns if p in url.lower() or p in title.lower())
                security_issues['potential_phishing'].append({
                    'url': url,
                    'title': title,
                    'timestamp': entry['timestamp'],
                    'pattern': matched_pattern
                })

            # Check for privacy tracking domains
            tracking_domains = [
                'doubleclick.net', 'googleadservices.com', 'facebook.com/tr',
                'google-analytics.com', 'googlesyndication.com', 'scorecardresearch.com'
            ]

            if any(tracker in domain for tracker in tracking_domains):
                security_issues['privacy_concerns'].append({
                    'url': url,
                    'domain': domain,
                    'timestamp': entry['timestamp']
                })

            # Check for social engineering keywords
            social_eng_keywords = [
                'winner', 'congratulations', 'prize', 'lottery',
                'free-money', 'urgent', 'act-now', 'limited-time'
            ]

            if any(keyword in url.lower() or keyword in title.lower() for keyword in social_eng_keywords):
                matched_keyword = next(k for k in social_eng_keywords if k in url.lower() or k in title.lower())
                security_issues['social_engineering'].append({
                    'url': url,
                    'title': title,
                    'timestamp': entry['timestamp'],
                    'keyword': matched_keyword
                })

        return security_issues

    def generate_comprehensive_report(self, browser_name: str, analysis: Dict, security_issues: Dict) -> str:
        """Generate detailed forensic analysis report"""

        report = []
        report.append("=" * 80)
        report.append(f"🔍 BROWSER HISTORY FORENSIC ANALYSIS - {browser_name.upper()}")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"System: {platform.system()} {platform.release()}")
        report.append(f"Total History Entries: {analysis.get('total_entries', 0):,}")

        if 'date_range' in analysis and analysis['date_range']:
            earliest = analysis['date_range']['earliest']
            latest = analysis['date_range']['latest']
            report.append(f"Date Range: {earliest.strftime('%Y-%m-%d')} to {latest.strftime('%Y-%m-%d')}")
            report.append(f"Analysis Period: {(latest - earliest).days} days")

        # EXECUTIVE SUMMARY
        report.append("\n" + "=" * 60)
        report.append("📊 EXECUTIVE SUMMARY")
        report.append("=" * 60)

        total_security_issues = sum(len(issues) for issues in security_issues.values())
        report.append(f"Total Security Issues Detected: {total_security_issues}")
        report.append(f"High Priority Threats: {len(security_issues.get('potential_phishing', []))}")
        report.append(f"Suspicious Downloads: {len(security_issues.get('suspicious_downloads', []))}")
        report.append(f"Insecure HTTP Sites: {len(security_issues.get('http_sites', []))}")
        report.append(f"Privacy Tracking Instances: {len(security_issues.get('privacy_concerns', []))}")

        # SECURITY ANALYSIS
        report.append("\n" + "=" * 60)
        report.append("🔒 SECURITY THREAT ANALYSIS")
        report.append("=" * 60)

        if security_issues.get('potential_phishing'):
            report.append("\n⚠️  POTENTIAL PHISHING SITES DETECTED:")
            report.append("-" * 50)
            for i, site in enumerate(security_issues['potential_phishing'][:10], 1):
                report.append(f"{i}. {site['url']}")
                report.append(f"   Title: {site['title']}")
                report.append(f"   Pattern: {site['pattern']}")
                report.append(f"   Time: {site['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
                report.append("")

        if security_issues.get('suspicious_downloads'):
            report.append("\n🔽 SUSPICIOUS DOWNLOADS:")
            report.append("-" * 50)
            for i, download in enumerate(security_issues['suspicious_downloads'][:10], 1):
                report.append(f"{i}. {download['url']}")
                report.append(f"   Time: {download['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
                report.append("")

        # BROWSING BEHAVIOR ANALYSIS
        report.append("\n" + "=" * 60)
        report.append("📈 BROWSING BEHAVIOR ANALYSIS")
        report.append("=" * 60)

        # Top visited domains
        report.append("\nTOP 15 VISITED DOMAINS:")
        report.append("-" * 50)
        for i, (domain, count) in enumerate(analysis.get('top_domains', [])[:15], 1):
            report.append(f"{i:2d}. {domain:<35} {count:>8,} visits")

        # Most active browsing hours
        browsing_times = analysis.get('browsing_times', {})
        if browsing_times:
            report.append("\nBROWSING ACTIVITY BY HOUR:")
            report.append("-" * 50)
            sorted_hours = sorted(browsing_times.items(), key=lambda x: x[1], reverse=True)
            for hour, count in sorted_hours[:10]:
                report.append(f"{hour:2d}:00 - {count:>6,} visits")

        # Most visited individual sites
        report.append("\nMOST FREQUENTLY VISITED SITES:")
        report.append("-" * 50)
        for i, site in enumerate(analysis.get('most_visited', [])[:10], 1):
            title_truncated = site['title'][:50] + "..." if len(site['title']) > 50 else site['title']
            report.append(f"{i:2d}. {site['domain']} ({site['visit_count']} visits)")
            report.append(f"    {title_truncated}")
            report.append("")

        # PRIVACY AND TRACKING ANALYSIS
        if security_issues.get('privacy_concerns'):
            report.append("\n" + "=" * 60)
            report.append("👁️  PRIVACY & TRACKING ANALYSIS")
            report.append("=" * 60)

            tracking_domains = Counter(entry['domain'] for entry in security_issues['privacy_concerns'])
            report.append("\nTOP TRACKING DOMAINS:")
            report.append("-" * 50)
            for domain, count in tracking_domains.most_common(10):
                report.append(f"{domain:<40} {count:>6,} instances")

        # RECOMMENDATIONS
        report.append("\n" + "=" * 60)
        report.append("💡 SECURITY RECOMMENDATIONS")
        report.append("=" * 60)

        recommendations = []

        if len(security_issues.get('potential_phishing', [])) > 0:
            recommendations.append("🚨 High Priority: Phishing sites detected - Review and block these domains")

        if len(security_issues.get('suspicious_downloads', [])) > 0:
            recommendations.append("🔍 Review all downloaded files for malware")

        if len(security_issues.get('http_sites', [])) > 10:
            recommendations.append("🔒 Consider using HTTPS Everywhere browser extension")

        if len(security_issues.get('privacy_concerns', [])) > 50:
            recommendations.append("🛡️  Consider using privacy-focused browser extensions")

        recommendations.extend([
            "📚 Provide security awareness training on phishing recognition",
            "🔄 Implement regular browser security updates",
            "🛡️  Deploy endpoint protection with web filtering",
            "📊 Schedule regular security assessments"
        ])

        for i, rec in enumerate(recommendations, 1):
            report.append(f"{i}. {rec}")

        report.append("\n" + "=" * 80)
        report.append(f"Report completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 80)

        return "\n".join(report)

    def save_csv_data(self, browser_name: str, history_data: List[Dict], security_issues: Dict):
        """Save detailed data to CSV files for further analysis"""

        # Main history CSV
        history_csv = os.path.join(self.output_dir, f"{browser_name.lower()}_complete_history.csv")
        with open(history_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['timestamp', 'url', 'title', 'domain', 'visit_count'])
            writer.writeheader()
            for entry in history_data:
                writer.writerow({
                    'timestamp': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    'url': entry['url'],
                    'title': entry['title'],
                    'domain': entry['domain'],
                    'visit_count': entry['visit_count']
                })

        # Security issues CSV
        security_csv = os.path.join(self.output_dir, f"{browser_name.lower()}_security_issues.csv")
        with open(security_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Issue Type', 'URL', 'Title', 'Timestamp', 'Details'])

            for issue_type, issues in security_issues.items():
                for issue in issues:
                    details = issue.get('pattern', issue.get('keyword', ''))
                    writer.writerow([
                        issue_type,
                        issue['url'],
                        issue.get('title', ''),
                        issue['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                        details
                    ])

        print(f"📊 CSV files saved: {history_csv}, {security_csv}")

    def analyze_browser(self, browser_name: str) -> Dict:
        """Main analysis function for a specific browser"""

        print(f"\n🔍 Starting {browser_name} analysis...")

        db_path = self.browser_paths.get(browser_name)
        if not db_path or not os.path.exists(db_path):
            print(f"❌ {browser_name} history database not found")
            return {'error': f'Database not found: {db_path}'}

        # Extract history data
        if browser_name in ['Chrome', 'Edge']:
            history_data = self.extract_chrome_history(db_path)
        elif browser_name == 'Firefox':
            history_data = self.extract_firefox_history(db_path)
        else:
            print(f"❌ Browser {browser_name} not yet supported")
            return {'error': f'Browser not supported: {browser_name}'}

        if not history_data:
            print(f"❌ No history data extracted from {browser_name}")
            return {'error': 'No history data found'}

        print(f"✅ Extracted {len(history_data):,} history entries")

        # Perform analysis
        print("📊 Analyzing browsing patterns...")
        analysis = self.analyze_browsing_patterns(history_data)

        print("🔒 Detecting security issues...")
        security_issues = self.detect_security_issues(history_data)

        # Generate comprehensive report
        print("📋 Generating report...")
        report_text = self.generate_comprehensive_report(browser_name, analysis, security_issues)

        # Save report to file
        report_filename = os.path.join(self.output_dir, f"{browser_name.lower()}_forensic_report.txt")
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(report_text)

        # Save CSV data
        self.save_csv_data(browser_name, history_data, security_issues)

        print(f"📁 Report saved: {report_filename}")

        return {
            'browser': browser_name,
            'total_entries': len(history_data),
            'security_issues_count': sum(len(issues) for issues in security_issues.values()),
            'analysis': analysis,
            'security_issues': security_issues,
            'report_file': report_filename
        }

    def analyze_all_browsers(self):
        """Analyze all available browsers on the system"""

        print("🚀 Starting comprehensive browser analysis...")
        print(f"🖥️  System: {platform.system()} {platform.release()}")

        results = {}

        for browser in self.supported_browsers:
            try:
                result = self.analyze_browser(browser)
                if 'error' not in result:
                    results[browser] = result
                    print(f"✅ {browser} analysis completed successfully")
                else:
                    print(f"⚠️  {browser}: {result['error']}")
            except Exception as e:
                print(f"❌ Error analyzing {browser}: {str(e)}")

        # Generate summary report
        if results:
            self.generate_summary_report(results)

        return results

    def generate_summary_report(self, all_results: Dict):
        """Generate a summary report across all browsers"""

        summary_lines = []
        summary_lines.append("=" * 80)
        summary_lines.append("🌐 MULTI-BROWSER SECURITY ANALYSIS SUMMARY")
        summary_lines.append("=" * 80)
        summary_lines.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary_lines.append(f"Browsers Analyzed: {len(all_results)}")

        total_entries = sum(result['total_entries'] for result in all_results.values())
        total_security_issues = sum(result['security_issues_count'] for result in all_results.values())

        summary_lines.append(f"Total History Entries: {total_entries:,}")
        summary_lines.append(f"Total Security Issues: {total_security_issues:,}")

        summary_lines.append("\nPER-BROWSER BREAKDOWN:")
        summary_lines.append("-" * 60)

        for browser, result in all_results.items():
            summary_lines.append(f"{browser}:")
            summary_lines.append(f"  Entries: {result['total_entries']:,}")
            summary_lines.append(f"  Security Issues: {result['security_issues_count']}")
            summary_lines.append("")

        # Save summary report
        summary_filename = os.path.join(self.output_dir, "multi_browser_summary.txt")
        with open(summary_filename, 'w', encoding='utf-8') as f:
            f.write("\n".join(summary_lines))

        print(f"📋 Summary report saved: {summary_filename}")


def main():
    """Main execution function"""
    print("=" * 60)
    print("🔍 BROWSER HISTORY ANALYZER - CYBERSECURITY TOOL")
    print("=" * 60)
    print("Forensic analysis tool for browser history security assessment")
    print("Supports: Chrome, Firefox, Edge, Safari")
    print("=" * 60)

    analyzer = BrowserHistoryAnalyzer()

    while True:
        print("\nSelect analysis option:")
        print("1. 🌐 Analyze all browsers")
        print("2. 🔍 Analyze specific browser")
        print("3. 📋 View supported browsers")
        print("4. 🚪 Exit")

        choice = input("\nEnter choice (1-4): ").strip()

        if choice == '1':
            analyzer.analyze_all_browsers()
        elif choice == '2':
            print("\nAvailable browsers:")
            for i, browser in enumerate(analyzer.supported_browsers, 1):
                print(f"{i}. {browser}")

            try:
                browser_choice = int(input("\nSelect browser (1-4): ")) - 1
                if 0 <= browser_choice < len(analyzer.supported_browsers):
                    browser_name = analyzer.supported_browsers[browser_choice]
                    analyzer.analyze_browser(browser_name)
                else:
                    print("❌ Invalid selection")
            except ValueError:
                print("❌ Please enter a valid number")
        elif choice == '3':
            print("\n📋 Supported Browsers:")
            for browser in analyzer.supported_browsers:
                path = analyzer.browser_paths.get(browser, 'Not found')
                status = "✅ Found" if path and os.path.exists(path) else "❌ Not found"
                print(f"  {browser}: {status}")
        elif choice == '4':
            print("👋 Thank you for using Browser History Analyzer!")
            break
        else:
            print("❌ Invalid choice. Please select 1-4.")


if __name__ == "__main__":
    main()
