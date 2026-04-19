import json
from collections import defaultdict, Counter
from datetime import datetime
from typing import Dict

class VulnerabilityMetricsAnalyzer:

    
    def __init__(self, results_file: str):
        self.results_file = results_file
        self.results = []
        self.load_results()
    
    def load_results(self):

        with open(self.results_file, 'r') as f:
            for line in f:
                if line.strip():
                    self.results.append(json.loads(line))
        print(f"Loaded {len(self.results)} test results\n")
    
    def detection_rate(self) -> Dict:

        total_tests = len(self.results)
        vulnerable = sum(1 for r in self.results if r.get('vulnerable', False))
        non_vulnerable = total_tests - vulnerable
        
        detection_rate = (vulnerable / total_tests * 100) if total_tests > 0 else 0
        
        return {
            'total_tests': total_tests,
            'vulnerabilities_found': vulnerable,
            'non_vulnerable': non_vulnerable,
            'detection_rate_percent': round(detection_rate, 2)
        }
    
    def true_positives_analysis(self) -> Dict:

        vulnerable_tests = [r for r in self.results if r.get('vulnerable', False)]
        

        true_positives = sum(1 for r in vulnerable_tests 
                           if r.get('reflected', False) or r.get('stored', False))
        

        potential_false_positives = len(vulnerable_tests) - true_positives
        
        return {
            'true_positives': true_positives,
            'potential_false_positives': potential_false_positives,
            'true_positive_rate': round((true_positives / len(vulnerable_tests) * 100) 
                                       if vulnerable_tests else 0, 2)
        }
    
    def coverage_analysis(self) -> Dict:

        unique_pages = set(r.get('page', '') for r in self.results)
        unique_forms = set((r.get('page', ''), r.get('form_action', '')) 
                          for r in self.results)
        unique_fields = set((r.get('page', ''), r.get('field', '')) 
                           for r in self.results)
        unique_payloads = set(r.get('payload_label', '') for r in self.results)
        
        tested_combinations = len(self.results)
        
        return {
            'unique_pages_tested': len(unique_pages),
            'unique_forms_tested': len(unique_forms),
            'unique_fields_tested': len(unique_fields),
            'unique_payload_types': len(unique_payloads),
            'total_test_combinations': tested_combinations,
            'pages': list(unique_pages)[:10],  # First 10 for display
            'payload_types': list(unique_payloads)
        }
    
    def time_to_first_discovery(self) -> Dict:

        if not self.results:
            return {'error': 'No results available'}
        
        # Sort by discovery time
        sorted_results = sorted(self.results, 
                               key=lambda x: x.get('discovered_at', ''))
        
        first_test_time = sorted_results[0].get('discovered_at')
        
        # Find first vulnerability
        first_vuln = next((r for r in sorted_results if r.get('vulnerable', False)), None)
        
        if not first_vuln:
            return {
                'first_vulnerability_found': False,
                'tests_until_first_discovery': len(self.results)
            }
        
        # Count tests until first discovery
        first_vuln_time = first_vuln.get('discovered_at')
        tests_before = sum(1 for r in sorted_results 
                          if r.get('discovered_at', '') < first_vuln_time)
        

        try:
            start_dt = datetime.fromisoformat(first_test_time.replace('Z', '+00:00'))
            vuln_dt = datetime.fromisoformat(first_vuln_time.replace('Z', '+00:00'))
            time_diff = (vuln_dt - start_dt).total_seconds()
        except:
            time_diff = None
        
        return {
            'first_vulnerability_found': True,
            'tests_until_first_discovery': tests_before + 1,
            'time_to_first_discovery_seconds': round(time_diff, 2) if time_diff else None,
            'first_vuln_page': first_vuln.get('page'),
            'first_vuln_payload': first_vuln.get('payload_label')
        }
    
    def unique_vulnerabilities(self) -> Dict:

        vulnerabilities = [r for r in self.results if r.get('vulnerable', False)]
        

        unique_by_location = set((r.get('page'), r.get('field')) 
                                for r in vulnerabilities)
        

        unique_by_vector = set((r.get('page'), r.get('field'), r.get('payload_label')) 
                              for r in vulnerabilities)
        

        reflected_count = sum(1 for r in vulnerabilities if r.get('reflected', False))
        stored_count = sum(1 for r in vulnerabilities if r.get('stored', False))
        
        # Group by page
        vulns_by_page = defaultdict(list)
        for vuln in vulnerabilities:
            vulns_by_page[vuln.get('page')].append({
                'field': vuln.get('field'),
                'payload': vuln.get('payload_label')
            })
        
        return {
            'unique_vulnerable_locations': len(unique_by_location),
            'unique_attack_vectors': len(unique_by_vector),
            'reflected_xss_count': reflected_count,
            'stored_xss_count': stored_count,
            'vulnerable_pages': len(vulns_by_page),
            'vulnerabilities_by_page': {k: len(v) for k, v in vulns_by_page.items()}
        }
    
    def payload_effectiveness(self) -> Dict:

        payload_stats = defaultdict(lambda: {'total': 0, 'successful': 0})
        
        for result in self.results:
            payload = result.get('payload_label', 'unknown')
            payload_stats[payload]['total'] += 1
            if result.get('vulnerable', False):
                payload_stats[payload]['successful'] += 1
        
        # Calculate success rates
        effectiveness = {}
        for payload, stats in payload_stats.items():
            success_rate = (stats['successful'] / stats['total'] * 100) if stats['total'] > 0 else 0
            effectiveness[payload] = {
                'total_tests': stats['total'],
                'successful_tests': stats['successful'],
                'success_rate_percent': round(success_rate, 2)
            }
        

        sorted_effectiveness = dict(sorted(effectiveness.items(), 
                                          key=lambda x: x[1]['success_rate_percent'], 
                                          reverse=True))
        
        return sorted_effectiveness
    
    def field_vulnerability_distribution(self) -> Dict:
        """Analyze vulnerability distribution across fields"""
        field_stats = defaultdict(lambda: {'total': 0, 'vulnerable': 0})
        
        for result in self.results:
            field = result.get('field', 'unknown')
            field_stats[field]['total'] += 1
            if result.get('vulnerable', False):
                field_stats[field]['vulnerable'] += 1
        
        distribution = {}
        for field, stats in field_stats.items():
            vuln_rate = (stats['vulnerable'] / stats['total'] * 100) if stats['total'] > 0 else 0
            distribution[field] = {
                'total_tests': stats['total'],
                'vulnerabilities': stats['vulnerable'],
                'vulnerability_rate_percent': round(vuln_rate, 2)
            }
        

        sorted_distribution = dict(sorted(distribution.items(), 
                                         key=lambda x: x[1]['vulnerabilities'], 
                                         reverse=True))
        
        return sorted_distribution
    
    def generate_full_report(self) -> Dict:
        """Generate complete vulnerability detection metrics report"""
        return {
            'detection_rate': self.detection_rate(),
            'true_positives': self.true_positives_analysis(),
            'coverage': self.coverage_analysis(),
            'time_to_discovery': self.time_to_first_discovery(),
            'unique_vulnerabilities': self.unique_vulnerabilities(),
            'payload_effectiveness': self.payload_effectiveness(),
            'field_distribution': self.field_vulnerability_distribution()
        }
    
    def print_report(self):
        """Print formatted report to console"""
        report = self.generate_full_report()
        
        print("=" * 80)
        print("VULNERABILITY DETECTION METRICS REPORT")
        print("=" * 80)
        
        print("\n1. DETECTION RATE")
        print("-" * 40)
        dr = report['detection_rate']
        print(f"Total Tests Performed: {dr['total_tests']}")
        print(f"Vulnerabilities Found: {dr['vulnerabilities_found']}")
        print(f"Non-Vulnerable: {dr['non_vulnerable']}")
        print(f"Detection Rate: {dr['detection_rate_percent']}%")
        
        print("\n2. TRUE POSITIVES ANALYSIS")
        print("-" * 40)
        tp = report['true_positives']
        print(f"True Positives: {tp['true_positives']}")
        print(f"Potential False Positives: {tp['potential_false_positives']}")
        print(f"True Positive Rate: {tp['true_positive_rate']}%")
        
        print("\n3. COVERAGE METRICS")
        print("-" * 40)
        cov = report['coverage']
        print(f"Unique Pages Tested: {cov['unique_pages_tested']}")
        print(f"Unique Forms Tested: {cov['unique_forms_tested']}")
        print(f"Unique Fields Tested: {cov['unique_fields_tested']}")
        print(f"Unique Payload Types: {cov['unique_payload_types']}")
        print(f"Total Test Combinations: {cov['total_test_combinations']}")
        print(f"\nPayload Types: {', '.join(cov['payload_types'])}")
        
        print("\n4. TIME TO FIRST DISCOVERY")
        print("-" * 40)
        ttd = report['time_to_discovery']
        if ttd.get('first_vulnerability_found'):
            print(f"Tests Until First Discovery: {ttd['tests_until_first_discovery']}")
            if ttd.get('time_to_first_discovery_seconds'):
                print(f"Time to First Discovery: {ttd['time_to_first_discovery_seconds']:.2f} seconds")
            print(f"First Vulnerable Page: {ttd.get('first_vuln_page', 'N/A')}")
            print(f"First Successful Payload: {ttd.get('first_vuln_payload', 'N/A')}")
        else:
            print("No vulnerabilities found")
        
        print("\n5. UNIQUE VULNERABILITIES")
        print("-" * 40)
        uv = report['unique_vulnerabilities']
        print(f"Unique Vulnerable Locations: {uv['unique_vulnerable_locations']}")
        print(f"Unique Attack Vectors: {uv['unique_attack_vectors']}")
        print(f"Reflected XSS: {uv['reflected_xss_count']}")
        print(f"Stored XSS: {uv['stored_xss_count']}")
        print(f"Vulnerable Pages: {uv['vulnerable_pages']}")
        print("\nVulnerabilities by Page:")
        for page, count in list(uv['vulnerabilities_by_page'].items())[:5]:
            print(f"  {page}: {count} vulnerabilities")
        
        print("\n6. PAYLOAD EFFECTIVENESS (Top 5)")
        print("-" * 40)
        for idx, (payload, stats) in enumerate(list(report['payload_effectiveness'].items())[:5], 1):
            print(f"{idx}. {payload}")
            print(f"   Tests: {stats['total_tests']} | "
                  f"Successful: {stats['successful_tests']} | "
                  f"Success Rate: {stats['success_rate_percent']}%")
        
        print("\n7. FIELD VULNERABILITY DISTRIBUTION (Top 5)")
        print("-" * 40)
        for idx, (field, stats) in enumerate(list(report['field_distribution'].items())[:5], 1):
            print(f"{idx}. {field}")
            print(f"   Tests: {stats['total_tests']} | "
                  f"Vulnerabilities: {stats['vulnerabilities']} | "
                  f"Rate: {stats['vulnerability_rate_percent']}%")
        
        print("\n" + "=" * 80)
    
    def export_to_json(self, output_file: str):
        """Export full report to JSON file"""
        report = self.generate_full_report()
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nReport exported to: {output_file}")



if __name__ == "__main__":

    print("ANALYZING XSS PROBE RESULTS")
    print("=" * 80 + "\n")
    
    xss_analyzer = VulnerabilityMetricsAnalyzer('xss_probe_results.ndjson')
    xss_analyzer.print_report()
    xss_analyzer.export_to_json('xss_metrics_report.json')
    

    print("\n\n")
    print("ANALYZING SQLI PROBE RESULTS")
    print("=" * 80 + "\n")
    
    try:
        sqli_analyzer = VulnerabilityMetricsAnalyzer('sqli_probe_results.ndjson')
        sqli_analyzer.print_report()
        sqli_analyzer.export_to_json('sqli_metrics_report.json')
    except FileNotFoundError:
        print("SQLi probe results file not found, skipping...")