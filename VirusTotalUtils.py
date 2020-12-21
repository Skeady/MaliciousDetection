import json
import os
import math
from MaliciousDetection import reporting
from virus_total_apis import PublicApi as VirusTotalPublicApi
from decouple import config
API_KEY = config('KEY')


class VirusTotalScan(object):
    def __init__(
        self,
        md5_hash,
        file_name
    ):
        self.md5_hash = md5_hash
        self.file_name = file_name
        self.virus_total_response = self.query_virus_total_db()
        # self.parsed_file_results = self.parse_file_results()
        self.report = self.create_report(self.file_name, self.virus_total_response)
        # self.malicious_files, self.non_malicious_files = self.filter_files()

        self.virus_total_objects = {self.file_name: {'md5_hash': self.md5_hash,
                                                     'virus_total_response': self.virus_total_response,
                                                     'report': self.report,
            }
        }

    def query_virus_total_db(self):
        virus_total_instance = VirusTotalPublicApi(API_KEY)
        return virus_total_instance.get_file_report(self.md5_hash)

    def parse_file_results(self):
        return

    def create_report(self, file_name, virus_total_response):
        file_name = self.file_name
        av_search_engines = '\n\t\t'.join(list(self.virus_total_response.get('results').get('scans').keys()))
        positives = self.virus_total_response.get('results').get('positives')
        total = self.virus_total_response.get('results').get('total')
        calculated_percentage = math.ceil((positives / total) * 100)
        return reporting.virus_total_file_report.format(file_name=file_name,
                                                        av_search_engines=av_search_engines,
                                                        positives=positives,
                                                        total=total,
                                                        calculated_percentage=calculated_percentage)

    """def filter_files(self):
        return malicious_files, non_malicious_files"""

