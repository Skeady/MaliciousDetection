import math
import logging
from MaliciousDetection import reporting
from virus_total_apis import PublicApi as VirusTotalPublicApi
from decouple import config
# API_KEY retrieved from Environmental Variable
API_KEY = config('KEY')
logging.getLogger(__name__)


class VirusTotalScan(object):
    """Class which Uses the VirusTotalPublicAPI to Query a passed
    MD5 hash against the VirusTotal Repository.
    Arguments:
        `md5_hash`: The Files MD5 Hash str()
        `file_name`: The File Name str()
    Returns:
        VirusTotalScan Object Containing:
            `md5_hash`: md5_hash str()
            `file_name`: file_name str()
            `virus_total_response`: virus_total_response dict()
            `report`: report str()
    """
    def __init__(
            self,
            md5_hash,
            file_name
    ):
        self.md5_hash = md5_hash
        self.file_name = file_name
        self.virus_total_response = self.query_virus_total_db()
        self.report = self.create_report(self.file_name, self.virus_total_response)

    # Uses API to query VirusTotal repository for MD5 hash
    def query_virus_total_db(self, md5_hash, file_name):
        try:
            virus_total_instance = VirusTotalPublicApi(API_KEY)
            return virus_total_instance.get_file_report(self.md5_hash)
        except Exception as e:
            logging.error(f'Unable to query VirusTotal repository for {self.file_name} got Error {e}')

    # Takes VirusTotal response to create report for the file
    def create_report(self, file_name, virus_total_response):
        try:
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
        except Exception as e:
            logging.error(f'Unable to create report for {self.file_name} got Error: {e}')