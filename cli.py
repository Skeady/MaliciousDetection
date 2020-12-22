import click
import logging
from MaliciousDetection import malware_detection

logging.getLogger(__name__)
formatter = '%(asctime)s [%(levelname)s] [%(threadName)s] [%(name)s] %(message)s'


@click.command()
@click.option('-p', '--path', type=str, required=True)
@click.option('-v', '--verbose', is_flag=True)
# Cli used to handle Args passed by user and setup logging
def cli(path, verbose):
    logging.basicConfig(filename='malware_detection.log',
                        format=formatter,
                        level=(logging.DEBUG if verbose else logging.INFO))
    logging.info('Starting malware_detection')
    malware_detection.run_file_scan(path)
    logging.info('Finished malware_detection')
    return
