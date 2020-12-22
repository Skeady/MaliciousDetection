import hashlib
import logging
from os import listdir
from os.path import isfile, join

logging.getLogger(__name__)

class Scan(object):
	"""Scans for files in directory path passed by user args.
	Arguments:
		`file_path`: Directory path str()
	Returns:
		Scan Object Containing:
		`file_path`: file_path str()
		`all_files`: all_files list()
		`individual_files`: individual_files dict()
	"""
	def __init__(
		self,
		file_path
	):
		self.file_path = file_path
		self.all_files = self.scan_files(self.file_path)
		self.individual_files = self.create_objects(self.all_files, self.file_path)

	# Scans for all files in path ensures only files are selected and not directories.
	def scan_files(self, file_path):
		try:
			return [f'{self.file_path}/{file}' for file in listdir(self.file_path) if isfile(join(self.file_path, file))]
		except Exception as e:
			logging.error(f'Unable to scan files for files at {self.file_path} got Error: {e}')

	# Loads chunks of the files binary used to calculate the MD5 hash
	def calculate_md5_hash(self, file):
		try:
			md5_hash = hashlib.md5()
			with open(file, "rb") as check_file:
				for binary_chunk in iter(lambda: check_file.read(4096), b""):
					md5_hash.update(binary_chunk)
			return md5_hash.hexdigest()
		except Exception as e:
			logging.error(f'unable to calculate MD5 hash for {file} got Error: {e}')

	# Creates individual objects for each file found in file_path
	def create_objects(self, all_files, file_path):
		try:
			_objects = {}
			for file in self.all_files:
				file_name = file.replace(f'{self.file_path}/', '')
				_objects.update({file_name: {'md5': self.calculate_md5_hash(file),
											 'path': self.file_path
								}
						}
				)
			return _objects
		except Exception as e:
			logging.error(f'Unable to generate individual objects for {self.all_files} got Error {e}')
