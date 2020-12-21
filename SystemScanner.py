import hashlib
from os import listdir
from os.path import isfile, join


class Scan(object):
	"""
		Object
			Search Directory for files
			Calculate file MD5 hash
			Querantine files
	"""
	def __init__(
		self,
		file_path
	):
		self.file_path = file_path
		self.file_objects = {}
		self.all_files = self.scan_files(self.file_path)

		for file in self.all_files:
			file_name = file.replace(f'{self.file_path}/', '')
			self.file_objects.update({file_name: {'md5': self.calculate_md5_hash(file),
												  'path': self.file_path
					}
				}
			)


		'''self.file_objects.append({})
		self.md5_hash = self.calculate_md5_hash()
		self.quarantine_files = self.quarantine_files()'''

	def scan_files(self, file_path):
		return [f'{self.file_path}/{file}' for file in listdir(self.file_path) if isfile(join(self.file_path, file))]

	'''/home/scoop/Downloads'''
	def calculate_md5_hash(self, file):
		md5_hash = hashlib.md5()
		with open (file, "rb") as check_file:
			for binary_chunk in iter(lambda: check_file.read(4096), b""):
				md5_hash.update(binary_chunk)
		return md5_hash.hexdigest()

	def quarantine_files(self):
		return None

