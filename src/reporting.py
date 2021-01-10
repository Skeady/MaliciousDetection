# Report Template to merge reports for all files.
report_generation_template = """
    The following files were found to be Malicious:
        {report}
"""

# Report Template to create report for individual files.
virus_total_file_report = """
        {file_name}:
            Appeared in the following Data bases:
                {av_search_engines}
            
            Number of poistives {positives} out of {total}
            
            There is a {calculated_percentage}% chance this file is malicious

"""

execution_wrap_up = """
	From the {total_files_checked} files identified:
        		{identifed_file_benign_files} are benign files
        		{total_files_checked} were checked against VirusTotal
        
        For the execution report please see {report_name}
        
        Please review malware_detection.log for the details listed below
        	- identified benign files
        	- Files found as not malicious on VirusTotal
        	- The exectution Logs.
    """