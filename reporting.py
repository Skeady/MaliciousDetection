virus_total_report_template = """
    The following files were found to be Malicious:
        {report}
"""

virus_total_file_report = """
        {file_name}:
            Appeared in the following Data bases:
                {av_search_engines}
            
            Number of poistives {positives} out of {total}
            
            There is a {calculated_percentage}% chance this file is malicious

"""