# Requires installation of analyzemft, libewf, pytsk3, sandboxapi, virustotal
# Recommended method for ensuring dependencies are met is running the below commands:
# python2.7 -m pip install pytsk3
# python2.7 -m pip install analyzemft
# python2.7 -m pip install libewf
# python2.7 -m pip install sandboxapi
# python2.7 -m pip install virustotal

from analyzemft import mft
from optparse import OptionParser
import argparse
import pytsk3
import pyewf
import time
import virustotal
import csv
import os
import hashlib
from sandboxapi import cuckoo, fireeye
from urllib2 import HTTPError

parser = argparse.ArgumentParser(description='Utility to search a disk image for files which might have been time stomped. '
                                        'Accepts a raw or E01 disk image as input. Extracts $MFT to perform initial analysis. '
                                        'Suspect files will be carved and can be submitted to VirusTotal.com, Cuckoo Sandbox '
                                        'or FireEye Appliance for further analysis. ')
parser.add_argument('-i', '--image', help="Path to image which is to be scanned.", required=True)
parser.add_argument('-f', '--format', help="Type of disk image supplied.", choices=['raw', 'ewf'], required=True)
parser.add_argument('-vt', '--virustotal', help="Submit suspicious files or hashes to VirusTotal.", action="store_true")
parser.add_argument('-c', '--cuckoo', help="Submit suspicious files to Cuckoo for analysis.", action="store_true")
parser.add_argument('-fe', '--fireeye', help="Submit suspicious files to FireEye appliance for analysis.", action="store_true")

# Class copied from analyzemft for compatibility purposes
class date_options:

    @staticmethod
    def fmt_excel(date_str):
        return '="{}"'.format(date_str)
    date_formatter = fmt_excel

# Class provided by the developer of pyewf for use in extending pytsk3
# Available at https://github.com/libyal/libewf/wiki/Python-development
class ewf_Img_Info(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super(ewf_Img_Info, self).__init__(
            url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._ewf_handle.close()

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()


def get_mft(image_handle, part_offset):

    # Open the user provided image handle and create an object representing the filesystem within the disk
    # using the handle and offset of the partition of interest. Then, extract the $MFT and write it
    # to the host.
    try:
        filesystem_object = pytsk3.FS_Info(image_handle, offset=part_offset * 512)
        file_object = filesystem_object.open("/$MFT")
        file_data = file_object.read_random(0,file_object.info.meta.size)
        outfile = open(os.getcwd()+'/$MFT', 'w')
        outfile.write(file_data)
        outfile.close            

    # If the partition does not have a supported filesystem or there is an error reading the filesystem
    # then the $MFT cannot be read and the program should exit since the remaining functionality requires
    # the $MFT
    except IOError as error:
        print "Partition does not seem to have a supported filesystem."
        print error
        exit()

def parse_mft(file):

    # The analyzeMFT library is only somewhat written to support being modular and used in another program/script.
    # As such, to access some functionality it is necessary to trick the library into believing it is being
    # called from command line. To do so, I have implemented OptionParser to pass arguguments in a way the 
    # library understands. The below arguments, stored in the variable options, tell analyzeMFT to use the local 
    # timezone, perform anomaly detection while processing the $MFT and that the arguments "inmemory", 
    # "debug" and "useGUI" are unset and therefore False.
    input_file = open(file, 'rb')
    args = ["--localtz", "True", "--anomaly", "True"]
    parser = OptionParser()
    parser.add_option("--inmemory", dest="inmemory")
    parser.add_option("--debug", dest="debug")
    parser.add_option("--localtz", dest="localtz")
    parser.add_option("--UseGUI", dest="UseGUI")
    parser.add_option("--anomaly", dest="anomaly")
    (options, args) = parser.parse_args(args)
    date_settings = date_options()

    # Read the first 1024 bytes of the $MFT. Each record is 1024 bytes so a single record is being read.
    # Also, open a handle to the CSV we will write all of the parsed $MFT data to.
    raw_record = input_file.read(1024)
    parsed_mft = csv.writer(open(os.getcwd()+"/parsed_mft.csv", 'wb'), dialect=csv.excel, quoting=1)

    # If the raw MFT record is not blank, pass the raw record to analyzeMFT's parser along with the 
    # necessary options set previously. If the parsed record is an actual file it will have $FILE_NAME
    # attributes. Some NTFS inodes are reserved or not used and therefore will not have a $FILE_NAME
    # record. If this is the case, do not attempt to read its name and mark it as haviing no FN record.
    #  When done, read the next 1024 bytes of the $MFT. The first iteration passes the argument 'True'
    # to the mft_to_csv function telling it to print the column headers. In doing so, we are skipping
    # reading in any attributes of $MFT since we are not concerned with an attacker timestomping it. 
    # The result is a CSV containing a parse $MFT.
    if raw_record != "":

        mft_record = {}
        mft_record = mft.parse_record(raw_record, options)

        parsed_mft.writerow(mft.mft_to_csv(mft_record, True, date_settings))
        raw_record = input_file.read(1024)
    
    while raw_record != "":
        
        mft_record = {}
        mft_record = mft.parse_record(raw_record, options)

        if mft_record['fncnt'] != 0:
            mft_record['filename'] = mft_record[('fn', 0)]["name"]
        else:
            mft_record['filename'] = "NoFNRecord"

        parsed_mft.writerow(mft.mft_to_csv(mft_record, False, date_settings))
        raw_record = input_file.read(1024)

def get_suspicious():

    # Read the entries, by row, of the parsed $MFT we previously saved as a CSV. 
    # If the "STF FN Shift" column is marked "Y" then analyzeMFT has determined there is
    # an anomalous shift of the $STANDARD_INFORMAITON and $FILE_NAME attributes. 
    # Also, if the "uSec Zero" colum is marked "Y" then the file has a completely 0 nano second
    # value which is suspicious. However, ensure these suspicious indicators are occuring in files
    # with an inode of greater than 27 since the first 27 inodes are NTFS metadata files and may
    # exhibit odd behavior. For each positive hit of suspicous behavior save the inode and filename 
    # as the key and value in the suspicious_inodes dictionary.
    suspicious_inodes = {}
    reader = csv.DictReader(open("parsed_mft.csv"))

    for row in reader:
        if row['STF FN Shift'] == 'Y' and int(row['Record Number']) > 27 and row['Filename #1'] != 'NoFNRecord':
            suspicious_inodes[row['Record Number']] = row['Filename #1']
        elif row['uSec Zero'] == 'Y' and int(row['Record Number']) > 27 and row['Filename #1'] != 'NoFNRecord':
            suspicious_inodes[row['Record Number']] = row['Filename #1']

    return suspicious_inodes

def carve_files(image_handle, part_offset, inode, file_name):
    
    # Check if the directory to save the suspicious files exists and create it if not.
    if not os.path.exists(os.getcwd()+"/carved_files"):
        os.makedirs(os.getcwd()+"/carved_files")

    # Open the disk image's filesystem as before but this time create an object representing
    # the file stored at the inode passed to the function. Read the file's contents from the
    # disk image and save it to the host in the carved_files folder using the same name
    try:
        filesystem_object = pytsk3.FS_Info(image_handle, offset=part_offset * 512)
        file_object = filesystem_object.open_meta(int(inode))
        file_data = file_object.read_random(0,file_object.info.meta.size)
        outfile = open(os.getcwd()+'/carved_files/%s' % file_name, 'wb')
        outfile.write(file_data)
        outfile.close()

    # As before when accessing $MFT if something has corrupted the disk image and the file system
    # cannot be access properly then abort the program
    except IOError, error:
        print("Partition does not have a supported filesystem.")
        print error
        exit()

def scan_vt():

    # Give the user of choosing to submit the suspicious files or simply their hashes
    user_selection = raw_input("You indicated to submit suspicious files to VirusTotal, do you wish to send"
    " the hash or actual file? \nNote: Submitting the file may reveal sensitive information to the VirusTotal service "
    " and can take considerable time if a large number of files are submitted.\nPlease enter 'hash' or 'file':")

    # Have the user input their VirusTotal API key and initiate a session to VirusTotal
    api_key = raw_input("Please enter your VirusTotal API key:")
    vt_handler = virustotal.VirusTotal(api_key)

    if not os.path.exists(os.getcwd()+"/reports"):
            os.makedirs(os.getcwd()+"/reports")
    
    # Create a CSV which will serve as a consolidated report of VirusTotal results
    consolidated_report = csv.writer(open(os.getcwd()+"/reports/virustotal_consolidated_report.csv", 'w'), dialect=csv.excel, delimiter=',')
    headers = ["Filename", "MD5 Hash", "SHA1 Hash", "SHA256 Hash", "Total A/V", "Positive Hits"]
    consolidated_report.writerow(headers)

    # For each file in the carved_files directory if the user selected to submit hashes
    # then get the MD5 hash of the file and attempt to get the results of the hash
    # search. If the search fails let the user know there was a problem and re-attempt
    # submission.
    for file in os.listdir(os.getcwd()+"/carved_files/"):
        if user_selection == 'hash':
            file_hash = hashlib.md5()
            with open(os.getcwd()+"/carved_files/%s" % file, "rb") as open_file:
                file_hash.update(open_file.read())
            try:
                report = vt_handler.get(str(file_hash.hexdigest()))
            except HTTPError as error:
                print "Unable to obtain successful connection to VirusTotal API.\n%s " % error
                print "Service may be down or perhaps you entered the wrong API key."
                scan_vt()

            print "Waiting for VirusTotal results of %s to return..." % file

            # If the hash returns no results inform the user and continue searching 
            # the remaining hashes.
            if report is None:
                print "No report based on hash of %s is available." % file
                break
            
            # Check if the VirusTotal search is done, if not wait and try again. If done,
            # grab and compile the report.
            while True and report is not None:
                try:
                    report.join()
                    assert report.done == True
                    break
                except:
                    print "Still waiting for VirusTotal results to return..."
                    time.sleep(3)
                    continue
        
        # Submit the suspicious files to VirusTotal. As with the hash search
        # let the user know if there were problems connecting to VirusTotal.
        elif user_selection == 'file':

            try:
                report = vt_handler.scan(os.getcwd()+"/carved_files/%s" % file, reanalyze = True)
                print "Waiting for VirusTotal results of %s to return..." % file

            except HTTPError as error:
                print "Unable to obtain successful connection to VirusTotal API. %s " % error
                print "Service may be down or perhaps you entered the wrong API key."
                scan_vt()

            # Check if the VirusTotal submission is done, if not wait and try again. If done,
            # grab and compile the report.
            while True:
                try:
                    report.join()
                    assert report.done == True
                    break
                except:
                    print "Still waiting for VirusTotal results to return..."
                    time.sleep(3)
                    continue
        
        # Make sure the user is inputting the correct option
        else:
            print "Incorrect input, please enter 'hash' or 'file' without quotations."
            scan_vt()

        # Write the pertinent information to the file's individual report. Will include all
        # antivirus vendors that reported positive for malicious activity and 
        # what type of malware the file may have been as well as basic analysis
        # to include hashes and a link to the report on the VirusTotal website.
        outfile = open(os.getcwd()+'/reports/%s_virustotal_report.txt' % file, 'w')
        outfile.write("File ID: " + report.id + "\n")
        outfile.write("Scan ID: " + report.scan_id + "\n")
        outfile.write("Permalink: " + report.permalink + "\n")
        outfile.write("SHA1 Hash: " + report.sha1 + "\n")
        outfile.write("SHA256 Hash: " + report.sha256 + "\n")
        outfile.write("MD5 Hash: " + report.md5 + "\n")
        outfile.write("Total antivirus products which scanned the file: " + str(report.total) + "\n")
        outfile.write("Total positive malicious/malware hits by antivirus: " + str(report.positives) + "\n")
        
        for antivirus, malware in report:
            if malware is not None:
                outfile.write("Antivirus: " + antivirus[0] + "\n")
                outfile.write("Antivirus version: " + antivirus[1] + "\n")
                outfile.write("Antivirus update: " + antivirus[2] + "\n")
                outfile.write("Malware: " + malware + "\n")

        outfile.close()

        # Write the consolidated information to the overall VirusTotal CSV report
        row = [file, report.md5, report.sha1, report.sha256, report.total, report.positives]
        consolidated_report.writerow(row)
        
def submit_cuckoo():
    
    # Collect the necessary information to interact with the Cuckoo sandbox. 
    # Note: Cuckoo's default implementation is to use a randomly generated
    # API key to validate legitiate user interactions. Sandboxapi's current
    # implementation does not allow for the ability to input an API key.
    # If the Cuckoo instance is configured for API key usage disable the API
    # key to enable this functionality.
    ip = raw_input("What is the IP of your sandbox? ")
    port = raw_input("What is the port of your sandbox API? ")
    
    # Establish a connection to the Cuckoo instance
    sandbox = cuckoo.CuckooAPI('http://%s:%s/' % (ip, port), verify_ssl=False)

    # Check if the reports folder exists and create it if not.
    if not os.path.exists(os.getcwd()+"/reports"):
            os.makedirs(os.getcwd()+"/reports")

    # If the sandbox could not be reached let the user know and provide the option
    # to try again.
    if not sandbox.is_available():
        selection = raw_input("Unable to connect to sandbox, do you wish to try again (yes/no)? ")
        if selection == 'yes':
            submit_cuckoo()
        elif selection == 'no':
            exit()
        else:
            print "Invalid input, retrying Cuckoo connection..."
            submit_cuckoo()

    # For each file in the carved_files directory, submit to the Cuckoo sandbox. 
    # Analysis may be lengthy so check every 30 seconds if the analysis is complete.
    # When the analysis shows as complete wait a final 30 seconds in the even the 
    # sandbox has completed analysis but not finished compiling the report.
    for file in os.listdir(os.getcwd()+"/carved_files"):
        with open(os.getcwd()+"/carved_files/%s" % file, "rb") as file_handle:
            file_id = sandbox.analyze(file_handle, file)
            print ("%s submitted to Cuckoo instance for analysis, please wait..." % file)
            time.sleep(10)

        while not sandbox.check(file_id):
            print ("%s is still being analyzed, checking again in 30 seconds..." % file)
            time.sleep(30)

        print ("%s done being analyzed, waiting 30 seconds for the report to finalize..." % file)
        time.sleep(30)

        # Download the HTML Cuckoo report and write it to the reports folder
        cuckoo_report = sandbox.report(file_id, report_format="html")
        outfile = open(os.getcwd()+'/reports/%s_cuckoo_report.html' % file, 'w')
        outfile.write(cuckoo_report)
        outfile.close                    
        
def submit_fireeye():

    # Collect the necessary information to interact with the FireEye sandbox.
    ip = raw_input("What is the IP of your sandbox? ")
    username = raw_input("What is your username for the sandbox? ")
    password = raw_input("What is your password for the sandbox? ")
    vm = raw_input("What VM environment do you want the sandbox to run? ")

    # Establish a connection to the FireEye instance.
    sandbox = fireeye.FireEyeAPI(username, password, "https://%s" % ip, vm, verify_ssl=False)

    # Check if the reports folder exists and create it if not.
    if not os.path.exists(os.getcwd()+"/reports"):
        os.makedirs(os.getcwd+"/reports")

    # Create a CSV which will serve as a consolidated report of FireEye results
    consolidated_report = csv.writer(open(os.getcwd()+"/reports/fireeye_consolidated_report.csv", 'w'), dialect=csv.excel, delimeter=',')
    headers = ["Filename", "MD5 Hash", "SHA256 Hash", "Is Malicious"]
    consolidated_report.writerow(headers)

    # If the sandbox could not be reached let the user know and provide the option
    # to try again.
    if not sandbox.is_available():
        selection = raw_input("Unable to connect to sandbox, do you wish to try again (yes/no)? ")
        if selection == 'yes':
            submit_fireeye()
        elif selection == 'no':
            exit()
        else:
            print "Invalid input, retrying FireEye connection..."
            submit_fireeye()

    # For each file in the carved_files directory, submit to the FireEye sandbox. 
    # Analysis may be lengthy so check every 30 seconds if the analysis is complete.
    # When the analysis shows as complete wait a final 30 seconds in the even the 
    # sandbox has completed analysis but not finished compiling the report.
    for file in os.listdir(os.getcwd()+"/carved_files/"):
        with open(os.getcwd()+"/carved_files/%s" % file, "rb") as file_handle:
            file_id = sandbox.analyze(file_handle, file)
            print ("%s submitted to FireEye appliance for analysis, please wait..." % file)

        while not sandbox.check(file_id):
            print ("%s is still being analyzed, checking again in 30 seconds..." % file)
            time.sleep(30)

        print ("%s done being analyzed, waiting 30 seconds for the report to finalize..." % file)
        time.sleep(30)
        fireeye_report = sandbox.report(file_id)

        # FireEye appliances do not support nice, graphical reports like Cuckoo so we need to 
        # collect the pertinent information out of the returned dictionary and write it
        # into a consolidated CSV.
        row = [file, fireeye_report['alert'][0]['explanation']['malwareDetected']['malware'][0]['md5Sum'], 
            fireeye_report['alert'][0]['explanation']['malwareDetected']['malware'][0]['Sha256'], fireeye_report['alert'][0]['malicious']]
        consolidated_report.writerow(row)

def main():
    args = parser.parse_args()
    image = args.image
    partition_starts = []

    # Check if the user provided image format is ewf. If so, use the libewf developer's provided class to extend
    # the capabilities of pytsk3 to include the ewf format. If the image format is not ewf then pytsk3 can handle the image natively.
    try:
        if args.format == "ewf":
            files = pyewf.glob(args.image)
            ewf_handle = pyewf.handle()
            ewf_handle.open(files)
            image_handle = ewf_Img_Info(ewf_handle)
        else:
            image_handle = pytsk3.Img_Info(url=image)

        # Once a handle to the image has been established print all of the detected partitions to the user and allow them to pick the partition of 
        # interest to be scanned. 
        print "Which partition should be scanned?"
        
        volume = pytsk3.Volume_Info(image_handle)
        for partition in volume:
            print partition.addr, partition.desc, "%s(%s)" % (partition.start, partition.start * 512), partition.len
            partition_starts.append(int(partition.start))
    
    except IOError, error:
        print error
        
    # Once the user has provided a partition number utilize get_mft() to extract the $MFT out of the image
    part_num = raw_input("Enter partition number: ")
    get_mft(image_handle, partition_starts[int(part_num)])      

    # Once the $MFT has been extracted, parse it to identify all files contained in the partition
    parse_mft(os.getcwd()+"/$MFT")

    # Get a dictionary of inodes and file names for every file that may have been time stomped
    suspicious_files = get_suspicious()

    # Using the dictionary of suspicious inodes/files, carve the indicated files out of the image
    for inode, file_name in suspicious_files.items():
        carve_files(image_handle,partition_starts[int(part_num)],inode,file_name)

    # Check which optional functionality the user requested to be performed with the suspicious files
    if args.virustotal is not False:
        scan_vt()

    if args.cuckoo is not False:
        submit_cuckoo()

    if args.fireeye is not False:
        submit_fireeye()

if __name__ == "__main__":
    main()
