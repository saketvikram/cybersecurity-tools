#!/usr/bin/python
# -*- coding: utf-8 -*-
import time
import os
import sys
import hashlib
import datetime
import re



def main():
    
    
    start = time.time()
    siv_mode = sys.argv[1]
    if siv_mode == "-i":
        initialization_mode()
    elif siv_mode == "-v":
        verification_mode()
    else:
        print(help_function.__doc__)
        sys.exit()
        
    


def initialization_mode():
    #verify_dir_name = input(" the path of the verification file: ")
    
    monitor_directory = sys.argv[3]
    verification_file_location = sys.argv[5]
    report_file_location = sys.argv[7]
    hash_function = sys.argv[9]
    is_verify_file_outside_monitor_directory = verification_file_location.find(monitor_directory, 0)
    is_report_file_outside_monitor_directory = report_file_location.find(monitor_directory, 0)
    overwrite_verify_name = ""
    overwrite_report_name = ""
    if hash_function != "sha1" and hash_function != "md5":
        sys.exit("The hash function is not supported. Please use md5 or sha1 as options")
    if os.path.exists(verification_file_location):
        overwrite_verify_name = input("Do you want to overwrite verification file? press yes. Press no to exit the program:")
    if overwrite_verify_name == "no":
        sys.exit("Program exited as user denied to overwrite ")
    if os.path.exists(report_file_location):
            overwrite_report_name = input("Do you want to overwrite report file? press yes. Press no to exit the program:")
    if overwrite_report_name == "no":
        sys.exit("Program exited as user denied to overwrite ")   
    if(os.path.isdir(monitor_directory)):
        start = time.time()
        file_number = 0
        subdirs_number = 0
        verifyfile = open(verification_file_location, "w+")
        hash_text = "sha" if hash_function == "sha1" else "md5"
        verifyfile.write("hash:"+ hash_text + '\n')
        for root, subdirs, files in os.walk(monitor_directory):
            dir_statinfo = os.stat(root)
            dir_info = ";" + str(dir_statinfo.st_uid)+";" + str(dir_statinfo.st_gid)+";" + oct(dir_statinfo.st_mode)[-3:] + ";" + str(dir_statinfo.st_mtime) + ";"
            verifyfile.write("root:" + root + dir_info + '\n' )
            #verifyfile.write("root:" + root +'\n' )
            subdirs_number = subdirs_number + len(subdirs)
            file_number = file_number + len(files)
            for filename in files:
                filepath = root + os.sep + filename
                statinfo = os.stat(filepath)
                verifyfile.write(filepath + ",")
                verifyfile.write(str(statinfo.st_size)+",")
                verifyfile.write(str(statinfo.st_uid)+",")
                verifyfile.write(str(statinfo.st_gid)+",")
                verifyfile.write(oct(statinfo.st_mode)[-3:]+",")
                verifyfile.write(str(statinfo.st_mtime)+",")
                if hash_function == "sha1":
                    hashstring = "{} ".format(shafile(filepath)) + '\n'
                    #print(hashstring)
                    verifyfile.write(hashstring)
                else:
                    hashstring = "{} ".format(md5file(filepath)) + '\n'
                    #print(hashstring)
                    verifyfile.write(hashstring)
        verifyfile.close()
        reportfile = open(report_file_location, "w+")
        reportfile.write(
            "Full path to the monitored directory: " + sys.argv[3] + '\n')
        reportfile.write(
            "Full path to the verification file: " + sys.argv[5] + '\n')
        reportfile.write("Number of directories parsed: " +
                         str(subdirs_number) + '\n')
        reportfile.write("Number of files parsed: " + str(file_number) + '\n')
        print(("Number of directories parsed: " + str(subdirs_number) + '\n'))
        print(("Number of files parsed: " + str(file_number) + '\n'))
        end = time.time()
        reportfile.write(
            "Time to complete the initialization mode : " + str(end - start) + '\n')
        reportfile.close()



def verification_mode():
    monitor_directory = sys.argv[3]
    verify_file_location = sys.argv[5]
    report_file_location = sys.argv[7]
    #hash_function = sys.argv[9]
    is_verify_file_outside_monitor_directory = verify_file_location.find(monitor_directory, 0)
    is_report_file_outside_monitor_directory = report_file_location.find(monitor_directory, 0)
    hash_function = ""
    overwrite_report_name=""
    #if hash_function != "sha1" and hash_function != "md5":
    #    sys.exit("The hash function is not supported. Please use md5 or sha1 as options")
   
    if os.path.exists(report_file_location):
        overwrite_report_name = input("Do you want to overwrite report file? press yes. Press no to exit the program:")
    if overwrite_report_name == "no":
        sys.exit("Program exited as user denied to overwrite ")   
    start = time.time()
    no_of_warning_changes = 0
    report_file_location = (
        
        report_file_location
    )
    
    reportfile = open(report_file_location, "w+")
    reportfile.write("Full pathname to monitored directory: " + monitor_directory + '\n')
    reportfile.write("Full pathname to verification file: " + verify_file_location + '\n')
    reportfile.write("Full pathname to report file: " + report_file_location + '\n')
    
    if os.path.exists(verify_file_location):
        is_verify_file_outside_monitor_directory = verify_file_location.find(
            monitor_directory, 0
        )
        # Read the verification file in a string
        with open(
            
            verify_file_location
        ) as myfile:
            verify_data = "".join(line.rstrip() for line in myfile)
        #print("This is original verify function{}".format(verify_data))    
        hash_function = verify_data[5:8]
        #print("This is hash function {}".format(hash_function))
        verify_data = verify_data[8:]
        
        # Iterate and read the monitored directory
        verify_dir_name = monitor_directory
        no_of_warnings = 0
        file_number = 0
        subdirs_number = 0
        for root, subdirs, files in os.walk(verify_dir_name):
            #print("Line 139 : " + root + "\n")
            root_index = verify_data.find("root:" + root)
            
            subdirs_number = subdirs_number + len(subdirs)
            file_number = file_number + len(files)
            if root_index == -1:
                reportfile.write("Warning - New directory: " + root + '\n')
                no_of_warning_changes += 1

                
            #else:
            next_root_index = verify_data.find("root:", root_index +5)
            #print("139 {} ".format(next_root_index) + "\n")
            # Filter string for all the files inside direcotry
            directory_files_data = ""
            if next_root_index == -1:
                directory_files_data = verify_data[root_index :]
            else:
                directory_files_data = verify_data[root_index : next_root_index ] 
            
            #print("Line 156 : " + verify_data + '\n')
            verify_data = verify_data.replace(directory_files_data, "", 1)
            #print("Line 158 : " + verify_data + '\n')
            # Remove the root directory entry from directory string
            # print("This is line 172 full dir data {}".format(directory_files_data))
            directory_info = directory_files_data.split(";")
            
            if len(directory_info) == 6:
                directory_files_data = directory_info[0] + directory_info[5]
                #Compare the access rights
                current_statinfo = os.stat(root)
                current_dir_permission = oct(current_statinfo.st_mode)[-3:]
                previous_dir_permission = directory_info[3]
                if current_dir_permission != previous_dir_permission:
                    no_of_warning_changes += 1
                    reportfile.write("Warning - Directory {} access permission for  has changed from {} to {}: ".format(root, previous_dir_permission,  current_dir_permission) + '\n')        
            
            
                # Compare the userid
                dir_current_userid = current_statinfo.st_uid
                dir_reported_userid = int(directory_info[1])
                if dir_current_userid != dir_reported_userid:
                    reportfile.write("Warning  - Directory {} Userid changed from {} to {} ".format(root, dir_reported_userid, dir_current_userid) + '\n')
                    no_of_warning_changes += 1 
                # Compare the groupid
                dir_current_groupid = current_statinfo.st_gid
                dir_reported_groupid = int(directory_info[2])
                if dir_current_groupid != dir_reported_groupid:
                    reportfile.write("Warning  - Directory {} Groupid changed from {} to {} ".format(root, dir_reported_groupid, dir_current_groupid) + '\n')
                    no_of_warning_changes += 1
                # Compare last modified for directory
                dir_current_last_modified = float(current_statinfo.st_mtime)
                dir_reported_last_modified = float(directory_info[4])
                time_diff = abs(dir_current_last_modified - dir_reported_last_modified)
            
                if(time_diff > 0.01):
                    reportfile.write("Warning  - Directory {} Time Last modified  changed from {} to {} ".format(root, dir_reported_last_modified, dir_current_last_modified) + '\n')
                    no_of_warning_changes += 1
            else:
                directory_files_data = directory_info[0]    
            
            
       
        

            directory_files_data = directory_files_data.replace("root:" + root, '', 1)
            
            
            for filename in files:

                filepath = root + os.sep + filename
                statinfo = os.stat(filepath)
                hash_digest = ""
                if hash_function == "sha":
                    hash_digest = shafile(filepath)
                else:
                    hash_digest = md5file(filepath)
                
                is_file_exist_index = directory_files_data.find(filepath)
                report_file_changed = ""
                file_data = ""
                if is_file_exist_index == -1:
                    reportfile.write("Warning - New file: " + filepath + '\n')
                    no_of_warning_changes += 1
                else:
                    next_file_index = directory_files_data.find(root, is_file_exist_index + len(filepath))
                    
                    if next_file_index == -1:
                        file_data = directory_files_data[is_file_exist_index :]
                    else:
                        file_data = directory_files_data[is_file_exist_index : next_file_index]
                    
                    directory_files_data = directory_files_data.replace(file_data, "", 1)
                    if(file_data):
                        file_list_data = file_data.split(",")

                        report_file_changed = FileModificationFieldsMessage(statinfo, file_list_data, filepath, hash_digest)

                    if report_file_changed:
                        reportfile.write(report_file_changed["diff_message"])
                        no_of_warning_changes += report_file_changed["change_count"]
            # Find the deleted files inside current directory:
            if directory_files_data:
                
                
                for match in re.finditer(root, directory_files_data):
                    #print((match.start(), match.end()))
                    current_file_index = directory_files_data.find(",", match.end()+1)
                    missing_file = directory_files_data[match.start():match.end()+1] + directory_files_data[match.end()+1:current_file_index]
                    reportfile.write("Warning - Deleted File :  {}".format(missing_file) + '\n')
                    no_of_warning_changes += 1 

            
        # Find the deleted directories and files in it:
        if verify_data:
             
            dir_start_index_list = []
            for match in re.finditer("root:", verify_data):
                dir_start_index_list.append(match.start())
            
            
            len_dir = len(dir_start_index_list)
            root_dir_string = ""
            
            for i in range(len_dir):
                 
                root_dir = ""
                if i == len_dir -1:
                    root_dir_string =  verify_data[dir_start_index_list[i]:]
                 
                    del_directory_info = root_dir_string.split(";")
                    
                    root_dir_string = del_directory_info[0] + del_directory_info[5]
                   
                    
                else:
                    root_dir_string = verify_data[dir_start_index_list[i]:dir_start_index_list[i+1]]
                    del_directory_info = root_dir_string.split(";")
                    root_dir_string = del_directory_info[0] + del_directory_info[5]
                    
                root_folder_name = ""
                current_file_index = root_dir_string.find(",")
                

                if current_file_index == -1:
                    #print(("Line 221 Deleted Directory: " + root_dir_string[5:]))
                    reportfile.write("Warning -  Deleted Directory :  {}".format(root_dir_string[5:]) + '\n')
                    no_of_warning_changes += 1
                else:
                    root_folder = root_dir_string[:current_file_index]
                    #print(("Line 227 : " +  root_folder))
                    root_list = root_folder.split("/")
                    root_len_list = (len(root_list)+1)/2
                    for num, name in enumerate(root_list):
                        if((num < root_len_list - 1) and num > 0):
                            root_folder_name = root_folder_name +"/" +  name
                    reportfile.write("Warning -  Deleted Directory :  {}".format(root_folder_name) + '\n')
                    no_of_warning_changes += 1
                    #print(("Line 232 Deleted Directory: " + root_folder_name))
                    file_list = root_dir_string.replace("root:" + root_folder_name, '', 1)
                    print(("Line 235 : " + file_list))
                    print("Line 241" + root_folder_name)
                    for match in re.finditer(root_folder_name, file_list):
                        current_file_index = file_list.find(",", match.end()+1)
                        file_data = file_list[match.start():current_file_index]
                        print("Line 244" + file_data)
                        file_data_list = file_data.split(",")
                        
                        reportfile.write("Warning -  Deleted File :  {}".format(file_data_list[0]) + '\n')
                        no_of_warning_changes += 1
        reportfile.write("Number of Directories parsed : {}".format(subdirs_number)  + '\n')
        reportfile.write("Number of files parsed : {}".format(file_number)  + '\n')
        
    reportfile.write("Number of warning issued : {}".format(no_of_warning_changes)  + '\n')                               
    end = time.time()
    reportfile.write(
            "Time to complete the verification mode : " + str(end - start) + '\n')
    reportfile.close()
    print("SIV run successful. Please check report for more information")
    #else:
    #    sys.exit("verification file does not exist")


def FileModificationFieldsMessage(statinfo, file_list_data, filepath, hash_digest):
    FileChangesDict = {}
    modified_file_message = ""
    changes_in_file = 0
    
    # Compare the file size
    current_file_size = statinfo.st_size
    reported_file_size = int(file_list_data[1])
    modified_file_message = ""
    if current_file_size != reported_file_size:
        modified_file_message = (
            modified_file_message
            + "Warning  - File {} size changed from {} bytes to {} bytes".format(
                filepath, reported_file_size, current_file_size
            ) + '\n'
        )
        changes_in_file += 1

    # Compare the userid
    current_userid = statinfo.st_uid
    reported_userid = int(file_list_data[2])
    if current_userid != reported_userid:
        modified_file_message = (
            modified_file_message
            + "Warning  - File {} Userid changed from {} to {} ".format(filepath, reported_userid, current_userid) + '\n'
        )
        changes_in_file += 1
    # Compare the groupid
    current_groupid = statinfo.st_gid
    reported_groupid = int(file_list_data[3])
    if current_groupid != reported_groupid:
        modified_file_message = (
            modified_file_message
            + "Warning  - File {} groupid changed from {} to {} ".format(filepath, reported_groupid, current_userid) + '\n'
        )
        changes_in_file += 1
    # Compare the access rights
    current_access_rights = oct(statinfo.st_mode)[-3:]
    reported_access_rights = file_list_data[4]
    if current_access_rights != reported_access_rights:
        modified_file_message = (
            modified_file_message
            + "Warning  - File {} access right changed from {} to {} ".format(filepath, reported_groupid, current_userid) + '\n'
        )
        changes_in_file += 1
    # Compare the last modified time

    current_last_modified = float(statinfo.st_mtime)
    reported_last_modified = float(file_list_data[5])
    
    time_diff = abs(current_last_modified - reported_last_modified)
    
    if(time_diff > 0.01):
       
        modified_file_message = (modified_file_message+ "Warning  - File {} Unix timestamp changed from {} to {}".format(filepath, reported_last_modified, current_last_modified)+ '\n')
        changes_in_file += 1

    reported_last_hash = file_list_data[6]
    if(hash_digest != reported_last_hash):
        modified_file_message = (modified_file_message+ "Warning  - File {} message digest changed from {} to {}".format(filepath, reported_last_hash, hash_digest)+ '\n')
        changes_in_file += 1

    if modified_file_message:
        FileChangesDict["diff_message"] = modified_file_message
        FileChangesDict["change_count"] = changes_in_file
    else:
        modified_file_message = ""
    return FileChangesDict


def md5file(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def shafile(fname):
    hash_md5 = hashlib.sha1()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()



def help_function():
    
    """
    System Integrity verifier takes a directory and writes all the files and folders present to a report.
    It also writes some features of file to report This happens in initialization mode.
    This then running in verification mode detects any changes in the directory of types
    if there are new folders, new files added, or existing files and folders deleted. 
    It also compares and reports changes in features of each file. This tool can be used to detect
    if any malicious agent is trying to make changes to sensitive files and folders in a system.
    
    Verification file has 2 types of entries. Lines starting with root: keyword are the directory names. The lines following them till next root: entry are files which are direct child files of the directory. The fields are separated by comma values: 

    FileName – Name of the File - String
    size_of_file – Size of file in bytes - Int
    name_of_user_owning_file – Owner of file 
    name_of group_owning_the_file – Group of file owner
    access_rights_of_file – Access rights of file
    time_of_last_update – Linux time stamp value of last update
    Message_digest – sha1 or md5 message digest of file calculated as per option
    Each of the entries is on a new line.

    The hash function can take 2 values : sha1 and md5. This is specified after -H.
    
    Initialization:
    
    python3 sivsaket.py -i -D path_to_monitor_directory -V path_to_verification_file -R path_to_report_file -H md5

    Verification:

    python3 sivsaket.py -v -D path_to_monitor_directory -V path_to_verification_file -R path_to_report_file

    Help:
    python3 sivsaket.py -h
    """
    return None

if __name__ == "__main__":
    main()
