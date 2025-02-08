
from statan import *
import importlib
from dyan import *
from conf import *
from optparse import OptionParser
import shutil
import time
import os
import sys
import subprocess
from analysis import *


if len(sys.argv) <= 1:
    print("Please give some options, type -h or --help for more information")
    sys.exit()


parser = OptionParser('Usage: %prog [Options] <file> [args]')

parser.add_option("-t", "--timeout", dest="timeout", help="timeout in seconds, default is 60 seconds", default="60", type="int")
parser.add_option("-p", "--perl", action="store_true", dest="perl", help="perl script (.pl)",  default=False)
parser.add_option("-P", "--python", action="store_true", dest="python", help="python script (.py)",  default=False)
parser.add_option("-z", "--php", action="store_true", dest="php", help="php script",  default=False)
parser.add_option("-s", "--shell", action="store_true", dest="shell_script", help="shell script",  default=False)
parser.add_option("-b", "--bash", action="store_true", dest="bash_script", help="BASH script",  default=False)
parser.add_option("-k", "--lkm", action="store_true", dest="lkm", help="load kernel module",  default=False)
parser.add_option("-x", "--printhexdump", action="store_true", dest="phexdump", help="print hex dump in call trace (both filtered and unfiltered call trace)", default=False)

(options, args) = parser.parse_args()

timeout = options.timeout
is_perl_script = options.perl
is_python_script = options.python
is_php_script = options.php
is_shell_script = options.shell_script
is_bash_script = options.bash_script
is_lkm = options.lkm
print_hexdump = options.phexdump


if is_perl_script:
    file_path = analysis_perl_path
    params = args[0:]
    mal_file = params[0]
    file_name = os.path.basename(mal_file)
    params[0] = analysis_mal_dir + '/' + file_name
    analysis_file_path = file_path

elif is_python_script:
    file_path = analysis_py_path
    params = args[0:]
    mal_file = params[0]
    file_name = os.path.basename(mal_file)
    params[0] = analysis_mal_dir + '/' + file_name
    analysis_file_path = file_path

elif is_php_script:
    file_path = analysis_php_path
    params = args[0:]
    mal_file = params[0]
    file_name = os.path.basename(mal_file)
    params[0] = analysis_mal_dir + '/' + file_name
    analysis_file_path = file_path

elif is_shell_script:
    file_path = analysis_sh_path
    params = args[0:]
    mal_file = params[0]
    file_name = os.path.basename(mal_file)
    params[0] = analysis_mal_dir + '/' + file_name
    analysis_file_path = file_path

elif is_bash_script:
    file_path = analysis_bash_path
    params = args[0:]
    mal_file = params[0]
    file_name = os.path.basename(mal_file)
    params[0] = analysis_mal_dir + '/' + file_name
    analysis_file_path = file_path

elif is_lkm:
    file_path = analysis_insmod_path
    params = args[0:]
    mal_file = params[0]
    file_name = os.path.basename(mal_file)
    params[0] = analysis_mal_dir + '/' + file_name
    analysis_file_path = file_path

else:
    file_path = args[0]
    mal_file = args[0]
    params = args[1:]
    os.chmod(file_path, 0o777)
    file_name = os.path.basename(file_path)
    analysis_file_path = analysis_mal_dir + "/" + file_name

filter_file_name = os.path.basename(file_path)

# Check if the given file is a ELF file
if not (is_perl_script or is_python_script or is_shell_script or is_bash_script or is_php_script):
    is_elf_file = True
# creating and cleaning the report directory (used to store the reports)
new_report_dir = report_dir + "/" + file_name
final_report = new_report_dir + "/final_report.txt"
desk_screenshot_path = new_report_dir + "/desktop.png"
pcap_output_path = new_report_dir + "/output.pcap"
capture_output_path = new_report_dir + "/capture_output.txt"

master_ssdeep_file = report_dir + "/ssdeep_master.txt"
ascii_str_file = new_report_dir + "/strings_ascii.txt"
unicode_str_file = new_report_dir + "/strings_unicode.txt"


# Creating the master ssdeep file
if not os.path.exists(master_ssdeep_file):
    mssdeepf = open(master_ssdeep_file, "w")
    mssdeepf.write("ssdeep,1.1--blocksize:hash:hash,filename\n")
    mssdeepf.close()

f = open(final_report, 'w')

# Dynamic analysis
f.write("==========================[DYNAMIC ANALYSIS RESULTS]==========================\n\n")

# reverting to clean snapshot and starting vm
analysis_vm = Vmware(host_vmrunpath, host_vmtype, host_analysis_vmpath)
analysis_vm.set_credentials(analysis_username, analysis_password)
analysis_vm.revert(analysis_clean_snapname)

#Changing the network type to bridged
cmd = 'sudo VBoxManage modifyvm ubuntu --nic1 bridged --bridgeadapter1 wlan0'.split()
subprocess.Popen(cmd)
time.sleep(2)   

print("Starting virtual machine for analysis")
if analysis_vm.start():
    print("...done...")
time.sleep(60)


#Getting VM's IP
print(analysis_ip)
analysis_ip = analysis_vm.get_ip()
print(analysis_ip)


iptables = Iptables(host_iface_to_sniff)
print("adding ip port redirection entries")
iptables.add_ip_port_redirect_entries()
iptables.display_ip_port_redirect_entries()
#os.chdir(os.path.dirname(inetsim_path))   # newly added
inetsim = Inetsim(inetsim_path)
print("cleaning inetsim log directory")
inetsim.clean_log_dir(inetsim_log_dir) # cleaning the log directory
print("cleaning inetsim report directory")
inetsim.clean_report_dir(inetsim_report_dir) # cleaning the report directory
print("starting inetsim")
inetsim.start()

print("Waiting for all the services to start")
time.sleep(40)

# transfer file to vm
analysis_copy_file_path = analysis_mal_dir + '/' + file_name
print("transferring file to virtual machine")
if analysis_vm.copytovm(mal_file, analysis_copy_file_path):
    print("...done...")


analysis_vm.execute_sysdig(analysis_sysdig_path, cap_filter, analysis_capture_out_file, filter_file_name)
print("starting monitoring on the analysis machine")
time.sleep(3)


# starting tcpdump
net = Tcpdump(host_tcpdumppath, pcap_output_path)
print("starting Network Monitor")
net.start_tcpdump(host_iface_to_sniff, analysis_ip)
time.sleep(5)

# executing file on the analysis machine
print("executing file for " + str(timeout) + " seconds")
analysis_vm.execute_file(analysis_file_path, params)
time.sleep(timeout)
print("...done...")


# run the sample using strace
analysis_vm.execute_strace_full(analysis_strace_path, analysis_strace_out_file, print_hexdump, analysis_file_path, params)
time.sleep(timeout)
print("...done...")


analysis_vm.execute_file("/usr/bin/ping",['-c', '3', '-W', '2', '8.8.8.8'])

# stopping sysdig
print("stopping monitoring")
analysis_vm.stop_sysdig()
time.sleep(4)

# stopping tcpdump
print("stopping Network Monitor")
net.stop_tcpdump()
time.sleep(3)
print('all done')


# copying sysdig capture file and strace output file to report directory

dirs = analysis_vm.list_dir(analysis_log_outpath)
log_files = analysis_vm.get_log_files_from_dir_list(dirs)
print(dirs,log_files)
if log_files:
    for log_file in log_files:
        log_file_path = analysis_log_outpath + '/' + log_file.decode()
        report_file_path = new_report_dir + "/" + log_file.decode()
        print(log_file_path,report_file_path)
        if analysis_vm.copyfromvm(log_file_path, report_file_path):
            print("successfully copied %s to report directory " % str(log_file))

# reading the sysdig captured file and dumping to a text file

cap_name = os.path.basename(analysis_capture_out_file)
capture_out_file = new_report_dir + '/' + cap_name
fname, ext = os.path.splitext(cap_name)
fname += ".txt"
capture_out_txt_file = new_report_dir + '/' + fname
analysis_vm.read_capture_and_dump(host_sysdig_path, capture_out_file, capture_out_txt_file, cap_format)
print("Dumped the captured data to the %s" % capture_out_txt_file)


# printing the captured data to report file

f.write("CALL TRACE ACTIVITIES\n")
f.write("=======================================\n")

sysdig_trace = analysis_vm.get_calltrace_activity(capture_out_txt_file)
print(sysdig_trace)
f.write(sysdig_trace)
f.write("\n")


strace_fname = os.path.basename(analysis_strace_out_file)
strace_out_fname = new_report_dir + "/" + strace_fname
strace_output = analysis_vm.get_calltrace_activity(strace_out_fname)
print(strace_output)
f.write(strace_output)
f.write("\n")


print("capturing desktop screenshot")
if analysis_vm.capturescreen(desk_screenshot_path):
    print("done, desktop screenshot saved as %s" % desk_screenshot_path)

print("suspending virtual machine")
if analysis_vm.suspend():
    print("...done...")

#--------------------------UPTO HERE DONE 
f.write("\n")
f.write("NETWORK ACTIVITIES\n")
f.write("=======================================\n\n")
# get and display tshark summary
f.write("DNS SUMMARY\n")
f.write("=======================================\n\n")
dns_summary = net.dns_summary()
print(dns_summary)
f.write(dns_summary.decode())
f.write("\n")
f.write("TCP CONVERSATIONS\n")
f.write("=======================================\n\n")
tcp_conversations = net.tcp_conv()
print(tcp_conversations)
f.write(tcp_conversations.decode())
f.write("\n")


# stopping inetsim, if internet option is not given

inetsim.stop()
time.sleep(8)  # This is requried so that all the inetsim services are stopped
f.write("INETSIM LOG DATA\n")
f.write("=======================================\n\n")
inetsim_log_data = inetsim.get_inetsim_log_data()
print(inetsim_log_data)
f.write(inetsim_log_data)
f.write("\n")
f.write("INETSIM REPORT DATA\n")
f.write("========================================\n\n")
inetsim_report_data = inetsim.get_inetsim_report_data()
print(inetsim_report_data)
f.write(inetsim_report_data)
f.write("\n")
print("done")
print("\n")

print("deleting ip port redirection entries")
iptables.delete_ip_port_redirect_entries()
iptables.display_ip_port_redirect_entries()

f.close()

print("Final report is stored in %s" % new_report_dir)


dyanamic_analyze_malware(file_name,args[0])