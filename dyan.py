
import subprocess
import sys
import os
import glob
import re
import psutil
import time;

#############################[inetsim class]#########################################


class Inetsim:
    def __init__(self, inetsim_path):
        self.inetsim_path = inetsim_path
        self.proc = None
        self.log_dir = ""
        self.report_dir = ""

    def clean_log_dir(self, log_dir):
        self.log_dir = log_dir
        current_dir = os.getcwd()
        os.chdir(self.log_dir)
        log_files = glob.glob('*')
        for log_file in log_files:
            if os.path.isfile(log_file):
                os.remove(log_file)
        os.chdir(current_dir)

    def clean_report_dir(self, report_dir):
        self.report_dir = report_dir
        current_dir = os.getcwd()
        os.chdir(self.report_dir)
        report_files = glob.glob('*')
        for report_file in report_files:
            if os.path.isfile(report_file):
                os.remove(report_file)
        os.chdir(current_dir)

    def start(self):
        self.proc = subprocess.Popen(["/usr/bin/sudo",self.inetsim_path])

    def stop(self):
        processes = psutil.process_iter()
        for proc in processes:
            if "inetsim_main" in proc.name():
                proc.terminate()


    def get_inetsim_log_data(self):
        service_log = self.log_dir + "/service.log"
        is_exist = os.path.exists(service_log)
        if is_exist:
            log_data = open(service_log).read()
            return log_data
        else: return "NO LOGS IN SERVICE.LOG"
    def get_inetsim_report_data(self):
        report_data = ""
        report_files = glob.glob(self.report_dir + "/*")
        for report_file in report_files:
            f = open(report_file)
            report_data += f.read()
            f.close()
        return report_data
##############################[end of inetsim class]###################################

##############################[vmware class] ##########################################


class Vmware:

    def __init__(self, host_vmrun_path, host_vmtype, vmpath):
        self.host_vmrun_path = host_vmrun_path
        self.host_vmtype = host_vmtype
        self.vmpath = vmpath
        self.username = ""
        self.password = ""

    def set_credentials(self, username, password):
        self.username = username
        self.password = password

    def revert(self,snapshot):#VBoxManage snapshot <vm-name> restore <snapshot-name>
        proc = subprocess.Popen([self.host_vmrun_path, b'snapshot', self.host_vmtype, 'restore', b'clean'], stdout=subprocess.PIPE)
        vm_stdout = proc.communicate()[0]
        if len(vm_stdout)==0:
            print(vm_stdout)
            print("Exiting the program")
            sys.exit()
        else:
            print("inga irkennnn")
            return 1

    def start(self):#VBoxManage startvm <vm-name> --type headless
        proc = subprocess.Popen([self.host_vmrun_path, b'startvm', self.host_vmtype, b'--type', b'headless'], stdout=subprocess.PIPE)
        vm_stdout = proc.communicate()[0]
        if len(vm_stdout)==0:
            print(vm_stdout)
            print("Exiting the program!!!")
            sys.exit()
        else:
            return 1

    def copytovm(self, src, dst):#VBoxManage guestcontrol ubuntu copyto ../book.zip /home/osboxes/ --username osboxes --password osboxes.org 
        proc = subprocess.Popen([self.host_vmrun_path, b"guestcontrol", self.host_vmtype,b"copyto",src,dst, b"--username",self.username, b"--password", self.password], stdout=subprocess.PIPE)
        time.sleep(2)
        make_exec = subprocess.Popen([self.host_vmrun_path, "guestcontrol", self.host_vmtype,"run","--username", self.username, "--password", self.password, "--exe","/usr/bin/sudo","--","/usr/bin/chmod","+x",dst], stdout=subprocess.PIPE)

        vm_stdout = proc.communicate()[0]
        if vm_stdout:
            print(vm_stdout)
            print("Exiting the program")
            sys.exit()
        else:
            return 1

    def copyfromvm(self, src, dst):#VBoxManage guestcontrol ubuntu copyfrom /home/osboxes/book.zip ./ --username osboxes --password osboxes.org
        give_privs = subprocess.Popen([self.host_vmrun_path, "guestcontrol", self.host_vmtype,"run","--username", self.username, "--password", self.password, "--exe","/usr/bin/sudo","--","/usr/bin/chown","osboxes",src], stdout=subprocess.PIPE)
        time.sleep(2)
        print("CHANGED PRIVS")
        proc = subprocess.Popen([self.host_vmrun_path, "guestcontrol", self.host_vmtype,"copyfrom",src,dst,"--username", self.username, "--password", self.password], stdout=subprocess.PIPE)
        vm_stdout = proc.communicate()[0]
        if vm_stdout:
            print(vm_stdout)
            print("Exiting the program")
            sys.exit()
        else:
            return 1

    def capturescreen(self, dst):#VBoxManage controlvm ubuntu  screenshotpng ./super
        proc = subprocess.Popen([self.host_vmrun_path, "controlvm", self.host_vmtype,"screenshotpng",dst], stdout=subprocess.PIPE)
        vm_stdout = proc.communicate()[0]
        print("\n\n\n\nSCREEN LA IDHU",vm_stdout)
        if len(vm_stdout)!=0:
            print(vm_stdout)
            print("Exiting the program")
            sys.exit()#VBoxManage controlvm "<vm-name>" poweroff
        else:
            return 1

    def suspend(self):#VBoxManage controlvm "<vm-name>" savestate
        proc = subprocess.Popen([self.host_vmrun_path, b'controlvm', self.host_vmtype,b'savestate'], stdout=subprocess.PIPE)
        vm_stdout = proc.communicate()[0]
        if len(vm_stdout)!=0:
            print(vm_stdout)
            print("Exiting the program")
            sys.exit()
        else:
            print('Done')
            return 1


    def stop(self):#VBoxManage controlvm "<vm-name>" poweroff
        proc = subprocess.check_call([self.host_vmrun_path, "controlvm", self.host_vmtype, "poweroff"], stdout=subprocess.PIPE)
        vm_stdout = proc.communicate()[0]
        if len(vm_stdout)==0:
            print("Exiting the program")
            sys.exit()
        else:
            return 1

# List directory in guest
    def list_dir(self, dir_name):#VBoxManage guestcontrol ubuntu run --username osboxes --password osboxes.org --exe "/bin/ls" --   /home/osboxes
        proc = subprocess.Popen([self.host_vmrun_path, "guestcontrol", self.host_vmtype,"run","--username", self.username, "--password", self.password, "--exe","/usr/bin/sudo","--","/usr/bin/ls",dir_name], stdout=subprocess.PIPE)
        vm_stdout = proc.communicate()[0]
        dirs = vm_stdout.split(b"\n")
        return dirs

# get .log, .txt and .csv related to dtrace and nori from log directory
    def get_log_files_from_dir_list(self, dir_list):
        log_files = []
        for each_file in dir_list:
            value = each_file.find(b".scap")
            value1 = each_file.find(b".txt")
            if value != -1 or value1 != -1:
                log_files.append(each_file)
        return log_files

    def list_process_guest(self):#VBoxManage guestcontrol ubuntu run --username osboxes --password osboxes.org --exe "/bin/ps" -- aux
        listprocess = subprocess.Popen([self.host_vmrun_path, "guestcontrol", self.host_vmtype,"run","--username", self.username, "--password", self.password, "--exe","/usr/bin/sudo","--","/usr/bin/ps","aux"], stdout=subprocess.PIPE)
        processes = listprocess.communicate()[0]
        process_list = processes.split("\r\n")
        for process in process_list:
            print(process)

    def stop_sysdig(self):#VBoxManage guestcontrol ubuntu run --username osboxes --password osboxes.org --exe "/bin/ps" -- aux
        
        ps_process = subprocess.Popen([self.host_vmrun_path, "guestcontrol", self.host_vmtype, "run", "--username", self.username, "--password", self.password, "--exe", "/usr/bin/sudo", "--", "/usr/bin/ps", "aux"], stdout=subprocess.PIPE)
        grep_process = subprocess.Popen(["grep", "/usr/bin/sysdig"], stdin=ps_process.stdout, stdout=subprocess.PIPE)

        processes = grep_process.communicate()[0]
        pids = re.findall(r'^\S+\s+(\d+)', processes.decode(), re.MULTILINE)
        for pid in pids:
            subprocess.check_call([self.host_vmrun_path, "guestcontrol", self.host_vmtype,"run","--username", self.username, "--password", self.password, "--exe","/usr/bin/sudo","--","/usr/bin/kill","-9",pid], stdout=subprocess.PIPE)

    def execute_file(self, mal_file, args):#VBoxManage guestcontrol ubuntu run --username osboxes --password osboxes.org --exe "/home/osboxes/bash" -- *arg
        cmd = [self.host_vmrun_path, "guestcontrol", self.host_vmtype,"run","--username", self.username, "--password", self.password, "--exe", mal_file, "--"]
        cmd.extend(args) 
        try:
            subprocess.check_call(cmd)
        except Exception as e:
            return 0

    def execute_sysdig(self, sysdig_file, cap_filter, cap_out_file, filter_file_name):
        cap_filter = cap_filter + " " + "and (proc.name=" + filter_file_name + " " + "or proc.aname=" + filter_file_name + ")"
        subprocess.Popen([self.host_vmrun_path, "guestcontrol", self.host_vmtype,"run","--username", self.username, "--password", self.password, "--exe","/usr/bin/sudo","--",sysdig_file, cap_filter, "-w", cap_out_file])

    def execute_sysdig_full(self, sysdig_file, cap_out_file, filter_file_name):
        cap_filter = "proc.name=" + filter_file_name + " " + "or proc.aname=" + filter_file_name
        subprocess.check_call([self.host_vmrun_path, "guestcontrol", self.host_vmtype,"run","--username", self.username, "--password", self.password, "--exe","/usr/bin/sudo", "--",sysdig_file, cap_filter, "-w", cap_out_file])

    def execute_strace_full(self, strace_path, strace_out_file, print_hexdump, mal_file, args):
        if print_hexdump:
            cmd = [self.host_vmrun_path, "guestcontrol", self.host_vmtype,"run","--username", self.username, "--password", self.password, "--exe","/usr/bin/sudo","--",strace_path, "-o", strace_out_file, "-s", "64", "-eread=all", "-ewrite=all", "-f", mal_file]
        else:
            cmd = [self.host_vmrun_path, "guestcontrol", self.host_vmtype,"run","--username", self.username, "--password", self.password, "--exe","/usr/bin/sudo","--",strace_path, "-o", strace_out_file, "-s", "216", "-f", mal_file]
        cmd.extend(args)
        try:
            subprocess.check_call(cmd)
        except Exception as e:
            return 0

    def read_capture_and_dump(self, host_sysdig_path, capture_out_file, capture_out_txt_file, cap_format):
        cap_format = '"' + cap_format + '"'
        cmd = host_sysdig_path + " " + "-p" + cap_format + " " + "-r" + " " + capture_out_file + " > " + capture_out_txt_file
        p = subprocess.Popen(cmd, shell=True)
        p.wait()

    def get_calltrace_activity(self, outfile_path):
        results = open(outfile_path).read()
        return results

    def get_ip(self):
        guestcontrol_command = ["sudo", "VBoxManage", "guestcontrol", "ubuntu", "run", "--username", "osboxes", "--password", "osboxes.org","--exe", "/usr/bin/sudo", "--", "ifconfig"]
        process = subprocess.Popen(guestcontrol_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(3)
        stdout, stderr = process.communicate()
        if stderr:
            raise Exception(f"Error in VBoxManage command: {stderr.decode()}")
        grep_command = ["grep", "-Po", "inet\\s(\\d+\\.\\d+\\.\\d+\\.\\d+)"]

        grep_process = subprocess.Popen(grep_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)
        grep_stdout, grep_stderr = grep_process.communicate(input=stdout)
        if grep_stderr:
            raise Exception(f"Error in grep command: {grep_stderr.decode()}")
        ip_address = grep_stdout.decode().split('\n')[0][5:]
        return ip_address



#######################################[end of vmware class]###################################
 
########################################[tcpdump class]############################################
class Tcpdump:
    def __init__(self, tcpdump_path, out_pcap):
        if not os.path.isfile(tcpdump_path):
            print("cannot find tcpdump in %s" % tcpdump_path)
            print("Exiting the program")
            sys.exit()

        self.tcpdump_path = tcpdump_path
        self.out_pcap = out_pcap
        self.proc = None

    def start_tcpdump(self, iface, ip):
        try:
            self.proc = subprocess.Popen(["sudo",self.tcpdump_path, '-n', '-i', iface, 'host %s' % ip,  '-w', self.out_pcap])
        except subprocess.CalledProcessError as e:
            print("ERROR RETURN CODE 33")
            return 0
    def stop_tcpdump(self):
        if self.proc != None:
            self.proc.terminate()

    def dns_summary(self):
        proc = subprocess.Popen(["sudo",self.tcpdump_path, '-n', '-r', self.out_pcap, "udp and port 53"], stdout=subprocess.PIPE)
        dns_queries = proc.communicate()[0]
        return dns_queries

    def tcp_conv(self):
        proc = subprocess.Popen(["sudo",self.tcpdump_path,'-n', '-q', '-r', self.out_pcap, "tcp"], stdout=subprocess.PIPE)
        tcp_conversations = proc.communicate()[0]
        return tcp_conversations


########################################[end of tcpdump class]######################################



########################################[iptables class]##########################################

class Iptables:

    def __init__(self, iface):
        self.iface = iface

    def add_ip_port_redirect_entries(self):
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "2:6", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "8", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "10:12", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "14:16", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "18", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "20:36", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "38:52", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "54:68", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "70:122", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "124:513", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "515:65535", "-j", "REDIRECT", "--to-port", "1"])

        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "7", "-j", "REDIRECT", "--to-port", "7"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "9", "-j", "REDIRECT", "--to-port", "9"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "13", "-j", "REDIRECT", "--to-port", "13"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "17", "-j", "REDIRECT", "--to-port", "17"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "19", "-j", "REDIRECT", "--to-port", "19"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "37", "-j", "REDIRECT", "--to-port", "37"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "69", "-j", "REDIRECT", "--to-port", "69"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "123", "-j", "REDIRECT", "--to-port", "123"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "514", "-j", "REDIRECT", "--to-port", "514"])

        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "2:6", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "8:12", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "14:16", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "18", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "20", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "22:24", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "26:36", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "38:52", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "54:78", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "81:109", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "111:112", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "114:442", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "444:464", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "466:989", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "991:994", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "996:6666", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "6668:65535", "-j", "REDIRECT", "--to-port", "1"])

        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "7", "-j", "REDIRECT", "--to-port", "7"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "13", "-j", "REDIRECT", "--to-port", "13"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "17", "-j", "REDIRECT", "--to-port", "17"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "19", "-j", "REDIRECT", "--to-port", "19"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "21", "-j", "REDIRECT", "--to-port", "21"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "25", "-j", "REDIRECT", "--to-port", "25"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "37", "-j", "REDIRECT", "--to-port", "37"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "79", "-j", "REDIRECT", "--to-port", "79"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "80"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "110", "-j", "REDIRECT", "--to-port", "110"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "113", "-j", "REDIRECT", "--to-port", "113"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "443"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "465", "-j", "REDIRECT", "--to-port", "465"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "990", "-j", "REDIRECT", "--to-port", "990"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "995", "-j", "REDIRECT", "--to-port", "995"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "6667", "-j", "REDIRECT", "--to-port", "6667"])

    def delete_ip_port_redirect_entries(self):
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "2:6", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "8", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "10:12", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "14:16", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "18", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "20:36", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "38:52", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "54:68", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "70:122", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "124:513", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "515:65535", "-j", "REDIRECT", "--to-port", "1"])

        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "7", "-j", "REDIRECT", "--to-port", "7"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "9", "-j", "REDIRECT", "--to-port", "9"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "13", "-j", "REDIRECT", "--to-port", "13"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "17", "-j", "REDIRECT", "--to-port", "17"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "19", "-j", "REDIRECT", "--to-port", "19"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "37", "-j", "REDIRECT", "--to-port", "37"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "69", "-j", "REDIRECT", "--to-port", "69"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "123", "-j", "REDIRECT", "--to-port", "123"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "514", "-j", "REDIRECT", "--to-port", "514"])

        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "2:6", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "8:12", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "14:16", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "18", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "20", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "22:24", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "26:36", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "38:52", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "54:78", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "81:109", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "111:112", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "114:442", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "444:464", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "466:989", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "991:994", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "996:6666", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "6668:65535", "-j", "REDIRECT", "--to-port", "1"])

        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "7", "-j", "REDIRECT", "--to-port", "7"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "13", "-j", "REDIRECT", "--to-port", "13"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "17", "-j", "REDIRECT", "--to-port", "17"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "19", "-j", "REDIRECT", "--to-port", "19"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "21", "-j", "REDIRECT", "--to-port", "21"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "25", "-j", "REDIRECT", "--to-port", "25"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "37", "-j", "REDIRECT", "--to-port", "37"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "79", "-j", "REDIRECT", "--to-port", "79"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "80"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "110", "-j", "REDIRECT", "--to-port", "110"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "113", "-j", "REDIRECT", "--to-port", "113"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "443"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "465", "-j", "REDIRECT", "--to-port", "465"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "990", "-j", "REDIRECT", "--to-port", "990"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "995", "-j", "REDIRECT", "--to-port", "995"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "6667", "-j", "REDIRECT", "--to-port", "6667"])


    def display_ip_port_redirect_entries(self):
        output = subprocess.check_output(["iptables", "-L", "-t" "nat"])
        print(output)


#############################################[end of fileregmon class]############################