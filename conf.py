
py_path = r'/usr/bin/python'
report_dir = r'./root/linux_reports'
dash_lines = "-" * 40
is_elf_file = False
virustotal_key = "3ac3d5a1bb43d11a74b02bd0ab87db5cd74362c70e050f5b779a381872d85314"

host_analysis_vmpath = r'/root/virtual_machines/Ubuntu12_04/Ubuntu12_04.vmx'
host_vmrunpath = r'/usr/bin/VBoxManage'
host_vmtype = r'ubuntu'
analysis_username = "osboxes"
analysis_password = "osboxes.org"
analysis_clean_snapname = "clean"
analysis_mal_dir = r"/home/osboxes/analysis"
analysis_py_path = r'/usr/bin/python'
analysis_perl_path = r'/usr/bin/perl'
analysis_bash_path = r'/bin/bash'
analysis_sh_path = r'/bin/sh'
analysis_insmod_path = r'/sbin/insmod'
analysis_php_path = r'/usr/bin/php'


################[static analyis variables]##########################
yara_packer_rules = r'./root/yara_rules/packer.yara'
yara_rules = r'./root/yara_rules/capabilities.yara'

#################[network variables]#################################
analysis_ip = "192.168.1.5"
host_iface_to_sniff = "wlan0"
host_tcpdumppath = "/usr/bin/tcpdump"

#######################[memory anlaysis variables]##################

vol_path = r'/home/osboxes/analysis/Volatility/vol.py'
mem_image_profile = '--profile=LinuxUbuntu1204x64'

######################[inetsim variables]#########################
inetsim_path = r"/usr/bin/inetsim"
inetsim_log_dir = r"/var/log/inetsim"
inetsim_report_dir = r"/var/log/inetsim/report"

######################[monitoring varibales]##########################

analysis_sysdig_path = r'/usr/bin/sysdig'
host_sysdig_path = r'/usr/bin/sysdig'
analysis_capture_out_file = r'/home/osboxes/analysis/logdir/capture.scap'

cap_format = "%proc.name (%thread.tid) %evt.dir %evt.type %evt.args"
cap_filter = r"""evt.type=clone or evt.type=execve or evt.type=chdir or evt.type=open or
evt.type=creat or evt.type=close or evt.type=socket or evt.type=bind or evt.type=connect or
evt.type=accept or evt.is_io=true or evt.type=unlink or evt.type=rename or evt.type=brk or
evt.type=mmap or evt.type=munmap or evt.type=kill or evt.type=pipe"""

analysis_strace_path = r'/usr/bin/strace'
strace_filter = r"-etrace=fork,clone,execve,chdir,open,creat,close,socket,connect,accept,bind,read,write,unlink,rename,kill,pipe,dup,dup2"
analysis_strace_out_file = r'/home/osboxes/analysis/logdir/trace.txt'

analysis_log_outpath = r'/home/osboxes/analysis/logdir'
params = []





