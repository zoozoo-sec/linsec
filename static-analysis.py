from statan import *
from conf import *
from optparse import OptionParser
import shutil
import time
import os
import sys
import glob
from analysis import *

# checking if filename and arguments are provided
if len(sys.argv) <= 1:
    print("Please give some options, type -h or --help for more information")
    sys.exit()

# adding and parsing  options
parser = OptionParser('Usage: %prog [Options] <file> [args]')

parser.add_option("-t", "--timeout", dest="timeout", help="timeout in seconds, default is 60 seconds", default="60", type="int")
parser.add_option("-i", "--internet", action="store_true", dest="internet", help = "connects to internet",  default=False)
parser.add_option("-p", "--perl", action="store_true", dest="perl", help="perl script (.pl)",  default=False)
parser.add_option("-P", "--python", action="store_true", dest="python", help="python script (.py)",  default=False)
parser.add_option("-z", "--php", action="store_true", dest="php", help="php script",  default=False)
parser.add_option("-s", "--shell", action="store_true", dest="shell_script", help="shell script",  default=False)
parser.add_option("-b", "--bash", action="store_true", dest="bash_script", help="BASH script",  default=False)
parser.add_option("-k", "--lkm", action="store_true", dest="lkm", help="load kernel module",  default=False)
parser.add_option("-C", "--ufctrace", action="store_true", dest="ufstrace", help="unfiltered call trace(full trace)", default=False)
parser.add_option("-e", "--femonitor", action="store_true", dest="femonitor", help="filtered system event monitoring", default=False)
parser.add_option("-E", "--ufemonitor", action="store_true", dest="ufemonitor", help="unfiltered system event monitoring", default=False)
parser.add_option("-m", "--memfor", action="store_true", dest="memfor", help="memory forensics", default=False)
parser.add_option("-M", "--vmemfor", action="store_true", dest="ver_memfor", help="verbose memory forensics(slow)", default=False)
parser.add_option("-x", "--printhexdump", action="store_true", dest="phexdump", help="print hex dump in call trace (both filtered and unfiltered call trace)", default=False)

(options, args) = parser.parse_args()

timeout = options.timeout
internet = options.internet
is_perl_script = options.perl
is_python_script = options.python
is_php_script = options.php
is_shell_script = options.shell_script
is_bash_script = options.bash_script
is_full_strace = options.ufstrace
is_femonitor = options.femonitor
is_ufemonitor = options.ufemonitor
is_ver_memfor = options.ver_memfor
is_lkm = options.lkm
is_memfor = options.memfor
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
if os.path.isdir(new_report_dir):
    shutil.rmtree(new_report_dir)
os.mkdir(new_report_dir)
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


f.write( "===========================[STATIC ANALYSIS RESULTS]===========================\n\n")
#static = Static(file_path)
static = Static(mal_file)
filetype = static.filetype()
print(("Filetype: %s" % filetype))
f.write("Filetype: %s" % filetype)
f.write("\n")

file_size = static.get_file_size()
print(("File Size: %0.2f KB (%s bytes)" % (file_size/1024.0, file_size)))
f.write("File Size: %0.2f KB (%s bytes)" % (file_size/1024.0, file_size))
f.write("\n")

md5sum = static.md5sum()
print(("md5sum: %s" % md5sum))
f.write("md5sum: %s" % md5sum)
f.write("\n")

fhash = static.ssdeep()
fuzzy_hash = fhash.split(b",")[0]
print(("ssdeep: %s" % fuzzy_hash))
f.write("ssdeep: %s" % fuzzy_hash)
f.write("\n")

if is_elf_file:
    elf_header = static.elf_header()
    print(elf_header)
    f.write(str(elf_header))
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")

ssdeep_compare = static.ssdeep_compare(master_ssdeep_file)
print("ssdeep comparison:")
print(ssdeep_compare)
print(dash_lines)
f.write("ssdeep comparison:")
f.write("\n")
f.write(str(ssdeep_compare))
f.write("\n")
f.write(dash_lines)
f.write("\n")
fm = open(master_ssdeep_file, 'a')
fm.write(str(fhash + b"\n"))
fm.close()


asc_strings = static.ascii_strings()
fs = open(ascii_str_file, 'w')
fs.write(str(asc_strings))
fs.close()
print("Strings:")
print(("\tAscii strings written to %s" % ascii_str_file))
f.write("Strings:")
f.write("\n")
f.write("\tAscii strings written to %s" % ascii_str_file)
f.write("\n")

unc_strings = static.unicode_strings()
fu = open(unicode_str_file, 'w')
fu.write(str(unc_strings))
fu.close()
print(("\tUnicode strings written to %s" % unicode_str_file))
print(dash_lines)
f.write("\tUnicode strings written to %s" % unicode_str_file)
f.write("\n")
f.write(dash_lines)
f.write("\n")

if is_elf_file and yara_packer_rules:
    yara_packer = str(static.yararules(yara_packer_rules))
    print("Packers:")
    print(("\t" + yara_packer))
    print(dash_lines)
    f.write("Packers:")
    f.write("\n")
    f.write("\t" + yara_packer)
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")

if yara_rules:
    yara_capabilities = str(static.yararules(yara_rules))
    print("Malware Capabilities and classification using YARA rules:")
    print(("\t" + yara_capabilities))
    print(dash_lines)
    f.write("Malware Capabilities and classification using YARA rules:")
    f.write("\n")
    f.write("\t" + yara_capabilities)
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")

print(("Virustotal:\n" + "\t"))
f.write("Virustotal:\n" + "\t")
f.write("\n")
avresults = static.virustotal(virustotal_key)
if avresults !=None:
    avvendors = list(avresults.keys())
    avvendors.sort()
    for avvendor in avvendors:
        print(("\t  " + avvendor + " ==> " + avresults[avvendor]))
        f.write("\t  " + avvendor + " ==> " + avresults[avvendor])
        f.write("\n")
print(dash_lines)
f.write(dash_lines)
f.write("\n")

#-------------------------VIRSUTOTAL AV CHECK:
print("STARTS HERE")
analysis_id = static.upload_file_to_virustotal(mal_file, virustotal_key)

if analysis_id:
        analysis_results = static.get_analysis_results(analysis_id, virustotal_key)
        detected_avs = static.parse_av_results(analysis_results)
for i in detected_avs:print(i)
f.write(f"{'-'*20}FILE DETECTED BY AVS{'-'*20}")
for i in detected_avs:f.write(f'\n {i}')

if is_elf_file:
    depends = static.dependencies()
    if depends:
        print("Dependencies:")
        print(depends)
        print(dash_lines)
        f.write("\nDependencies:")
        f.write("\n")
        f.write(str(depends))
        f.write("\n")
        f.write(dash_lines)
        f.write("\n")

    prog_header = static.program_header()
    print("Program Header Information:")
    print(prog_header)
    print(dash_lines)
    f.write("Program Header Information:")
    f.write("\n")
    f.write(str(prog_header))
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")

    sect_header = static.section_header()
    print("Section Header Information:")
    print(sect_header)
    print(dash_lines)
    f.write("Section Header Information:")
    f.write("\n")
    f.write(str(sect_header))
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")

    syms = static.symbols()
    print("Symbol Information:")
    print(syms)
    print(dash_lines)
    f.write("Symbol Information:")
    f.write("\n")
    f.write(str(syms))
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")
f.close()

print("ALL DONE")

#ANALYSE THE REPORT GEMINI
static_analyze_malware(file_name,args[0])
