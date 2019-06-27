FireWall project is the final project of Workshop in information security in cooperation with industry experts from Check Point.

Grade: 100

The FireWall consists of a Linux Kernel module and an application layer which sum up to a physical device which protects the inner network from outer threats.

During the project, self researched on last-year discovered CVE-2018-10933 and developed protection against it by the implementation of SHH man-in-the-middle on the FireWall which is able to validate connection integrity. 
Another positive byproduct of this approach is the ability to inspect and filter the content passed over SSH encrypted communication.

FireWall contains also a Data Leak Prevention (DLP) module, which is able to block data leakage of code of different languages (C, C++, C#, Java, Python) while allowing innocent data or documentation sharing to pass.

Features:
* Filtering packets based on rules while logging them in a compact manner
* Blockage of XMAS packets AKA Kamikaze packet which is used by attackers for TCP/IP stack fingerprinting
* Stateful inspection for blocking files based on their content (i.e. executables or suspicious big files)
* Capable of handling TCP, UDP, SMTP, SSH, and FTP protocols:
* TCP connection is maintained according to state machine
* Enabling FTP data connection, in which, the client acts as a server and opens ports, therefore, using dynamic rules and removing them once the connection is closed
* Protection against last-year SSH LibAuth bypass AKA CVE-2018-10933
* Configurable and generic Data Leakage Module for different languages (C, C++, C#, Java, Python) while allowing innocent data or documentation sharing to pass.
