![visitors](https://visitor-badge.glitch.me/badge?page_id=AvivYaniv.FireWall.issue.1) <br/>
[![HitCount](http://hits.dwyl.com/AvivYaniv/FireWall.svg)](http://hits.dwyl.com/AvivYaniv/FireWall) <br/>

FireWall project is the final project of Workshop in information security at Tel-Aviv University in cooperation with industry experts from Check Point.

Grade: 100

Lines of Code :~10,000

The FireWall consists of a Linux Kernel module and an application layer that sum up to a physical device that protects the inner network from outer threats.

During the project, self researched on last-year discovered [CVE-2018-10933](https://nvd.nist.gov/vuln/detail/CVE-2018-10933) and [developed protection against it by the implementation of SHH man-in-the-middle on the FireWall which is able to validate connection integrity](https://medium.com/@AvivYaniv/firewall-defense-from-libssh-authentication-bypass-aka-cve-2018-10993-1a6d3d1bef87). 
Another positive byproduct of this approach is the ability to inspect and filter the content passed over [SSH](https://en.wikipedia.org/wiki/Secure_Shell) encrypted communication.

FireWall contains also a [Data Leak Prevention (DLP)](https://en.wikipedia.org/wiki/Data_loss_prevention_software) module, which is able to block data leakage of code of different languages (C, C++, C#, Java, Python) while allowing innocent data or document sharing to pass.

Features:
* Filtering packets based on rules while logging them in a compact manner
* Blockage of [XMAS packets AKA Kamikaze packet](https://en.wikipedia.org/wiki/Christmas_tree_packet) which is used by attackers for TCP/IP stack fingerprinting
* Stateful inspection for blocking files based on their content (i.e. executables or suspicious big files)
* Capable of handling TCP, UDP, SMTP, FTP, ***and SSH*** protocols:
* TCP connection is maintained according to a state machine
* Enabling [FTP](https://en.wikipedia.org/wiki/File_Transfer_Protocol) data connection, in which, the client acts as a server and opens ports, therefore, using dynamic rules and removing them once the connection is closed
* [Protection](https://medium.com/@AvivYaniv/firewall-defense-from-libssh-authentication-bypass-aka-cve-2018-10993-1a6d3d1bef87) against last-year [SSH LibAuth bypass AKA CVE-2018-10933](https://nvd.nist.gov/vuln/detail/CVE-2018-10933)
* Configurable and generic Data Leakage Module for different languages (C, C++, C#, Java, Python) while allowing innocent data or document sharing to pass.

<p align="center">
    <img src="https://github.com/AvivYaniv/FireWall/blob/master/logo/Firewall.png" width="30%"/>
<p/>
