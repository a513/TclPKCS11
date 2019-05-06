#! /usr/bin/env tclsh
package require pki
lappend auto_path .
#package require pki::pkcs11
load tclpkcs11.so Tclpkcs11
#Задайте путь к вашей библиотеке PKCS#11
set pkcs11_module "/usr/local/lib64/librtpkcs11ecp_2.0.so"
#set pkcs11_module "/usr/local/lib64/libls11sw2016.so"
puts "Connect the Token and press Enter"
gets stdin yes

set handle [pki::pkcs11::loadmodule $pkcs11_module]
set slots [pki::pkcs11::listslots $handle]
foreach slotinfo $slots {
	set slotid [lindex $slotinfo 0]
	set slotlabel [lindex $slotinfo 1]
	set slotflags [lindex $slotinfo 2]

	if {[lsearch -exact $slotflags TOKEN_PRESENT] != -1} {
		set token_slotlabel $slotlabel
		set token_slotid $slotid
#Найден слот с токеном
		break
	}
}

proc usage {use error} {
    puts "Copyright(C) Orlov Vladimir (http://soft.lissi.ru) 2019"
    if {$use == 1} {
	puts $error
	puts "Usage:\ndigest <stribog256|stribog512> <file for digest>\n"
    }
}

set countcert [llength $argv]
if { $countcert != 2 } {
    usage 1 "Bad usage!"
    exit
}
set digest_algo [lindex $argv 0]
if {$digest_algo != "stribog256" && $digest_algo != "stribog512"} {
    usage 1 "Bad usage!"
    exit
}
set file [lindex $argv 1]
if {![file exists $file]} {
    usage 1 "File $file not exist"
    exit
}
puts "Loading file for digest: $file"
set fd [open $file]
chan configure $fd -translation binary
set cert_user [read $fd]
close $fd
if {$cert_user == "" } {
    usage 1 "Bad file with certificate user: $file"
    exit
}

set aa [dict create pkcs11_handle $handle pkcs11_slotid $token_slotid]
set digest_hex    [pki::pkcs11::digest $digest_algo $cert_user  $aa]
puts "digest_hex=$digest_hex"
puts [string length $digest_hex]

set digest_hex    [pki::pkcs11::dgst $digest_algo $cert_user ]
puts "digest_hex_not_pkcs11=$digest_hex"
puts [string length $digest_hex]

exit
