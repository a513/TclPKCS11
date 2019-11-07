#! /usr/bin/env tclsh

#set pkcs11_module "/usr/local/lib/libcackey.so"
set pkcs11_module "/usr/local/lib64/libls11sw2016.so"
#set pkcs11_module "/usr/local/lib64/librtpkcs11ecp_2.0.so"

load ./tclpkcs11.so Tclpkcs11

set handle [pki::pkcs11::loadmodule $pkcs11_module]
puts "Handle: $handle"
if {0} {
set slots [pki::pkcs11::listslots $handle]
puts "Slots: $slots"
foreach slotinfo $slots {
	set slotid [lindex $slotinfo 0]
	set slotlabel [lindex $slotinfo 1]
	set slotflags [lindex $slotinfo 2]

	if {[lsearch -exact $slotflags TOKEN_PRESENT] != -1} {
		set token_slotlabel $slotlabel
		set token_slotid $slotid
		break
	}
}
}
set token_slotid 0
#puts "$token_slotlabel: $slotid"
puts "token_slotid = \"$token_slotid\""

puts "Enter SO-PIN  for you token:"
#set password "87654321"
gets stdin password
puts "Enter new label  for you token:"
gets stdin label
set ret [pki::pkcs11::inittoken $handle $token_slotid $password $label]
if {$ret == 0 } {
    puts "Bad SO-PIN"
    exit
}
set slots [pki::pkcs11::listslots $handle]
foreach slotinfo $slots {
    set slotid [lindex $slotinfo 0]
    set slotlabel [lindex $slotinfo 1]
    set slotflags [lindex $slotinfo 2]
    set tokeninfo [lindex $slotinfo 3]
    puts "$tokeninfo"
}
set sopin "87654321"
set userpin "1111"
puts "Enter SO-PIN  for you token:"
#set password "87654321"
gets stdin sopin
puts "Enter user PIN  for you token:"
gets stdin userpin
set ret [pki::pkcs11::inituserpin $handle $token_slotid $sopin $userpin]
if {$ret == 0 } {
    puts "inituserpin: Bad SO-PIN"
    exit
}
puts "Enter new user PIN  for you token:"
gets stdin newpin
set ret [pki::pkcs11::setpin $handle $token_slotid user $userpin $newpin]
puts "RET=$ret"
exit

